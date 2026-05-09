import dotenv from "dotenv";
import { StreamingTextResponse, LangChainStream } from "ai";
import { Replicate } from "langchain/llms/replicate";
import { CallbackManager } from "langchain/callbacks";
import clerk from "@clerk/clerk-sdk-node";
import MemoryManager from "@/app/utils/memory";
import { currentUser } from "@clerk/nextjs";
import { NextResponse } from "next/server";
import { rateLimit } from "@/app/utils/rateLimit";
import crypto from "crypto";
import { promises as fsAudit } from "fs";
import path from "path";

// ---------------------------------------------------------------------------
// Audit helpers
// ---------------------------------------------------------------------------
const AUDIT_LOG_PATH = path.resolve(process.cwd(), "logs", "ai_decisions.jsonl");
/** Retention period expressed as days; consumers of the log must honour this. */
const AUDIT_RETENTION_DAYS = 90;

function sha256(text: string): string {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

async function writeAuditRecord(record: Record<string, unknown>): Promise<void> {
  const line = JSON.stringify(record) + "\n";
  // Ensure the logs directory exists before writing.
  await fsAudit.mkdir(path.dirname(AUDIT_LOG_PATH), { recursive: true });
  await fsAudit.appendFile(AUDIT_LOG_PATH, line, { encoding: "utf8" });
}

dotenv.config({ path: `.env.local` });

function containsMaliciousContent(input: string): boolean {
  if (!input || typeof input !== 'string') return false;

  // Check for shell command patterns
  const shellCommandPattern = /(?:^|\s|;|\||&|`)(\s*)(rm\s+-|chmod\s+|chown\s+|wget\s+|curl\s+|bash\s+|sh\s+|exec\s+|eval\s+|system\s*\(|popen\s*\(|subprocess|os\.system|__import__|nc\s+-|ncat\s+|netcat\s+|python\s+-c|perl\s+-e|ruby\s+-e|php\s+-r)/i;
  if (shellCommandPattern.test(input)) return true;

  // Check for base64-encoded content (long base64 strings that may hide payloads)
  const base64Pattern = /(?:[A-Za-z0-9+\/]{40,}={0,2})/;
  if (base64Pattern.test(input)) {
    try {
      const decoded = Buffer.from(input.match(base64Pattern)![0], 'base64').toString('utf8');
      if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(decoded)) return true;
      if (shellCommandPattern.test(decoded)) return true;
    } catch {}
  }

  // Check for binary/non-printable characters
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(input)) return true;

  // Check for prompt injection patterns
  const promptInjectionPattern = /(?:ignore\s+(?:previous|above|prior|all)\s+instructions?|disregard\s+(?:previous|above|prior|all)|forget\s+(?:previous|above|prior|all)|you\s+are\s+now|act\s+as\s+(?:a\s+)?(?:different|new|another)|new\s+instructions?\s*:|system\s*:\s*you|<\s*system\s*>|\[\s*system\s*\]|###\s*system|###\s*instruction)/i;
  if (promptInjectionPattern.test(input)) return true;

  // Check for leetspeak obfuscation of dangerous words
  const normalizedInput = input
    .replace(/4/g, 'a').replace(/3/g, 'e').replace(/1/g, 'i')
    .replace(/0/g, 'o').replace(/5/g, 's').replace(/7/g, 't')
    .replace(/\$/g, 's').replace(/@/g, 'a').replace(/!/g, 'i');
  const leetspeakDangerPattern = /(?:exec|eval|system|shell|cmd|bash|exploit|malware|payload|inject)/i;
  if (leetspeakDangerPattern.test(normalizedInput) && !leetspeakDangerPattern.test(input)) return true;

  // Check for script/executable patterns
  const executablePattern = /(?:MZ[\x00-\xff]{2}|\x7fELF|#!\s*\/(?:bin|usr)|<script[\s>]|\.exe\b|\.sh\b|\.bat\b|\.ps1\b)/i;
  if (executablePattern.test(input)) return true;

  return false;
}

/**
 * Sanitize input strings before passing to the AI model or using in file paths.
 * - Removes null bytes and ASCII control characters (except newline/tab)
 * - Strips prompt-injection-style delimiters
 * - Truncates to a safe maximum length
 */
function sanitizeInput(input: string | null | undefined, maxLength = 4000): string {
  if (!input) return "";
  return input
    .replace(/\0/g, "")                        // remove null bytes
    .replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "") // remove control chars except \t and \n
    .replace(/###ENDPREAMBLE###|###ENDSEEDCHAT###/gi, "") // strip file-format delimiters
    .slice(0, maxLength);
}

export async function POST(request: Request) {
  const { prompt: rawPrompt, isText, userId, userName } = await request.json();
  const prompt = sanitizeInput(rawPrompt);
  let clerkUserId;
  let user;
  let clerkUserName;

  const identifier = request.url + "-" + (clerkUserId || "anonymous");
  const { success } = await rateLimit(identifier);
  if (!success) {
    console.log("INFO: rate limit exceeded");
    await writeAuditRecord({
      traceId,
      event: "rate_limit_exceeded",
      timestamp: new Date().toISOString(),
      principal: userId || "anonymous",
      url: request.url,
      retentionDays: AUDIT_RETENTION_DAYS,
    }).catch((err) => { throw new Error(`Audit write failed (rate_limit): ${err}`); });
    return new NextResponse(
      JSON.stringify({ Message: "Hi, the companions can't talk this fast." }),
      {
        status: 429,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }

  // XXX Companion name passed here. Can use as a key to get backstory, chat history etc.
  const rawName = request.headers.get("name");
  const name = sanitizeInput(rawName, 100).replace(/[^a-zA-Z0-9_\-]/g, ""); // allow only safe filename chars
  if (!name) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion name." }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
  const companion_file_name = name + ".txt";

  user = await currentUser();
  clerkUserId = user?.id;
  clerkUserName = user?.firstName;

  if (!clerkUserId || !!!(await clerk.users.getUser(clerkUserId))) {
    await writeAuditRecord({
      traceId,
      event: "auth_failure",
      timestamp: new Date().toISOString(),
      principal: clerkUserId || "unknown",
      retentionDays: AUDIT_RETENTION_DAYS,
    }).catch((err) => { throw new Error(`Audit write failed (auth_failure): ${err}`); });
    return new NextResponse(
      JSON.stringify({ Message: "User not authorized" }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }

  // Load character "PREAMBLE" from character file. These are the core personality
  // characteristics that are used in every prompt. Additional background is
  // only included if it matches a similarity comparioson with the current
  // discussion. The PREAMBLE should include a seed conversation whose format will
  // vary by the model using it.
  const fs = require("fs").promises;
  const data = await fs.readFile("companions/" + companion_file_name, "utf8");

  // Clunky way to break out PREAMBLE and SEEDCHAT from the character file
  const presplit = data.split("###ENDPREAMBLE###");
  const preamble = presplit[0];
  const seedsplit = presplit[1].split("###ENDSEEDCHAT###");
  const seedchat = seedsplit[0];

  const companionKey = {
    companionName: name!,
    userId: clerkUserId!,
    modelName: "vicuna13b",
  };
  const memoryManager = await MemoryManager.getInstance();

  const { stream, handlers } = LangChainStream();

  const records = await memoryManager.readLatestHistory(companionKey);
  if (records.length === 0) {
    await memoryManager.seedChatHistory(seedchat, "\n\n", companionKey);
  }
  await memoryManager.writeToHistory(
    "### Human: " + prompt + "\n",  // prompt is already sanitized above
    companionKey
  );

  // Query Pinecone

  let recentChatHistoryRaw = await memoryManager.readLatestHistory(companionKey);
  // Minimise: keep only the last 10 lines of chat history injected into the prompt
  const recentChatHistory = recentChatHistoryRaw
    .split("\n")
    .filter((line: string) => line.trim().length > 0)
    .slice(-10)
    .join("\n");

  // Right now the preamble is included in the similarity search, but that
  // shouldn't be an issue

  const similarDocs = await memoryManager.vectorSearch(
    recentChatHistory,
    companion_file_name
  );

  const MAX_RELEVANT_DOCS = 3;
  const MAX_RELEVANT_CHARS = 500;
  let relevantHistory = "";
  if (!!similarDocs && similarDocs.length !== 0) {
    // Minimise: limit to top 3 docs and cap total characters at 500
    relevantHistory = similarDocs
      .slice(0, MAX_RELEVANT_DOCS)
      .map((doc: { pageContent: string }) => doc.pageContent)
      .join("\n")
      .slice(0, MAX_RELEVANT_CHARS);
  }

    // Call OpenAI for inference
  const model = new OpenAI({
    modelName: "gpt-3.5-turbo-instruct",
    maxTokens: 2048,
    openAIApiKey: process.env.OPENAI_API_KEY,
    callbackManager: CallbackManager.fromHandlers(handlers),
  });

  // Turn verbose on for debugging
  model.verbose = true;

  // Sanitization: check LLM output for dynamic code execution primitives
  const DANGEROUS_PATTERNS = [
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /\bexecSync\s*\(/i,
    /\bspawn\s*\(/i,
    /\bspawnSync\s*\(/i,
    /\bsubprocess\b/i,
    /\bnew\s+Function\s*\(/i,
    /\bsetTimeout\s*\(\s*['"`]/i,
    /\bsetInterval\s*\(\s*['"`]/i,
    /\brequire\s*\(/i,
    /\bimport\s*\(/i,
    /\bchild_process\b/i,
    /\bvm\.run/i,
    /\bos\.system\s*\(/i,
    /\bos\.popen\s*\(/i,
    /\b__import__\s*\(/i,
    /\bcompile\s*\(/i,
    /\bexecfile\s*\(/i,
  ];

  function sanitizeLLMOutput(output: string): string {
    for (const pattern of DANGEROUS_PATTERNS) {
      if (pattern.test(output)) {
        console.warn(
          `[SECURITY] Dangerous pattern detected in LLM output: ${pattern}`
        );
        return "[Response blocked: output contained unsafe content.]"
      }
    }
    return output;
  }

  const llmPrompt = `${preamble}  
       
       Below are relevant details about ${sanitizeInput(name, 100)}'s past:
       ${sanitizeInput(relevantHistory)}

       Below is a relevant conversation history

       ${sanitizeInput(recentChatHistory)}
       ### ${name}:
       `;

  console.log('LLM_INTERACTION_PROMPT:', JSON.stringify({ model: 'replicate/vicuna-13b', userId: clerkUserId, companionName: name, prompt: llmPrompt }));

    // Minimise preamble injection: strip seedchat section before injecting into prompt
  const preambleOnly = preamble.slice(0, 1000);

    let rawResp: unknown;
  try {
    rawResp = await model.call(
      `${preamble}  
       
       Below are relevant details about ${name}'s past:
       ${relevantHistory}

       Below is a relevant conversation history

       ${recentChatHistory}
       ### ${name}:
       `
    );
  } catch (err) {
    auditLog({
      event: "TOOL_INVOCATION_ERROR",
      actor: clerkUserId,
      requestedModel: REQUESTED_MODEL,
      policyVersion: POLICY_VERSION,
      reason: String(err),
    });
    return new NextResponse(
      JSON.stringify({ Message: "Model inference failed" }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }

  // Validate model output before trusting it.
  if (typeof rawResp !== "string" && !Array.isArray(rawResp)) {
    auditLog({
      event: "TOOL_OUTPUT_REJECTED",
      actor: clerkUserId,
      requestedModel: REQUESTED_MODEL,
      policyVersion: POLICY_VERSION,
      reason: "Unexpected output type from model",
    });
    return new NextResponse(
      JSON.stringify({ Message: "Invalid model output" }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }

  let resp = String(rawResp);

  // Strip any content that looks like an injected tool-escalation directive.
  const DISALLOWED_OUTPUT_PATTERN = /<tool[^>]*>|\bexec\b|\beval\b/gi;
  if (DISALLOWED_OUTPUT_PATTERN.test(resp)) {
    auditLog({
      event: "TOOL_OUTPUT_REJECTED",
      actor: clerkUserId,
      requestedModel: REQUESTED_MODEL,
      policyVersion: POLICY_VERSION,
      reason: "Model output contained disallowed escalation pattern",
    });
    return new NextResponse(
      JSON.stringify({ Message: "Model output rejected by policy" }),
      { status: 403, headers: { "Content-Type": "application/json" } }
    );
  }

  console.log('LLM_INTERACTION_RESPONSE:', JSON.stringify({ model: 'replicate/vicuna-13b', userId: clerkUserId, companionName: name, response: resp }));

  resp = sanitizeLLMOutput(resp);

  // Right now just using super shoddy string manip logic to get at
  // the dialog.

  const MAX_RESPONSE_CHARS = 1000;
  const cleaned = resp.replaceAll(",", "");
  const chunks = cleaned.split("###");
  // Minimise: take only the first chunk, strip system-marker prefixes, and cap at 1000 chars
  const rawResponse = chunks[0];
  const response = rawResponse
    .replace(/^(Human:|System:|Assistant:|###)/gim, "")
    .trim()
    .slice(0, MAX_RESPONSE_CHARS);

  await memoryManager.writeToHistory("### " + (modelResponse ?? "").trim(), companionKey);
  await writeAuditRecord({
    traceId,
    event: "memory_write",
    timestamp: new Date().toISOString(),
    principal: clerkUserId,
    companionName: name,
    retentionDays: AUDIT_RETENTION_DAYS,
  }).catch((err) => { throw new Error(`Audit write failed (memory_write): ${err}`); });
  var Readable = require("stream").Readable;

  // --- Synthetic Content Provenance, Labeling & Watermarking ---
  const MODEL_ID =
    "replicate/vicuna-13b:6282abe6a492de4145d7bb601023762212f9ddbbe78278bd6771c8b3b2f2a13b";
  const contentOriginTag = "AI_GENERATED";
  const timestamp = new Date().toISOString();

  // Build provenance metadata object
  const provenanceMetadata = {
    model: MODEL_ID,
    timestamp,
    contentOrigin: contentOriginTag,
    label: "SYNTHETIC_AI_CONTENT",
  };

  // Compute HMAC-SHA256 signature over provenance metadata for integrity
  const crypto = require("crypto");
  const signingSecret = process.env.PROVENANCE_SIGNING_SECRET || "default-insecure-secret";
  const provenanceJson = JSON.stringify(provenanceMetadata);
  const signature = crypto
    .createHmac("sha256", signingSecret)
    .update(provenanceJson)
    .digest("hex");

  // Watermark: prepend a clearly delimited provenance block to the streamed content
  const watermark =
    `[AI-GENERATED CONTENT | Model: ${MODEL_ID} | Generated: ${timestamp} | Origin: ${contentOriginTag}]\n`;
  const labeledResponse = watermark + response;

  let s = new Readable();
  s.push(labeledResponse);
  s.push(null);
  if (response !== undefined && response.length > 1) {
    await memoryManager.writeToHistory("### " + response.trim(), companionKey);
  }

  // Attach provenance headers to the HTTP response for client transparency
  const provenanceHeaders = {
    "X-AI-Content-Label": "SYNTHETIC_AI_CONTENT",
    "X-AI-Model-ID": MODEL_ID,
    "X-AI-Content-Timestamp": timestamp,
    "X-AI-Content-Origin": contentOriginTag,
    "X-AI-Provenance-Metadata": provenanceJson,
    "X-AI-Provenance-Signature": `sha256=${signature}`,
  };

  return new StreamingTextResponse(s, { headers: provenanceHeaders });
}
