import dotenv from "dotenv";
import { StreamingTextResponse, LangChainStream } from "ai";
import { Replicate } from "langchain/llms/replicate";
import { CallbackManager } from "langchain/callbacks";
import clerk from "@clerk/clerk-sdk-node";
import MemoryManager from "@/app/utils/memory";
import { currentUser } from "@clerk/nextjs";
import { NextResponse } from "next/server";
import { rateLimit } from "@/app/utils/rateLimit";

dotenv.config({ path: `.env.local` });

// Patterns indicative of malicious or injected content
const SHELL_COMMAND_PATTERN = /(?:^|\s|;|\||&)(?:bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess|os\.system|`[^`]*`|\$\([^)]*\))/i;
const BASE64_INJECTION_PATTERN = /(?:[A-Za-z0-9+/]{20,}={0,2})(?:\s|$)/;
const LEET_SPEAK_PATTERN = /(?:[e3][x*][e3][c*]|[s$][y*][s$][t+][e3][m*]|[p*][a@][s$][s$][w*][o0][r*][d*])/i;
const PROMPT_INJECTION_PATTERN = /(?:ignore\s+(?:previous|above|prior|all)\s+instructions?|disregard\s+(?:previous|above|prior|all)|you\s+are\s+now|new\s+instructions?:|system\s*:|<\s*system\s*>|\[\s*system\s*\])/i;
const HIDDEN_CONTENT_PATTERN = /(?:\\u00[0-9a-f]{2}|\\x[0-9a-f]{2}|\\0[0-7]{2}|\u200b|\u200c|\u200d|\ufeff)/i;

function sanitizeInput(input: string): { safe: boolean; reason?: string } {
  if (!input || typeof input !== "string") {
    return { safe: true };
  }
  const trimmed = input.trim();
  if (SHELL_COMMAND_PATTERN.test(trimmed)) {
    return { safe: false, reason: "Shell command pattern detected" };
  }
  if (BASE64_INJECTION_PATTERN.test(trimmed)) {
    // Attempt to decode and re-check
    const b64matches = trimmed.match(/[A-Za-z0-9+/]{20,}={0,2}/g) || [];
    for (const match of b64matches) {
      try {
        const decoded = Buffer.from(match, "base64").toString("utf8");
        if (
          SHELL_COMMAND_PATTERN.test(decoded) ||
          PROMPT_INJECTION_PATTERN.test(decoded)
        ) {
          return { safe: false, reason: "Base64-encoded malicious content detected" };
        }
      } catch {
        // Not valid base64, skip
      }
    }
  }
  if (LEET_SPEAK_PATTERN.test(trimmed)) {
    return { safe: false, reason: "Leetspeak obfuscation detected" };
  }
  if (PROMPT_INJECTION_PATTERN.test(trimmed)) {
    return { safe: false, reason: "Prompt injection attempt detected" };
  }
  if (HIDDEN_CONTENT_PATTERN.test(trimmed)) {
    return { safe: false, reason: "Hidden or obfuscated content detected" };
  }
  return { safe: true };
}

export async function POST(request: Request) {
  const { prompt: rawPrompt, isText, userId, userName } = await request.json();
  // Sanitize prompt: ensure it is a non-empty string and strip control characters
  if (!rawPrompt || typeof rawPrompt !== "string") {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid prompt." }),
      {
        status: 400,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }
  const sanitizeInput = (input: string): string =>
    input
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "") // strip non-printable control chars
      .trim()
      .slice(0, 4096); // enforce max length
  const prompt = sanitizeInput(rawPrompt);
  let clerkUserId;
  let user;
  let clerkUserName;

  const identifier = request.url + "-" + (userId || "anonymous");
  const { success } = await rateLimit(identifier);
  if (!success) {
    console.error(
    JSON.stringify({
      event: "TOOL_INVOCATION_RATE_LIMITED",
      policyVersion: POLICY_VERSION,
      actor: clerkUserId,
      requestedModel: REQUESTED_MODEL,
      reason: "Rate limit exceeded",
      timestamp: new Date().toISOString(),
    })
  );
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
  // Validate name: only allow alphanumeric characters, hyphens, and underscores to prevent path traversal
  if (!rawName || !/^[a-zA-Z0-9_-]{1,64}$/.test(rawName)) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion name." }),
      {
        status: 400,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }
  const name = rawName;
  const companion_file_name = name + ".txt";

  user = await currentUser();
  clerkUserId = user?.id;
  clerkUserName = user?.firstName;

  if (!clerkUserId || !!!(await clerk.users.getUser(clerkUserId))) {
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
  const path = require("path");
  const companionsDir = path.resolve("companions");
  const resolvedPath = path.resolve(companionsDir, companion_file_name);
  // Ensure the resolved path is strictly within the companions directory
  if (!resolvedPath.startsWith(companionsDir + path.sep)) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion name." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
  const data = await fs.readFile(resolvedPath, "utf8");

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
    "### Human: " + prompt + "\n",
    companionKey
  );

  // Query Pinecone

  const rawChatHistory = await memoryManager.readLatestHistory(companionKey);
  // Data minimisation: limit injected history to the last 10 lines
  const recentChatHistory = rawChatHistory
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

  let relevantHistory = "";
  if (!!similarDocs && similarDocs.length !== 0) {
    // Data minimisation: limit to first 3 docs, cap each doc at 500 chars
    relevantHistory = similarDocs
      .slice(0, 3)
      .map((doc) => (doc.pageContent ?? "").slice(0, 500))
      .join("\n");
  }

  // Call OpenAI for inference (approved LLM)
  const model = new OpenAI({
    modelName: "gpt-3.5-turbo-instruct",
    maxTokens: 2048,
    openAIApiKey: process.env.OPENAI_API_KEY,
    callbackManager: CallbackManager.fromHandlers(handlers),
  });

  // Turn verbose on for debugging
  model.verbose = true;

  // Dangerous code execution primitives to block in LLM output
  const DANGEROUS_PATTERNS = [
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /\bexecSync\s*\(/i,
    /\bspawnSync\s*\(/i,
    /\bspawn\s*\(/i,
    /\bsubprocess\b/i,
    /\bchild_process\b/i,
    /\bnew\s+Function\s*\(/i,
    /\bsetTimeout\s*\(\s*['"`]/i,
    /\bsetInterval\s*\(\s*['"`]/i,
    /\bimportScripts\s*\(/i,
    /\brequire\s*\(/i,
    /\b__import__\s*\(/i,
    /\bos\.system\s*\(/i,
    /\bos\.popen\s*\(/i,
    /\bRuntime\.exec\s*\(/i,
    /\bProcessBuilder\b/i,
  ];

  function sanitizeLLMOutput(raw: string): string {
    for (const pattern of DANGEROUS_PATTERNS) {
      if (pattern.test(raw)) {
        console.warn(
          `[SECURITY] Blocked LLM output containing dangerous pattern: ${pattern}`
        );
        return "";
      }
    }
    // Strip any null bytes or non-printable control characters
    return raw.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  }

  const llmPrompt = `${preamble}  
       
       Below are relevant details about ${name}'s past:
       ${sanitizeInput(relevantHistory)}

       Below is a relevant conversation history

       ${sanitizeInput(recentChatHistory)}
       ### ${name}:
       `;

  console.log("[LLM REQUEST] model=vicuna-13b prompt:", llmPrompt);

    const inferenceInput = `${preamble}  
       
       Below are relevant details about ${name}'s past:
       ${relevantHistory}

       Below is a relevant conversation history

       ${recentChatHistory}
       ### ${name}:
       `;

  let rawResp: unknown;
  try {
    rawResp = await model.call(inferenceInput);
  } catch (inferenceError) {
    // Fail-closed: log the failure to the audit trail then surface the error
    await writeAuditRecord({
      event: "inference_error",
      error: inferenceError instanceof Error ? inferenceError.message : String(inferenceError),
    }).catch((auditErr) => {
      // Audit write itself failed — emit to stderr so it is visible in log aggregation
      console.error("[AUDIT FAILURE]", auditErr);
    });
    throw inferenceError; // do NOT swallow — fail closed
  }

  const resp = String(rawResp ?? "");

  // Log the completed inference to the audit trail
  await writeAuditRecord({
    event: "inference_complete",
    modelId: "replicate/vicuna-13b",
    modelVersion: "6282abe6a492de4145d7bb601023762212f9ddbbe78278bd6771c8b3b2f2a13b",
    inputHash: require("crypto").createHash("sha256").update(inferenceInput).digest("hex"),
    outputHash: require("crypto").createHash("sha256").update(resp).digest("hex"),
  }).catch((auditErr) => {
    console.error("[AUDIT FAILURE]", auditErr);
    // Re-throw so the caller knows the audit trail is broken
    throw auditErr;
  });

  console.log("[LLM RESPONSE] model=vicuna-13b response:", resp);

  // Validate and sanitize LLM output before any further processing
  resp = sanitizeLLMOutput(resp);

  // Right now just using super shoddy string manip logic to get at
  // the dialog.

  const cleaned = resp.replaceAll(",", "");
  const chunks = cleaned.split("###");
  // Data minimisation: allowlist only the first chunk, strip internal markers,
  // and cap the response at 1000 characters before returning to the client.
  const rawResponse = chunks[0];
  const response = rawResponse
    .replace(/###[\s\S]*/g, "")       // strip any residual prompt markers
    .replace(/Below are relevant details[\s\S]*/gi, "") // strip leaked context
    .replace(/Below is a relevant conversation[\s\S]*/gi, "")
    .trim()
    .slice(0, 1000);

    try {
    await memoryManager.writeToHistory("### " + response.trim(), companionKey);
  } catch (historyErr) {
    await writeAuditRecord({
      event: "history_write_error",
      error: historyErr instanceof Error ? historyErr.message : String(historyErr),
    }).catch((auditErr) => console.error("[AUDIT FAILURE]", auditErr));
    throw historyErr;
  }

  await writeAuditRecord({ event: "history_written" }).catch((auditErr) => {
    console.error("[AUDIT FAILURE]", auditErr);
    throw auditErr;
  });

  var Readable = require("stream").Readable;

  let s = new Readable();
  s.push(response);
  s.push(null);
  if (response !== undefined && response.length > 1) {
    try {
      await memoryManager.writeToHistory("### " + response.trim(), companionKey);
    } catch (historyErr) {
      await writeAuditRecord({
        event: "history_write_error",
        error: historyErr instanceof Error ? historyErr.message : String(historyErr),
      }).catch((auditErr) => console.error("[AUDIT FAILURE]", auditErr));
      throw historyErr;
    }
  } | Generated: ${generatedAt}]\n`;
  const labeledResponse = aiLabel + response;

  // (2) Compute a lightweight HMAC-SHA256 provenance signature over the labeled content
  const crypto = require("crypto");
  const signingSecret = process.env.PROVENANCE_SIGNING_SECRET || "default-provenance-secret";
  const provenanceSignature = crypto
    .createHmac("sha256", signingSecret)
    .update(labeledResponse)
    .digest("hex");

  let s = new Readable();
  s.push(labeledResponse);
  s.push(null);
  if (response !== undefined && response.length > 1) {
    await memoryManager.writeToHistory("### " + response.trim(), companionKey);
  }

  // (3) Attach provenance metadata headers to the response
  return new StreamingTextResponse(s, {
    headers: {
      "X-AI-Generated": "true",
      "X-AI-Model-ID": MODEL_ID,
      "X-AI-Content-Origin": "replicate-vicuna-13b",
      "X-AI-Generated-At": generatedAt,
      "X-AI-Provenance-Signature": provenanceSignature,
      "X-Content-Label": "synthetic-ai-generated",
    },
  });
}
