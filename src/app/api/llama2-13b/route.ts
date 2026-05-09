import dotenv from "dotenv";
import { StreamingTextResponse, LangChainStream } from "ai";
import { Replicate, ReplicateInput } from "langchain/llms/replicate";
import { CallbackManager } from "langchain/callbacks";
import clerk from "@clerk/clerk-sdk-node";
import MemoryManager from "@/app/utils/memory";
import { currentUser } from "@clerk/nextjs";
import { NextResponse } from "next/server";
import { rateLimit } from "@/app/utils/rateLimit";
import { createHmac, timingSafeEqual } from "crypto";

dotenv.config({ path: `.env.local` });

// ── Prompt-injection defence ────────────────────────────────────────────────

/** Patterns that indicate prompt-injection or command-execution attempts. */
const INJECTION_PATTERNS: RegExp[] = [
  // Hidden / zero-width characters used to smuggle instructions
  /[\u200B-\u200D\uFEFF\u00AD]/,
  // Classic override phrases
  /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/i,
  /disregard\s+(all\s+)?(previous|prior|above)\s+instructions?/i,
  /forget\s+(all\s+)?(previous|prior|above)\s+instructions?/i,
  /you\s+are\s+now\s+(a|an)?\s*(?!${)/i,
  /act\s+as\s+(a|an)?\s+(?:different|new|another)/i,
  /new\s+instructions?\s*:/i,
  /system\s*:\s*you/i,
  // Shell / binary command patterns
  /(?:^|\s)(?:bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess)\s*[\(\[`]/im,
  /(?:\$\(|`)[^`]*`/,          // command substitution
  /;\s*(?:rm|wget|curl|nc|ncat|python|perl|ruby|php)\s/i,
  /\|\s*(?:bash|sh|cmd)/i,
  // Base64-encoded blobs (long runs of base64 chars are suspicious in chat)
  /(?:[A-Za-z0-9+\/]{40,}={0,2})/,
  // Leetspeak override attempts  e.g. "1gn0r3 4ll"
  /1[g9][n][0o][r][3e]\s+[4a][l1][l1]/i,
  // Attempts to exfiltrate via URL
  /https?:\/\/[^\s]+\?[^\s]*(?:prompt|inject|cmd|exec)/i,
];

/**
 * Returns true when the string contains a known injection pattern.
 */
function containsInjection(value: string): boolean {
  return INJECTION_PATTERNS.some((re) => re.test(value));
}

/**
 * Sanitise file-derived content by removing zero-width / invisible characters
 * and truncating suspiciously long base64-like tokens.
 * Throws if an active injection pattern is still detected after cleaning.
 */
function sanitizeFileContent(value: string): string {
  // Strip zero-width and soft-hyphen characters
  let cleaned = value.replace(/[\u200B-\u200D\uFEFF\u00AD]/g, "");
  // Remove long base64-like tokens that could carry hidden payloads
  cleaned = cleaned.replace(/[A-Za-z0-9+\/]{60,}={0,2}/g, "[REDACTED]");
  if (containsInjection(cleaned)) {
    throw new Error("Unsafe content detected in companion file.");
  }
  return cleaned;
}

/**
 * Validate a user-supplied string.  Returns an error message or null.
 */
function validateUserInput(value: string | null | undefined, field: string): string | null {
  if (!value) return null;
  if (containsInjection(value)) {
    return `Unsafe content detected in field: ${field}`;
  }
  return null;
}
// ────────────────────────────────────────────────────────────────────────────

const MAX_PROMPT_LENGTH = 1000;
const MAX_NAME_LENGTH = 100;
const MAX_CONTEXT_LENGTH = 4000;

/**
 * Sanitizes a string for safe inclusion in an LLM prompt.
 * Removes null bytes, strips common prompt-injection patterns,
 * and trims excessive whitespace.
 */
function sanitizeInput(input: string, maxLength: number): string {
  if (typeof input !== "string") return "";
  return input
    .replace(/\0/g, "")                          // remove null bytes
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "") // remove control chars (keep \t \n \r)
    .replace(/###(ENDPREAMBLE|ENDSEEDCHAT|SYSTEM|INST|SYS|HUMAN|ASSISTANT)###/gi, "") // strip delimiter injection
    .replace(/\[\/?INST\]/gi, "")               // strip llama instruction tags
    .replace(/<\/?s>/gi, "")                    // strip llama BOS/EOS tags
    .replace(/ignore (all )?(previous|prior|above) instructions?/gi, "") // strip classic injection
    .trim()
    .slice(0, maxLength);
}

export async function POST(request: Request) {
  const rawBody = await request.json();
  const rawPrompt: string = typeof rawBody.prompt === "string" ? rawBody.prompt : "";
  const isText: boolean = !!rawBody.isText;
  const userId: string = typeof rawBody.userId === "string" ? rawBody.userId : "";
  const userName: string = typeof rawBody.userName === "string" ? rawBody.userName : "";
  const prompt = sanitizeInput(rawPrompt, MAX_PROMPT_LENGTH);
  let clerkUserId;
  let user;
  let clerkUserName;

  const identifier = request.url + "-" + (userId || "anonymous");
  const { success } = await rateLimit(identifier);
  if (!success) {
    console.log("INFO: rate limit exceeded");
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
  const rawName = request.headers.get("name") ?? "";
  const name = sanitizeInput(rawName, MAX_NAME_LENGTH);

  if (!name) {
    return new NextResponse(
      JSON.stringify({ Message: "Companion name is required" }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  // Prevent path traversal in the companion file name
  const safeName = name.replace(/[^a-zA-Z0-9_\-]/g, "_");
  const companion_file_name = safeName + ".txt";

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

  /**
   * Validates companion file content against prompt injection and malicious content.
   * Throws an error with a descriptive message if suspicious content is detected.
   */
  function validateCompanionFileContent(content: string): void {
    // 1. Reject binary / non-printable characters (allow common whitespace)
    // eslint-disable-next-line no-control-regex
    if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(content)) {
      throw new Error("Companion file contains binary or non-printable characters.");
    }

    // 2. Reject invisible / zero-width Unicode characters often used to hide text
    if (/[\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u2028\u2029]/.test(content)) {
      throw new Error("Companion file contains hidden or invisible Unicode characters.");
    }

    // 3. Reject suspiciously long base64-encoded blobs (40+ contiguous base64 chars)
    if (/[A-Za-z0-9+/]{40,}={0,2}/.test(content)) {
      throw new Error("Companion file contains a suspected base64-encoded payload.");
    }

    // 4. Reject leetspeak patterns (common substitutions: 3=e, 4=a, 0=o, 1=i/l, 5=s, 7=t)
    if (/\b(?:[a-zA-Z]*[34015789][a-zA-Z0-9]*){3,}\b/.test(content)) {
      throw new Error("Companion file contains suspected leetspeak content.");
    }

    // 5. Reject shell command sequences
    const shellPatterns = [
      /`[^`]+`/,                          // backtick execution
      /\$\([^)]+\)/,                      // $(...) subshell
      /;\s*(rm|wget|curl|bash|sh|python|perl|nc|ncat|chmod|chown|sudo|su)\b/i,
      /\|\s*(bash|sh|python|perl|nc|ncat)\b/i,
      />>?\s*\/(?:etc|tmp|var|usr|bin|dev)/i,  // redirect to sensitive paths
    ];
    for (const pattern of shellPatterns) {
      if (pattern.test(content)) {
        throw new Error("Companion file contains suspected shell command sequences.");
      }
    }

    // 6. Reject common prompt injection / jailbreak phrases
    const injectionPatterns = [
      /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/i,
      /disregard\s+(all\s+)?(previous|prior|above)\s+instructions?/i,
      /forget\s+(all\s+)?(previous|prior|above)\s+instructions?/i,
      /you\s+are\s+now\s+(a\s+)?(?:dan|jailbreak|unrestricted|evil|malicious)/i,
      /act\s+as\s+(if\s+you\s+are\s+)?(?:dan|jailbreak|unrestricted|evil|malicious)/i,
      /pretend\s+(you\s+are|to\s+be)\s+(?:dan|jailbreak|unrestricted|evil|malicious)/i,
      /system\s*:\s*you\s+are/i,          // fake system prompt injection
      /###\s*system/i,                    // markdown-style system block injection
      /<\s*system\s*>/i,                  // XML-style system tag injection
    ];
    for (const pattern of injectionPatterns) {
      if (pattern.test(content)) {
        throw new Error("Companion file contains suspected prompt injection content.");
      }
    }
  }

  const data = await fs.readFile("companions/" + companion_file_name, "utf8");

  try {
    validateCompanionFileContent(data);
  } catch (validationError: any) {
    console.error("Companion file validation failed:", validationError.message);
    return new NextResponse(
      JSON.stringify({ Message: "Companion file contains disallowed content and cannot be loaded." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  // Clunky way to break out PREAMBLE and SEEDCHAT from the character file
  const presplit = data.split("###ENDPREAMBLE###");
  const preamble = sanitizeInput(presplit[0] ?? "", MAX_CONTEXT_LENGTH);
  const seedsplit = (presplit[1] ?? "").split("###ENDSEEDCHAT###");
  const seedchat = sanitizeInput(seedsplit[0] ?? "", MAX_CONTEXT_LENGTH);

  // --- Audit / forensic readiness setup ---
  const crypto = require("crypto");
  const correlationId = crypto.randomUUID(); // shared trace ID for all steps
  const HISTORY_RETENTION_DAYS = 90;        // retention policy: purge after 90 days
  const MODEL_ID = "a16z-infra/llama13b-v2-chat";
  const MODEL_VERSION = "df7690f1994d94e96ad9d568eac121aecf50684a0b0963b25a41cc40061269e5";

  function auditLog(event: string, details: Record<string, unknown>) {
    // Writes a structured, append-only audit record to stdout (captured by
    // log aggregation) and to a persistent audit file.
    const record = JSON.stringify({
      correlationId,
      timestamp: new Date().toISOString(),
      principal: clerkUserId,
      event,
      ...details,
    });
    console.log("[AUDIT]", record);
    // Persist to append-only audit log (fire-and-forget write; errors surfaced)
    require("fs").promises
      .appendFile("audit/llama2-13b-audit.log", record + "\n")
      .catch((err: unknown) => {
        // Audit write failure is fatal — fail closed
        console.error("[AUDIT WRITE FAILURE]", err);
        throw new Error("Audit logging failed; aborting request.");
      });
  }
  // --- End audit setup ---

  const companionKey = {
    companionName: name!,
    userId: clerkUserId!,
    modelName: "llama2-13b",
  };
  const memoryManager = await MemoryManager.getInstance();

  auditLog("memory.readLatestHistory", { companionName: name, step: "rate-limit-and-history-check" });
  const records = await memoryManager.readLatestHistory(companionKey);
  if (records.length === 0) {
    await memoryManager.seedChatHistory(seedchat, "\n\n", companionKey);
  }
  // Retention policy: HISTORY_RETENTION_DAYS applies to all history writes
  auditLog("memory.writeToHistory", { entry: "user-prompt", retentionDays: HISTORY_RETENTION_DAYS });
  await memoryManager.writeToHistory("User: " + prompt + "\n", companionKey);

  // Query Pinecone

  let recentChatHistory = (await memoryManager.readLatestHistory(companionKey))
    .split("\n")
    .filter((line: string) => line.trim() !== "")
    .slice(-10)
    .join("\n");

  // Right now the preamble is included in the similarity search, but that
  // shouldn't be an issue

  auditLog("memory.vectorSearch", { companionFile: companion_file_name });
  const similarDocs = await memoryManager.vectorSearch(
    recentChatHistory,
    companion_file_name
  );

  let relevantHistory = "";
  if (!!similarDocs && similarDocs.length !== 0) {
    relevantHistory = similarDocs
      .slice(0, 3)
      .map((doc) => doc.pageContent.slice(0, 200))
      .join("\n");
  }
    // The Replicate/LLaMA2 model (a16z-infra/llama13b-v2-chat) is not in the
  // organisation's approved LLM registry and has been disabled.
  return new NextResponse(
    JSON.stringify({
      Message:
        "The requested model is not approved for use by this organisation's LLM policy.",
    }),
    {
      status: 403,
      headers: { "Content-Type": "application/json" },
    }
  );

  // Dead code retained for reference only — remove when a registry-approved
  // model replacement has been selected.
  /*
  const { stream, handlers } = LangChainStream();
  const model = new Replicate({
    model:
      "a16z-infra/llama13b-v2-chat:df7690f1994d94e96ad9d568eac121aecf50684a0b0963b25a41cc40061269e5",
    input: { max_length: 2048 },
    callbackManager: CallbackManager.fromHandlers(handlers),
  });
  model.verbose = true;
    const modelPrompt = `
       ONLY generate NO more than three sentences as ${name}. DO NOT generate more than three sentences. 
       Make sure the output you generate starts with '${name}:' and ends with a period.

       ${preamble}

       Below are relevant details about ${name}'s past and the conversation you are in.
       ${relevantHistory}


       ${recentChatHistory}\n${name}:`;

  const inputHash = crypto.createHash("sha256").update(modelPrompt).digest("hex");
  auditLog("model.callStart", {
    modelId: MODEL_ID,
    modelVersion: MODEL_VERSION,
    inputHash,
  });

  let rawResp: unknown;
  try {
    rawResp = await model.call(modelPrompt);
  } catch (err) {
    auditLog("model.callError", {
      modelId: MODEL_ID,
      modelVersion: MODEL_VERSION,
      inputHash,
      error: String(err),
    });
    // Fail closed — do not silently swallow the error
    throw err;
  }

  let resp = String(rawResp);
  const outputHash = crypto.createHash("sha256").update(resp).digest("hex");
  auditLog("model.callComplete", {
    modelId: MODEL_ID,
    modelVersion: MODEL_VERSION,
    inputHash,
    outputHash,
  });
  */

  let resp = "";
  // Call OpenAI for inference
  const model = new OpenAI({
    modelName: "gpt-3.5-turbo-instruct",
    openAIApiKey: process.env.OPENAI_API_KEY,
    maxTokens: 2048,
    callbackManager: CallbackManager.fromHandlers(handlers),
  });

  // Turn verbose on for debugging
  model.verbose = true;

  const llmPrompt = `
       ONLY generate NO more than three sentences as ${name}. DO NOT generate more than three sentences. 
       Make sure the output you generate starts with '${name}:' and ends with a period.

       ${preamble}

       Below are relevant details about ${name}'s past and the conversation you are in.
       ${relevantHistory}


       ${recentChatHistory}\n${name}:`;

  console.log("[LLM Interaction] Model: llama2-13b | Prompt sent to LLM:", llmPrompt);

  let resp = String(
    await model
      .call(llmPrompt)
      .catch(console.error)
  );

  console.log("[LLM Interaction] Model: llama2-13b | Response received from LLM:", resp);

  // Validate and sanitize LLM output for dangerous dynamic code execution primitives
  const DANGEROUS_PATTERNS = [
    /\beval\s*\(/gi,
    /\bexec\s*\(/gi,
    /\bsubprocess\b/gi,
    /\bos\.system\s*\(/gi,
    /\b__import__\s*\(/gi,
    /\bFunction\s*\(/gi,
    /\bnew\s+Function\b/gi,
    /\bsetTimeout\s*\(/gi,
    /\bsetInterval\s*\(/gi,
    /\bexecSync\s*\(/gi,
    /\bspawnSync\s*\(/gi,
    /\bspawn\s*\(/gi,
    /\bexecFile\s*\(/gi,
    /\bchild_process\b/gi,
    /\brequire\s*\(/gi,
    /\bimport\s*\(/gi,
  ];

  const hasDangerousContent = DANGEROUS_PATTERNS.some((pattern) =>
    pattern.test(resp)
  );

  if (hasDangerousContent) {
    console.error(
      "[SECURITY] Dangerous code execution primitive detected in LLM output. Blocking response."
    );
    return new Response("Response blocked due to policy violation.", {
      status: 400,
    });
  }

  // Sanitize: strip any residual dangerous tokens as a secondary defense
  const sanitized = DANGEROUS_PATTERNS.reduce(
    (text, pattern) => text.replace(pattern, "[REDACTED]"),
    resp
  );

  // Right now just using super shoddy string manip logic to get at
  // the dialog.

  const cleaned = sanitized.replaceAll(",", "");
  const chunks = cleaned.split("\n");
  const response = chunks[0];
  // const response = chunks.length > 1 ? chunks[0] : chunks[0];

  auditLog("memory.writeToHistory", { entry: "assistant-response", retentionDays: HISTORY_RETENTION_DAYS });
  await memoryManager.writeToHistory("" + response.trim(), companionKey);
  var Readable = require("stream").Readable;

  let s = new Readable();
  s.push(response);
  s.push(null);
  if (response !== undefined && response.length > 1) {
    auditLog("memory.writeToHistory", { entry: "assistant-response-stream", retentionDays: HISTORY_RETENTION_DAYS });
    await memoryManager.writeToHistory("" + response.trim(), companionKey);
  }

  // --- Synthetic Content Provenance & Labeling ---
  const provenanceModel =
    "a16z-infra/llama13b-v2-chat:df7690f1994d94e96ad9d568eac121aecf50684a0b0963b25a41cc40061269e5";
  const provenanceTimestamp = new Date().toISOString();
  const provenanceLabel = "AI-Generated Synthetic Content";
  const provenanceOrigin = "Replicate/LLaMA2-13B";

  // Cryptographic HMAC-SHA256 signature over provenance fields
  const crypto = require("crypto");
  const signingSecret = process.env.PROVENANCE_SIGNING_SECRET || "default-insecure-secret";
  const provenancePayload = JSON.stringify({
    model: provenanceModel,
    timestamp: provenanceTimestamp,
    label: provenanceLabel,
    origin: provenanceOrigin,
  });
  const provenanceSignature = crypto
    .createHmac("sha256", signingSecret)
    .update(provenancePayload)
    .digest("hex");

  // Watermark: prepend a visible synthetic-content marker to the text
  const watermarkedResponse = `[AI-GENERATED] ${response}`;
  let sw = new Readable();
  sw.push(watermarkedResponse);
  sw.push(null);

  return new StreamingTextResponse(sw, {
    headers: {
      "X-Provenance-Model": provenanceModel,
      "X-Provenance-Timestamp": provenanceTimestamp,
      "X-Provenance-Label": provenanceLabel,
      "X-Provenance-Origin": provenanceOrigin,
      "X-Provenance-Signature": provenanceSignature,
      "X-Content-Type-AI": "synthetic",
    },
  });
}
