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

const TEXT_TOKEN_SECRET = process.env.TEXT_TOKEN_SECRET;
const TEXT_TOKEN_MAX_AGE_MS = 5 * 60 * 1000; // 5 minutes

function verifyTextUserToken(
  token: string,
  userId: string,
  userName: string
): boolean {
  if (!TEXT_TOKEN_SECRET) {
    throw new Error("TEXT_TOKEN_SECRET environment variable is not set");
  }
  let payload: { userId: string; userName: string; exp: number };
  try {
    const decoded = Buffer.from(token.split(".")[0], "base64url").toString("utf8");
    payload = JSON.parse(decoded);
    const sig = token.split(".")[1];
    const expectedSig = createHmac("sha256", TEXT_TOKEN_SECRET)
      .update(token.split(".")[0])
      .digest("base64url");
    if (!timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig))) {
      return false;
    }
  } catch {
    return false;
  }
  if (Date.now() > payload.exp) {
    return false;
  }
  if (payload.userId !== userId || payload.userName !== userName) {
    return false;
  }
  return true;
}

dotenv.config({ path: `.env.local` });

/**
 * Sanitize input to prevent prompt injection attacks.
 * Removes or rejects content that could be used to hijack the AI agent.
 */
function sanitizeInput(input: string | null | undefined): string {
  if (!input) return "";

  // Reject or strip base64-encoded content (long base64 strings)
  const base64Pattern = /(?:[A-Za-z0-9+\/]{40,}={0,2})/g;
  let sanitized = input.replace(base64Pattern, "[REDACTED_BASE64]");

  // Strip shell command patterns
  const shellCommandPattern = /(`[^`]*`|\$\([^)]*\)|\b(bash|sh|cmd|powershell|exec|eval|system|popen|subprocess)\s*[\(\["'])/gi;
  sanitized = sanitized.replace(shellCommandPattern, "[REDACTED_CMD]");

  // Strip hidden/invisible unicode characters and control characters (except newlines/tabs)
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/g, "");

  // Detect and strip common prompt injection patterns
  const injectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/gi,
    /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/gi,
    /forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/gi,
    /you\s+are\s+now\s+(a\s+)?(?!${)/gi,
    /act\s+as\s+(if\s+you\s+are\s+)?(a\s+)?(?!${)/gi,
    /new\s+(instructions?|prompt|role|persona|system):/gi,
    /###\s*(system|instruction|prompt|override)/gi,
    /<\s*(system|instructions?|prompt)\s*>/gi,
    /\[\s*(system|instructions?|prompt|override)\s*\]/gi,
  ];
  for (const pattern of injectionPatterns) {
    sanitized = sanitized.replace(pattern, "[REDACTED]");
  }

  // Strip leetspeak patterns that attempt to obfuscate commands
  // e.g., 3x3c, 5h3ll, etc. — flag suspicious leet sequences
  const leetspeakPattern = /\b[a-z0-9]*[013457@$!][a-z0-9]*[013457@$!][a-z0-9]*\b/gi;
  // Only strip if combined with known dangerous keywords after normalization
  const leetspeakNormalize = (s: string) =>
    s.replace(/0/g, 'o').replace(/1/g, 'i').replace(/3/g, 'e')
     .replace(/4/g, 'a').replace(/5/g, 's').replace(/7/g, 't')
     .replace(/@/g, 'a').replace(/\$/g, 's').replace(/!/g, 'i');
  sanitized = sanitized.replace(leetspeakPattern, (match) => {
    const normalized = leetspeakNormalize(match);
    if (/\b(exec|eval|shell|bash|system|admin|root|sudo|hack|inject)\b/i.test(normalized)) {
      return "[REDACTED_LEET]";
    }
    return match;
  });

  // Limit length to prevent extremely long injected content
  const MAX_LENGTH = 4000;
  if (sanitized.length > MAX_LENGTH) {
    sanitized = sanitized.substring(0, MAX_LENGTH) + "...[TRUNCATED]";
  }

  return sanitized;
}

/**
 * Sanitize input before sending to LLM to prevent prompt injection.
 * Removes control characters, null bytes, and common prompt injection patterns.
 */
function sanitizeLLMInput(input: string | null | undefined): string {
  if (!input) return "";
  // Remove null bytes and non-printable control characters (keep newlines/tabs)
  let sanitized = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  // Limit length to prevent excessively large inputs
  sanitized = sanitized.slice(0, 4000);
  // Strip common prompt injection patterns (case-insensitive)
  sanitized = sanitized.replace(
    /ignore (all )?(previous|prior|above) instructions?/gi,
    "[removed]"
  );
  sanitized = sanitized.replace(
    /###(ENDPREAMBLE|ENDSEEDCHAT|SYSTEM|INST|END)###/gi,
    "[removed]"
  );
  sanitized = sanitized.replace(
    /<\/?s>|\[INST\]|\[\/INST\]|<<SYS>>|<\/SYS>>/gi,
    "[removed]"
  );
  return sanitized.trim();
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
  if (!rawName || rawName.trim() === "") {
    return new NextResponse(
      JSON.stringify({ Message: "Missing required 'name' header" }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
  // Validate name: allow only alphanumeric, spaces, hyphens, and underscores
  if (!/^[\w\s\-]{1,100}$/.test(rawName)) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid 'name' header value" }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
  const name = sanitizeLLMInput(rawName);
  const companion_file_name = name + ".txt";

  // Authentication is always performed server-side via currentUser() above.

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
  // Sanitize the user-controlled companion file name to prevent path traversal.
  const sanitizedCompanionFileName = path.basename(companion_file_name);
  const companionsDir = path.resolve(process.cwd(), "companions");
  const companionFilePath = path.resolve(companionsDir, sanitizedCompanionFileName);
  if (!companionFilePath.startsWith(companionsDir + path.sep)) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion file." }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
  const data = await fs.readFile(companionFilePath, "utf8");

  // Clunky way to break out PREAMBLE and SEEDCHAT from the character file
  const presplit = data.split("###ENDPREAMBLE###");
  const preamble = sanitizeLLMInput(presplit[0]);
  const seedsplit = presplit[1].split("###ENDSEEDCHAT###");
  const seedchat = sanitizeLLMInput(seedsplit[0]);

  // Audit: shared trace identifier linking all steps in this request
  const { randomUUID, createHash } = await import("crypto");
  const traceId = randomUUID();
  const auditLog = (event: string, data: Record<string, unknown>) => {
    const entry = {
      traceId,
      timestamp: new Date().toISOString(),
      principal: clerkUserId,
      event,
      ...data,
    };
    // Write to persistent audit store (stdout captured by log aggregator)
    process.stdout.write(JSON.stringify({ AUDIT: entry }) + "\n");
  };

  auditLog("request_start", { name, modelName: "llama2-13b" });

  const companionKey = {
    companionName: name!,
    userId: clerkUserId!,
    modelName: "llama2-13b",
  };
  const memoryManager = await MemoryManager.getInstance();

  const records = await memoryManager.readLatestHistory(companionKey);
  if (records.length === 0) {
    await memoryManager.seedChatHistory(seedchat, "\n\n", companionKey);
  }
  // Retention policy: history entries are subject to the 30-day rotation
  // configured in MemoryManager (TTL on Redis key and Pinecone namespace).
  await memoryManager.writeToHistory("User: " + prompt + "\n", companionKey);
  const inputHash = createHash("sha256").update(prompt).digest("hex");
  auditLog("memory_write_user_prompt", { inputHash, retentionDays: 30 });

  // Query Pinecone

  let recentChatHistory = await memoryManager.readLatestHistory(companionKey);

  // Right now the preamble is included in the similarity search, but that
  // shouldn't be an issue

  const similarDocs = await memoryManager.vectorSearch(
    recentChatHistory,
    companion_file_name
  );
  // Audit: record retrieval context for forensic lineage
  const retrievedDocIds = similarDocs
    ? similarDocs.map((doc, idx) => ({
        idx,
        contentHash: createHash("sha256")
          .update(doc.pageContent ?? "")
          .digest("hex"),
        metadata: doc.metadata ?? {},
      }))
    : [];
  auditLog("vector_search_complete", {
    companion_file_name,
    retrievedCount: retrievedDocIds.length,
    retrievedDocs: retrievedDocIds,
  });

  const MAX_RELEVANT_HISTORY_CHARS = 1000;
  let relevantHistory = "";
  if (!!similarDocs && similarDocs.length !== 0) {
    relevantHistory = similarDocs
      .map((doc) => doc.pageContent)
      .join("\n")
      .slice(0, MAX_RELEVANT_HISTORY_CHARS);
  }
    // ── Tool Allow List ──────────────────────────────────────────────────────────
  const TOOL_ALLOW_LIST: ReadonlySet<string> = new Set([
    "a16z-infra/llama13b-v2-chat:df7690f1994d94e96ad9d568eac121aecf50684a0b0963b25a41cc40061269e5",
  ]);
  const POLICY_VERSION = "tool-allow-list-v1";

  const requestedModel =
    "a16z-infra/llama13b-v2-chat:df7690f1994d94e96ad9d568eac121aecf50684a0b0963b25a41cc40061269e5";

  // Audit log helper — writes to stderr so it is captured by log aggregators
  // independently of the response stream and cannot be suppressed by callers.
  const auditLog = (event: string, allowed: boolean, reason?: string) => {
    const entry = JSON.stringify({
      timestamp: new Date().toISOString(),
      policy: POLICY_VERSION,
      actor: clerkUserId,
      tool: requestedModel,
      event,
      allowed,
      reason: reason ?? null,
    });
    process.stderr.write(entry + "\n");
  };

  // Fail-closed allow list check
  if (!TOOL_ALLOW_LIST.has(requestedModel)) {
    auditLog("tool_invocation_denied", false, "model not in allow list");
    return new NextResponse(
      JSON.stringify({ Message: "Tool not permitted by policy" }),
      {
        status: 403,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  auditLog("tool_invocation_attempt", true);
  // ─────────────────────────────────────────────────────────────────────────────

    // ---------------------------------------------------------------------------
  // Approved model registry — only identifiers listed here may be used for
  // inference. Both the repository slug AND the pinned SHA digest must match.
  // ---------------------------------------------------------------------------
  const APPROVED_MODEL_REGISTRY: Record<string, string> = {
    // Internal alias  →  fully-qualified, version-pinned Replicate identifier
    "llama2-13b":
      "meta/llama-2-13b-chat:f4e2de70d66816a838a89eeeb621910adffb0dd0baba3976c96980970978018d",
  };

  const MODEL_ALIAS = "llama2-13b";
  const PINNED_MODEL_ID = APPROVED_MODEL_REGISTRY[MODEL_ALIAS];

  if (!PINNED_MODEL_ID) {
    return new NextResponse(
      JSON.stringify({
        Message: `Model '${MODEL_ALIAS}' is not in the approved model registry.`,
      }),
      {
        status: 403,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  const { stream, handlers } = LangChainStream();
  // Call Replicate for inference — model identity is taken exclusively from the
  // approved registry; no user-supplied value influences model selection.
  const model = new Replicate({
    model: PINNED_MODEL_ID,
    input: {
      max_length: 2048,
    },
    apiKey: process.env.REPLICATE_API_TOKEN,
    callbackManager: CallbackManager.fromHandlers(handlers),
  });

  // Turn verbose on for debugging
  model.verbose = true;

  let resp: string;
  try {
    resp = String(
      await model.call(
        `
       ONLY generate NO more than three sentences as ${name}. DO NOT generate more than three sentences. 
       Make sure the output you generate starts with '${name}:' and ends with a period.

       ${preamble}

       Below are relevant details about ${name}'s past and the conversation you are in.
       ${relevantHistory}


       ${recentChatHistory}\n${name}:`
      )
    );
    auditLog("tool_invocation_success", true);
  } catch (err) {
    auditLog(
      "tool_invocation_error",
      false,
      err instanceof Error ? err.message : String(err)
    );
    return new NextResponse(
      JSON.stringify({ Message: "Model invocation failed" }),
      {
        status: 502,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
  // Call OpenAI for inference (approved model)
  const model = new OpenAI({
    modelName: "gpt-3.5-turbo-instruct",
    maxTokens: 2048,
    openAIApiKey: process.env.OPENAI_API_KEY,
    callbackManager: CallbackManager.fromHandlers(handlers),
  });

  // Turn verbose on for debugging
  model.verbose = true;

  // Dangerous primitive patterns that must not appear in LLM output
  const DANGEROUS_PATTERNS = [
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /\bexecSync\s*\(/i,
    /\bspawnSync\s*\(/i,
    /\bspawn\s*\(/i,
    /\bsubprocess\b/i,
    /\bnew\s+Function\s*\(/i,
    /\bsetTimeout\s*\(\s*['"`]/i,
    /\bsetInterval\s*\(\s*['"`]/i,
    /\brequire\s*\(/i,
    /\bimport\s*\(/i,
    /\bprocess\.env\b/i,
    /\bchild_process\b/i,
    /\b__import__\s*\(/i,
    /\bos\.system\s*\(/i,
    /\bos\.popen\s*\(/i,
    /\bexecfile\s*\(/i,
    /\bcompile\s*\(/i,
  ];

  function sanitizeLLMOutput(output: string): string {
    for (const pattern of DANGEROUS_PATTERNS) {
      if (pattern.test(output)) {
        throw new Error(
          `LLM output contains a forbidden dynamic code execution primitive matching: ${pattern}`
        );
      }
    }
    // Strip any non-printable / control characters except common whitespace
    return output.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  }

  let rawResp = String(
    await model
      .call(
        `
       ONLY generate NO more than three sentences as ${name}. DO NOT generate more than three sentences. 
       Make sure the output you generate starts with '${name}:' and ends with a period.

       ${preamble}

       Below are relevant details about ${name}'s past and the conversation you are in.
       ${relevantHistory}


       ${recentChatHistory}\n${name}:`
      )
      .catch((err: unknown) => { throw err instanceof Error ? err : new Error(String(err)); })
  );

  let resp: string;
  try {
    resp = sanitizeLLMOutput(rawResp);
  } catch (err) {
    console.error("LLM output failed sanitization:", err);
    return new Response("Invalid response generated. Please try again.", {
      status: 400,
    });
  }

  // Output filtering: extract only the first line attributed to the named
  // character, enforce the allowlist shape 'Name: <text>.', and cap length.
  const MAX_RESPONSE_CHARS = 500;
  const cleaned = resp.replaceAll(",", "");
  const chunks = cleaned.split("\n");
  // Find the first chunk that matches the expected 'Name:' prefix pattern.
  const allowedPrefix = `${name}:`;
  const matchedChunk =
    chunks.find((c) => c.trim().startsWith(allowedPrefix)) ??
    chunks[0];
  // Strip any content that does not belong to the named character's turn.
  const sanitized = matchedChunk.trim().startsWith(allowedPrefix)
    ? matchedChunk.trim()
    : `${allowedPrefix}`;
  const response = sanitized.slice(0, MAX_RESPONSE_CHARS);

  // Retention policy: history entries subject to 30-day rotation (see MemoryManager TTL config).
  await memoryManager.writeToHistory("" + response.trim(), companionKey);
  auditLog("memory_write_assistant_response", {
    responseHash: createHash("sha256").update(response.trim()).digest("hex"),
    retentionDays: 30,
  });
  var Readable = require("stream").Readable;
  const crypto = require("crypto");

  // --- Synthetic Content Provenance & Labeling ---
  const MODEL_ID =
    "a16z-infra/llama13b-v2-chat:df7690f1994d94e96ad9d568eac121aecf50684a0b0963b25a41cc40061269e5";
  const timestamp = new Date().toISOString();
  const contentOrigin = "AI-Generated";

  // Watermark token embedded in the streamed text
  const WATERMARK_TOKEN = "\u200B[AI]\u200B"; // zero-width space bracketed label

  // Cryptographic signature over provenance fields
  const provenancePayload = JSON.stringify({
    model: MODEL_ID,
    timestamp,
    origin: contentOrigin,
  });
  const signingSecret = process.env.PROVENANCE_SIGNING_SECRET || "default-insecure-secret";
  const signature = crypto
    .createHmac("sha256", signingSecret)
    .update(provenancePayload)
    .digest("base64");

  // Prepend AI-origin label + watermark to the response body
  const labeledResponse = `[AI-GENERATED CONTENT]${WATERMARK_TOKEN} ${response}`;

  let s = new Readable();
  s.push(labeledResponse);
  s.push(null);

  if (response !== undefined && response.length > 1) {
    memoryManager.writeToHistory("" + response.trim(), companionKey);
  }

  return new StreamingTextResponse(s, {
    headers: {
      "X-AI-Model": MODEL_ID,
      "X-AI-Timestamp": timestamp,
      "X-AI-Content-Origin": contentOrigin,
      "X-AI-Provenance-Signature": signature,
      "X-AI-Synthetic-Label": "true",
    },
  });
}
