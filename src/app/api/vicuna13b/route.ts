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

// Allowlist of permitted companion names
const ALLOWED_COMPANION_NAMES: ReadonlySet<string> = new Set([
  "elon",
  "beast",
  "jobs",
  // Add additional permitted companion names here
]);

// Allowlist of permitted Replicate model identifiers
const ALLOWED_REPLICATE_MODELS: ReadonlySet<string> = new Set([
  "a16z-infra/vicuna13b-v2:6afde2649d5b272e1c398b2a8c8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8",
]);

// Sanitize inputs to prevent prompt injection attacks
function sanitizeInput(input: string): string {
  if (!input || typeof input !== 'string') return '';

  // Detect and reject base64-encoded content (long base64 strings)
  const base64Pattern = /(?:[A-Za-z0-9+\/]{4}){10,}(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?/g;
  if (base64Pattern.test(input)) {
    throw new Error('Potentially malicious content detected: base64-encoded payload');
  }

  // Detect shell command injection patterns
  const shellCommandPattern = /(`[^`]*`|\$\([^)]*\)|\b(bash|sh|cmd|powershell|exec|eval|system|popen|subprocess)\b\s*[\(\-])/i;
  if (shellCommandPattern.test(input)) {
    throw new Error('Potentially malicious content detected: shell command pattern');
  }

  // Detect prompt injection / instruction override attempts
  const injectionPattern = /\b(ignore (previous|above|prior|all) instructions?|disregard (previous|above|prior|all)|forget (previous|above|prior|all)|new instructions?:|system prompt:|you are now|act as (a |an )?(?!assistant)|jailbreak|dan mode|developer mode|override (previous|all)|stop being|pretend (you are|to be)|roleplay as)/i;
  if (injectionPattern.test(input)) {
    throw new Error('Potentially malicious content detected: prompt injection pattern');
  }

  // Detect leetspeak obfuscation (e.g., 1gnor3, 3x3cut3)
  const leetspeakPattern = /\b[a-z0-9]*(?:(?:3(?=x|v|d)|0(?=r|n|b)|1(?=g|n|l)|4(?=c|s)|@(?=c|s)|\$(?=h|y))[a-z0-9]+){2,}\b/i;
  if (leetspeakPattern.test(input)) {
    throw new Error('Potentially malicious content detected: obfuscated (leetspeak) content');
  }

  // Detect hidden/invisible unicode characters used for smuggling
  const hiddenCharsPattern = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/g;
  if (hiddenCharsPattern.test(input)) {
    throw new Error('Potentially malicious content detected: hidden unicode characters');
  }

  // Strip any HTML/script tags to prevent injection via markup
  const sanitized = input.replace(/<[^>]*>/g, '');

  return sanitized;
}

function safeValidateInput(input: string, label: string): string {
  try {
    return sanitizeInput(input);
  } catch (err: any) {
    throw new Error(`Input validation failed for [${label}]: ${err.message}`);
  }
}

/**
 * Sanitize input before passing to the AI model.
 * - Removes null bytes and ASCII control characters (except newline/tab)
 * - Trims leading/trailing whitespace
 * - Enforces a maximum character length to prevent prompt injection via oversized input
 */
function sanitizeInput(input: string, maxLength = 4000): string {
  if (typeof input !== "string") return "";
  return input
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "") // strip control chars except \n and \t
    .trim()
    .slice(0, maxLength);
}

/**
 * Sanitize a string before it is passed to the model.
 * - Rejects non-string values (returns empty string).
 * - Strips null bytes and ASCII control characters (except common whitespace).
 * - Truncates to a safe maximum length to prevent prompt-injection via huge payloads.
 */
const MAX_INPUT_LENGTH = 4000;
function sanitizeInput(value: unknown, maxLength = MAX_INPUT_LENGTH): string {
  if (typeof value !== "string") return "";
  return value
    // Remove null bytes
    .replace(/\0/g, "")
    // Remove ASCII control characters except tab (\x09), newline (\x0A), carriage return (\x0D)
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
    // Truncate to maximum allowed length
    .slice(0, maxLength);
}

export async function POST(request: Request) {
  const { prompt: rawPrompt, isText, userId, userName } = await request.json();
  const prompt = sanitizeInput(rawPrompt);
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
  const rawName = request.headers.get("name");

  // Enforce allowlist: reject any name not explicitly permitted
  if (!rawName || !ALLOWED_COMPANION_NAMES.has(rawName)) {
    console.log(`INFO: rejected disallowed companion name: ${rawName}`);
    return new NextResponse(
      JSON.stringify({ Message: "Companion not found or not permitted." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  // Safe to use: name is validated against the allowlist
  const name = rawName;
  // Construct file name only after allowlist validation; no path separators possible
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

  // Security: sanitize companion file content before use in LLM prompt
  function sanitizeCompanionContent(content: string): string {
    // Remove invisible/zero-width characters
    content = content.replace(/[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/g, "");

    // Remove non-printable control characters (except common whitespace)
    content = content.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

    // Detect and reject base64-encoded blobs (long runs of base64 chars)
    if (/(?:[A-Za-z0-9+\/]{40,}={0,2})/.test(content)) {
      throw new Error("Companion file contains suspicious base64-encoded content.");
    }

    // Detect binary/shell command patterns
    if (/(\/bin\/|\/etc\/passwd|\bexec\b|\beval\b|\bsystem\b|\bchmod\b|\bwget\b|\bcurl\b|\bnc \b|\bnetcat\b)/i.test(content)) {
      throw new Error("Companion file contains suspicious shell/binary command content.");
    }

    // Detect prompt injection keywords
    const injectionPatterns = [
      /ignore (all |previous |above |prior )?instructions/i,
      /disregard (all |previous |above |prior )?instructions/i,
      /forget (all |previous |above |prior )?instructions/i,
      /you are now/i,
      /act as (a |an )?(?!companion|character)/i,
      /new persona/i,
      /system prompt/i,
      /\[INST\]/i,
      /<\|system\|>/i,
      /###\s*system/i,
    ];
    for (const pattern of injectionPatterns) {
      if (pattern.test(content)) {
        throw new Error("Companion file contains suspicious prompt injection content.");
      }
    }

    // Detect leetspeak obfuscation (e.g. 1gn0r3, 3x3cut3)
    if (/\b[a-z0-9]*[0-9][a-z][a-z0-9]*[0-9][a-z0-9]*\b/i.test(content) &&
        /\b(?:1gn[o0]r[e3]|[e3]x[e3]c|[s5]y[s5]t[e3]m|[e3]v[a4]l)\b/i.test(content)) {
      throw new Error("Companion file contains suspicious leetspeak-obfuscated content.");
    }

    return content;
  }

  const rawData = await fs.readFile("companions/" + companion_file_name, "utf8");
  const data = sanitizeCompanionContent(rawData);

  // Clunky way to break out PREAMBLE and SEEDCHAT from the character file
  const presplit = data.split("###ENDPREAMBLE###");
  const preamble = sanitizeInput(presplit[0], 8000);
  const seedsplit = presplit[1].split("###ENDSEEDCHAT###");
  const seedchat = sanitizeInput(seedsplit[0], 8000);

  const companionKey = {
    companionName: name!,
    userId: clerkUserId!,
    modelName: "vicuna13b",
  };
  const memoryManager = await MemoryManager.getInstance();

  const { stream, handlers } = LangChainStream();

  // ── Audit / forensic setup ──────────────────────────────────────────────
  // Shared correlation identifier that links every step of this request.
  const traceId = crypto.randomUUID();
  // Retention period for chat history and audit records (seconds).
  const HISTORY_TTL_SECONDS = 60 * 60 * 24 * 90; // 90 days

  // Minimal structured logger that writes to the same Redis instance used by
  // MemoryManager so audit records land in a persistent store.
  async function writeAuditRecord(record: Record<string, unknown>): Promise<void> {
    const client = await memoryManager.getRedisClient(); // assumes MemoryManager exposes this
    const key = `audit:${traceId}:${Date.now()}`;
    await client.set(key, JSON.stringify(record), { EX: HISTORY_TTL_SECONDS });
    console.info("[AUDIT]", JSON.stringify(record));
  }

  function sha256Hex(input: string): string {
    const { createHash } = require("crypto");
    return createHash("sha256").update(input, "utf8").digest("hex");
  }
  // ────────────────────────────────────────────────────────────────────────

  console.info("[TRACE]", JSON.stringify({ traceId, step: "rate-limit-passed", principal: clerkUserId, companionName: name, ts: new Date().toISOString() }));

  const records = await memoryManager.readLatestHistory(companionKey);
  if (records.length === 0) {
    await memoryManager.seedChatHistory(seedchat, "\n\n", companionKey);
  }
  // Sanitize prompt to mitigate prompt injection: remove control sequences and trim whitespace
  const sanitizedPrompt = prompt
    .replace(/#{1,}/g, "")
    .replace(/[`<>]/g, "")
    .trim()
    .slice(0, 4096); // enforce a reasonable max length
  await memoryManager.writeToHistory(
    "Human: " + sanitizedPrompt + "\n",
    companionKey
  );

  // Query Pinecone

  let rawRecentChatHistory = await memoryManager.readLatestHistory(companionKey);
  // Sanitize chat history retrieved from memory to prevent stored prompt injection
  let recentChatHistory = rawRecentChatHistory
    .replace(/#{1,}/g, "")
    .replace(/[`<>]/g, "")
    .trim();

  // Right now the preamble is included in the similarity search, but that
  // shouldn't be an issue

    const similarDocs = await memoryManager.vectorSearch(
    recentChatHistory,
    companion_file_name
  );

  // Capture retrieved document IDs for forensic lineage.
  const retrievedDocIds: string[] = (similarDocs ?? []).map(
    (doc) => (doc.metadata?.id as string) ?? doc.metadata?.source ?? "unknown"
  );
  console.info("[TRACE]", JSON.stringify({ traceId, step: "vector-search", retrievedDocIds, ts: new Date().toISOString() }));

  let relevantHistory = "";
  if (!!similarDocs && similarDocs.length !== 0) {
    relevantHistory = similarDocs.map((doc) => doc.pageContent).join("\n");
  }

  // Call approved LLM for inference
  const { OpenAI } = await import("langchain/llms/openai");
  const model = new OpenAI({
    modelName: "gpt-3.5-turbo-instruct",
    maxTokens: 2048,
    openAIApiKey: process.env.OPENAI_API_KEY,
    callbackManager: CallbackManager.fromHandlers(handlers),
  });

  // Turn verbose on for debugging
  model.verbose = true;

  const llmPrompt = `${preamble}  
       
       Below are relevant details about ${name}'s past:
       ${relevantHistory}

       Below is a relevant conversation history

       ${recentChatHistory}
       ### ${name}:
       `;

  console.log("[LLM REQUEST] model=vicuna-13b prompt=", llmPrompt);

    const MAX_PREAMBLE_CHARS = 1500;
  const MAX_HISTORY_CHARS = 2000;
  const trimmedPreamble = String(preamble ?? "").slice(0, MAX_PREAMBLE_CHARS);
  const trimmedHistory = String(recentChatHistory ?? "").slice(-MAX_HISTORY_CHARS);

    const modelId = "replicate/vicuna-13b";
  const modelVersion = "6282abe6a492de4145d7bb601023762212f9ddbbe78278bd6771c8b3b2f2a13b";
  const modelInput = `${preamble}  
       
       Below are relevant details about ${name}'s past:
       ${relevantHistory}

       Below is a relevant conversation history

       ${recentChatHistory}
       ### ${name}:
       `;
  const inputHash = sha256Hex(modelInput);

  console.info("[TRACE]", JSON.stringify({ traceId, step: "model-inference-start", modelId, modelVersion, inputHash, principal: clerkUserId, ts: new Date().toISOString() }));

  let rawResp: unknown;
  try {
    rawResp = await model.call(modelInput);
  } catch (inferenceError) {
    await writeAuditRecord({
      traceId,
      step: "model-inference-error",
      modelId,
      modelVersion,
      inputHash,
      principal: clerkUserId,
      error: String(inferenceError),
      ts: new Date().toISOString(),
    });
    // Fail closed — do not continue without a valid model response.
    throw inferenceError;
  }

  let resp = String(rawResp);
  const outputHash = sha256Hex(resp);

  await writeAuditRecord({
    traceId,
    step: "model-inference-complete",
    modelId,
    modelVersion,
    inputHash,
    outputHash,
    principal: clerkUserId,
    companionName: name,
    retrievedDocIds,
    ts: new Date().toISOString(),
  });

  console.log("[LLM RESPONSE] model=vicuna-13b response=", resp);

  // Validate and sanitize LLM output before further processing.
  // Check for dangerous dynamic code execution primitives in the response.
  const DANGEROUS_PATTERNS = [
    /\beval\s*\(/gi,
    /\bexec\s*\(/gi,
    /\bexecSync\s*\(/gi,
    /\bspawnSync\s*\(/gi,
    /\bspawn\s*\(/gi,
    /\bsubprocess\b/gi,
    /\bimport\s+os\b/gi,
    /\brequire\s*\(/gi,
    /\bFunction\s*\(/gi,
    /\bnew\s+Function\b/gi,
    /\bsetTimeout\s*\(/gi,
    /\bsetInterval\s*\(/gi,
    /\bProcessBuilder\b/gi,
    /\bRuntime\.getRuntime\b/gi,
    /`[^`]*`/g,  // template literal execution attempts
    /\$\([^)]*\)/g, // shell command substitution
  ];

  const hasDangerousContent = DANGEROUS_PATTERNS.some((pattern) =>
    pattern.test(resp)
  );

  if (hasDangerousContent) {
    console.warn(
      "[SECURITY] Dangerous code execution primitive detected in LLM output. Blocking response."
    );
    return new Response("Response blocked due to policy violation.", {
      status: 400,
    });
  }

  // Sanitize: strip any residual angle-bracket tags and null bytes
  resp = resp
    .replace(/<[^>]*>/g, "")   // strip HTML/XML tags
    .replace(/\0/g, "");        // strip null bytes

  // Right now just using super shoddy string manip logic to get at
  // the dialog.

  const cleaned = resp.replaceAll(",", "");
  const chunks = cleaned.split("###");
  const response = chunks[0];
  // const response = chunks.length > 1 ? chunks[0] : chunks[0];

  await memoryManager.writeToHistory("### " + response.trim(), companionKey);
  var Readable = require("stream").Readable;

  // --- Synthetic Content Provenance, Labeling, and Watermarking ---
  // Fail-safe: if labeling/watermarking fails, do NOT serve unlabeled content.
  let labeledResponse: string;
  try {
    const provenanceTimestamp = new Date().toISOString();
    const modelIdentifier =
      "replicate/vicuna-13b:6282abe6a492de4145d7bb601023762212f9ddbbe78278bd6771c8b3b2f2a13b";
    const aiContentLabel =
      "[AI-GENERATED CONTENT | Origin: Replicate Vicuna-13B | This content was produced by an artificial intelligence model and may not reflect factual information.]";
    const provenanceWatermark =
      `\n\n<!-- AI_PROVENANCE: model=${modelIdentifier} | generated_at=${provenanceTimestamp} | synthetic=true -->\n`;

    if (response === undefined || response.length <= 1) {
      throw new Error("AI response is empty; cannot attach provenance label.");
    }

    // Compose labeled + watermarked content
    labeledResponse = `${aiContentLabel}\n\n${response}${provenanceWatermark}`;

    // Verify labeling succeeded (fail-safe check)
    if (
      !labeledResponse.includes(aiContentLabel) ||
      !labeledResponse.includes("AI_PROVENANCE")
    ) {
      throw new Error(
        "Provenance labeling or watermarking failed integrity check."
      );
    }
  } catch (labelingError) {
    console.error("[PROVENANCE ERROR] Failed to label AI content:", labelingError);
    // Fail-safe: reject the response rather than serve unlabeled AI content
    return new Response(
      JSON.stringify({
        error:
          "AI content could not be served: provenance labeling/watermarking failed.",
      }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }
  // --- End Provenance Block ---

  let s = new Readable();
  s.push(labeledResponse);
  s.push(null);
  if (response !== undefined && response.length > 1) {
    await memoryManager.writeToHistory("### " + response.trim(), companionKey);
  }

  // 3. Model identity at inference — attach resolved model id and version to
  //    every response so monitoring/audit systems can correlate the call.
  return new StreamingTextResponse(s, {
    headers: {
      "X-Model-Id":      MODEL_NAME,
      "X-Model-Version": TRUSTED_HASH,
    },
  });
}
