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

// Security: sanitize inputs to prevent prompt injection and malicious command execution
function containsMaliciousContent(text: string): boolean {
  if (!text) return false;

  // Check for invisible/hidden Unicode characters (zero-width, soft hyphen, etc.)
  const invisibleCharsPattern = /[\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00A0]/;
  if (invisibleCharsPattern.test(text)) return true;

  // Check for base64-encoded content (long base64 strings that could hide instructions)
  const base64Pattern = /(?:[A-Za-z0-9+\/]{40,}={0,2})/;
  if (base64Pattern.test(text)) return true;

  // Check for shell/binary commands
  const shellCommandPattern = /(?:^|\s|;|\||&)(?:bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess|os\.system|`[^`]+`|\$\([^)]+\))/i;
  if (shellCommandPattern.test(text)) return true;

  // Check for common prompt injection / jailbreak patterns
  const promptInjectionPattern = /(?:ignore\s+(all\s+)?(?:previous|prior|above)\s+instructions?|disregard\s+(?:your|all)\s+(?:previous|prior|above)|you\s+are\s+now\s+(?:a\s+)?(?:dan|jailbreak|unrestricted)|act\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:an?\s+)?(?:evil|malicious|unrestricted|jailbroken)|forget\s+(?:all\s+)?(?:your\s+)?(?:previous\s+)?(?:instructions?|training|rules?|guidelines?)|new\s+instructions?\s*:|system\s*:\s*you\s+are)/i;
  if (promptInjectionPattern.test(text)) return true;

  // Check for leetspeak obfuscation (e.g., 3x3cut3, 1gnor3)
  const leetspeakPattern = /(?:[1!][gq][n][o0][r][3e]|[3e][xX][3e][cC][uU][tT][3e]|[5s][yY][5s][tT][3e][mM]|[pP][wW][nN]|[hH][4a][cC][kK])/;
  if (leetspeakPattern.test(text)) return true;

  // Check for binary data or non-printable ASCII characters
  // eslint-disable-next-line no-control-regex
  const binaryPattern = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/;
  if (binaryPattern.test(text)) return true;

  return false;
}

/**
 * Sanitize input strings before passing to the AI model.
 * - Removes null bytes and control characters (except newlines/tabs)
 * - Strips prompt-injection patterns (e.g. ###SYSTEM, <|im_start|>, etc.)
 * - Truncates to a maximum allowed length
 */
function sanitizeInput(input: string, maxLength = 4000): string {
  if (typeof input !== "string") return "";
  return input
    // Remove null bytes
    .replace(/\x00/g, "")
    // Remove non-printable control characters except \n, \r, \t
    .replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
    // Strip common prompt-injection delimiters
    .replace(/<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>/gi, "")
    // Strip lines that attempt to override system/preamble context
    .replace(/###\s*(SYSTEM|ENDPREAMBLE|ENDSEEDCHAT|INST|END)/gi, "")
    // Collapse excessive whitespace runs (keep single newlines)
    .replace(/[ \t]{2,}/g, " ")
    // Enforce maximum length
    .slice(0, maxLength);
}

export async function POST(request: Request) {
  const { prompt: rawPrompt, isText, userId, userName } = await request.json();
  const prompt = sanitizeInput(String(rawPrompt ?? ""), 2000);
  let clerkUserId;
  let user;
  let clerkUserName;

  const identifier = request.url + "-" + "anonymous";
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
  // Allowlist of permitted companion names to prevent path traversal and prompt injection
  const ALLOWED_COMPANION_NAMES: ReadonlySet<string> = new Set([
    "elon",
    "beast",
    "jobs",
    "socrates",
    // Add additional permitted companion names here
  ]);

  const name = request.headers.get("name");

  if (
    !name ||
    !ALLOWED_COMPANION_NAMES.has(name) ||
    !/^[a-zA-Z0-9_-]+$/.test(name)
  ) {
    console.log(`INFO: rejected disallowed or invalid companion name: ${name}`);
    return new NextResponse(
      JSON.stringify({ Message: "Companion not found or not permitted." }),
      {
        status: 400,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }

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
  const rawData = await fs.readFile("companions/" + companion_file_name, "utf8");

  // --- Prompt Injection / Malicious Content Sanitization ---
  function sanitizeCompanionFileContent(content: string): string {
    // 1. Reject files containing non-printable / binary bytes (except common whitespace)
    // eslint-disable-next-line no-control-regex
    if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(content)) {
      throw new Error("Companion file contains binary or non-printable characters.");
    }

    // 2. Strip invisible / zero-width Unicode characters often used to hide injections
    const invisibleCharsRegex =
      /[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180B-\u180D\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\u3164\uFEFF\uFFA0]/g;
    content = content.replace(invisibleCharsRegex, "");

    // 3. Detect base64-encoded blocks that could hide injected instructions
    const base64BlockRegex = /(?:[A-Za-z0-9+\/]{40,}={0,2})/g;
    if (base64BlockRegex.test(content)) {
      throw new Error("Companion file contains suspicious base64-encoded content.");
    }

    // 4. Detect shell / system command patterns
    const shellCommandRegex =
      /(?:(?:^|\s)(?:bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess|os\.system|`[^`]+`|\$\([^)]+\))|(?:rm\s+-rf|chmod|chown|wget|curl\s+.*http|nc\s+|ncat\s+|netcat\s+))/im;
    if (shellCommandRegex.test(content)) {
      throw new Error("Companion file contains suspicious shell or system commands.");
    }

    // 5. Detect common prompt-injection instruction keywords
    const injectionKeywordsRegex =
      /(?:ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions?|disregard\s+(?:all\s+)?(?:previous|above|prior)|you\s+are\s+now\s+(?:a\s+)?(?:different|new|another)|forget\s+(?:all\s+)?(?:previous|your)\s+instructions?|act\s+as\s+(?:if\s+you\s+(?:are|were)|a\s+)?(?:jailbreak|DAN|unrestricted)|do\s+not\s+follow\s+(?:your\s+)?(?:guidelines|rules|instructions?)|override\s+(?:your\s+)?(?:safety|content|system))/im;
    if (injectionKeywordsRegex.test(content)) {
      throw new Error("Companion file contains suspicious prompt-injection instructions.");
    }

    // 6. Detect leetspeak substitution patterns used to obfuscate injections
    //    e.g. "1gn0r3", "d1sr3g4rd", "3x3cut3"
    const leetspeakInjectionRegex =
      /(?:1[g9][n]0[r][3e]|d[1i][s5][r][3e][g9][4a][r][d]|[3e][x][3e][c][u][t][3e]|[0o][v][3e][r][r][1i][d][3e])/i;
    if (leetspeakInjectionRegex.test(content)) {
      throw new Error("Companion file contains suspicious leetspeak-encoded content.");
    }

    return content;
  }

  let data: string;
  try {
    data = sanitizeCompanionFileContent(rawData);
  } catch (err: any) {
    console.error("Companion file failed security check:", err.message);
    return new NextResponse(
      JSON.stringify({ Message: "Companion file contains disallowed content." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
  // --- End Sanitization ---

  // Clunky way to break out PREAMBLE and SEEDCHAT from the character file
  const presplit = data.split("###ENDPREAMBLE###");
  const preamble = sanitizeInput(presplit[0], 3000);
  const seedsplit = presplit[1].split("###ENDSEEDCHAT###");
  const seedchat = sanitizeInput(seedsplit[0], 3000);

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
  // Sanitize prompt to mitigate prompt injection: strip characters commonly used to escape prompt context
  const sanitizedPrompt = (prompt || "").replace(/[\r\n]+/g, " ").replace(/#{3,}/g, "").slice(0, 4096);
  await memoryManager.writeToHistory(
    "### Human: " + sanitizedPrompt + "\n",
    companionKey
  );
  // Note: `prompt` is already sanitized above before this write.

  // Query Pinecone

  const MAX_HISTORY_CHARS = 1200;
  let recentChatHistory = (await memoryManager.readLatestHistory(companionKey)).slice(-MAX_HISTORY_CHARS);

  // Right now the preamble is included in the similarity search, but that
  // shouldn't be an issue

  const similarDocs = await memoryManager.vectorSearch(
    recentChatHistory,
    companion_file_name
  );

  const MAX_DOCS = 3;
  const MAX_DOC_CHARS = 300;
  let relevantHistory = "";
  if (!!similarDocs && similarDocs.length !== 0) {
    relevantHistory = similarDocs
      .slice(0, MAX_DOCS)
      .map((doc) => (doc.pageContent ?? "").slice(0, MAX_DOC_CHARS))
      .join("\n");
  }

  // Call OpenAI for inference using approved GPT model
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

  console.log("[LLM INTERACTION] Prompt sent to Vicuna-13b:", llmPrompt);

    const MAX_PREAMBLE_CHARS = 1000;
  const truncatedPreamble = preamble.slice(0, MAX_PREAMBLE_CHARS);

    // Fail closed on inference errors — do NOT silently swallow with .catch(console.error).
  let rawResp: unknown;
  try {
    rawResp = await model.call(inferenceInput);
  } catch (inferenceErr) {
    try {
      await writeAuditRecord({
        event: "AI_INFERENCE_ERROR",
        correlationId,
        timestamp: new Date().toISOString(),
        principal: clerkUserId,
        modelId: MODEL_ID,
        modelVersion: MODEL_VERSION,
        inputHash,
        error: String(inferenceErr),
      });
    } catch (_auditErr) {
      // Best-effort error audit; primary error is re-thrown below.
    }
    throw inferenceErr;
  }
  let resp = String(rawResp);

  console.log("[LLM INTERACTION] Response received from Vicuna-13b:", resp);

  // Validate and sanitize LLM output before further processing.
  // Reject responses containing dynamic code execution primitives.
  const DANGEROUS_PATTERNS = [
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /\bexecSync\s*\(/i,
    /\bspawnSync\s*\(/i,
    /\bspawn\s*\(/i,
    /\bsubprocess\b/i,
    /\bos\.system\s*\(/i,
    /\bchild_process\b/i,
    /\bnew\s+Function\s*\(/i,
    /\bsetTimeout\s*\(\s*['"`]/i,
    /\bsetInterval\s*\(\s*['"`]/i,
    /\bimportlib\b/i,
    /\b__import__\s*\(/i,
    /\bcompile\s*\(/i,
    /\bexecfile\s*\(/i,
    /\brunpy\b/i,
    /\bpopen\s*\(/i,
    /\bshell\s*=\s*True/i,
    /`[^`]*`/,
    /\$\([^)]*\)/,
  ];

  const containsDangerousPrimitive = DANGEROUS_PATTERNS.some((pattern) =>
    pattern.test(resp)
  );

  if (containsDangerousPrimitive) {
    console.warn(
      "[SECURITY] LLM response contained a dynamic code execution primitive and was rejected."
    );
    resp = "I'm sorry, I cannot respond to that.";
  }

  // Strip any remaining potentially executable content: remove backtick
  // command substitution and script-like blocks as a secondary safeguard.
  const sanitized = resp
    .replace(/`[^`]*`/g, "")
    .replace(/\$\([^)]*\)/g, "")
    .replace(/<script[\s\S]*?<\/script>/gi, "");

  // Right now just using super shoddy string manip logic to get at
  // the dialog.

  const cleaned = sanitized.replaceAll(",", "");
  const chunks = cleaned.split("###");
  const response = chunks[0];
  // const response = chunks.length > 1 ? chunks[0] : chunks[0];

  await memoryManager.writeToHistory("### " + response.trim(), companionKey);

  // ── Post-inference audit record ──────────────────────────────────────────────
  try {
    await writeAuditRecord({
      event: "AI_INFERENCE_RESPONSE",
      correlationId,
      timestamp: new Date().toISOString(),
      principal: clerkUserId,
      companionName: name,
      modelId: MODEL_ID,
      modelVersion: MODEL_VERSION,
      inputHash,
      outputHash: sha256(response),
      outputLength: response.length,
      requestTimestamp,
      responseTimestamp: new Date().toISOString(),
    });
  } catch (auditErr) {
    throw new Error(`Audit log write failed after inference: ${auditErr}`);
  }
  // ─────────────────────────────────────────────────────────────────────────────

  var Readable = require("stream").Readable;

  // --- Synthetic-content provenance, labeling & watermarking ---
  const MODEL_ID =
    "replicate/vicuna-13b:6282abe6a492de4145d7bb601023762212f9ddbbe78278bd6771c8b3b2f2a13b";
  const generatedAt = new Date().toISOString();

  // (1) Visible AI-origin label prepended to every response
  const AI_LABEL = "[AI-GENERATED CONTENT | Model: vicuna-13b | Origin: Replicate]\n";
  // (2) Lightweight text watermark appended to the content
  const WATERMARK = "\n<!-- ai-watermark: synthetic-content | vicuna-13b -->";
  const labeledResponse = AI_LABEL + response + WATERMARK;

  // (3) Cryptographic HMAC-SHA-256 signature over provenance fields
  const crypto = require("crypto");
  const provenancePayload = JSON.stringify({
    model: MODEL_ID,
    generatedAt,
    contentOrigin: "replicate-api",
  });
  const signingSecret = process.env.PROVENANCE_SIGNING_SECRET ?? "default-dev-secret";
  const provenanceSignature = crypto
    .createHmac("sha256", signingSecret)
    .update(provenancePayload)
    .digest("hex");

  let s = new Readable();
  s.push(labeledResponse);
  s.push(null);
  if (response !== undefined && response.length > 1) {
    await memoryManager.writeToHistory("### " + response.trim(), companionKey);
  }

  // (4) Attach provenance metadata as response headers
  return new StreamingTextResponse(s, {
    headers: {
      "X-AI-Model-Id": MODEL_ID,
      "X-AI-Generated-At": generatedAt,
      "X-AI-Content-Origin": "replicate-api",
      "X-AI-Content-Label": "synthetic",
      "X-AI-Provenance-Payload": provenancePayload,
      "X-AI-Provenance-Signature": `hmac-sha256=${provenanceSignature}`,
    },
  });
}
