import dotenv from "dotenv";
import { StreamingTextResponse, LangChainStream } from "ai";
import { Replicate, ReplicateInput } from "langchain/llms/replicate";
import { CallbackManager } from "langchain/callbacks";
import clerk from "@clerk/clerk-sdk-node";
import MemoryManager from "@/app/utils/memory";
import { currentUser } from "@clerk/nextjs";
import { NextResponse } from "next/server";
import { rateLimit } from "@/app/utils/rateLimit";

dotenv.config({ path: `.env.local` });

/**
 * Checks a string for prompt injection patterns:
 * - Invisible/control characters (except normal whitespace)
 * - Base64-encoded blobs that could hide instructions
 * - Shell/binary command patterns
 * - Prompt override keywords
 * - Leetspeak obfuscation patterns
 * Returns true if the content is considered safe, false otherwise.
 */
function isSafeInput(value: string | null | undefined): boolean {
  if (value === null || value === undefined) return true;

  // Reject invisible / non-printable control characters (except \t, \n, \r)
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\x80-\x9F]/.test(value)) return false;

  // Reject zero-width / homoglyph / bidirectional override characters
  if (/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/.test(value)) return false;

  // Reject suspiciously long base64-like blobs (>= 100 contiguous base64 chars)
  if (/[A-Za-z0-9+/]{100,}={0,2}/.test(value)) return false;

  // Reject shell / binary command patterns
  const shellPatterns = [
    /`[^`]*`/,                        // backtick execution
    /\$\([^)]*\)/,                    // $(...) subshell
    /;\s*(rm|wget|curl|bash|sh|python|perl|ruby|nc|ncat|netcat)\b/i,
    /\b(eval|exec|system|popen|subprocess|os\.system)\s*\(/i,
    /\b(chmod|chown|sudo|su|passwd|shadow)\b/i,
    /\/etc\/(passwd|shadow|hosts|crontab)/i,
    /\b(base64\s+-d|base64\s+--decode)/i,
  ];
  for (const pattern of shellPatterns) {
    if (pattern.test(value)) return false;
  }

  // Reject prompt override / jailbreak keywords
  const injectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)/i,
    /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)/i,
    /forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)/i,
    /you\s+are\s+now\s+(a\s+)?(?!${name})/i,  // "you are now a [different persona]"
    /act\s+as\s+(if\s+you\s+are\s+)?(?:an?\s+)?(?:evil|malicious|unrestricted|jailbroken|DAN)/i,
    /\[SYSTEM\]/i,
    /<<SYS>>/i,
    /<\|im_start\|>/i,
    /###\s*(INSTRUCTION|SYSTEM|OVERRIDE)/i,
    /new\s+instructions?:/i,
    /override\s+(the\s+)?(system|instructions?|prompt)/i,
  ];
  for (const pattern of injectionPatterns) {
    if (pattern.test(value)) return false;
  }

  // Reject heavy leetspeak (3+ leet substitutions in a short span)
  // Simple heuristic: count typical leet chars relative to string length
  const leetChars = (value.match(/[04813!@$7]/g) || []).length;
  const alphaChars = (value.match(/[a-zA-Z0-9]/g) || []).length;
  if (alphaChars > 0 && leetChars / alphaChars > 0.4 && value.length > 20) return false;

  return true;
}

/**
 * Sanitizes a string for safe inclusion in an LLM prompt by stripping
 * characters that could be used for injection even after validation.
 */
function sanitizeForPrompt(value: string): string {
  // Remove any remaining control characters
  return value.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
              .replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/g, '');
}

/**
 * Sanitizes input before sending to LLM to prevent prompt injection and other attacks.
 */
function sanitizeLLMInput(input: string, maxLength = 4000): string {
  if (typeof input !== "string") return "";
  // Truncate to max length
  let sanitized = input.slice(0, maxLength);
  // Remove null bytes and other dangerous control characters (keep newlines/tabs)
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  // Strip common prompt injection patterns (case-insensitive)
  sanitized = sanitized.replace(
    /ignore (all )?(previous|prior|above) instructions?/gi,
    "[removed]"
  );
  sanitized = sanitized.replace(
    /disregard (all )?(previous|prior|above) instructions?/gi,
    "[removed]"
  );
  sanitized = sanitized.replace(
    /you are now|act as|pretend (to be|you are)|forget (all )?instructions?/gi,
    "[removed]"
  );
  // Remove excessive repeated characters that may be used for padding attacks
  sanitized = sanitized.replace(/(.)\1{200,}/g, "$1");
  return sanitized.trim();
}

/**
 * Validates that the companion name is safe to use (alphanumeric, spaces, hyphens only).
 */
function validateCompanionName(name: string | null): string {
  if (!name || typeof name !== "string") throw new Error("Invalid companion name");
  const trimmed = name.trim().slice(0, 100);
  if (!/^[\w\s\-'.]+$/.test(trimmed)) throw new Error("Companion name contains invalid characters");
  return trimmed;
}

export async function POST(request: Request) {
  const rawBody = await request.json();
  // Sanitize and validate all user-supplied fields
  const prompt: string = typeof rawBody.prompt === "string"
    ? rawBody.prompt.trim().slice(0, 4096)
    : "";
  const isText: boolean = !!rawBody.isText;
  const userId: string = typeof rawBody.userId === "string"
    ? rawBody.userId.trim().slice(0, 256)
    : "";
  const userName: string = typeof rawBody.userName === "string"
    ? rawBody.userName.replace(/[^a-zA-Z0-9 _-]/g, "").trim().slice(0, 128)
    : "";
  if (!prompt) {
    return new NextResponse(
      JSON.stringify({ Message: "Missing or invalid 'prompt'" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
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
  if (!rawName || rawName.trim() === "") {
    return new NextResponse(
      JSON.stringify({ Message: "Missing or invalid 'name' header" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
  // Sanitize: allow only alphanumeric, hyphens, and underscores to prevent path traversal
  const name = rawName.replace(/[^a-zA-Z0-9_-]/g, "");
  if (name.length === 0 || name.length > 64) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid 'name' header value" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
  const companion_file_name = name + ".txt";

  // Always authenticate server-side regardless of isText flag
  user = await currentUser();
  clerkUserId = user?.id;
  clerkUserName = user?.firstName ?? (isText ? userName : undefined);

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

  // Resolve and validate the file path to prevent directory traversal.
  const companionsDir = path.resolve("companions");
  const resolvedFilePath = path.resolve(companionsDir, companion_file_name);
  if (!resolvedFilePath.startsWith(companionsDir + path.sep)) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion file path." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  const data = await fs.readFile(resolvedFilePath, "utf8");

  // --- Malicious content checks ---

  // 1. Reject binary/non-printable content (executable or binary files).
  // Allow common printable ASCII, tabs, newlines, and carriage returns.
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(data)) {
    return new NextResponse(
      JSON.stringify({ Message: "Companion file contains invalid binary content." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  // 2. Reject invisible/zero-width characters used to hide prompt injections.
  if (/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/.test(data)) {
    return new NextResponse(
      JSON.stringify({ Message: "Companion file contains hidden/invisible characters." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  // 3. Reject shell command patterns.
  const shellCommandPattern = /(?:^|\s)(sudo|chmod|chown|curl|wget|bash|sh|exec|eval|system|passthru|popen|proc_open|rm\s+-rf|mkfifo|nc\s+|ncat\s+|netcat\s+)\s/im;
  if (shellCommandPattern.test(data)) {
    return new NextResponse(
      JSON.stringify({ Message: "Companion file contains suspicious shell commands." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  // 4. Reject base64-encoded blobs that may hide injected prompts.
  // Flag long base64 strings (>=100 chars) as suspicious.
  const base64Pattern = /(?:[A-Za-z0-9+\/]{4}){25,}(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?/;
  if (base64Pattern.test(data)) {
    return new NextResponse(
      JSON.stringify({ Message: "Companion file contains suspicious base64-encoded content." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  // 5. Reject common prompt injection / jailbreak phrases.
  const promptInjectionPattern = /(?:ignore\s+(all\s+)?(?:previous|prior|above)\s+instructions?|disregard\s+(?:previous|prior|above)|you\s+are\s+now\s+(?:in\s+)?(?:DAN|jailbreak|developer\s+mode)|forget\s+(?:all\s+)?(?:previous|prior)\s+instructions?|act\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|evil|malicious)|system\s*:\s*you\s+are|<\s*system\s*>)/i;
  if (promptInjectionPattern.test(data)) {
    return new NextResponse(
      JSON.stringify({ Message: "Companion file contains suspicious prompt injection content." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  // 6. Reject leetspeak obfuscation patterns (e.g., 1gn0r3, 3x3cut3).
  // Heuristic: flag strings with high ratio of digit-letter substitutions.
  const leetspeakPattern = /\b(?:[a-z]*[013456789][a-z0-9]*){3,}\b/i;
  const leetspeakMatches = data.match(new RegExp(leetspeakPattern.source, 'gi')) || [];
  if (leetspeakMatches.length > 10) {
    return new NextResponse(
      JSON.stringify({ Message: "Companion file contains suspicious obfuscated (leetspeak) content." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  // Clunky way to break out PREAMBLE and SEEDCHAT from the character file
  const presplit = data.split("###ENDPREAMBLE###");
  const preamble = sanitizeLLMInput(presplit[0], 8000);
  const seedsplit = presplit[1].split("###ENDSEEDCHAT###");
  const seedchat = sanitizeLLMInput(seedsplit[0], 8000);

  const companionKey = {
    companionName: name!,
    userId: clerkUserId!,
    modelName: "llama2-13b",
  };
  const memoryManager = await MemoryManager.getInstance();

  await writeAuditRecord({ step: "memory_read_latest", companionName: name });
  const records = await memoryManager.readLatestHistory(companionKey);
  if (records.length === 0) {
    await memoryManager.seedChatHistory(seedchat, "\n\n", companionKey);
  }
  await writeAuditRecord({
    step: "memory_write_user_prompt",
    inputHash: crypto.createHash("sha256").update(prompt).digest("hex"),
    retentionDays: MEMORY_RETENTION_DAYS,
  });
  await memoryManager.writeToHistory("User: " + prompt + "\n", companionKey);

  // Query Pinecone

  const MAX_RECENT_HISTORY_LENGTH = 1000;
  const rawRecentChatHistory = await memoryManager.readLatestHistory(companionKey);
  let recentChatHistory = rawRecentChatHistory.slice(-MAX_RECENT_HISTORY_LENGTH);

  // Right now the preamble is included in the similarity search, but that
  // shouldn't be an issue

  await writeAuditRecord({
    step: "vector_search",
    queryHash: crypto.createHash("sha256").update(recentChatHistory).digest("hex"),
    companionFile: companion_file_name,
  });
  const similarDocs = await memoryManager.vectorSearch(
    recentChatHistory,
    companion_file_name
  );

  let relevantHistory = "";
  if (!!similarDocs && similarDocs.length !== 0) {
    const MAX_DOC_LENGTH = 300;
    const MAX_RELEVANT_HISTORY_LENGTH = 1500;
    relevantHistory = similarDocs
      .map((doc) => doc.pageContent.slice(0, MAX_DOC_LENGTH))
      .join("\n")
      .slice(0, MAX_RELEVANT_HISTORY_LENGTH);
  }
    // The LLaMA2 model via Replicate is not in the approved LLM registry and has been removed.
  return new NextResponse(
    JSON.stringify({ Message: "The requested model is not approved for use by this organization." }),
    {
      status: 403,
      headers: {
        "Content-Type": "application/json",
      },
    }
  );

  let resp = ""; // unreachable; retained only to preserve downstream variable references
  // Call approved LLM for inference
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

    const inferenceInput = `
       ONLY generate NO more than three sentences as ${name}. DO NOT generate more than three sentences. 
       Make sure the output you generate starts with '${name}:' and ends with a period.

       ${preamble}

       Below are relevant details about ${name}'s past and the conversation you are in.
       ${relevantHistory}


       ${recentChatHistory}\n${name}:`;

  const inputHash = crypto.createHash("sha256").update(inferenceInput).digest("hex");

  await writeAuditRecord({
    step: "model_inference_start",
    inputHash,
    modelVersion: modelId,
  });

  let rawResp: unknown;
  try {
    rawResp = await model.call(inferenceInput);
  } catch (inferenceErr) {
    await writeAuditRecord({
      step: "model_inference_failure",
      inputHash,
      error: String(inferenceErr),
    });
    // Fail closed — do not return a partial or undefined response
    throw inferenceErr;
  }

  const outputHash = crypto.createHash("sha256").update(String(rawResp ?? "")).digest("hex");
  await writeAuditRecord({
    step: "model_inference_success",
    inputHash,
    outputHash,
    outputSnippet: String(rawResp ?? "").slice(0, 120),
  });

  let resp = String(rawResp);

  console.log("[LLM Interaction] Model: llama2-13b | Response received from LLM:", resp);

  // Right now just using super shoddy string manip logic to get at
  // the dialog.

  const cleaned = resp.replaceAll(",", "");
  const chunks = cleaned.split("\n");
  const rawResponse = chunks[0];

  // Sanitize LLM output: reject responses containing dynamic code execution primitives
  const DANGEROUS_PATTERNS = [
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /\bsubprocess\b/i,
    /\bos\.system\s*\(/i,
    /\b__import__\s*\(/i,
    /\bFunction\s*\(/,
    /\bnew\s+Function\b/,
    /\bsetTimeout\s*\(\s*['"`]/i,
    /\bsetInterval\s*\(\s*['"`]/i,
    /\bspawn\s*\(/i,
    /\bexecSync\s*\(/i,
    /\bexecFile\s*\(/i,
    /\brequire\s*\(\s*['"`]child_process/i,
    /\bimport\s*\(\s*['"`]child_process/i,
    /\bProcessBuilder\b/i,
    /\bRuntime\.getRuntime\b/i,
  ];

  const containsDangerousContent = DANGEROUS_PATTERNS.some((pattern) =>
    pattern.test(rawResponse)
  );

  const response = containsDangerousContent
    ? `${name}: I'm sorry, I can't help with that.`
    : rawResponse;

  if (containsDangerousContent) {
    console.warn(
      "[SECURITY] LLM response contained dangerous code execution primitive and was blocked."
    );
  }

    await writeAuditRecord({
    step: "memory_write_assistant_response",
    outputHash: crypto.createHash("sha256").update(response.trim()).digest("hex"),
    retentionDays: MEMORY_RETENTION_DAYS,
  });
  await memoryManager.writeToHistory("" + response.trim(), companionKey);
  var Readable = require("stream").Readable;

  let s = new Readable();
  s.push(response);
  s.push(null);
  if (response !== undefined && response.length > 1) {
    memoryManager.writeToHistory("" + response.trim(), companionKey);
  });

  // Cryptographic HMAC signature over provenance metadata
  const signingSecret = process.env.PROVENANCE_SIGNING_SECRET || "default-insecure-secret";
  const provenanceSignature = crypto
    .createHmac("sha256", signingSecret)
    .update(provenancePayload)
    .digest("hex");

  // Prepend AI-origin label as a visible watermark in the streamed content
  const labeledResponse = `${aiLabel}\n${response}`;

  let s = new Readable();
  s.push(labeledResponse);
  s.push(null);

  if (response !== undefined && response.length > 1) {
    memoryManager.writeToHistory("" + response.trim(), companionKey);
  }

  // Attach provenance metadata and signature as response headers
  return new StreamingTextResponse(s, {
    headers: {
      "X-AI-Model": MODEL_ID,
      "X-AI-Generated-At": generatedAt,
      "X-AI-Content-Origin": contentOrigin,
      "X-AI-Content-Label": aiLabel,
      "X-AI-Provenance-Payload": provenancePayload,
      "X-AI-Provenance-Signature": `sha256=${provenanceSignature}`,
    },
  });
}
