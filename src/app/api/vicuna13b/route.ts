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

// Security: sanitize inputs to prevent prompt injection attacks
function sanitizeInput(input: string | null | undefined, fieldName: string): string {
  if (input === null || input === undefined) return "";

  // Check for invisible/hidden Unicode characters (zero-width, soft hyphen, etc.)
  const invisibleCharsPattern = /[\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u2064\u206A-\u206F\uFEFF\u00A0]/g;
  if (invisibleCharsPattern.test(input)) {
    throw new Error(`Suspicious invisible characters detected in ${fieldName}`);
  }

  // Check for base64-encoded payloads (long base64 strings that could hide commands)
  const base64Pattern = /(?:[A-Za-z0-9+\/]{40,}={0,2})/;
  if (base64Pattern.test(input)) {
    // Attempt to decode and check if it contains shell commands
    const base64Matches = input.match(/[A-Za-z0-9+\/]{40,}={0,2}/g) || [];
    for (const match of base64Matches) {
      try {
        const decoded = Buffer.from(match, "base64").toString("utf8");
        if (containsShellCommands(decoded)) {
          throw new Error(`Base64-encoded shell commands detected in ${fieldName}`);
        }
      } catch (e: any) {
        if (e.message.includes("detected in")) throw e;
        // Not valid base64, ignore
      }
    }
  }

  // Check for shell/binary commands
  if (containsShellCommands(input)) {
    throw new Error(`Shell or binary commands detected in ${fieldName}`);
  }

  // Check for leetspeak patterns that may obfuscate commands
  const leetspeakCommandPattern = /(?:3x3c|3x3C|\$\{|`[^`]*`|\$\([^)]*\)|\beval\b|\bexec\b|\bsystem\b|\bpassthru\b|\bpopen\b)/i;
  if (leetspeakCommandPattern.test(input)) {
    throw new Error(`Suspicious obfuscated content detected in ${fieldName}`);
  }

  // Check for prompt injection patterns (attempts to override system instructions)
  const promptInjectionPattern = /(?:ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)|you\s+are\s+now|new\s+instructions?:|system\s*:\s*you|<\s*system\s*>|\[\s*system\s*\]|###\s*system|forget\s+(everything|all)|disregard\s+(all\s+)?(previous|prior))/i;
  if (promptInjectionPattern.test(input)) {
    throw new Error(`Prompt injection attempt detected in ${fieldName}`);
  }

  return input;
}

function containsShellCommands(text: string): boolean {
  const shellCommandPattern = /(?:\b(?:bash|sh|zsh|cmd|powershell|python|perl|ruby|php|node|curl|wget|nc|ncat|netcat|chmod|chown|sudo|su|rm\s+-rf|mkfifo|mknod|dd\s+if|base64\s+-d|eval|exec|system|popen|subprocess|os\.system|child_process|spawn|fork|execve|execvp)\b|\$\(|`[^`]*`|\|\s*(?:bash|sh|cmd)|;\s*(?:bash|sh|rm|curl|wget)|&&\s*(?:bash|sh|rm|curl|wget)|\bcat\s+\/etc\/(passwd|shadow|hosts)\b|\/bin\/(?:sh|bash|nc)|\bchmod\s+[0-7]{3,4}\b)/i;
  return shellCommandPattern.test(text);
}

// Sanitize user-controlled input before passing to the AI model
function sanitizeInput(input: string | null | undefined, maxLength = 4000): string {
  if (!input) return "";
  // Remove null bytes and control characters (except newlines/tabs which are legitimate)
  let sanitized = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  // Trim leading/trailing whitespace
  sanitized = sanitized.trim();
  // Enforce maximum length to prevent prompt injection via oversized input
  if (sanitized.length > maxLength) {
    sanitized = sanitized.substring(0, maxLength);
  }
  return sanitized;
}

// Validate companion name: only allow alphanumeric, spaces, hyphens, underscores
function sanitizeName(name: string | null | undefined): string | null {
  if (!name) return null;
  const trimmed = name.trim();
  if (!/^[a-zA-Z0-9 _-]{1,100}$/.test(trimmed)) {
    return null;
  }
  return trimmed;
}

export async function POST(request: Request) {
  const { prompt: rawPrompt, isText, userId, userName } = await request.json();
  const prompt = sanitizeInput(rawPrompt, 2000);
  let clerkUserId;
  let user;
  let clerkUserName;

  // userId will be resolved from the authenticated session below
  const identifier = request.url + "-" + "session";
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
  const name = sanitizeName(request.headers.get("name"));
  if (!name) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid or missing companion name." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
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
  const path = require("path");

  // Resolve the companion file path and ensure it stays within the companions/ directory.
  const companionsDir = path.resolve(process.cwd(), "companions");
  const resolvedPath = path.resolve(companionsDir, companion_file_name);
  if (!resolvedPath.startsWith(companionsDir + path.sep)) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion file path." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  const data = await fs.readFile(resolvedPath, "utf8");

  /**
   * Sanitize a string extracted from the companion file before it is injected
   * into an LLM prompt.  Throws if suspicious content is detected.
   */
  function sanitizeCompanionText(text: string, label: string): string {
    // 1. Reject binary / non-printable bytes (except common whitespace).
    if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(text)) {
      throw new Error(`Companion ${label} contains binary/control characters.`);
    }

    // 2. Reject invisible / zero-width Unicode characters often used to hide text.
    if (/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/.test(text)) {
      throw new Error(`Companion ${label} contains hidden Unicode characters.`);
    }

    // 3. Reject suspiciously long base64-like blobs (>= 100 contiguous base64 chars).
    if (/[A-Za-z0-9+/]{100,}={0,2}/.test(text)) {
      throw new Error(`Companion ${label} contains a suspected base64-encoded payload.`);
    }

    // 4. Reject common shell-command patterns.
    if (/(?:bash|sh|cmd|powershell|exec|eval|system|popen|subprocess|os\.system|`[^`]+`|\$\([^)]+\))/.test(text)) {
      throw new Error(`Companion ${label} contains suspected shell commands.`);
    }

    // 5. Reject prompt-injection trigger phrases (case-insensitive).
    const injectionPatterns = [
      /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i,
      /disregard\s+(all\s+)?(previous|prior|above)\s+instructions/i,
      /you\s+are\s+now\s+(a|an)?\s*(?:different|new|evil|unrestricted)/i,
      /act\s+as\s+(if\s+you\s+are|a|an)?\s*(?:jailbreak|dan|unrestricted)/i,
      /system\s*prompt/i,
      /<\s*script[^>]*>/i,
    ];
    for (const pattern of injectionPatterns) {
      if (pattern.test(text)) {
        throw new Error(`Companion ${label} contains a suspected prompt-injection pattern.`);
      }
    }

    // 6. Basic leetspeak heuristic: flag if >15 % of alpha chars are digit-substitutions
    //    for common letters (3→e, 0→o, 1→i/l, 4→a, 5→s, 7→t).
    const alphaAndLeet = text.replace(/[^a-zA-Z013457]/g, "");
    const leetChars = (text.match(/[013457]/g) || []).length;
    if (alphaAndLeet.length > 40 && leetChars / alphaAndLeet.length > 0.15) {
      throw new Error(`Companion ${label} contains suspected leetspeak-encoded content.`);
    }

    return text;
  }

  // Clunky way to break out PREAMBLE and SEEDCHAT from the character file
  const presplit = data.split("###ENDPREAMBLE###");
  if (presplit.length < 2) {
    return new NextResponse(
      JSON.stringify({ Message: "Companion file format invalid." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  let preamble: string;
  let seedchat: string;
  try {
    preamble = sanitizeCompanionText(presplit[0], "preamble");
    const seedsplit = presplit[1].split("###ENDSEEDCHAT###");
    seedchat = sanitizeCompanionText(seedsplit[0], "seedchat");
  } catch (err: any) {
    console.error("Companion file failed safety check:", err?.message);
    return new NextResponse(
      JSON.stringify({ Message: "Companion file contains disallowed content." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

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
  // Sanitize prompt to mitigate prompt injection: remove sequences that could
  // be interpreted as model instructions or role delimiters.
  const sanitizedPrompt = (prompt || "")
    .replace(/#{1,}/g, "")
    .replace(/`{1,}/g, "")
    .replace(/<[^>]*>/g, "")
    .slice(0, 2000); // enforce a reasonable length limit
  await memoryManager.writeToHistory(
    "Human: " + sanitizedPrompt + "\n",
    companionKey
  );

  // Query Pinecone

  let recentChatHistory = await memoryManager.readLatestHistory(companionKey);

  // Right now the preamble is included in the similarity search, but that
  // shouldn't be an issue

  // Vector search removed to comply with external credentials policy (max 3 systems)
  const similarDocs: any[] = [];

  const MAX_SIMILAR_DOCS = 3;
  const MAX_DOC_CHARS = 300;
  const MAX_HISTORY_CHARS = 1500;
  const MAX_PREAMBLE_CHARS = 1000;

  let relevantHistory = "";
  if (!!similarDocs && similarDocs.length !== 0) {
    relevantHistory = similarDocs
      .slice(0, MAX_SIMILAR_DOCS)
      .map((doc) => String(doc.pageContent ?? "").slice(0, MAX_DOC_CHARS))
      .join("\n");
  }

  // Call approved OpenAI model for inference
  const model = new OpenAI({
    modelName: "gpt-3.5-turbo-instruct",
    maxTokens: 2048,
    openAIApiKey: process.env.OPENAI_API_KEY,
    callbackManager: CallbackManager.fromHandlers(handlers),
  });

  // Turn verbose on for debugging
  model.verbose = true;

  // Sanitize LLM output by detecting and removing dangerous dynamic code execution primitives
  const DANGEROUS_PATTERNS = [
    /\beval\s*\(/gi,
    /\bexec\s*\(/gi,
    /\bexecSync\s*\(/gi,
    /\bspawn\s*\(/gi,
    /\bspawnSync\s*\(/gi,
    /\bsubprocess\b/gi,
    /\bos\.system\s*\(/gi,
    /\bchild_process\b/gi,
    /\bnew\s+Function\s*\(/gi,
    /\bsetTimeout\s*\(\s*['"`]/gi,
    /\bsetInterval\s*\(\s*['"`]/gi,
    /\bimportlib\b/gi,
    /\b__import__\s*\(/gi,
    /\bcompile\s*\(/gi,
    /\bexecfile\s*\(/gi,
    /\binput\s*\(/gi,
  ];

  function sanitizeLLMOutput(text: string): string {
    let sanitized = text;
    for (const pattern of DANGEROUS_PATTERNS) {
      if (pattern.test(sanitized)) {
        console.warn(`[SECURITY] Dangerous pattern detected in LLM output: ${pattern}`);
        sanitized = sanitized.replace(pattern, "[REDACTED]");
      }
    }
    return sanitized;
  }

  let rawResp = String(
    await model
      .call(
        `${String(preamble ?? "").slice(0, MAX_PREAMBLE_CHARS)}  
       
       Below are relevant details about ${name}'s past:
       ${relevantHistory}

       Below is a relevant conversation history

       ${String(recentChatHistory ?? "").slice(-MAX_HISTORY_CHARS)}
       ### ${name}:
       `
      )
      .catch(console.error)
  );

  let resp = sanitizeLLMOutput(rawResp);

  // Right now just using super shoddy string manip logic to get at
  // the dialog.

  const cleaned = resp.replaceAll(",", "");
  const chunks = cleaned.split("###");
  const response = chunks[0];
  // const response = chunks.length > 1 ? chunks[0] : chunks[0];

  // Structured decision audit record — written to persistent log sink
  console.log(
    JSON.stringify({
      event: "model_inference_decision",
      traceId,
      timestamp: new Date().toISOString(),
      principal: clerkUserId,
      companionName: name,
      modelId: MODEL_ID,
      inputHash,
      retrievedDocIds,
      outputSnippet: response.trim().slice(0, 200),
      inferenceLatencyMs,
      retentionDays: MEMORY_RETENTION_DAYS,
    })
  );
  await memoryManager.writeToHistory("### " + response.trim(), companionKey);
  var Readable = require("stream").Readable;

  // --- Synthetic Content Provenance & Labeling ---
  const MODEL_ID =
    "replicate/vicuna-13b:6282abe6a492de4145d7bb601023762212f9ddbbe78278bd6771c8b3b2f2a13b";
  const generatedAt = new Date().toISOString();
  const contentOrigin = "AI-Generated";

  // (1) Prepend a visible AI-origin label to the content
  const labeledResponse =
    `[AI-GENERATED CONTENT | Model: ${MODEL_ID} | Generated: ${generatedAt}]\n` +
    response;

  // (2) Compute a lightweight HMAC-SHA256 provenance signature
  const crypto = require("crypto");
  const signingSecret =
    process.env.PROVENANCE_SIGNING_SECRET || "default-provenance-secret";
  const provenanceSignature = crypto
    .createHmac("sha256", signingSecret)
    .update(response)
    .digest("hex");

  let s = new Readable();
  s.push(labeledResponse);
  s.push(null);
  if (response !== undefined && response.length > 1) {
    await memoryManager.writeToHistory("### " + response.trim(), companionKey);
  }

  // (3) Attach provenance metadata and signature as response headers
  return new StreamingTextResponse(s, {
    headers: {
      "X-Content-Origin": contentOrigin,
      "X-AI-Model-ID": MODEL_ID,
      "X-Generated-At": generatedAt,
      "X-Provenance-Signature": provenanceSignature,
      "X-Watermark": `vicuna13b:${generatedAt}:${provenanceSignature.slice(0, 16)}`,
    },
  });
}
