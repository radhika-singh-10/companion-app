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

// Sanitization: reject inputs containing hidden prompts, invisible chars,
// base64 blobs, leetspeak patterns, shell/binary commands, or control chars.
function containsMaliciousContent(input: string): boolean {
  if (!input || typeof input !== "string") return false;

  // Invisible / zero-width characters
  if (/[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/u.test(input)) return true;

  // Control characters (except common whitespace)
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u.test(input)) return true;

  // Base64-encoded blobs (long runs of base64 chars)
  if (/(?:[A-Za-z0-9+/]{40,}={0,2})/.test(input)) return true;

  // Shell / binary command patterns
  const shellPatterns = [
    /\b(bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess)\s*[\(\[\{`]/i,
    /[;&|`$]\s*(rm|wget|curl|nc|ncat|python|perl|ruby|php|node)\b/i,
    /\b(chmod|chown|sudo|su|passwd|shadow|etc\/passwd)\b/i,
    /(\.\.\/){2,}/,
    /<script[\s>]/i,
    /\bDROP\s+TABLE\b/i,
    /\bSELECT\s+\*\s+FROM\b/i,
  ];
  for (const pattern of shellPatterns) {
    if (pattern.test(input)) return true;
  }

  // Leetspeak obfuscation heuristic: excessive digit-for-letter substitution
  const leetCount = (input.match(/[013457@$!]/g) || []).length;
  const alphaCount = (input.match(/[a-zA-Z]/g) || []).length;
  if (alphaCount > 0 && leetCount / (alphaCount + leetCount) > 0.4 && input.length > 20) return true;

  // Prompt injection keywords attempting to override instructions
  const injectionPatterns = [
    /ignore (all |previous |above |prior )?(instructions?|prompts?|rules?|constraints?)/i,
    /disregard (all |previous |above |prior )?(instructions?|prompts?|rules?)/i,
    /you are now/i,
    /new (persona|role|identity|instructions?)/i,
    /act as (an? )?(unrestricted|unfiltered|evil|malicious|jailbreak)/i,
    /\[SYSTEM\]/i,
    /###\s*(SYSTEM|INSTRUCTION|OVERRIDE)/i,
  ];
  for (const pattern of injectionPatterns) {
    if (pattern.test(input)) return true;
  }

  return false;
}

/**
 * Sanitize a string before injecting it into an LLM prompt.
 * Removes characters commonly used for prompt injection and trims whitespace.
 */
function sanitizeInput(value: string, maxLength = 4000): string {
  if (typeof value !== "string") return "";
  // Strip null bytes, and characters used for prompt injection / jailbreaks
  return value
    .replace(/\0/g, "")
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "") // non-printable control chars
    .replace(/```/g, "'''")                              // code-fence injection
    .replace(/<\/?[^>]+(>|$)/g, "")                     // strip HTML/XML tags
    .trim()
    .slice(0, maxLength);
}

/**
 * Validate that a companion name is safe to use as a file-system key and in prompts.
 * Only allows alphanumeric characters, spaces, hyphens, and underscores.
 */
function validateName(name: string | null): string {
  if (!name || typeof name !== "string") {
    throw new Error("Invalid or missing companion name");
  }
  const trimmed = name.trim();
  if (!/^[a-zA-Z0-9 _-]{1,64}$/.test(trimmed)) {
    throw new Error("Companion name contains invalid characters or exceeds length limit");
  }
  return trimmed;
}

export async function POST(request: Request) {
  const rawBody = await request.json();
  const prompt: string = sanitizeInput(String(rawBody.prompt ?? ""));
  const isText: boolean = Boolean(rawBody.isText);
  const userId: string = sanitizeInput(String(rawBody.userId ?? ""), 128);
  const userName: string = sanitizeInput(String(rawBody.userName ?? ""), 128);
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
  let name: string;
  try {
    name = validateName(request.headers.get("name"));
  } catch {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion name." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
  const companion_file_name = name + ".txt";

  if (isText) {
    // Authenticate via Bearer token in Authorization header — do NOT trust userId/userName from request body
    const authHeader = request.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return new NextResponse(
        JSON.stringify({ Message: "User not authorized" }),
        {
          status: 401,
          headers: { "Content-Type": "application/json" },
        }
      );
    }
    const token = authHeader.slice(7);
    let verifiedUser;
    try {
      // Verify the token server-side using Clerk's verifyToken
      const { verifyToken } = await import("@clerk/nextjs/server");
      const payload = await verifyToken(token, {
        secretKey: process.env.CLERK_SECRET_KEY,
      });
      verifiedUser = await clerk.users.getUser(payload.sub);
    } catch {
      return new NextResponse(
        JSON.stringify({ Message: "User not authorized" }),
        {
          status: 401,
          headers: { "Content-Type": "application/json" },
        }
      );
    }
    clerkUserId = verifiedUser.id;
    clerkUserName = verifiedUser.firstName ?? undefined;
  } else {
    user = await currentUser();
    clerkUserId = user?.id;
    clerkUserName = user?.firstName;
  }

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

  // Resolve and validate the file path to prevent path traversal
  const companionsDir = path.resolve("companions");
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

  /**
   * Validates companion file content for malicious prompt injection patterns.
   * Checks for: invisible/non-printable characters, base64-encoded blobs,
   * leetspeak obfuscation, shell/binary commands, and common prompt injection phrases.
   */
  function validateCompanionContent(content: string): void {
    // Reject non-printable / invisible characters (excluding normal whitespace)
    if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u200B-\u200F\u202A-\u202E\uFEFF]/.test(content)) {
      throw new Error("Companion file contains hidden or non-printable characters.");
    }

    // Reject large base64-encoded blobs (40+ consecutive base64 chars)
    if (/[A-Za-z0-9+/]{40,}={0,2}/.test(content)) {
      throw new Error("Companion file contains suspicious base64-encoded content.");
    }

    // Reject shell/binary command patterns
    const shellPatterns = [
      /\$\([^)]*\)/,           // $(command)
      /`[^`]+`/,               // `command`
      /\beval\s*\(/i,          // eval(
      /\bexec\s*\(/i,          // exec(
      /\bsystem\s*\(/i,        // system(
      /\bpasswd\b/i,           // passwd references
      /\/etc\/shadow/i,        // /etc/shadow
      /<script[\s>]/i,         // <script>
      /javascript\s*:/i,       // javascript:
    ];
    for (const pattern of shellPatterns) {
      if (pattern.test(content)) {
        throw new Error("Companion file contains suspicious shell or script commands.");
      }
    }

    // Reject common prompt injection / jailbreak phrases
    const injectionPatterns = [
      /ignore (all |previous |above |prior )?(instructions?|prompts?|rules?|constraints?)/i,
      /disregard (all |previous |above |prior )?(instructions?|prompts?|rules?|constraints?)/i,
      /forget (all |previous |above |prior )?(instructions?|prompts?|rules?|constraints?)/i,
      /you are now/i,
      /act as (a |an )?(different|new|another|unrestricted)/i,
      /new persona/i,
      /jailbreak/i,
      /do anything now/i,
      /DAN mode/i,
      /override (your )?(instructions?|rules?|constraints?|programming)/i,
    ];
    for (const pattern of injectionPatterns) {
      if (pattern.test(content)) {
        throw new Error("Companion file contains suspicious prompt injection content.");
      }
    }

    // Reject leetspeak obfuscation heuristic: excessive digit-for-letter substitution
    // e.g., "1gnor3 4ll 1nstruct10ns"
    const words = content.split(/\s+/);
    const leetspeakWordCount = words.filter(w => /[a-zA-Z]/.test(w) && /[0-9]/.test(w) && w.length > 3).length;
    if (leetspeakWordCount > 10) {
      throw new Error("Companion file contains suspicious leetspeak-obfuscated content.");
    }
  }

  const data = await fs.readFile(resolvedPath, "utf8");

  // Clunky way to break out PREAMBLE and SEEDCHAT from the character file
  const presplit = data.split("###ENDPREAMBLE###");
  const preamble = sanitizeInput(presplit[0], 8000);
  const seedsplit = presplit[1].split("###ENDSEEDCHAT###");
  const seedchat = sanitizeInput(seedsplit[0], 8000);

  // Validate file-derived content before use in model prompt
  if (containsMaliciousContent(preamble)) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion file content detected." }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

  const companionKey = {
    companionName: name!,
    userId: clerkUserId!,
    modelName: "llama2-13b",
  };
  const memoryManager = await MemoryManager.getInstance();

  const records = await memoryManager.readLatestHistory(companionKey);
  writeAuditRecord({ event: "memory_read", recordCount: records.length });
  if (records.length === 0) {
    await memoryManager.seedChatHistory(seedchat, "\n\n", companionKey);
    writeAuditRecord({ event: "memory_seeded" });
  }
  try {
    await memoryManager.writeToHistory("User: " + prompt + "\n", companionKey);
    writeAuditRecord({ event: "memory_write", role: "user", retentionDays: HISTORY_RETENTION_DAYS });
  } catch (histErr) {
    writeAuditRecord({ event: "memory_write_error", role: "user", error: String(histErr) });
    throw histErr; // fail-closed
  }

  // Query Pinecone

  const fullChatHistory = await memoryManager.readLatestHistory(companionKey);
  const recentChatHistory = fullChatHistory
    .split("\n")
    .filter((line: string) => line.trim() !== "")
    .slice(-MAX_HISTORY_LINES)
    .join("\n");

  // Right now the preamble is included in the similarity search, but that
  // shouldn't be an issue

    const similarDocs = await memoryManager.vectorSearch(
    recentChatHistory,
    companion_file_name
  );
  writeAuditRecord({ event: "vector_search", resultCount: similarDocs?.length ?? 0 });

  let relevantHistory = "";
  if (!!similarDocs && similarDocs.length !== 0) {
    relevantHistory = similarDocs.map((doc) => doc.pageContent).join("\n");
  }
    // Call internal inference proxy — Replicate credential is held server-side
  // by the proxy and is NOT referenced in this route.
  const inferencePrompt = `
       ONLY generate NO more than three sentences as ${name}. DO NOT generate more than three sentences. 
       Make sure the output you generate starts with '${name}:' and ends with a period.

       ${preamble}

       Below are relevant details about ${name}'s past and the conversation you are in.
       ${relevantHistory}


       ${recentChatHistory}\n${name}:`;

  const inferenceResponse = await fetch(
    process.env.INFERENCE_SERVICE_URL + "/api/infer/llama2-13b",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ prompt: inferencePrompt }),
    }
  );

  if (!inferenceResponse.ok) {
    return new NextResponse("Inference service error", { status: 500 });
  }

  let resp = String(await inferenceResponse.text());
  // Call OpenAI for inference (approved model)
  const model = new OpenAI({
    modelName: "gpt-3.5-turbo-instruct",
    maxTokens: 2048,
    openAIApiKey: process.env.OPENAI_API_KEY,
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

  console.log("[LLM INTERACTION] Model: llama2-13b | Prompt sent to LLM:", llmPrompt);

    const modelId =
    "a16z-infra/llama13b-v2-chat:df7690f1994d94e96ad9d568eac121aecf50684a0b0963b25a41cc40061269e5";
  const promptText = `
       ONLY generate NO more than three sentences as ${name}. DO NOT generate more than three sentences. 
       Make sure the output you generate starts with '${name}:' and ends with a period.

       ${preamble}

       Below are relevant details about ${name}'s past and the conversation you are in.
       ${relevantHistory}


       ${recentChatHistory}\n${name}:`;
  const inputHash = crypto
    .createHash("sha256")
    .update(promptText)
    .digest("hex");

  writeAuditRecord({
    event: "model_inference_start",
    modelId,
    principal: clerkUserId,
    inputHash,
  });

  let rawResp: unknown;
  try {
    rawResp = await model.call(promptText);
  } catch (modelErr) {
    writeAuditRecord({
      event: "model_inference_error",
      modelId,
      inputHash,
      error: String(modelErr),
    });
    throw modelErr; // fail-closed — do not continue without a valid response
  }

  let resp = String(rawResp);
  const outputHash = crypto
    .createHash("sha256")
    .update(resp)
    .digest("hex");

  writeAuditRecord({
    event: "model_inference_complete",
    modelId,
    principal: clerkUserId,
    inputHash,
    outputHash,
  });

  console.log("[LLM INTERACTION] Model: llama2-13b | Response received from LLM:", resp);

  // Right now just using super shoddy string manip logic to get at
  // the dialog.

  const cleaned = resp.replaceAll(",", "");
  const chunks = cleaned.split("\n");
  const response = chunks[0];
  // const response = chunks.length > 1 ? chunks[0] : chunks[0];

  // Validate and sanitize LLM output for dangerous dynamic code execution primitives
  const DANGEROUS_PATTERNS = [
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /\bexecfile\s*\(/i,
    /\bcompile\s*\(/i,
    /\b__import__\s*\(/i,
    /\bsubprocess\s*\./i,
    /\bos\.system\s*\(/i,
    /\bos\.popen\s*\(/i,
    /\bspawn\s*\(/i,
    /\bchild_process\b/i,
    /\bnew\s+Function\s*\(/i,
    /\bsetTimeout\s*\(\s*['"`]/i,
    /\bsetInterval\s*\(\s*['"`]/i,
    /\bimportlib\b/i,
    /\bpickle\s*\./i,
    /\bshlex\b/i,
    /\bRuntime\.exec\s*\(/i,
    /\bProcessBuilder\b/i,
  ];

  const containsDangerousContent = DANGEROUS_PATTERNS.some((pattern) =>
    pattern.test(response)
  );

  if (containsDangerousContent) {
    console.warn(
      "[SECURITY] LLM response contained dangerous code execution primitive and was blocked."
    );
    return new Response("Response blocked due to policy violation.", {
      status: 400,
    });
  }

  try {
    await memoryManager.writeToHistory("" + response.trim(), companionKey);
    writeAuditRecord({
      event: "memory_write",
      role: "assistant",
      retentionDays: HISTORY_RETENTION_DAYS,
    });
  } catch (histErr) {
    writeAuditRecord({ event: "memory_write_error", role: "assistant", error: String(histErr) });
    throw histErr; // fail-closed
  }
  var Readable = require("stream").Readable;

  let s = new Readable();
  s.push(response);
  s.push(null);
  // Removed duplicate writeToHistory call to avoid double-writing history

  // --- Synthetic Content Provenance & Labeling ---
  const crypto = require("crypto");

  const provenanceMetadata = {
    "x-ai-generated": "true",
    "x-ai-content-label": "SYNTHETIC_AI_CONTENT",
    "x-ai-model-id": "a16z-infra/llama13b-v2-chat:df7690f1994d94e96ad9d568eac121aecf50684a0b0963b25a41cc40061269e5",
    "x-ai-model-provider": "Replicate/LLaMA2-13B",
    "x-ai-content-timestamp": new Date().toISOString(),
    "x-ai-content-origin": "llama2-13b-route",
  };

  // Cryptographic HMAC signature over provenance fields
  const signingSecret = process.env.AI_PROVENANCE_SIGNING_SECRET || "default-insecure-secret";
  const signaturePayload = JSON.stringify({
    model: provenanceMetadata["x-ai-model-id"],
    provider: provenanceMetadata["x-ai-model-provider"],
    timestamp: provenanceMetadata["x-ai-content-timestamp"],
    origin: provenanceMetadata["x-ai-content-origin"],
  });
  const provenanceSignature = crypto
    .createHmac("sha256", signingSecret)
    .update(signaturePayload)
    .digest("hex");
  provenanceMetadata["x-ai-provenance-signature"] = provenanceSignature;

  // Watermark: prepend an AI-origin label to the generated text
  const watermarkedResponse =
    `[AI-GENERATED CONTENT | Model: Replicate/LLaMA2-13B | ${provenanceMetadata["x-ai-content-timestamp"]}]\n` +
    response;

  let sLabeled = new Readable();
  sLabeled.push(watermarkedResponse);
  sLabeled.push(null);

  return new StreamingTextResponse(sLabeled, { headers: provenanceMetadata });
}
