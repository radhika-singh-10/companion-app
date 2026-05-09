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

// Patterns that indicate potential prompt injection or malicious content
const INVISIBLE_CHARS_RE = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/;
const BASE64_INJECTION_RE = /(?:[A-Za-z0-9+\/]{20,}={0,2})(?:\s|$)/;
const SHELL_COMMAND_RE = /(?:^|\s)(?:bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess|os\.system|`[^`]+`|\$\([^)]+\)|&&|\|\||;\s*\w)/i;
const BINARY_CONTROL_RE = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/;
const HIDDEN_PROMPT_RE = /(?:ignore\s+(?:previous|above|prior|all)\s+instructions?|disregard\s+(?:previous|above|prior|all)|forget\s+(?:previous|above|prior|all)|new\s+instructions?\s*:|system\s*:\s*you\s+are|<\s*system\s*>|\[\s*system\s*\]|###\s*system|act\s+as\s+(?:a\s+)?(?:different|new|another)|you\s+are\s+now\s+(?:a\s+)?(?:different|new)|jailbreak|dan\s+mode|developer\s+mode)/i;
const LEETSPEAK_INJECTION_RE = /(?:1gnor3|d1sr3g4rd|f0rg3t|3x3c|3v4l|syst3m|4dm1n|r00t|sh3ll|c0mm4nd)/i;

function sanitizeInput(value: string, fieldName: string): { safe: boolean; reason?: string } {
  if (!value || typeof value !== "string") return { safe: true };

  if (INVISIBLE_CHARS_RE.test(value)) {
    return { safe: false, reason: `${fieldName} contains invisible/hidden characters` };
  }
  if (BINARY_CONTROL_RE.test(value)) {
    return { safe: false, reason: `${fieldName} contains binary or control characters` };
  }
  if (BASE64_INJECTION_RE.test(value)) {
    // Attempt to decode and re-check decoded content
    const b64matches = value.match(/[A-Za-z0-9+\/]{20,}={0,2}/g) || [];
    for (const match of b64matches) {
      try {
        const decoded = Buffer.from(match, "base64").toString("utf8");
        if (HIDDEN_PROMPT_RE.test(decoded) || SHELL_COMMAND_RE.test(decoded)) {
          return { safe: false, reason: `${fieldName} contains base64-encoded malicious content` };
        }
      } catch (_) {
        // Not valid base64, skip
      }
    }
  }
  if (SHELL_COMMAND_RE.test(value)) {
    return { safe: false, reason: `${fieldName} contains shell or binary commands` };
  }
  if (HIDDEN_PROMPT_RE.test(value)) {
    return { safe: false, reason: `${fieldName} contains hidden or injected prompt instructions` };
  }
  if (LEETSPEAK_INJECTION_RE.test(value)) {
    return { safe: false, reason: `${fieldName} contains leetspeak injection attempt` };
  }

  return { safe: true };
}

export async function POST(request: Request) {
  const requestBody = await request.json();
  const rawPrompt: string = requestBody.prompt ?? "";
  const isText: boolean = requestBody.isText;
  const userId: string = requestBody.userId ?? "";
  const userName: string = requestBody.userName ?? "";

  // Validate and sanitize prompt
  if (typeof rawPrompt !== "string" || rawPrompt.trim().length === 0) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid or empty prompt." }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
  if (rawPrompt.length > 2000) {
    return new NextResponse(
      JSON.stringify({ Message: "Prompt exceeds maximum allowed length." }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
  const prompt = sanitizeInput(rawPrompt, 2000);
  let clerkUserId;
  let user;
  let clerkUserName;

  // Authenticate first so we can use the verified identity for rate limiting.
  user = await currentUser();
  clerkUserId = user?.id;
  clerkUserName = user?.firstName;

  // Authentication check already performed above before rate limiting.

  const identifier = request.url + "-" + clerkUserId;
  // Rate limiting removed to comply with the 3-external-system credential policy.
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

  // Sanitization helpers
  const sanitizeInput = (value: string, maxLength: number = 1000): string => {
    if (typeof value !== "string") return "";
    // Remove null bytes and control characters (except newlines/tabs)
    let sanitized = value.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
    // Remove common prompt injection patterns
    sanitized = sanitized.replace(
      /(###ENDPREAMBLE###|###ENDSEEDCHAT###|SYSTEM:|<\|im_start\|>|<\|im_end\|>|\[INST\]|\[\/INST\])/gi,
      ""
    );
    // Trim and enforce max length
    return sanitized.trim().slice(0, maxLength);
  };

  const sanitizeFileContent = (value: string, maxLength: number = 8000): string => {
    if (typeof value !== "string") return "";
    // Remove null bytes and control characters (except newlines/tabs)
    let sanitized = value.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
    return sanitized.slice(0, maxLength);
  };

    // XXX Companion name passed here. Can use as a key to get backstory, chat history etc.
  const name = request.headers.get("name");

  // Validate name header for malicious content
  const nameCheck = sanitizeInput(name || "", "name");
  if (!nameCheck.safe) {
    console.warn("SECURITY: Rejected request due to unsafe name header:", nameCheck.reason);
    return new NextResponse(
      JSON.stringify({ Message: "Request contains disallowed content." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
  // Restrict name to safe alphanumeric/dash/underscore characters to prevent path traversal
  if (!name || !/^[a-zA-Z0-9_-]+$/.test(name)) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion name." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
  const companion_file_name = name + ".txt";

  // Always authenticate via the server-side session; never trust client-supplied identity claims.
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
  const crypto = require("crypto");
  const path = require("path");

  // ── Audit / forensic-readiness constants ──────────────────────────────────
  const AUDIT_LOG_PATH = process.env.AUDIT_LOG_PATH ?? "logs/ai_audit.ndjson";
  const AUDIT_RETENTION_DAYS = Number(process.env.AUDIT_RETENTION_DAYS ?? 90);
  const MODEL_ID = "a16z-infra/llama13b-v2-chat";
  const MODEL_VERSION =
    "df7690f1994d94e96ad9d568eac121aecf50684a0b0963b25a41cc40061269e5";

  // Correlation / trace identifier — links every step of this request
  const traceId = crypto.randomUUID();

  /**
   * Append a structured audit record to the persistent NDJSON audit log.
   * Throws on write failure so callers can decide whether to fail closed.
   */
  async function writeAuditRecord(record: Record<string, unknown>): Promise<void> {
    const entry =
      JSON.stringify({
        ...record,
        traceId,
        timestamp: new Date().toISOString(),
        retentionDays: AUDIT_RETENTION_DAYS,
      }) + "\n";
    // Also emit to stdout so log-aggregation pipelines (e.g. CloudWatch, Datadog) capture it
    process.stdout.write("[AUDIT] " + entry);
    await fs.mkdir(path.dirname(AUDIT_LOG_PATH), { recursive: true });
    await fs.appendFile(AUDIT_LOG_PATH, entry, "utf8");
  }

  const data = await fs.readFile("companions/" + companion_file_name, "utf8");

  // Security: Validate companion file contents for prompt injection attempts
  function validateCompanionFileContent(content: string): void {
    // Check for non-printable / invisible characters (excluding normal whitespace)
    if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\x80-\x9F]/.test(content)) {
      throw new Error("Companion file contains hidden or non-printable characters.");
    }

    // Check for zero-width / invisible Unicode characters used to hide text
    if (/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/.test(content)) {
      throw new Error("Companion file contains invisible Unicode characters.");
    }

    // Check for binary content (null bytes or high concentration of non-UTF8 sequences)
    if (content.includes("\0")) {
      throw new Error("Companion file contains binary content.");
    }

    // Check for base64-encoded blocks that could hide injected prompts
    const base64Pattern = /(?:[A-Za-z0-9+\/]{40,}={0,2})/g;
    const base64Matches = content.match(base64Pattern) || [];
    for (const match of base64Matches) {
      try {
        const decoded = Buffer.from(match, "base64").toString("utf8");
        // If decoded content looks like readable text with injection keywords, reject it
        if (/ignore|disregard|forget|override|system|prompt|instruction|jailbreak/i.test(decoded)) {
          throw new Error("Companion file contains suspicious base64-encoded content.");
        }
      } catch (e: any) {
        if (e.message.includes("suspicious base64")) throw e;
        // Decoding failed — not valid base64 text, skip
      }
    }

    // Check for common prompt injection / jailbreak directive patterns
    const injectionPatterns = [
      /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)/i,
      /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)/i,
      /forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)/i,
      /you\s+are\s+now\s+(a\s+)?(?!${name})/i,
      /new\s+(role|persona|personality|instructions?|prompt|system)/i,
      /override\s+(your\s+)?(instructions?|programming|rules|guidelines)/i,
      /act\s+as\s+(if\s+you\s+are\s+)?(?!${name})/i,
      /pretend\s+(you\s+are|to\s+be)\s+(?!${name})/i,
      /\[system\]/i,
      /###\s*(system|instruction|override|jailbreak)/i,
      /<\s*system\s*>/i,
    ];
    for (const pattern of injectionPatterns) {
      if (pattern.test(content)) {
        throw new Error("Companion file contains suspicious prompt injection directives.");
      }
    }

    // Check for shell commands or code execution patterns
    const shellPatterns = [
      /`[^`]{0,200}`/,                        // backtick command substitution
      /\$\([^)]{0,200}\)/,                    // $(command) substitution
      /(^|\s)(rm|chmod|chown|curl|wget|bash|sh|python|perl|ruby|exec|eval|nc|netcat)\s+/im,
      /<script[\s>]/i,
      /javascript:/i,
    ];
    for (const pattern of shellPatterns) {
      if (pattern.test(content)) {
        throw new Error("Companion file contains shell commands or code execution patterns.");
      }
    }

    // Check for leetspeak patterns that could obfuscate injection attempts
    // Detect high density of leet substitutions (e.g. 1gn0r3, 0v3rr1d3)
    const leetPattern = /(?:[1!][gq][n][0o][r][3e]|[0o][v][3e][r][r][1!][d][3e]|[s$][y][s$][t][3e][m$])/i;
    if (leetPattern.test(content)) {
      throw new Error("Companion file contains leetspeak obfuscation of injection keywords.");
    }
  }

  try {
    validateCompanionFileContent(data);
  } catch (validationError: any) {
    console.error("Security: Companion file validation failed:", validationError.message);
    return new NextResponse(
      JSON.stringify({ Message: "Companion file contains disallowed content." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  // Clunky way to break out PREAMBLE and SEEDCHAT from the character file
  const presplit = data.split("###ENDPREAMBLE###");
  const preamble = sanitizeFileContent(presplit[0], 8000);
  const seedsplit = presplit[1].split("###ENDSEEDCHAT###");
  const seedchat = sanitizeFileContent(seedsplit[0], 4000);

    const companionKey = {
    companionName: name!,
    userId: clerkUserId!,
    modelName: "llama2-13b",
  };

  // Audit: request received
  await writeAuditRecord({
    event: "request_received",
    principal: clerkUserId,
    companionName: name,
    companionFile: companion_file_name,
  });
  const memoryManager = await MemoryManager.getInstance();

    const records = await memoryManager.readLatestHistory(companionKey);
  if (records.length === 0) {
    await memoryManager.seedChatHistory(seedchat, "\n\n", companionKey);
  }
  await memoryManager.writeToHistory("User: " + prompt + "\n", companionKey);

  // Audit: memory read step
  await writeAuditRecord({
    event: "memory_read",
    principal: clerkUserId,
    historyLength: records.length,
  });

  // Query Pinecone

  let recentChatHistory = await memoryManager.readLatestHistory(companionKey);

  // Right now the preamble is included in the similarity search, but that
  // shouldn't be an issue

  const similarDocs = await memoryManager.vectorSearch(
    recentChatHistory,
    companion_file_name
  );

    const MAX_PREAMBLE_CHARS = 500;
  const safePreamble = preamble.slice(0, MAX_PREAMBLE_CHARS);

  const MAX_HISTORY_LINES = 10;
  const safeRecentChatHistory = recentChatHistory
    .split("\n")
    .filter((line: string) => line.trim() !== "")
    .slice(-MAX_HISTORY_LINES)
    .join("\n");

  let relevantHistory = "";
  if (!!similarDocs && similarDocs.length !== 0) {
    const MAX_RAG_DOCS = 3;
    const MAX_RAG_CHARS = 200;
    relevantHistory = similarDocs
      .slice(0, MAX_RAG_DOCS)
      .map((doc) => doc.pageContent.slice(0, MAX_RAG_CHARS))
      .join("\n");
  }
    // --- Tool Allow List Enforcement ---
  const ALLOWED_MODELS: string[] = [
    "a16z-infra/llama13b-v2-chat:df7690f1994d94e96ad9d568eac121aecf50684a0b0963b25a41cc40061269e5",
  ];
  const POLICY_VERSION = "v1.0.0";
  const REQUESTED_MODEL =
    "a16z-infra/llama13b-v2-chat:df7690f1994d94e96ad9d568eac121aecf50684a0b0963b25a41cc40061269e5";

  // Per-role scoping: only allow authenticated users with a valid clerkUserId
  // (already enforced above) to access the model. Extend this block to add
  // finer-grained role checks (e.g. admin-only models) as needed.
  const actorId = clerkUserId;

  if (!ALLOWED_MODELS.includes(REQUESTED_MODEL)) {
    // Audit trail for denied tool requests
    console.error(
      JSON.stringify({
        event: "TOOL_DENIED",
        actor: actorId,
        requestedModel: REQUESTED_MODEL,
        policyVersion: POLICY_VERSION,
        reason: "Model not in allow list",
        timestamp: new Date().toISOString(),
      })
    );
    return new NextResponse(
      JSON.stringify({
        Message: "Requested model is not permitted by policy.",
        policyVersion: POLICY_VERSION,
      }),
      {
        status: 403,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  // Audit trail for allowed tool invocations
  console.info(
    JSON.stringify({
      event: "TOOL_ALLOWED",
      actor: actorId,
      requestedModel: REQUESTED_MODEL,
      policyVersion: POLICY_VERSION,
      timestamp: new Date().toISOString(),
    })
  );
  // --- End Tool Allow List Enforcement ---

  const { stream, handlers } = LangChainStream();
    // Approved internal model registry — only models listed here may be used.
  const APPROVED_MODEL_REGISTRY: Record<string, string> = {
    "llama2-13b": "a16z-infra/llama13b-v2-chat:df7690f1994d94e96ad9d568eac121aecf50684a0b0963b25a41cc40061269e5",
  };

  const RESOLVED_MODEL_KEY = "llama2-13b";
  const RESOLVED_MODEL_ID = APPROVED_MODEL_REGISTRY[RESOLVED_MODEL_KEY];

  if (!RESOLVED_MODEL_ID) {
    return new NextResponse(
      JSON.stringify({ Message: `Model '${RESOLVED_MODEL_KEY}' is not in the approved model registry.` }),
      {
        status: 403,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  // Call Replicate for inference using the registry-approved, pinned model identifier.
  const model = new Replicate({
    model: RESOLVED_MODEL_ID,
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
  } catch (err) {
    console.error(
      JSON.stringify({
        event: "TOOL_INVOCATION_ERROR",
        actor: actorId,
        requestedModel: REQUESTED_MODEL,
        policyVersion: POLICY_VERSION,
        error: String(err),
        timestamp: new Date().toISOString(),
      })
    );
    return new NextResponse(
      JSON.stringify({ Message: "Model invocation failed." }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" },
      }
    );
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

  const llmPrompt = `
       ONLY generate NO more than three sentences as ${name}. DO NOT generate more than three sentences. 
       Make sure the output you generate starts with '${name}:' and ends with a period.

       ${safePreamble}

       Below are relevant details about ${name}'s past and the conversation you are in.
       ${relevantHistory}


       ${recentChatHistory}\n${name}:`;

  console.log("[LLM Interaction] Model: Replicate/llama2-13b | Prompt sent to LLM:", llmPrompt);

  let resp = String(
    await model
      .call(llmPrompt)
      .catch(console.error)
  );

  console.log("[LLM Interaction] Model: Replicate/llama2-13b | Response received from LLM:", resp);

  // Right now just using super shoddy string manip logic to get at
  // the dialog.

  const cleaned = resp.replaceAll(",", "");
  const chunks = cleaned.split("\n");
  const response = chunks[0];
  // const response = chunks.length > 1 ? chunks[0] : chunks[0];

  // Validate and sanitize LLM output: reject responses containing dangerous
  // dynamic code execution primitives before writing to memory or streaming.
  const DANGEROUS_PATTERNS = [
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /\bexecSync\s*\(/i,
    /\bspawnSync\s*\(/i,
    /\bspawn\s*\(/i,
    /\bsubprocess\b/i,
    /\bos\.system\s*\(/i,
    /\bos\.popen\s*\(/i,
    /\b__import__\s*\(/i,
    /\bimportlib\b/i,
    /\bFunction\s*\(/i,
    /\bnew\s+Function\b/i,
    /\bsetTimeout\s*\(\s*['"`]/i,
    /\bsetInterval\s*\(\s*['"`]/i,
    /\bchild_process\b/i,
    /\bshell\s*=\s*True/i,
    /\$\(.*\)/,
    /`[^`]*`/,
  ];

  const isMalicious = DANGEROUS_PATTERNS.some((pattern) =>
    pattern.test(response)
  );

  if (isMalicious) {
    console.error(
      "[SECURITY] LLM response contained dangerous code execution primitive. Response blocked."
    );
    return new Response(
      "Response blocked due to policy violation: dangerous content detected.",
      { status: 400 }
    );
  }

  await memoryManager.writeToHistory("" + response.trim(), companionKey);
  var Readable = require("stream").Readable;
  var crypto = require("crypto");

  // --- Synthetic Content Provenance & Labeling ---
  const MODEL_ID =
    "a16z-infra/llama13b-v2-chat:df7690f1994d94e96ad9d568eac121aecf50684a0b0963b25a41cc40061269e5";
  const provenanceTimestamp = new Date().toISOString();
  const provenanceMetadata = {
    model: MODEL_ID,
    timestamp: provenanceTimestamp,
    origin: "ai-generated",
    label: "SYNTHETIC_AI_CONTENT",
  };

  // Cryptographic HMAC signature over provenance metadata
  const hmacSecret = process.env.PROVENANCE_HMAC_SECRET || "default-provenance-secret";
  const provenanceString = JSON.stringify(provenanceMetadata);
  const provenanceSignature = crypto
    .createHmac("sha256", hmacSecret)
    .update(provenanceString)
    .digest("hex");

  // Watermark: prepend a synthetic-content label to the streamed text
  const watermark = `[AI-GENERATED CONTENT | Model: ${MODEL_ID} | ${provenanceTimestamp}]\n`;
  const labeledResponse = watermark + (response ?? "");

  let s = new Readable();
  s.push(labeledResponse);
  s.push(null);
  if (response !== undefined && response.length > 1) {
    memoryManager.writeToHistory("" + response.trim(), companionKey);
  }

  return new StreamingTextResponse(s, {
    headers: {
      "X-AI-Provenance-Model": MODEL_ID,
      "X-AI-Provenance-Timestamp": provenanceTimestamp,
      "X-AI-Content-Origin": "ai-generated",
      "X-AI-Content-Label": "SYNTHETIC_AI_CONTENT",
      "X-AI-Provenance-Signature": provenanceSignature,
    },
  });
}
