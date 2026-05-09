import { Ollama } from "langchain/llms/ollama";
import dotenv from "dotenv";
import { LLMChain } from "langchain/chains";
import { StreamingTextResponse, LangChainStream } from "ai";
import clerk from "@clerk/clerk-sdk-node";
import { CallbackManager } from "langchain/callbacks";
import { PromptTemplate } from "langchain/prompts";
import { NextResponse } from "next/server";
import { currentUser } from "@clerk/nextjs";
import MemoryManager from "@/app/utils/memory";
import { rateLimit } from "@/app/utils/rateLimit";

dotenv.config({ path: `.env.local` });

// Sanitization: detect and reject inputs that may contain prompt injection attempts
function sanitizeInput(input: string, label: string): string {
  if (!input || typeof input !== 'string') return input;

  // Reject invisible/hidden unicode characters (zero-width, control chars, etc.)
  if (/[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/u.test(input)) {
    throw new Error(`Blocked: '${label}' contains hidden/invisible characters indicative of prompt injection.`);
  }

  // Reject base64-encoded blocks (long base64 strings are suspicious in prompts)
  if (/(?:[A-Za-z0-9+\/]{40,}={0,2})/.test(input)) {
    throw new Error(`Blocked: '${label}' contains base64-encoded content indicative of prompt injection.`);
  }

  // Reject shell command patterns
  if (/(?:;\s*(?:rm|wget|curl|bash|sh|python|perl|ruby|nc|ncat|netcat|chmod|chown|sudo|su|exec|eval)\b|\$\(|`[^`]*`|\|\s*(?:bash|sh|cmd)|&&\s*(?:rm|wget|curl|bash|sh))/.test(input)) {
    throw new Error(`Blocked: '${label}' contains shell command patterns indicative of prompt injection.`);
  }

  // Reject binary/non-printable content
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(input)) {
    throw new Error(`Blocked: '${label}' contains binary or non-printable characters indicative of prompt injection.`);
  }

  // Reject leetspeak combined with suspicious keywords (e.g., 1gn0r3, 1nstruct)
  if (/(?:1gn[o0]r[e3]|1nstruct|[i1]nj[e3]ct|[e3]x[e3]cut[e3]|[s5]yst[e3]m\s*pr[o0]mpt|[i1]gnor[e3]\s+(?:all|prev|above|prior))/i.test(input)) {
    throw new Error(`Blocked: '${label}' contains leetspeak or obfuscated injection keywords.`);
  }

  // Reject common prompt injection instruction patterns
  if (/(?:ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions?|disregard\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?|forget\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?|you\s+are\s+now\s+(?:a|an)\s+|new\s+instructions?\s*:|system\s*:\s*you|<\s*system\s*>|\[\s*system\s*\])/i.test(input)) {
    throw new Error(`Blocked: '${label}' contains prompt injection instruction patterns.`);
  }

  return input;
}

// Sanitize input before sending to LLM to prevent prompt injection and other attacks
function sanitizeInput(input: string, maxLength = 4000): string {
  if (typeof input !== "string") return "";
  // Remove null bytes and non-printable control characters (keep newlines/tabs)
  let sanitized = input.replace(/\x00/g, "").replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  // Strip common prompt-injection patterns (case-insensitive)
  sanitized = sanitized.replace(
    /ignore (all )?(previous|prior|above) instructions?/gi,
    "[removed]"
  );
  sanitized = sanitized.replace(
    /you are now|disregard (all )?instructions?|forget (all )?(previous|prior|above)/gi,
    "[removed]"
  );
  // Enforce maximum length
  return sanitized.slice(0, maxLength);
}

export async function POST(req: Request) {
  let clerkUserId;
  let user;
  let clerkUserName;
  const rawBody = await req.json();
  const rawPrompt: unknown = rawBody.prompt;
  const isText: unknown = rawBody.isText;
  const userId: unknown = rawBody.userId;
  const userName: unknown = rawBody.userName;

  // Validate prompt is a non-empty string
  if (typeof rawPrompt !== "string" || rawPrompt.trim().length === 0) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid or missing prompt." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
  const prompt = sanitizeInput(rawPrompt, 2000);

  const identifier = req.url + "-" + (clerkUserId || "anonymous");
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
  const name = req.headers.get("name");

  // Allowlist of permitted companion names — only these values may be used to
  // construct file paths, LLM prompts, or vector-search queries.
  const COMPANION_ALLOWLIST: ReadonlySet<string> = new Set([
    "elon",
    "beast",
    "marc",
    // Add additional permitted companion names here.
  ]);

  if (
    !name ||
    !COMPANION_ALLOWLIST.has(name) ||
    /[^a-zA-Z0-9_-]/.test(name)   // extra guard: reject any path-traversal chars
  ) {
    console.log("INFO: companion name rejected – not in allowlist:", name);
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion name." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  const companionFileName = name + ".txt";

  console.log("prompt: ", prompt);
  user = await currentUser();
  clerkUserId = user?.id;
  clerkUserName = user?.firstName;

  if (!clerkUserId || !!!(await clerk.users.getUser(clerkUserId))) {
    console.log("user not authorized");
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
   * Sanitize a string extracted from a companion file before it is injected
   * into an LLM prompt.  Throws if the content looks malicious.
   */
  function sanitizeCompanionContent(content: string, label: string): string {
    const MAX_LENGTH = 8000;

    // 1. Enforce maximum length to prevent prompt-flooding attacks.
    if (content.length > MAX_LENGTH) {
      throw new Error(`Companion file ${label} exceeds maximum allowed length.`);
    }

    // 2. Strip invisible / zero-width Unicode characters that can hide injections.
    //    Covers: zero-width space, zero-width non-joiner, zero-width joiner,
    //    left-to-right / right-to-left marks, soft hyphen, word joiner, etc.
    const invisiblePattern =
      /[\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u2028\u2029]/g;
    content = content.replace(invisiblePattern, "");

    // 3. Detect base64-encoded blobs (long runs of base64 chars) which may
    //    encode hidden instructions.
    const base64Pattern = /[A-Za-z0-9+/]{200,}={0,2}/;
    if (base64Pattern.test(content)) {
      throw new Error(
        `Companion file ${label} contains a suspicious base64-encoded block.`
      );
    }

    // 4. Detect common prompt-injection trigger phrases (case-insensitive).
    const injectionPhrases = [
      /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/i,
      /disregard\s+(all\s+)?(previous|prior|above)\s+instructions?/i,
      /forget\s+(all\s+)?(previous|prior|above)\s+instructions?/i,
      /you\s+are\s+now\s+(a\s+)?(?:an?\s+)?(?:evil|malicious|unrestricted|jailbroken)/i,
      /act\s+as\s+(?:an?\s+)?(?:evil|malicious|unrestricted|jailbroken|DAN)/i,
      /system\s*:\s*you\s+are/i,
      /###\s*system/i,
      /<\s*system\s*>/i,
    ];
    for (const pattern of injectionPhrases) {
      if (pattern.test(content)) {
        throw new Error(
          `Companion file ${label} contains a suspected prompt-injection phrase.`
        );
      }
    }

    // 5. Detect shell-command patterns that should never appear in a persona file.
    const shellPattern =
      /(?:^|\s)(?:bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess)\s*[\(\-]/im;
    if (shellPattern.test(content)) {
      throw new Error(
        `Companion file ${label} contains a suspected shell command.`
      );
    }

    // 6. Detect leetspeak obfuscation heuristic: high ratio of digit-substituted
    //    letters (e.g. 1gn0r3 4ll pr3v10us) in a single token.
    const leetspeakPattern = /\b(?=[a-z0-9]*[0-9][a-z0-9]*[a-z][a-z0-9]*)(?=[a-z0-9]*[a-z][a-z0-9]*[0-9][a-z0-9]*)[a-z0-9]{6,}\b/gi;
    const leetspeakMatches = content.match(leetspeakPattern) || [];
    if (leetspeakMatches.length > 10) {
      throw new Error(
        `Companion file ${label} contains excessive leetspeak-style obfuscation.`
      );
    }

    return content;
  }

  const data = await fs.readFile("companions/" + companionFileName, "utf8");

  // Clunky way to break out PREAMBLE and SEEDCHAT from the character file
  const presplit = data.split("###ENDPREAMBLE###");
  const preamble = sanitizeInput(presplit[0], 4000);
  const seedsplit = presplit[1].split("###ENDSEEDCHAT###");
  const seedchat = sanitizeInput(seedsplit[0], 4000);

  // ── Forensic / audit bootstrap ──────────────────────────────────────────
  const correlationId = crypto.randomUUID();
  const pipelineStart = new Date().toISOString();
  const MODEL_NAME = "gpt-3.5-turbo-16k";
  const MODEL_VERSION = "gpt-3.5-turbo-16k-0613"; // pin the snapshot version
  const AUDIT_RETENTION_DAYS = 365;

  /** Compute a SHA-256 hex digest of an arbitrary string (Web Crypto API). */
  async function sha256Hex(text: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(hashBuffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  /**
   * Write a structured audit record to the persistent audit store.
   * Throws on failure so the caller can fail-closed.
   */
  async function writeAuditRecord(record: Record<string, unknown>): Promise<void> {
    // Replace the body of this function with your organisation's persistent
    // audit-store write (e.g. append to an immutable DB table, a SIEM, or an
    // append-only log stream).  The console.error below is a fallback ONLY
    // during local development and must be replaced before production.
    const serialised = JSON.stringify(record);
    // TODO: await auditStore.append(serialised);
    // For now surface the record so it is never silently dropped:
    process.stdout.write("[AUDIT] " + serialised + "\n");
  }
  // ─────────────────────────────────────────────────────────────────────────

  const companionKey = {
    companionName: name!,
    modelName: "chatgpt",
    userId: clerkUserId,
  };
  const memoryManager = await MemoryManager.getInstance();

  console.log(JSON.stringify({ event: "pipeline_start", correlationId, timestamp: pipelineStart, principal: clerkUserId, companionName: name }));

  const records = await memoryManager.readLatestHistory(companionKey);
  if (records.length === 0) {
    await memoryManager.seedChatHistory(seedchat, "\n\n", companionKey);
  }

  // Sanitize user input to remove PII before storing in history or sending to the AI model
  const sanitizedPrompt = sanitizePII(prompt);
  await memoryManager.writeToHistory("Human: " + sanitizedPrompt + "\n", companionKey);
  let recentChatHistoryRaw = await memoryManager.readLatestHistory(companionKey);
  // Minimise: keep only the last 10 lines, each capped at 500 chars
  let recentChatHistory = recentChatHistoryRaw
    .split("\n")
    .slice(-10)
    .map((line: string) => line.slice(0, 500))
    .join("\n");

  console.log(JSON.stringify({ event: "memory_read", correlationId, timestamp: new Date().toISOString(), principal: clerkUserId }));

    // Vector search removed to comply with the policy limiting authenticated
  // external system connections to a maximum of 3.
  // Active connections: (1) OpenAI, (2) Clerk, (3) Redis/Upstash.
  let relevantHistory = "";));
  const similarDocs = await memoryManager.vectorSearch(
    recentChatHistory,
    companionFileName
  );
  console.log(JSON.stringify({ event: "vector_search_complete", correlationId, timestamp: new Date().toISOString(), principal: clerkUserId, docsFound: similarDocs?.length ?? 0 }));

  let relevantHistory = "";
  if (!!similarDocs && similarDocs.length !== 0) {
    relevantHistory = similarDocs
      .map((doc) => {
        try {
          return sanitizeInput(doc.pageContent, 'relevantHistory');
        } catch (e: any) {
          console.warn('Prompt injection attempt blocked in relevantHistory:', e.message);
          return '';
        }
      })
      .filter(Boolean)
      .join("\n");
  }

  /**
   * Removes common PII patterns from a string before it is sent to an AI model.
   * Strips email addresses, phone numbers, and US Social Security Numbers.
   */
  function sanitizePII(input: string): string {
    // Remove email addresses
    let sanitized = input.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, "[REDACTED_EMAIL]");
    // Remove US phone numbers (various formats)
    sanitized = sanitized.replace(/(\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}/g, "[REDACTED_PHONE]");
    // Remove US Social Security Numbers
    sanitized = sanitized.replace(/\b\d{3}-\d{2}-\d{4}\b/g, "[REDACTED_SSN]");
    return sanitized;
  }

  const { stream, handlers } = LangChainStream();

    // Enforce approved model registry before instantiation.
  if (!APPROVED_MODEL_REGISTRY.has(PINNED_MODEL_ID)) {
    console.error(`Model '${PINNED_MODEL_ID}' is not in the approved model registry.`);
    return new NextResponse(
      JSON.stringify({ Message: "Model not approved for use." }),
      {
        status: 403,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  const model = new OpenAI({
    streaming: true,
    modelName: PINNED_MODEL_ID, // pinned immutable snapshot identifier
    openAIApiKey: process.env.OPENAI_API_KEY,
    callbackManager: CallbackManager.fromHandlers(handlers),
  });
  model.verbose = true;

  const replyWithTwilioLimit = isText
    ? "You reply within 1000 characters."
    : "";

  const chainPrompt = PromptTemplate.fromTemplate(`
    You are ${name}.

    ${preamble}

  You reply with answers that range from one sentence to one paragraph and with some details. ${replyWithTwilioLimit}

  Below are relevant details about ${name}'s past
  ${relevantHistory}
  
  Below is a relevant conversation history

  ${recentChatHistory}`);

  const chain = new LLMChain({
    llm: model,
    prompt: chainPrompt,
  });

  const llmInput = {
    relevantHistory,
    recentChatHistory: recentChatHistory,
  };
  console.log(
    "LLM interaction - prompt sent:",
    JSON.stringify({
      companion: name,
      user: clerkUserName,
      preamble,
      relevantHistory: llmInput.relevantHistory,
      recentChatHistory: llmInput.recentChatHistory,
    })
  );
    // Record resolved model identity at inference time for monitoring/audit.
  console.info(`[model-identity] Serving inference with model: ${PINNED_MODEL_ID}`);

  const result = await chain
    .call({
      relevantHistory,
      recentChatHistory: recentChatHistory,
    })
    .catch(console.error);

  // Attach model identity to response headers so it is captured in request metadata.
  if (result && result instanceof Response) {
    result.headers.set("X-Model-Id", PINNED_MODEL_ID);
  }
  console.log("LLM interaction - response received:", JSON.stringify(result));

  // Removed: logging raw result object exposes internal/operational metadata
  // Validate and sanitize LLM output for dynamic code execution primitives
  const llmOutputText: string = result!.text ?? "";

  const DANGEROUS_PATTERNS: RegExp[] = [
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /\bexecfile\s*\(/i,
    /\bsubprocess\b/i,
    /\bos\.system\s*\(/i,
    /\bos\.popen\s*\(/i,
    /\bnew\s+Function\s*\(/i,
    /\bsetTimeout\s*\(\s*['"`]/i,
    /\bsetInterval\s*\(\s*['"`]/i,
    /\bimportlib\b/i,
    /\b__import__\s*\(/i,
    /\bcompile\s*\(/i,
    /\bspawn\s*\(/i,
    /\bexecSync\s*\(/i,
    /\bspawnSync\s*\(/i,
    /\bchild_process\b/i,
  ];

  const containsDangerousPrimitive = (text: string): boolean => {
    return DANGEROUS_PATTERNS.some((pattern) => pattern.test(text));
  };

  if (containsDangerousPrimitive(llmOutputText)) {
    console.warn("LLM output contained dangerous code execution primitive. Response blocked.");
    return new NextResponse("Response blocked due to policy violation.", { status: 400 });
  }

  const chatHistoryRecord = await memoryManager.writeToHistory(
    llmOutputText + "\n",
    companionKey
  );
  // Removed: logging raw chatHistoryRecord exposes internal/operational metadata
  if (isText) {
    return NextResponse.json(llmOutputText);
  }
  return new StreamingTextResponse(stream);
}
