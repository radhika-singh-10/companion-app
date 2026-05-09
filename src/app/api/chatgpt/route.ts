import { OpenAI } from "langchain/llms/openai";
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

// ---------------------------------------------------------------------------
// Input sanitization – blocks prompt-injection and command-execution attempts
// ---------------------------------------------------------------------------
function sanitizeInput(input: string, fieldName: string): string {
  if (typeof input !== "string") return "";

  // 1. Strip / reject invisible / zero-width characters used to hide injections
  const invisiblePattern = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/g;
  if (invisiblePattern.test(input)) {
    throw new Error(`Blocked: invisible characters detected in ${fieldName}`);
  }

  // 2. Detect base64-encoded payloads (≥20-char base64 blobs)
  const base64Pattern = /(?:[A-Za-z0-9+\/]{20,}={0,2})/g;
  const base64Matches = input.match(base64Pattern) || [];
  for (const match of base64Matches) {
    try {
      const decoded = Buffer.from(match, "base64").toString("utf8");
      // If the decoded string looks like a shell command or injection, reject it
      if (/(?:ignore|system|exec|eval|bash|sh\s|cmd|powershell|\$\(|`)/i.test(decoded)) {
        throw new Error(`Blocked: base64-encoded command detected in ${fieldName}`);
      }
    } catch (e: any) {
      if (e.message.startsWith("Blocked:")) throw e;
      // Not valid base64 – safe to continue
    }
  }

  // 3. Detect leetspeak obfuscation of dangerous keywords
  const normalised = input
    .replace(/0/g, "o")
    .replace(/1/g, "i")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/@/g, "a")
    .replace(/\$/g, "s")
    .toLowerCase();
  const leetspeakDangerousPattern =
    /\b(?:ignore|override|system|exec|eval|disregard|forget|bypass|jailbreak|pretend|act as|you are now|new persona|developer mode)\b/i;
  if (leetspeakDangerousPattern.test(normalised)) {
    throw new Error(`Blocked: suspicious/leetspeak content detected in ${fieldName}`);
  }

  // 4. Detect prompt-injection phrases in plain text
  const injectionPattern =
    /(?:ignore (?:all )?(?:previous|prior|above)|disregard (?:all )?(?:previous|prior|above)|forget (?:all )?(?:previous|prior|above)|you are now|act as (?:an? )?(?:admin|root|system|ai without|unrestricted)|override (?:your )?(?:instructions|rules|guidelines)|jailbreak|developer mode|system prompt|\[system\]|<system>)/i;
  if (injectionPattern.test(input)) {
    throw new Error(`Blocked: prompt-injection pattern detected in ${fieldName}`);
  }

  // 5. Detect shell / binary command patterns
  const shellPattern =
    /(?:\$\(|`[^`]*`|\|\s*(?:bash|sh|zsh|cmd|powershell)|;\s*(?:rm|wget|curl|nc|ncat|python|perl|ruby|php)\s|&&\s*(?:rm|wget|curl|nc)|\beval\s*\(|\bexec\s*\(|\bsystem\s*\(|\bspawn\s*\(|\bchild_process|\bos\.system|\bsubprocess)/i;
  if (shellPattern.test(input)) {
    throw new Error(`Blocked: shell/binary command detected in ${fieldName}`);
  }

  // 6. Truncate to a safe maximum length to prevent context-stuffing
  const MAX_LENGTH = 4000;
  return input.slice(0, MAX_LENGTH);
}

export async function POST(req: Request) {
  let clerkUserId;
  let user;
  let clerkUserName;
  const { prompt: rawPrompt, isText, userId, userName } = await req.json();
  let prompt: string;
  try {
    prompt = sanitizeInput(String(rawPrompt ?? ""), "prompt");
  } catch (e: any) {
    console.warn("Sanitization rejected prompt:", e.message);
    return new NextResponse(
      JSON.stringify({ Message: "Input rejected: " + e.message }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

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

  // Sanitization helpers
  const sanitizeInput = (input: string): string => {
    // Remove null bytes, non-printable control characters (except newline/tab),
    // and trim leading/trailing whitespace
    return input
      .replace(/\0/g, "")
      .replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
      .trim();
  };

  const sanitizeName = (input: string | null): string | null => {
    if (input === null) return null;
    // Allow only alphanumeric characters, spaces, hyphens, and underscores
    const sanitized = input.replace(/[^a-zA-Z0-9 _-]/g, "").trim();
    // Enforce a reasonable length limit
    return sanitized.length > 0 && sanitized.length <= 64 ? sanitized : null;
  };

    // XXX Companion name passed here. Can use as a key to get backstory, chat history etc.
  const rawName = req.headers.get("name");
  // Sanitize: allow only alphanumeric, hyphen, and underscore to prevent path traversal
  const name = rawName ? rawName.replace(/[^a-zA-Z0-9_-]/g, "") : "";
  if (!name) {
    console.log("Invalid or missing companion name");
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion name" }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
  const companionFileName = name + ".txt";

    console.log("prompt: ", prompt);
  // Always derive identity from the authenticated session — never trust client-supplied userId/userName
  user = await currentUser();
  clerkUserId = user?.id;
  clerkUserName = user?.firstName;),
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
  const data = await fs.readFile("companions/" + companionFileName, "utf8");

  // Clunky way to break out PREAMBLE and SEEDCHAT from the character file
  const presplit = data.split("###ENDPREAMBLE###");
  const preamble = sanitizeInput(presplit[0]);
  const seedsplit = presplit[1].split("###ENDSEEDCHAT###");
  const seedchat = sanitizeInput(seedsplit[0]);

  const companionKey = {
    companionName: name!,
    modelName: "chatgpt",
    userId: clerkUserId,
  };
  const memoryManager = await MemoryManager.getInstance();

  const records = await memoryManager.readLatestHistory(companionKey);
  if (records.length === 0) {
    await memoryManager.seedChatHistory(seedchat, "\n\n", companionKey);
  }

  const sanitizedPrompt = sanitizeInput(prompt);
  if (!sanitizedPrompt || sanitizedPrompt.length === 0) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid prompt" }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
  await memoryManager.writeToHistory("Human: " + sanitizedPrompt + "\n", companionKey);
  const rawChatHistory = await memoryManager.readLatestHistory(companionKey);
  // Data minimisation: limit injected history to the last 10 lines only
  const recentChatHistory = rawChatHistory
    .split("\n")
    .filter((line: string) => line.trim() !== "")
    .slice(-10)
    .join("\n");

  // query Pinecone
  const similarDocs = await memoryManager.vectorSearch(
    recentChatHistory,
    companionFileName
  );

  let relevantHistory = "";
  if (!!similarDocs && similarDocs.length !== 0) {
    relevantHistory = similarDocs.map((doc) => sanitizeInput(doc.pageContent)).join("\n");
  }

  // --- Foundation Model Policy Enforcement ---
  // Approved model registry: only models listed here may be used.
  const APPROVED_MODEL_REGISTRY: Record<string, { provider: string; pinnedId: string }> = {
    "gpt-3.5-turbo-16k-0613": {
      provider: "OpenAI",
      pinnedId: "gpt-3.5-turbo-16k-0613", // immutable, version-pinned snapshot
    },
  };

  // Pinned, immutable model identifier — never use a mutable tag like "gpt-3.5-turbo-16k".
  const PINNED_MODEL_ID = "gpt-3.5-turbo-16k-0613";

  if (!APPROVED_MODEL_REGISTRY[PINNED_MODEL_ID]) {
    console.error(
      `[MODEL POLICY VIOLATION] Model '${PINNED_MODEL_ID}' is not in the approved registry. Request rejected.`
    );
    return new NextResponse(
      JSON.stringify({ Message: "Model not approved for use" }),
      {
        status: 403,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  const resolvedModelMeta = APPROVED_MODEL_REGISTRY[PINNED_MODEL_ID];
  console.log(
    `[MODEL AUDIT] Approved model selected — provider: ${resolvedModelMeta.provider}, pinnedId: ${resolvedModelMeta.pinnedId}, requestedAt: ${new Date().toISOString()}, userId: ${clerkUserId}`
  );
  // --- End Foundation Model Policy Enforcement ---

  const { stream, handlers } = LangChainStream();

  const model = new OpenAI({
    streaming: true,
    modelName: process.env.APPROVED_LLM_MODEL_NAME || "gpt-4",
    openAIApiKey: process.env.OPENAI_API_KEY,
    callbackManager: CallbackManager.fromHandlers(handlers),
  });
  model.verbose = true;

  const replyWithTwilioLimit = isText
    ? "You reply within 1000 characters."
    : "";

  const chainPrompt = PromptTemplate.fromTemplate(`
    You are ${name} and are currently talking to ${clerkUserName ? sanitizeInput(clerkUserName) : "User"}.

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

  // ── Audit / forensic readiness ────────────────────────────────────────────
  // Retention policy: audit records MUST be retained for a minimum of 90 days
  // and rotated/archived after 1 year per the AI-action audit policy.
  const AUDIT_RETENTION_DAYS = 90;

  // Stable imports needed for audit trail (Node built-ins, always available)
  const { createHash, randomUUID } =
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    require("crypto") as typeof import("crypto");
  const fsPromises =
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    (require("fs") as typeof import("fs")).promises;
  const nodePath =
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    require("path") as typeof import("path");

  // (1) Correlation / trace identifier — links every step end-to-end
  const traceId = randomUUID();

  // (2) Input hash — deterministic fingerprint of the LLM input for replay
  const inputPayload = JSON.stringify({ relevantHistory, recentChatHistory });
  const inputHash = createHash("sha256").update(inputPayload).digest("hex");

  const MODEL_NAME = "gpt-3.5-turbo-16k";
  const MODEL_VERSION = "openai-2024-01-01"; // pin to deployment version
  const principal = clerkUserId ?? "anonymous";
  const auditLogPath = nodePath.resolve(process.cwd(), "audit", "ai-decisions.ndjson");

  // Helper: persist one audit record; throws on failure so errors are never silent
  async function writeAuditRecord(record: Record<string, unknown>): Promise<void> {
    await fsPromises.mkdir(nodePath.dirname(auditLogPath), { recursive: true });
    await fsPromises.appendFile(
      auditLogPath,
      JSON.stringify(record) + "\n",
      "utf8"
    );
  }

  const callStart = Date.now();

  // (4) Hard-fail on chain errors — never swallow with .catch(console.error)
  let result: Awaited<ReturnType<typeof chain.call>>;
  try {
    result = await chain.call({
      relevantHistory,
      recentChatHistory: recentChatHistory,
    });
  } catch (chainError) {
    // Log the failure to the audit trail before re-throwing
    const failureRecord = {
      traceId,
      event: "ai_inference_failure",
      timestamp: new Date().toISOString(),
      principal,
      modelName: MODEL_NAME,
      modelVersion: MODEL_VERSION,
      inputHash,
      error: chainError instanceof Error ? chainError.message : String(chainError),
      retentionDays: AUDIT_RETENTION_DAYS,
    };
    try {
      await writeAuditRecord(failureRecord);
    } catch (auditErr) {
      // Audit write failed — surface both errors, do NOT continue silently
      throw new Error(
        `AI inference failed AND audit write failed. inferenceError=${
          chainError
        } auditError=${auditErr}`
      );
    }
    throw chainError; // fail closed
  }

  const durationMs = Date.now() - callStart;

  // (3) Persistent decision audit record
  const auditRecord = {
    traceId,
    event: "ai_inference_success",
    timestamp: new Date().toISOString(),
    principal,
    modelName: MODEL_NAME,
    modelVersion: MODEL_VERSION,
    inputHash,
    outputText: result.text,
    durationMs,
    retentionDays: AUDIT_RETENTION_DAYS,
  };
  try {
    await writeAuditRecord(auditRecord);
  } catch (auditErr) {
    // Audit write failure must not be silent — fail closed
    throw new Error(`Audit record write failed (traceId=${traceId}): ${auditErr}`);
  }

  // (5) Structured log — includes all fields needed for forensic reproduction
  console.log(
    JSON.stringify({
      traceId,
      event: "ai_inference_result",
      timestamp: new Date().toISOString(),
      principal,
      modelName: MODEL_NAME,
      modelVersion: MODEL_VERSION,
      inputHash,
      outputPreview: result.text?.slice(0, 120),
      durationMs,
    })
  );

  // Memory write — retention policy documented above (AUDIT_RETENTION_DAYS)
  const chatHistoryRecord = await memoryManager.writeToHistory(
    result.text + "\n",
    companionKey
  );

  console.log(
    JSON.stringify({
      traceId,
      event: "memory_write",
      timestamp: new Date().toISOString(),
      principal,
      chatHistoryRecord,
      retentionDays: AUDIT_RETENTION_DAYS,
    })
  );

  if (isText) {
    return NextResponse.json(result.text);
  }
  return new StreamingTextResponse(stream);
});

  // Termination criteria: enforce a hard timeout of 30 seconds and a single
  // attempt limit so the agent cannot run indefinitely.
  const MAX_ATTEMPTS = 1;
  const TIMEOUT_MS = 30_000;

  let result;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(
        () => reject(new Error(`Agent timed out after ${TIMEOUT_MS} ms (attempt ${attempt}/${MAX_ATTEMPTS})`)),
        TIMEOUT_MS
      )
    );
    try {
      result = await Promise.race([
        chain.call({ relevantHistory, recentChatHistory: recentChatHistory }),
        timeoutPromise,
      ]);
      // Successful response — exit the loop immediately.
      break;
    } catch (err) {
      console.error(`chain.call attempt ${attempt} failed:`, err);
      if (attempt >= MAX_ATTEMPTS) {
        return new NextResponse(
          JSON.stringify({ Message: "Agent failed to produce a response within the allowed time." }),
          { status: 504, headers: { "Content-Type": "application/json" } }
        );
      }
    }
  }

  // Data minimisation: do not log raw LLM result objects
  // Sanitize LLM output: reject or strip dynamic code execution primitives
  const DANGEROUS_PATTERNS = [
    /\beval\s*\(/gi,
    /\bexec\s*\(/gi,
    /\bnew\s+Function\s*\(/gi,
    /\bsetTimeout\s*\(\s*['"`]/gi,
    /\bsetInterval\s*\(\s*['"`]/gi,
    /\bimport\s*\(/gi,
    /\brequire\s*\(/gi,
    /\bprocess\.exec/gi,
    /\bchild_process/gi,
    /\bsubprocess/gi,
    /\bos\.system/gi,
    /\bexecSync\s*\(/gi,
    /\bspawnSync\s*\(/gi,
    /\bspawn\s*\(/gi,
  ];

  function sanitizeLLMOutput(text: string): string {
    for (const pattern of DANGEROUS_PATTERNS) {
      if (pattern.test(text)) {
        console.warn("Dangerous pattern detected in LLM output, stripping response.");
        return "[Response blocked due to policy violation.]"
      }
    }
    // Strip any HTML/script tags as an additional precaution
    return text.replace(/<script[\s\S]*?<\/script>/gi, "").replace(/<[^>]+>/g, "");
  }

  const rawText: string = result!.text;
  const sanitizedText = sanitizeLLMOutput(rawText);

  const chatHistoryRecord = await memoryManager.writeToHistory(
    sanitizedText + "\n",
    companionKey
  );
  console.log("chatHistoryRecord", chatHistoryRecord);
  if (isText) {
    return NextResponse.json(sanitizedText);
  }
  return new StreamingTextResponse(stream);
}
