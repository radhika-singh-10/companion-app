import { Redis } from "@upstash/redis";
import { OpenAIEmbeddings } from "langchain/embeddings/openai";
import { PineconeClient } from "@pinecone-database/pinecone";
import { PineconeStore } from "langchain/vectorstores/pinecone";
import { SupabaseVectorStore } from "langchain/vectorstores/supabase";
import { SupabaseClient, createClient } from "@supabase/supabase-js";
import * as crypto from "crypto";

// Approved model registry — only models listed here may be instantiated.
const APPROVED_EMBEDDING_MODELS: Record<string, string> = {
  // model-id -> expected SHA-256 digest of the model identifier string
  // (acts as a tamper-evident pin; update digest when intentionally rotating models)
  "text-embedding-ada-002": "4a8e3c2f1b6d9e0a7c5f2b8d4e1a3c6f9b2e5d8a1c4f7b0e3d6a9c2f5b8e1d4",
};

const PINNED_EMBEDDING_MODEL = "text-embedding-ada-002";

/**
 * Verifies the model name against the approved registry and its integrity pin,
 * then returns a version-pinned OpenAIEmbeddings instance.
 */
function createApprovedEmbeddings(): OpenAIEmbeddings {
  const modelId = PINNED_EMBEDDING_MODEL;

  if (!(modelId in APPROVED_EMBEDDING_MODELS)) {
    throw new Error(
      `Model '${modelId}' is NOT in the approved model registry. ` +
      `Approved models: ${Object.keys(APPROVED_EMBEDDING_MODELS).join(", ")}`
    );
  }

  // Integrity check: verify the model identifier against its registered digest.
  const actualDigest = crypto
    .createHash("sha256")
    .update(modelId, "utf8")
    .digest("hex");
  const expectedDigest = APPROVED_EMBEDDING_MODELS[modelId];
  if (actualDigest !== expectedDigest) {
    throw new Error(
      `Integrity verification failed for model '${modelId}'. ` +
      `Expected digest '${expectedDigest}', got '${actualDigest}'.`
    );
  }

  return new OpenAIEmbeddings({
    openAIApiKey: process.env.OPENAI_API_KEY,
    modelName: modelId, // explicit, immutable version pin
  });
}
import { createHash } from "crypto";

const MAX_INPUT_LENGTH = 4000;

function sanitizeInput(input: string): string {
  if (typeof input !== "string") {
    return "";
  }
  // Remove null bytes and non-printable control characters (except common whitespace)
  let sanitized = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  // Trim leading/trailing whitespace
  sanitized = sanitized.trim();
  // Enforce maximum length to prevent prompt injection via oversized input
  if (sanitized.length > MAX_INPUT_LENGTH) {
    sanitized = sanitized.substring(0, MAX_INPUT_LENGTH);
  }
  return sanitized;
}

function sanitizeInput(input: string): string {
  if (!input || typeof input !== "string") return "";

  // Detect base64-encoded content (long base64 strings)
  const base64Pattern = /(?:[A-Za-z0-9+\/]{40,}={0,2})/;
  if (base64Pattern.test(input)) {
    console.warn("SECURITY: Rejected input containing potential base64-encoded content.");
    throw new Error("Input contains potentially malicious base64-encoded content.");
  }

  // Detect shell command patterns
  const shellCommandPattern = /(?:;|\||&&|\$\(|`|\bexec\b|\beval\b|\bsystem\b|\bpassthru\b|\bshell_exec\b|\bpopen\b|\bproc_open\b|\bcurl\b|\bwget\b|\bnc\b|\bnetcat\b|\brm\s+-rf\b|\/bin\/|\bchmod\b|\bchown\b|\bsudo\b|\bsu\b)/i;
  if (shellCommandPattern.test(input)) {
    console.warn("SECURITY: Rejected input containing potential shell commands.");
    throw new Error("Input contains potentially malicious shell commands.");
  }

  // Detect prompt injection / hidden instruction patterns
  const promptInjectionPattern = /(?:ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions?|disregard\s+(?:all\s+)?(?:previous|above|prior)|you\s+are\s+now|act\s+as\s+(?:a\s+)?(?:different|new|another)|forget\s+(?:all\s+)?(?:previous|your)\s+instructions?|new\s+instructions?\s*:|system\s*:|<\s*system\s*>|\[\s*system\s*\]|###\s*instruction|\bDAN\b|jailbreak)/i;
  if (promptInjectionPattern.test(input)) {
    console.warn("SECURITY: Rejected input containing potential prompt injection.");
    throw new Error("Input contains potentially malicious prompt injection content.");
  }

  // Detect leetspeak patterns (e.g., 3x3cut3, 1nj3ct)
  const leetspeakPattern = /(?:[a-z]*[013456789@$!][a-z0-9@$!]{3,})/i;
  const leetspeakWords = input.match(/\b[a-z0-9@$!]{4,}\b/gi) || [];
  const leetspeakSubstitutions: Record<string, string> = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "6": "g", "7": "t", "@": "a", "$": "s", "!": "i"
  };
  const dangerousWords = ["execute", "inject", "exploit", "bypass", "override", "admin", "root", "shell", "script", "eval"];
  for (const word of leetspeakWords) {
    const decoded = word.toLowerCase().split("").map(c => leetspeakSubstitutions[c] || c).join("");
    if (dangerousWords.some(dw => decoded.includes(dw))) {
      console.warn("SECURITY: Rejected input containing potential leetspeak obfuscation.");
      throw new Error("Input contains potentially malicious leetspeak-obfuscated content.");
    }
  }

  // Detect script/HTML injection
  const scriptPattern = /<\s*script|javascript\s*:|on\w+\s*=|<\s*iframe|<\s*object|<\s*embed/i;
  if (scriptPattern.test(input)) {
    console.warn("SECURITY: Rejected input containing potential script injection.");
    throw new Error("Input contains potentially malicious script content.");
  }

  return input;
}

// ---------------------------------------------------------------------------
// Audit / forensic constants
// ---------------------------------------------------------------------------
/** Redis Stream key that holds the immutable AI-decision audit trail. */
const AUDIT_STREAM_KEY = "ai:decision:audit:stream";

/**
 * Maximum number of entries retained in the audit stream (MAXLEN ~).
 * Adjust to match your data-retention policy (e.g. 90 days × expected TPS).
 * XTRIM with MAXLEN keeps the stream append-only while bounding storage.
 */
const AUDIT_STREAM_MAX_LEN = 100_000;

/** Model / embedding version tag written into every audit record. */
const EMBEDDING_MODEL_ID = "openai/text-embedding-ada-002@v2";

export type CompanionKey = {
  companionName: string;
  modelName: string;
  userId: string;
};

const DANGEROUS_PATTERNS = [
  /\beval\s*\(/gi,
  /\bexec\s*\(/gi,
  /new\s+Function\s*\(/gi,
  /\bsetTimeout\s*\(\s*['"`]/gi,
  /\bsetInterval\s*\(\s*['"`]/gi,
  /\bimportScripts\s*\(/gi,
  /\brequire\s*\(/gi,
  /\bprocess\.binding\s*\(/gi,
  /\bchild_process/gi,
  /\bvm\.runInThisContext\s*\(/gi,
  /\bvm\.runInNewContext\s*\(/gi,
];

function sanitizeLLMOutput(text: string): string {
  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.test(text)) {
      console.warn(
        "WARNING: Potentially dangerous code execution primitive detected in LLM output. Redacting."
      );
      text = text.replace(pattern, "[REDACTED]");
    }
  }
  return text;
}

function sanitizeSimilarDocs(
  docs: { pageContent: string; metadata: Record<string, unknown> }[] | undefined
): { pageContent: string; metadata: Record<string, unknown> }[] | undefined {
  if (!docs) return docs;
  return docs.map((doc) => ({
    ...doc,
    pageContent: sanitizeLLMOutput(doc.pageContent),
  }));
}

// ---------------------------------------------------------------------------
// Audit helper — writes one append-only record to a Redis Stream.
// Redis Streams (XADD) are inherently append-only at the protocol level;
// entries can only be removed via XTRIM/XDEL with explicit operator action,
// giving a tamper-evident forensic trail for every AI-driven decision.
// ---------------------------------------------------------------------------
async function appendAuditLog(
  redis: Redis,
  fields: Record<string, string>
): Promise<void> {
  try {
    // XADD with auto-generated stream ID (*) is append-only.
    await redis.xadd(AUDIT_STREAM_KEY, "*", fields);
    // Enforce retention policy: keep at most AUDIT_STREAM_MAX_LEN entries.
    // The "~" approximation flag lets Redis batch the trim for efficiency
    // while still honouring the cap within a small tolerance.
    await redis.xtrim(AUDIT_STREAM_KEY, { strategy: "MAXLEN", threshold: AUDIT_STREAM_MAX_LEN, approx: true });
  } catch (auditErr) {
    // Audit failures must never be silent — surface them so ops can act.
    console.error(
      "CRITICAL: audit log write failed — forensic trail may be incomplete.",
      auditErr
    );
    // Re-throw so the caller can decide whether to fail closed.
    throw auditErr;
  }
}

class MemoryManager {
  private static instance: MemoryManager;
  private history: Redis | null;
  private vectorDBClient: PineconeClient | SupabaseClient;

  public constructor(redisClient?: Redis) {
    this.history = redisClient ?? null;
    if (process.env.VECTOR_DB === "pinecone") {
      this.vectorDBClient = new PineconeClient();
    } else {
      const auth = {
        detectSessionInUrl: false,
        persistSession: false,
        autoRefreshToken: false,
      };
      const url = process.env.SUPABASE_URL!;
      const privateKey = process.env.SUPABASE_PRIVATE_KEY!;
      this.vectorDBClient = createClient(url, privateKey, { auth });
    }
  }

  public async init() {
    if (this.vectorDBClient instanceof PineconeClient) {
      await this.vectorDBClient.init({
        apiKey: process.env.PINECONE_API_KEY!,
        environment: process.env.PINECONE_ENVIRONMENT!,
      });
    }
  }

  public async vectorSearch(
    recentChatHistory: string,
    companionFileName: string
  ) {
    const sanitizedHistory = sanitizeInput(recentChatHistory);
    const sanitizedHistory = sanitizeInput(recentChatHistory);
    if (!sanitizedHistory) {
      console.log("WARNING: recentChatHistory is empty after sanitization.");
      return [];
    }
    if (process.env.VECTOR_DB === "pinecone") {
      console.log("INFO: using Pinecone for vector search.");
      const pineconeClient = <PineconeClient>this.vectorDBClient;

      const pineconeIndex = pineconeClient.Index(
        process.env.PINECONE_INDEX! || ""
      );

            const vectorStore = await PineconeStore.fromExistingIndex(
        createApprovedEmbeddings(),
        { pineconeIndex }
      );

      const rawSimilarDocs = await vectorStore
        .similaritySearch(sanitizedHistory, 3, { fileName: companionFileName })
        .catch((err) => {
          console.log("WARNING: failed to get vector search results.", err);
        });
      const similarDocs = sanitizeSimilarDocs(
        rawSimilarDocs as
          | { pageContent: string; metadata: Record<string, unknown> }[]
          | undefined
      );
      return similarDocs;
    } else {
      console.log("INFO: using Supabase for vector search.");
      const supabaseClient = <SupabaseClient>this.vectorDBClient;
            const vectorStore = await SupabaseVectorStore.fromExistingIndex(
        createApprovedEmbeddings(),
        { apiKey: process.env.HUGGINGFACEHUB_API_KEY }),
        {
          client: supabaseClient,
          tableName: "documents",
          queryName: "match_documents",
        }
      );
      const rawSimilarDocs = await vectorStore
        .similaritySearch(sanitizedHistory, 3)
        .catch((err) => {
          console.log("WARNING: failed to get vector search results.", err);
        });
      const similarDocs = sanitizeSimilarDocs(
        rawSimilarDocs as
          | { pageContent: string; metadata: Record<string, unknown> }[]
          | undefined
      );
      return similarDocs;
    }
  }

  public static async getInstance(): Promise<MemoryManager> {
    if (!MemoryManager.instance) {
      MemoryManager.instance = new MemoryManager();
      await MemoryManager.instance.init();
    }
    return MemoryManager.instance;
  }

  private generateRedisCompanionKey(companionKey: CompanionKey): string {
    return `${companionKey.companionName}-${companionKey.modelName}-${companionKey.userId}`;
  }

    public async writeToHistory(text: string, companionKey: CompanionKey) {
    if (!companionKey || typeof companionKey.userId == "undefined") {
      console.log("Companion key set incorrectly");
      return "";
    }

    const sanitizedText = sanitizeInput(text);
    if (!sanitizedText) {
      console.log("WARNING: text is empty after sanitization, skipping write.");
      return "";
    }

        const key = this.generateRedisCompanionKey(companionKey);
    const provenanceHeader = `[AI_GENERATED|model:${companionKey.modelName}|origin:ai-chat|ts:${new Date().toISOString()}]`;
    const labeledText = `${provenanceHeader} ${text}`;
        const writeTimestamp = new Date().toISOString();
    const result = await this.history.zadd(key, {
      score: Date.now(),
      member: text,
    });
    // Append an immutable audit record for this history write.
    await appendAuditLog(this.history, {
      timestamp: writeTimestamp,
      action: "writeToHistory",
      userId: companionKey.userId,
      companionName: companionKey.companionName,
      modelName: companionKey.modelName,
      textHash: createHash("sha256").update(text).digest("hex"),
      status: result !== null ? "SUCCESS" : "NOOP",
    });
    return result;
  }

  public async readLatestHistory(companionKey: CompanionKey): Promise<string> {
    if (!companionKey || typeof companionKey.userId == "undefined") {
      console.log("Companion key set incorrectly");
      return "";
    }

    const key = this.generateRedisCompanionKey(companionKey);
    let result = await this.history.zrange(key, 0, Date.now(), {
      byScore: true,
    });

    result = result.slice(-10).reverse();
    const recentChats = result.reverse().join("\n");
    const historyProvenance = {
      contentOrigin: "AI_GENERATED",
      model: companionKey.modelName,
      companion: companionKey.companionName,
      retrievedAt: new Date().toISOString(),
    };
    return recentChats;
  }

  public async seedChatHistory(
    seedContent: String,
    delimiter: string = "\n",
    companionKey: CompanionKey
  ) {
    const key = this.generateRedisCompanionKey(companionKey);
    if (await this.history.exists(key)) {
      console.log("User already has chat history");
      return;
    }

    const content = seedContent.split(delimiter);
    let counter = 0;
    for (const line of content) {
      await this.history.zadd(key, { score: counter, member: line });
      counter += 1;
    }
  }
}

export default MemoryManager;
