import { Redis } from "@upstash/redis";
import { OpenAIEmbeddings } from "langchain/embeddings/openai";
import { PineconeClient } from "@pinecone-database/pinecone";
import { PineconeStore } from "langchain/vectorstores/pinecone";
import { SupabaseVectorStore } from "langchain/vectorstores/supabase";
import { SupabaseClient, createClient } from "@supabase/supabase-js";

// Approved model registry — only models listed here may be instantiated.
const APPROVED_EMBEDDING_REGISTRY: Record<string, { provider: string; version: string }> = {
  "text-embedding-3-small": { provider: "openai", version: "text-embedding-3-small" },
  "text-embedding-3-large": { provider: "openai", version: "text-embedding-3-large" },
};

const PINNED_EMBEDDING_MODEL = "text-embedding-3-small";

/**
 * Factory that enforces model identity, version pinning, and registry validation.
 * Throws if the requested model is not in the approved registry.
 */
function createApprovedEmbeddings(): OpenAIEmbeddings {
  const modelId = PINNED_EMBEDDING_MODEL;
  const registryEntry = APPROVED_EMBEDDING_REGISTRY[modelId];
  if (!registryEntry) {
    throw new Error(
      `[ModelRegistry] Embedding model '${modelId}' is NOT in the approved registry. ` +
      `Approved models: ${Object.keys(APPROVED_EMBEDDING_REGISTRY).join(", ")}`
    );
  }
  // Record resolved model identity for audit/traceability.
  console.info(
    `[ModelRegistry] Resolved embedding model — id: '${modelId}', ` +
    `provider: '${registryEntry.provider}', version: '${registryEntry.version}'`
  );
  return new OpenAIEmbeddings({
    openAIApiKey: process.env.OPENAI_API_KEY,
    modelName: modelId,
  });
}
import { createHash, randomUUID } from "crypto";

export type SyntheticProvenance = {
  modelIdentifier: string;
  embeddingProvider: string;
  generatedAt: string;
  contentOrigin: string;
  syntheticLabel: string;
};

export type ProvenanceDocument = {
  pageContent: string;
  metadata: Record<string, unknown>;
  provenance: SyntheticProvenance;
};

function attachProvenance(
  docs: { pageContent: string; metadata: Record<string, unknown> }[],
  modelIdentifier: string
): ProvenanceDocument[] {
  const provenance: SyntheticProvenance = {
    modelIdentifier,
    embeddingProvider: "OpenAI",
    generatedAt: new Date().toISOString(),
    contentOrigin: "AI-generated vector similarity search",
    syntheticLabel: "SYNTHETIC_AI_CONTENT",
  };
  return docs.map((doc) => ({
    pageContent: doc.pageContent,
    metadata: doc.metadata,
    provenance,
  }));
}

export type CompanionKey = {
  companionName: string;
  modelName: string;
  userId: string;
};

const DANGEROUS_PATTERNS = [
  /\beval\s*\(/gi,
  /\bexec\s*\(/gi,
  /new\s+Function\s*\(/gi,
  /setTimeout\s*\(\s*['"`]/gi,
  /setInterval\s*\(\s*['"`]/gi,
  /\bimport\s*\(/gi,
  /require\s*\(/gi,
  /process\.binding\s*\(/gi,
  /child_process/gi,
  /__proto__/gi,
  /constructor\s*\[/gi,
];

function sanitizeDocs(docs: any[] | void): any[] {
  if (!docs) return [];
  return docs.filter((doc) => {
    const content: string = typeof doc.pageContent === "string" ? doc.pageContent : JSON.stringify(doc);
    for (const pattern of DANGEROUS_PATTERNS) {
      if (pattern.test(content)) {
        console.warn(
          "WARNING: Potentially dangerous content detected in vector search result and was removed.",
          { pattern: pattern.toString() }
        );
        return false;
      }
    }
    return true;
  });
}

const MAX_INPUT_LENGTH = 4000;

function sanitizeInput(input: string): string {
  if (typeof input !== "string") {
    return "";
  }
  // Trim whitespace
  let sanitized = input.trim();
  // Remove null bytes and non-printable control characters (except common whitespace)
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  // Enforce maximum length to prevent prompt injection via oversized input
  if (sanitized.length > MAX_INPUT_LENGTH) {
    sanitized = sanitized.substring(0, MAX_INPUT_LENGTH);
  }
  return sanitized;
}

function sanitizeInput(input: string): string {
  // Reject or strip base64-encoded content (long base64 strings)
  const base64Pattern = /(?:[A-Za-z0-9+\/]{40,}={0,2})/g;
  if (base64Pattern.test(input)) {
    throw new Error("Suspicious input detected: possible base64-encoded content.");
  }

  // Reject shell command patterns
  const shellCommandPattern = /(?:;|&&|\|\||`|\$\(|\bexec\b|\beval\b|\bsystem\b|\bpassthru\b|\bshell_exec\b|\bpopen\b|\bproc_open\b|\bcmd\.exe\b|\/bin\/(?:sh|bash|zsh|ksh|csh)|\bpowershell\b)/i;
  if (shellCommandPattern.test(input)) {
    throw new Error("Suspicious input detected: possible shell command injection.");
  }

  // Reject binary/non-printable characters
  // eslint-disable-next-line no-control-regex
  const binaryPattern = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/;
  if (binaryPattern.test(input)) {
    throw new Error("Suspicious input detected: binary or non-printable characters.");
  }

  // Reject leetspeak patterns combined with suspicious keywords
  const leetspeakPattern = /(?:(?:3x3c|3x3C|\$h3ll|5h3ll|1njec|1nj3c|pr0mpt|pr0mp7|syst3m|syst3|3val|3v4l))/i;
  if (leetspeakPattern.test(input)) {
    throw new Error("Suspicious input detected: possible leetspeak obfuscation.");
  }

  // Reject prompt injection attempts targeting AI instructions
  const promptInjectionPattern = /(?:ignore\s+(?:previous|above|prior|all)\s+instructions?|disregard\s+(?:previous|above|prior|all)|you\s+are\s+now|act\s+as\s+(?:a\s+)?(?:different|new|another)|forget\s+(?:your|all|previous)|new\s+instructions?\s*:|system\s*:\s*you|<\s*system\s*>|\[\s*system\s*\])/i;
  if (promptInjectionPattern.test(input)) {
    throw new Error("Suspicious input detected: possible prompt injection attempt.");
  }

  // Truncate to a safe maximum length
  const MAX_LENGTH = 4000;
  if (input.length > MAX_LENGTH) {
    input = input.slice(0, MAX_LENGTH);
  }

  return input;
}

// Audit record shape written to Redis for every AI-driven action
interface AuditRecord {
  traceId: string;
  action: string;
  principal: string;
  modelId: string;
  inputHash: string;
  timestamp: string;
  outcome: "started" | "success" | "failure";
  detail?: string;
}

class MemoryManager {
  private static instance: MemoryManager;
  private history: Redis;
  private vectorDBClient: PineconeClient | SupabaseClient;
  private static readonly AUDIT_KEY = "ai:audit:log";

  /**
   * Writes a structured audit record to the persistent Redis audit log.
   * Uses a sorted set scored by epoch ms so records are time-ordered and
   * queryable. Failures are logged to stderr but never swallowed silently —
   * the caller's error propagation is unaffected.
   */
  private async auditLog(record: AuditRecord): Promise<void> {
    try {
      await this.history.zadd(MemoryManager.AUDIT_KEY, {
        score: Date.now(),
        member: JSON.stringify(record),
      });
    } catch (auditErr) {
      // Audit failures must be visible; write to stderr and re-throw so the
      // caller knows the audit trail is broken.
      console.error("AUDIT FAILURE: could not write audit record.", auditErr);
      throw auditErr;
    }
  }

  public constructor(redisClient: Redis) {
    this.history = redisClient;
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
    companionFileName: string,
    principal: string = "system",
    traceId: string = randomUUID()
  ) {
    const modelId = process.env.VECTOR_DB === "pinecone"
      ? `pinecone:${process.env.PINECONE_INDEX ?? "default"}`
      : "supabase:documents";
    const inputHash = createHash("sha256").update(recentChatHistory).digest("hex");

    await this.auditLog({
      traceId,
      action: "vectorSearch",
      principal,
      modelId,
      inputHash,
      timestamp: new Date().toISOString(),
      outcome: "started",
      detail: `companionFileName=${companionFileName}`,
    });

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

      let similarDocs;
      try {
        similarDocs = await vectorStore.similaritySearch(
          recentChatHistory,
          3,
          { fileName: companionFileName }
        );
      } catch (err) {
        await this.auditLog({
          traceId,
          action: "vectorSearch",
          principal,
          modelId,
          inputHash,
          timestamp: new Date().toISOString(),
          outcome: "failure",
          detail: String(err),
        });
        console.error("ERROR: failed to get Pinecone vector search results.", err);
        throw err;
      }

      await this.auditLog({
        traceId,
        action: "vectorSearch",
        principal,
        modelId,
        inputHash,
        timestamp: new Date().toISOString(),
        outcome: "success",
        detail: `resultCount=${similarDocs?.length ?? 0}`,
      });
      return similarDocs;
    } else {
      console.log("INFO: using Supabase for vector search.");
      const supabaseClient = <SupabaseClient>this.vectorDBClient;
      const vectorStore = await SupabaseVectorStore.fromExistingIndex(
        createApprovedEmbeddings(),
        {
          client: supabaseClient,
          tableName: "documents",
          queryName: "match_documents",
        }
      );

      let similarDocs;
      try {
        similarDocs = await vectorStore.similaritySearch(recentChatHistory, 3);
      } catch (err) {
        await this.auditLog({
          traceId,
          action: "vectorSearch",
          principal,
          modelId,
          inputHash,
          timestamp: new Date().toISOString(),
          outcome: "failure",
          detail: String(err),
        });
        console.error("ERROR: failed to get Supabase vector search results.", err);
        throw err;
      }

      await this.auditLog({
        traceId,
        action: "vectorSearch",
        principal,
        modelId,
        inputHash,
        timestamp: new Date().toISOString(),
        outcome: "success",
        detail: `resultCount=${similarDocs?.length ?? 0}`,
      });
      return similarDocs;
    }
  }
    if (!companionFileName) {
      console.log("WARNING: companionFileName is empty after sanitization.");
      return [];
    }
    if (process.env.VECTOR_DB === "pinecone") {
      console.log("INFO: using Pinecone for vector search.");
      const pineconeClient = <PineconeClient>this.vectorDBClient;

      const pineconeIndex = pineconeClient.Index(
        process.env.PINECONE_INDEX! || ""
      );

      const vectorStore = await PineconeStore.fromExistingIndex(
        new CohereEmbeddings({ apiKey: process.env.COHERE_API_KEY }),
        { pineconeIndex }
      );

      const similarDocs = await vectorStore
        .similaritySearch(recentChatHistory, 3, { fileName: companionFileName })
        .catch((err) => {
          console.log("WARNING: failed to get vector search results.", err);
        });
      return sanitizeDocs(similarDocs);
    } else {
      console.log("INFO: using Supabase for vector search.");
      const supabaseClient = <SupabaseClient>this.vectorDBClient;
      const vectorStore = await SupabaseVectorStore.fromExistingIndex(
        new CohereEmbeddings({ apiKey: process.env.COHERE_API_KEY }),
        {
          client: supabaseClient,
          tableName: "documents",
          queryName: "match_documents",
        }
      );
      const similarDocs = await vectorStore
        .similaritySearch(recentChatHistory, 3)
        .catch((err) => {
          console.log("WARNING: failed to get vector search results.", err);
        });
      return sanitizeDocs(similarDocs);
    }
  }

  public static async getInstance(): Promise<MemoryManager> {
    if (!MemoryManager.instance) {
      const redisClient = Redis.fromEnv();
      MemoryManager.instance = new MemoryManager(redisClient);
      await MemoryManager.instance.init();
    }
    return MemoryManager.instance;
  }

  private generateRedisCompanionKey(companionKey: CompanionKey): string {
    return `${companionKey.companionName}-${companionKey.modelName}-${companionKey.userId}`;
  }

  public async writeToHistory(
    text: string,
    companionKey: CompanionKey,
    traceId: string = randomUUID()
  ) {
    if (!companionKey || typeof companionKey.userId == "undefined") {
      console.log("Companion key set incorrectly");
      return "";
    }

    const principal = companionKey.userId;
    const inputHash = createHash("sha256").update(text).digest("hex");

    await this.auditLog({
      traceId,
      action: "writeToHistory",
      principal,
      modelId: companionKey.modelName,
      inputHash,
      timestamp: new Date().toISOString(),
      outcome: "started",
      detail: `companionName=${companionKey.companionName}`,
    });

    const key = this.generateRedisCompanionKey(companionKey);
    const result = await this.history.zadd(key, {
      score: Date.now(),
      member: text,
    });

    await this.auditLog({
      traceId,
      action: "writeToHistory",
      principal,
      modelId: companionKey.modelName,
      inputHash,
      timestamp: new Date().toISOString(),
      outcome: "success",
      detail: `redisKey=${key}`,
    });

    return result;
  }

  public async readLatestHistory(
    companionKey: CompanionKey,
    traceId: string = randomUUID()
  ): Promise<string> {
    if (!companionKey || typeof companionKey.userId == "undefined") {
      console.log("Companion key set incorrectly");
      return "";
    }

    const principal = companionKey.userId;

    await this.auditLog({
      traceId,
      action: "readLatestHistory",
      principal,
      modelId: companionKey.modelName,
      inputHash: createHash("sha256").update(this.generateRedisCompanionKey(companionKey)).digest("hex"),
      timestamp: new Date().toISOString(),
      outcome: "started",
      detail: `companionName=${companionKey.companionName}`,
    });

    const key = this.generateRedisCompanionKey(companionKey);
    let result = await this.history.zrange(key, 0, Date.now(), {
      byScore: true,
    });

    result = result.slice(-10).reverse();
    const recentChats = result
      .reverse()
      .map((entry) => entry.slice(0, 200))
      .join("\n");
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
