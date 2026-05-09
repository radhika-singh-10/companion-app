import { Redis } from "@upstash/redis";
import { OpenAIEmbeddings } from "langchain/embeddings/openai";

// --- Model Registry Policy ---
const APPROVED_EMBEDDING_MODELS: Record<string, string> = {
  // registry key -> pinned model version
  "text-embedding-ada-002": "text-embedding-ada-002",
};
const PINNED_EMBEDDING_MODEL = "text-embedding-ada-002"; // immutable version pin

function createApprovedEmbeddings(apiKey: string | undefined): OpenAIEmbeddings {
  if (!APPROVED_EMBEDDING_MODELS[PINNED_EMBEDDING_MODEL]) {
    throw new Error(
      `Model '${PINNED_EMBEDDING_MODEL}' is not in the approved model registry. ` +
      `Approved models: ${Object.keys(APPROVED_EMBEDDING_MODELS).join(", ")}`
    );
  }
  console.log(
    `INFO: model-identity modelName=${PINNED_EMBEDDING_MODEL} version=${APPROVED_EMBEDDING_MODELS[PINNED_EMBEDDING_MODEL]} source=OpenAI registry=approved`
  );
  return new OpenAIEmbeddings({
    openAIApiKey: apiKey,
    modelName: PINNED_EMBEDDING_MODEL,
  });
}
// --- End Model Registry Policy ---
import { PineconeClient } from "@pinecone-database/pinecone";
import { PineconeStore } from "langchain/vectorstores/pinecone";
import { SupabaseVectorStore } from "langchain/vectorstores/supabase";
import { SupabaseClient, createClient } from "@supabase/supabase-js";
import * as crypto from "crypto";

// ---------------------------------------------------------------------------
// Audit helpers
// ---------------------------------------------------------------------------

/** Stable SHA-256 hex digest of an arbitrary string value. */
function sha256(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

/** Generate a random correlation / trace identifier. */
function newTraceId(): string {
  return crypto.randomUUID();
}

interface AuditRecord {
  traceId: string;
  timestamp: string;        // ISO-8601
  principal: string;        // userId or 'system'
  operation: string;
  modelId: string;
  modelVersion: string;
  inputHash: string;
  outputSummary: string;
  status: "success" | "failure";
  errorMessage?: string;
  extra?: Record<string, unknown>;
}

/**
 * Persist a structured audit record to Redis under the key
 * `audit:<traceId>:<timestamp-ms>`.  Failures are logged to stderr but
 * never swallowed silently — the caller receives the error so it can
 * decide whether to fail-closed.
 */
async function persistAuditRecord(
  redis: Redis,
  record: AuditRecord
): Promise<void> {
  const key = `audit:${record.traceId}:${Date.now()}`;
  try {
    await redis.set(key, JSON.stringify(record), { ex: 60 * 60 * 24 * 90 }); // 90-day TTL
  } catch (err) {
    // Log to stderr AND re-throw so callers are aware of the audit failure.
    console.error(
      `[AUDIT-FAILURE] Could not persist audit record for traceId=${record.traceId} operation=${record.operation}`,
      err
    );
    throw err;
  }
}

export type ContentProvenance = {
  modelIdentifier: string;
  embeddingProvider: string;
  generatedAt: string;
  contentOrigin: string;
  syntheticLabel: string;
};

export type ProvenanceDocument = {
  pageContent: string;
  metadata: Record<string, unknown>;
  provenance: ContentProvenance;
};

function attachProvenance(
  docs: { pageContent: string; metadata: Record<string, unknown> }[],
  modelIdentifier: string
): ProvenanceDocument[] {
  const provenance: ContentProvenance = {
    modelIdentifier,
    embeddingProvider: "openai/text-embedding-ada-002",
    generatedAt: new Date().toISOString(),
    contentOrigin: "ai-vector-similarity-search",
    syntheticLabel: "AI_GENERATED_CONTENT",
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
  /\bexecSync\s*\(/gi,
  /\bspawn\s*\(/gi,
  /\bspawnSync\s*\(/gi,
  /\bfork\s*\(/gi,
  /\bnew\s+Function\s*\(/gi,
  /\bsetTimeout\s*\(\s*['"`]/gi,
  /\bsetInterval\s*\(\s*['"`]/gi,
  /\bimport\s*\(/gi,
  /\brequire\s*\(/gi,
  /\bprocess\.binding\s*\(/gi,
  /\bvm\.runInNewContext\s*\(/gi,
  /\bvm\.runInThisContext\s*\(/gi,
  /\bvm\.runInContext\s*\(/gi,
  /\bchild_process/gi,
  /\bsubprocess/gi,
];

function sanitizeDocumentContent(content: string): string {
  let sanitized = content;
  for (const pattern of DANGEROUS_PATTERNS) {
    sanitized = sanitized.replace(pattern, "[REDACTED]");
  }
  return sanitized;
}

function sanitizeSimilarDocs(
  docs: { pageContent: string; metadata: Record<string, unknown> }[] | void
): { pageContent: string; metadata: Record<string, unknown> }[] | void {
  if (!docs) return docs;
  return docs.map((doc) => ({
    ...doc,
    pageContent: sanitizeDocumentContent(doc.pageContent),
  }));
}

class MemoryManager {
  private static instance: MemoryManager;
  private history: Redis;
  private vectorDBClient: PineconeClient | SupabaseClient;

  public constructor(redisClient: Redis) {
    this.history = redisClient;
        if (process.env.VECTOR_DB === "pinecone") {
      console.log("INFO: using Pinecone for vector search.");
      const pineconeClient = <PineconeClient>this.vectorDBClient;

      const pineconeIndex = pineconeClient.Index(
        process.env.PINECONE_INDEX! || ""
      );

      console.log("LLM_INTERACTION: Initializing OpenAIEmbeddings for Pinecone vector store.", { model: "text-embedding-ada-002", vectorDB: "pinecone" });
            const vectorStore = await PineconeStore.fromExistingIndex(
        createApprovedEmbeddings(process.env.OPENAI_API_KEY),
        { pineconeIndex }
      );

      const similarDocs = await vectorStore
        .similaritySearch(recentChatHistory, 3, { fileName: companionFileName })
        .catch((err) => {
          console.log("WARNING: failed to get vector search results.", err);
        });
      console.log(
        `INFO: inference-request modelName=${PINNED_EMBEDDING_MODEL} version=${APPROVED_EMBEDDING_MODELS[PINNED_EMBEDDING_MODEL]} store=pinecone`
      );
      return similarDocs;
      return similarDocs.map((doc) => ({
        pageContent: doc.pageContent.slice(0, 500),
      }));
      return similarDocs.map((doc) => ({
        pageContent: doc.pageContent.slice(0, 500),
      }));
      return attachProvenance(
        similarDocs,
        `supabase/${"documents"}`
      );
      return attachProvenance(
        similarDocs,
        `pinecone/${process.env.PINECONE_INDEX ?? "unknown"}`
      );
    } else {
      console.log("INFO: using Supabase for vector search.");
      const supabaseClient = <SupabaseClient>this.vectorDBClient;
      console.log("LLM_INTERACTION: Initializing OpenAIEmbeddings for Supabase vector store.", { model: "text-embedding-ada-002", vectorDB: "supabase" });
      const vectorStore = await SupabaseVectorStore.fromExistingIndex(
        new OpenAIEmbeddings({ openAIApiKey: (() => {
          const key = process.env.OPENAI_API_KEY;
          if (!key || key.trim() === "") throw new Error("Missing required environment variable: OPENAI_API_KEY");
          return key;
        })() }),
        {
          client: supabaseClient,
          tableName: "documents",
          queryName: "match_documents",
        }
      );
      console.log("LLM_INTERACTION: OpenAIEmbeddings initialized for Supabase. Performing similarity search.", { query: recentChatHistory, topK: 3 });
      const sanitizedChatHistory = this.sanitizeInput(recentChatHistory);
      const similarDocs = await vectorStore
        .similaritySearch(sanitizedChatHistory, 3)
        .catch((err) => {
          console.log("WARNING: failed to get vector search results.", err);
        });
      console.log("LLM_INTERACTION: Supabase similarity search completed.", { resultCount: similarDocs ? similarDocs.length : 0, results: similarDocs });
      return similarDocs;
    } else {
      const auth = {
        detectSessionInUrl: false,
        persistSession: false,
        autoRefreshToken: false,
      };
      const url = process.env.SUPABASE_URL;
      const privateKey = process.env.SUPABASE_PRIVATE_KEY;
      if (!url || url.trim() === "") {
        throw new Error("Missing required environment variable: SUPABASE_URL");
      }
      if (!privateKey || privateKey.trim() === "") {
        throw new Error("Missing required environment variable: SUPABASE_PRIVATE_KEY");
      }
      this.vectorDBClient = createClient(url, privateKey, { auth });
    }
  }

  public async init() {
    if (this.vectorDBClient instanceof PineconeClient) {
      await this.vectorDBClient.init({
        apiKey: (() => {
          const key = process.env.PINECONE_API_KEY;
          if (!key || key.trim() === "") throw new Error("Missing required environment variable: PINECONE_API_KEY");
          return key;
        })(),
        environment: process.env.PINECONE_ENVIRONMENT!,
      });
    }
  }

    public async vectorSearch(
    recentChatHistory: string,
    companionFileName: string,
    principal: string = "system",
    traceId: string = newTraceId()
  ) {
    const modelId = "OpenAIEmbeddings";
    const modelVersion = process.env.OPENAI_API_VERSION ?? "default";
    const inputHash = sha256(recentChatHistory);
    const timestamp = new Date().toISOString();
    const dbBackend = process.env.VECTOR_DB === "pinecone" ? "pinecone" : "supabase";

    console.log(
      `[AUDIT] vectorSearch start traceId=${traceId} principal=${principal} ` +
      `backend=${dbBackend} model=${modelId} inputHash=${inputHash} ts=${timestamp}`
    );

    let similarDocs: Awaited<ReturnType<typeof vectorStore.similaritySearch>> | undefined;
    let vectorStore: PineconeStore | SupabaseVectorStore;

    try {
      if (dbBackend === "pinecone") {
        console.log("INFO: using Pinecone for vector search.");
        const pineconeClient = <PineconeClient>this.vectorDBClient;
        const pineconeIndex = pineconeClient.Index(
          process.env.PINECONE_INDEX! || ""
        );
        vectorStore = await PineconeStore.fromExistingIndex(
          new OpenAIEmbeddings({ openAIApiKey: process.env.OPENAI_API_KEY }),
          { pineconeIndex }
        );
        similarDocs = await vectorStore.similaritySearch(
          recentChatHistory,
          3,
          { fileName: companionFileName }
        );
      } else {
        console.log("INFO: using Supabase for vector search.");
        const supabaseClient = <SupabaseClient>this.vectorDBClient;
        vectorStore = await SupabaseVectorStore.fromExistingIndex(
          new OpenAIEmbeddings({ openAIApiKey: process.env.OPENAI_API_KEY }),
          {
            client: supabaseClient,
            tableName: "documents",
            queryName: "match_documents",
          }
        );
        similarDocs = await vectorStore.similaritySearch(recentChatHistory, 3);
      }

      const outputSummary = similarDocs
        ? `${similarDocs.length} docs returned; firstPageContentHash=${
            similarDocs[0] ? sha256(similarDocs[0].pageContent) : "none"
          }`
        : "no results";

      await persistAuditRecord(this.history, {
        traceId,
        timestamp,
        principal,
        operation: "vectorSearch",
        modelId,
        modelVersion,
        inputHash,
        outputSummary,
        status: "success",
        extra: { backend: dbBackend, companionFileName, topK: 3 },
      });

      console.log(
        `[AUDIT] vectorSearch success traceId=${traceId} ${outputSummary}`
      );
      return similarDocs;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      console.error(
        `[AUDIT] vectorSearch FAILED traceId=${traceId} principal=${principal} error=${errorMessage}`
      );
      // Best-effort audit record for the failure; if this also throws we
      // still propagate the original error below.
      try {
        await persistAuditRecord(this.history, {
          traceId,
          timestamp,
          principal,
          operation: "vectorSearch",
          modelId,
          modelVersion,
          inputHash,
          outputSummary: "error",
          status: "failure",
          errorMessage,
          extra: { backend: dbBackend, companionFileName, topK: 3 },
        });
      } catch (auditErr) {
        console.error(
          `[AUDIT-FAILURE] Could not write failure audit record traceId=${traceId}`,
          auditErr
        );
      }
      // Fail closed — do not swallow the error.
      throw err;
    }
  }),
        { pineconeIndex }
      );

      const similarDocs = await vectorStore
        .similaritySearch(recentChatHistory, 3, { fileName: companionFileName })
        .catch((err) => {
          console.log("WARNING: failed to get vector search results.", err);
        });
      return sanitizeSimilarDocs(similarDocs);
    } else {
      console.log("INFO: using Supabase for vector search.");
      const supabaseClient = <SupabaseClient>this.vectorDBClient;
      const vectorStore = await SupabaseVectorStore.fromExistingIndex(
                new HuggingFaceInferenceEmbeddings({ apiKey: process.env.HUGGINGFACEHUB_API_KEY }),
          {
            client: supabaseClient,
          tableName: "documents",
          queryName: "match_documents",
        }
      );
      const sanitizedHistory = MemoryManager.sanitizeInput(recentChatHistory);
      const similarDocs = await vectorStore
        .similaritySearch(sanitizedHistory, 3)
        .catch((err) => {
          console.log("WARNING: failed to get vector search results.", err);
        });
      return sanitizeSimilarDocs(similarDocs);
    }
  }

  private static sanitizeInput(input: string): string {
    // Reject or strip base64-encoded blobs (long base64 strings)
    const base64Pattern = /(?:[A-Za-z0-9+\/]{40,}={0,2})/g;
    if (base64Pattern.test(input)) {
      throw new Error("Input contains potentially malicious base64-encoded content.");
    }

    // Reject shell command patterns
    const shellCommandPattern = /(?:;|&&|\|\||`|\$\(|\bexec\b|\beval\b|\bsystem\b|\bpassthru\b|\bpopen\b|\bshell_exec\b|\bspawn\b|\bchild_process\b)/i;
    if (shellCommandPattern.test(input)) {
      throw new Error("Input contains potentially malicious shell command content.");
    }

    // Reject prompt injection patterns (common jailbreak / override phrases)
    const promptInjectionPattern = /(?:ignore\s+(all\s+)?previous\s+instructions|disregard\s+(all\s+)?previous|you\s+are\s+now|act\s+as\s+(?:an?\s+)?(?:evil|unrestricted|jailbroken|DAN)|forget\s+(all\s+)?previous|new\s+instructions?:|system\s*:\s*you|<\s*system\s*>|\[\s*system\s*\])/i;
    if (promptInjectionPattern.test(input)) {
      throw new Error("Input contains potentially malicious prompt injection content.");
    }

    // Reject leetspeak obfuscation patterns (e.g. 3x3cut3, 5h3ll)
    const leetspeakPattern = /(?:[3@][x×][3e][c¢][u][t7][3e]|[5$][h][3e][l1][l1]|[1i][g9][n][o0][r3][e3])/i;
    if (leetspeakPattern.test(input)) {
      throw new Error("Input contains potentially malicious leetspeak-obfuscated content.");
    }

    // Strip null bytes and non-printable control characters (except common whitespace)
    const sanitized = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

    return sanitized;
  }

  public static async getInstance(): Promise<MemoryManager> {
    if (!MemoryManager.instance) {
      MemoryManager.instance = new MemoryManager();
      await MemoryManager.instance.init();
    }
    return MemoryManager.instance;
  }

  private generateRedisCompanionKey(companionKey: CompanionKey): string {
    const sanitize = (value: string): string =>
      value.replace(/[^a-zA-Z0-9_\-]/g, "_");
    const safeName = sanitize(companionKey.companionName);
    const safeModel = sanitize(companionKey.modelName);
    const safeUser = sanitize(companionKey.userId);
    return `${safeName}-${safeModel}-${safeUser}`;
  }

  private sanitizeInput(input: string, maxLength: number = 4000): string {
    if (typeof input !== "string") {
      return "";
    }
    // Remove null bytes
    let sanitized = input.replace(/\0/g, "");
    // Trim whitespace
    sanitized = sanitized.trim();
    // Enforce maximum length
    if (sanitized.length > maxLength) {
      sanitized = sanitized.substring(0, maxLength);
    }
    // Remove common prompt-injection patterns (e.g. instruction overrides)
    sanitized = sanitized.replace(
      /ignore (all )?(previous|prior|above) instructions?/gi,
      "[removed]"
    );
    sanitized = sanitized.replace(
      /system\s*:/gi,
      "[removed]"
    );
    return sanitized;
  }

    public async writeToHistory(
    text: string,
    companionKey: CompanionKey,
    traceId: string = newTraceId()
  ) {
    if (!companionKey || typeof companionKey.userId == "undefined") {
      console.log("Companion key set incorrectly");
      return "";
    }

    const key = this.generateRedisCompanionKey(companionKey);
    const timestamp = new Date().toISOString();
    const inputHash = sha256(text);

    const result = await this.history.zadd(key, {
      score: Date.now(),
      member: text,
    });

    // Audit record — best-effort; failure is logged but does not suppress the write result.
    try {
      await persistAuditRecord(this.history, {
        traceId,
        timestamp,
        principal: companionKey.userId,
        operation: "writeToHistory",
        modelId: companionKey.modelName,
        modelVersion: "n/a",
        inputHash,
        outputSummary: `zadd result=${result}`,
        status: "success",
        extra: {
          companionName: companionKey.companionName,
          redisKey: key,
        },
      });
    } catch (auditErr) {
      console.error(
        `[AUDIT-FAILURE] writeToHistory audit record failed traceId=${traceId}`,
        auditErr
      );
    }

    console.log(
      `[AUDIT] writeToHistory traceId=${traceId} principal=${companionKey.userId} ` +
      `model=${companionKey.modelName} inputHash=${inputHash} ts=${timestamp}`
    );
    return result;
  }

    const key = this.generateRedisCompanionKey(companionKey);
    const sanitizedText = this.sanitizeInput(text);
    if (!sanitizedText) {
      console.log("Sanitized text is empty, skipping write.");
      return "";
    }
        const sanitizedText = MemoryManager.sanitizeInput(text);
    const result = await this.history.zadd(key, {
      score: Date.now(),
      member: sanitizedText,
    });

    return result;
  }

    public async readLatestHistory(
    companionKey: CompanionKey,
    traceId: string = newTraceId()
  ): Promise<string> {
    if (!companionKey || typeof companionKey.userId == "undefined") {
      console.log("Companion key set incorrectly");
      return "";
    }

    const key = this.generateRedisCompanionKey(companionKey);
    const timestamp = new Date().toISOString();

    let result = await this.history.zrange(key, 0, Date.now(), {
      byScore: true,
    });
    result = result.slice(-30).reverse();
    const recentChats = result.reverse().join("\n");

    const outputHash = sha256(recentChats);

    // Audit record — best-effort.
    try {
      await persistAuditRecord(this.history, {
        traceId,
        timestamp,
        principal: companionKey.userId,
        operation: "readLatestHistory",
        modelId: companionKey.modelName,
        modelVersion: "n/a",
        inputHash: sha256(key),
        outputSummary: `${result.length} entries retrieved; outputHash=${outputHash}`,
        status: "success",
        extra: {
          companionName: companionKey.companionName,
          redisKey: key,
          entriesReturned: result.length,
        },
      });
    } catch (auditErr) {
      console.error(
        `[AUDIT-FAILURE] readLatestHistory audit record failed traceId=${traceId}`,
        auditErr
      );
    }

    console.log(
      `[AUDIT] readLatestHistory traceId=${traceId} principal=${companionKey.userId} ` +
      `model=${companionKey.modelName} entries=${result.length} outputHash=${outputHash} ts=${timestamp}`
    );
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
      const sanitizedLine = MemoryManager.sanitizeInput(line);
      await this.history.zadd(key, { score: counter, member: sanitizedLine });
      counter += 1;
    }
      await this.history.zadd(key, { score: counter, member: sanitizedLine });
      counter += 1;
    }
  }
}

export default MemoryManager;
