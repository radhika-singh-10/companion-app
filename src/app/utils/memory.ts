import { Redis } from "@upstash/redis";
import { OpenAIEmbeddings } from "langchain/embeddings/openai";

// Approved model registry entry — must match the organisation's approved model list.
// Version is pinned; any change here requires a registry review and approval.
const APPROVED_EMBEDDING_MODEL = "text-embedding-ada-002" as const;
const APPROVED_EMBEDDING_MODEL_VERSION = "002" as const; // semver patch pinned
// Integrity note: OpenAI does not expose per-request model digests via the
// LangChain SDK. The pinned model name is the strongest version-pinning
// mechanism available at this layer. Rotate this constant when the registry
// approves a new model version.
import { PineconeClient } from "@pinecone-database/pinecone";
import { PineconeStore } from "langchain/vectorstores/pinecone";
import { SupabaseVectorStore } from "langchain/vectorstores/supabase";
import { SupabaseClient, createClient } from "@supabase/supabase-js";
import { createHash, randomUUID } from "crypto";

const DANGEROUS_PATTERNS = [
  /\beval\s*\(/i,
  /\bexec\s*\(/i,
  /\bsubprocess\b/i,
  /\bFunction\s*\(/i,
  /\bsetTimeout\s*\(/i,
  /\bsetInterval\s*\(/i,
  /\brequire\s*\(/i,
  /\bimport\s*\(/i,
  /\b__import__\s*\(/i,
];

function sanitizeDocs(docs: any): any[] {
  if (!Array.isArray(docs)) {
    console.log("WARNING: similarDocs is not an array, returning empty.");
    return [];
  }
  return docs.filter((doc) => {
    if (!doc || typeof doc.pageContent !== "string") {
      console.log("WARNING: dropping doc with missing or non-string pageContent.");
      return false;
    }
    for (const pattern of DANGEROUS_PATTERNS) {
      if (pattern.test(doc.pageContent)) {
        console.log(
          `WARNING: dropping doc containing dangerous pattern (${pattern}) in pageContent.`
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

// ---------------------------------------------------------------------------
// Provenance helpers – satisfy synthetic-content labeling & watermarking policy
// ---------------------------------------------------------------------------
const AI_CONTENT_LABEL = "AI_GENERATED" as const;
const EMBEDDING_MODEL_ID = "openai/text-embedding-ada-002";

function attachProvenance(docs: any[] | void): any[] | void {
  if (!docs) return docs;
  const timestamp = new Date().toISOString();
  return docs.map((doc) => ({
    ...doc,
    metadata: {
      ...(doc.metadata ?? {}),
      // Provenance fields
      contentOrigin: AI_CONTENT_LABEL,
      syntheticLabel: "This content was retrieved via AI-generated vector embeddings.",
      embeddingModel: EMBEDDING_MODEL_ID,
      retrievedAt: timestamp,
      watermark: `AI-GENERATED|${EMBEDDING_MODEL_ID}|${timestamp}`,
    },
  }));
}
// ---------------------------------------------------------------------------

export type CompanionKey = {
  companionName: string;
  modelName: string;
  userId: string;
};

/**
 * Sanitizes input before passing to vector search to prevent prompt injection.
 * Checks for: shell commands, base64-encoded blobs, binary/non-printable chars,
 * hidden prompt overrides, and common leetspeak/obfuscation patterns.
 */
function sanitizeSearchInput(input: string): string {
  if (!input || typeof input !== "string") {
    throw new Error("Invalid input: input must be a non-empty string.");
  }

  // Reject if input contains non-printable / binary characters
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(input)) {
    throw new Error("Suspicious input detected: binary or non-printable characters.");
  }

  // Reject if input contains base64-encoded blobs (long runs of base64 chars)
  if (/(?:[A-Za-z0-9+\/]{40,}={0,2})/.test(input)) {
    throw new Error("Suspicious input detected: possible base64-encoded content.");
  }

  // Reject common shell command patterns
  const shellPatterns = [
    /\b(bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess)\s*[\(\[\{`]/i,
    /[;&|`$]\s*\w+/,
    /\.\.\/|\.\.\\/,
    /<\s*script/i,
    /\bimport\s+os\b/i,
    /\brm\s+-rf\b/i,
    /\bcurl\s+/i,
    /\bwget\s+/i,
    /\bnc\s+/i,
    /\bchmod\s+/i,
    /\bchown\s+/i,
  ];
  for (const pattern of shellPatterns) {
    if (pattern.test(input)) {
      throw new Error("Suspicious input detected: possible shell command.");
    }
  }

  // Reject hidden prompt injection attempts (common override phrases)
  const promptInjectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /disregard\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /forget\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /you\s+are\s+now\s+(a|an)\s+/i,
    /act\s+as\s+(a|an)\s+/i,
    /new\s+instructions?:/i,
    /system\s*:/i,
    /\[INST\]/i,
    /###\s*instruction/i,
  ];
  for (const pattern of promptInjectionPatterns) {
    if (pattern.test(input)) {
      throw new Error("Suspicious input detected: possible prompt injection.");
    }
  }

  // Reject leetspeak obfuscation (excessive digit substitution for letters)
  const leetspeakPattern = /(?:[a-z]*[013456789][a-z]*){5,}/i;
  if (leetspeakPattern.test(input.replace(/\s/g, ""))) {
    throw new Error("Suspicious input detected: possible leetspeak obfuscation.");
  }

  // Truncate to a safe maximum length
  const MAX_LENGTH = 4000;
  return input.slice(0, MAX_LENGTH);
}

const MAX_DOC_CONTENT_LENGTH = 1000;

function minimiseDocs(
  docs: Array<{ pageContent: string; metadata: Record<string, unknown> }> | undefined
): Array<{ pageContent: string }> {
  if (!docs) return [];
  return docs.map((doc) => ({
    pageContent: doc.pageContent.slice(0, MAX_DOC_CONTENT_LENGTH),
  }));
}

// ---------------------------------------------------------------------------
// Audit record shape written to Redis for every AI-driven operation.
// ---------------------------------------------------------------------------
interface AuditRecord {
  traceId: string;        // correlation ID linking all steps of one request
  timestamp: string;      // ISO-8601 UTC
  principal: string;      // userId or 'system'
  modelId: string;        // e.g. 'openai/text-embedding-ada-002'
  operation: string;      // 'vectorSearch' | 'writeToHistory' | 'readLatestHistory'
  inputHash: string;      // SHA-256 of the raw input
  outputSummary: string;  // truncated / count of results
  status: 'success' | 'error';
  errorMessage?: string;
}

const AUDIT_STREAM_KEY = "ai:audit:log";
const MODEL_ID = "openai/text-embedding-ada-002"; // single source of truth for the embedding model

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function getRedisClient(): Redis {
  return Redis.fromEnv();
}

class MemoryManager {
  private static instance: MemoryManager;
  private vectorDBClient: PineconeClient | SupabaseClient;

  public constructor() {
    if (process.env.VECTOR_DB === "pinecone") {
      this.vectorDBClient = new PineconeClient();
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
      const pineconeApiKey = process.env.PINECONE_API_KEY;
      const pineconeEnvironment = process.env.PINECONE_ENVIRONMENT;
      if (!pineconeApiKey || pineconeApiKey.trim() === "") {
        throw new Error("Missing required environment variable: PINECONE_API_KEY");
      }
      if (!pineconeEnvironment || pineconeEnvironment.trim() === "") {
        throw new Error("Missing required environment variable: PINECONE_ENVIRONMENT");
      }
      await this.vectorDBClient.init({
        apiKey: pineconeApiKey,
        environment: pineconeEnvironment,
      });
    }
  }

    // Internal helper: persist a structured audit record to Redis.
  private async logAuditRecord(record: AuditRecord): Promise<void> {
    try {
      await this.history.zadd(AUDIT_STREAM_KEY, {
        score: Date.now(),
        member: JSON.stringify(record),
      });
    } catch (auditErr) {
      // Audit failures must never be silent — surface them as errors.
      console.error("AUDIT ERROR: failed to write audit record.", auditErr);
      throw new Error(`Audit logging failure: ${auditErr}`);
    }
  }

  public async vectorSearch(
    recentChatHistory: string,
    companionFileName: string,
    principal: string = "system",
    traceId: string = randomUUID()
  ) {
    const inputHash = sha256(recentChatHistory + companionFileName);
    const baseAudit: Omit<AuditRecord, "status" | "outputSummary" | "errorMessage"> = {
      traceId,
      timestamp: new Date().toISOString(),
      principal,
      modelId: MODEL_ID,
      operation: "vectorSearch",
      inputHash,
    };

    if (process.env.VECTOR_DB === "pinecone") {
      console.log("INFO: using Pinecone for vector search.", { traceId });
      const pineconeClient = <PineconeClient>this.vectorDBClient;

      const pineconeIndex = pineconeClient.Index(
        process.env.PINECONE_INDEX! || ""
      );

            console.log(
        `INFO: model identity — name=${APPROVED_EMBEDDING_MODEL} version=${APPROVED_EMBEDDING_MODEL_VERSION} registry=approved`
      );
      const vectorStore = await PineconeStore.fromExistingIndex(
        new OpenAIEmbeddings({
          openAIApiKey: process.env.OPENAI_API_KEY,
          modelName: APPROVED_EMBEDDING_MODEL,
        }),
        { pineconeIndex }
      );
          return key;
        })() }),
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
        await this.logAuditRecord({
          ...baseAudit,
          status: "error",
          outputSummary: "",
          errorMessage: String(err),
        });
        console.error("ERROR: failed to get Pinecone vector search results.", { traceId, err });
        throw err; // fail closed — do not swallow
      }

      await this.logAuditRecord({
        ...baseAudit,
        status: "success",
        outputSummary: `resultCount:${similarDocs?.length ?? 0}`,
      });
      return similarDocs;
    } else {
      console.log("INFO: using Supabase for vector search.", { traceId });
      const supabaseClient = <SupabaseClient>this.vectorDBClient;
            console.log(
        `INFO: model identity — name=${APPROVED_EMBEDDING_MODEL} version=${APPROVED_EMBEDDING_MODEL_VERSION} registry=approved`
      );
      const vectorStore = await SupabaseVectorStore.fromExistingIndex(
        new OpenAIEmbeddings({
          openAIApiKey: process.env.OPENAI_API_KEY,
          modelName: APPROVED_EMBEDDING_MODEL,
        }),
        {
          client: supabaseClient,
          tableName: "documents",
          queryName: "match_documents",
        }
      );
          return key;
        })() }),
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
        await this.logAuditRecord({
          ...baseAudit,
          status: "error",
          outputSummary: "",
          errorMessage: String(err),
        });
        console.error("ERROR: failed to get Supabase vector search results.", { traceId, err });
        throw err; // fail closed — do not swallow
      }

      await this.logAuditRecord({
        ...baseAudit,
        status: "success",
        outputSummary: `resultCount:${similarDocs?.length ?? 0}`,
      });
      return similarDocs;
    }
  }),
        { pineconeIndex }
      );

      const rawDocs = await vectorStore
        .similaritySearch(recentChatHistory, 3, { fileName: companionFileName })
        .catch((err) => {
          console.log("WARNING: failed to get vector search results.", err);
        });
      const similarDocs = sanitizeDocs(rawDocs);
      return similarDocs;
    } else {
      // Vector search backend: Supabase
      const supabaseClient = <SupabaseClient>this.vectorDBClient;
            console.log("LLM interaction: calling OpenAIEmbeddings for Supabase vector search.");
      const vectorStore = await SupabaseVectorStore.fromExistingIndex(
        new OpenAIEmbeddings({ openAIApiKey: process.env.OPENAI_API_KEY }),
        { apiKey: process.env.HUGGINGFACEHUB_API_KEY }),
          {
            client: supabaseClient,
          tableName: "documents",
          queryName: "match_documents",
        }
      );
      const rawDocs = await vectorStore
        .similaritySearch(recentChatHistory, 3)
        .catch((err) => {
          console.log("WARNING: failed to get vector search results.", err);
        });
      const similarDocs = sanitizeDocs(rawDocs);
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

  private sanitizeKeySegment(segment: string): string {
    // Allow only alphanumeric characters, hyphens, and underscores to prevent key collision/IDOR
    return segment.replace(/[^a-zA-Z0-9_-]/g, "_");
  }

  private generateRedisCompanionKey(companionKey: CompanionKey): string {
    const safeName = this.sanitizeKeySegment(companionKey.companionName);
    const safeModel = this.sanitizeKeySegment(companionKey.modelName);
    const safeUser = this.sanitizeKeySegment(companionKey.userId);
    return `${safeUser}:${safeName}:${safeModel}`;
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

    const auditBase: Omit<AuditRecord, "status" | "outputSummary" | "errorMessage"> = {
      traceId,
      timestamp: new Date().toISOString(),
      principal: companionKey.userId,
      modelId: companionKey.modelName || MODEL_ID,
      operation: "writeToHistory",
      inputHash: sha256(text),
    };

    const key = this.generateRedisCompanionKey(companionKey);
    let result;
    try {
      result = await this.history.zadd(key, {
        score: Date.now(),
        member: text,
      });
    } catch (err) {
      await this.logAuditRecord({
        ...auditBase,
        status: "error",
        outputSummary: "",
        errorMessage: String(err),
      });
      throw err;
    }

    await this.logAuditRecord({
      ...auditBase,
      status: "success",
      outputSummary: `redisResult:${result}`,
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

    const auditBase: Omit<AuditRecord, "status" | "outputSummary" | "errorMessage"> = {
      traceId,
      timestamp: new Date().toISOString(),
      principal: companionKey.userId,
      modelId: companionKey.modelName || MODEL_ID,
      operation: "readLatestHistory",
      inputHash: sha256(JSON.stringify(companionKey)),
    };

    const key = this.generateRedisCompanionKey(companionKey);
    let result = await this.history.zrange(key, 0, Date.now(), {
      byScore: true,
    });

    result = result.slice(-30).reverse();
    const recentChats = result.reverse().join("\n");
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
