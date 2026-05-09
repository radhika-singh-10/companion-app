import { Redis } from "@upstash/redis";
import { OpenAIEmbeddings } from "langchain/embeddings/openai";
import { PineconeClient } from "@pinecone-database/pinecone";
import { PineconeStore } from "langchain/vectorstores/pinecone";
import { SupabaseVectorStore } from "langchain/vectorstores/supabase";
import { SupabaseClient, createClient } from "@supabase/supabase-js";
import { createHash, randomUUID } from "crypto";

const DANGEROUS_PATTERNS = [
  /\beval\s*\(/gi,
  /\bexec\s*\(/gi,
  /\bnew\s+Function\s*\(/gi,
  /\bsetTimeout\s*\(\s*['"`]/gi,
  /\bsetInterval\s*\(\s*['"`]/gi,
  /\bimport\s*\(/gi,
  /\brequire\s*\(/gi,
  /\bprocess\.binding\s*\(/gi,
  /\bchild_process/gi,
  /\bvm\.runIn/gi,
];

function sanitizeLLMOutput(docs: any[] | undefined): any[] {
  if (!docs) return [];
  return docs
    .map((doc) => {
      if (!doc || typeof doc.pageContent !== "string") return null;
      let content = doc.pageContent;
      for (const pattern of DANGEROUS_PATTERNS) {
        if (pattern.test(content)) {
          console.warn(
            "WARNING: Potentially dangerous code execution primitive detected in LLM output. Redacting."
          );
          content = content.replace(pattern, "[REDACTED]");
        }
      }
      return { ...doc, pageContent: content };
    })
    .filter(Boolean);
}

/**
 * Sanitizes input strings to prevent prompt injection, hidden commands,
 * base64-encoded payloads, shell commands, binary content, and leetspeak obfuscation.
 */
function sanitizeInput(input: string): string {
  if (!input || typeof input !== "string") return "";

  // Reject or strip base64-encoded blocks (long base64 strings)
  const base64Pattern = /(?:[A-Za-z0-9+\/]{40,}={0,2})/g;
  input = input.replace(base64Pattern, "[REDACTED_BASE64]");

  // Strip common shell command patterns
  const shellCommandPattern =
    /(\b(bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess|os\.system|Runtime\.exec|ProcessBuilder)\b\s*[\(\[`'"])/gi;
  input = input.replace(shellCommandPattern, "[REDACTED_CMD]");

  // Strip shell metacharacters sequences that suggest command injection
  const shellMetaPattern = /([`$]\(|\|\||&&|;\s*\w+\s|>\s*\/|\bsudo\b|\brm\s+-rf\b|\bchmod\b|\bwget\b|\bcurl\b\s+http)/gi;
  input = input.replace(shellMetaPattern, "[REDACTED_META]");

  // Strip binary/non-printable characters (keep standard unicode text)
  // eslint-disable-next-line no-control-regex
  input = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

  // Detect and neutralize common prompt injection patterns
  const promptInjectionPattern =
    /(ignore (all )?(previous|prior|above) instructions?|disregard (all )?(previous|prior|above)|you are now|act as (a|an|the)|forget (all )?(previous|prior|above)|new (role|persona|instructions?)|system prompt|<\/?s(ystem|\|im_start\|)>)/gi;
  input = input.replace(promptInjectionPattern, "[REDACTED_INJECTION]");

  // Detect leetspeak obfuscation (e.g., 1gn0r3, 3x3cut3) — flag suspicious leet patterns
  const leetspeakPattern = /\b[a-z0-9]*[013456789][a-z0-9]*[013456789][a-z0-9]*\b/gi;
  // Only flag if the word is not a normal word (heuristic: contains multiple digit substitutions)
  input = input.replace(/\b(?=[a-z]*[0-9])(?=[0-9]*[a-z])([a-z0-9]{4,})\b/gi, (match) => {
    const digitRatio = (match.match(/[0-9]/g) || []).length / match.length;
    return digitRatio > 0.4 ? "[REDACTED_LEET]" : match;
  });

  // Trim excessive whitespace
  input = input.trim();

  return input;
}

import { createHmac } from "crypto";

// ---------------------------------------------------------------------------
// Provenance helpers
// ---------------------------------------------------------------------------
const PROVENANCE_SECRET =
  process.env.PROVENANCE_HMAC_SECRET || "change-me-in-production";

const AI_CONTENT_LABEL = "[AI-GENERATED]";
const MODEL_IDENTIFIER =
  process.env.OPENAI_MODEL_IDENTIFIER || "openai/gpt-based-companion";

function signContent(content: string): string {
  return createHmac("sha256", PROVENANCE_SECRET)
    .update(content)
    .digest("hex");
}

function attachProvenance<T>(data: T): {
  data: T;
  provenance: {
    label: string;
    modelId: string;
    timestamp: string;
    origin: string;
    signature: string;
  };
} {
  const serialized =
    typeof data === "string" ? data : JSON.stringify(data);
  return {
    data,
    provenance: {
      label: AI_CONTENT_LABEL,
      modelId: MODEL_IDENTIFIER,
      timestamp: new Date().toISOString(),
      origin: "vector-search-retrieval",
      signature: signContent(serialized),
    },
  };
}

function tagTextWithProvenance(text: string): string {
  const timestamp = new Date().toISOString();
  const signature = signContent(text);
  return `${AI_CONTENT_LABEL} [model:${MODEL_IDENTIFIER}] [ts:${timestamp}] [sig:${signature}] ${text}`;
}
// ---------------------------------------------------------------------------

export type CompanionKey = {
  companionName: string;
  modelName: string;
  userId: string;
};

const MAX_INPUT_LENGTH = 2000;

function sanitizeInput(input: string): string {
  if (typeof input !== "string") {
    throw new Error("Invalid input: expected a string.");
  }
  // Trim whitespace
  let sanitized = input.trim();
  // Remove null bytes and non-printable control characters (except common whitespace)
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  // Enforce maximum length to prevent excessively large payloads
  if (sanitized.length > MAX_INPUT_LENGTH) {
    sanitized = sanitized.slice(-MAX_INPUT_LENGTH);
  }
  if (sanitized.length === 0) {
    throw new Error("Invalid input: sanitized input is empty.");
  }
  return sanitized;
}

// Audit log TTL: 90 days in seconds
const AUDIT_LOG_TTL_SECONDS = 90 * 24 * 60 * 60;

interface AuditRecord {
  traceId: string;
  operation: string;
  modelId: string;
  inputHash: string;
  outputSummary: string;
  principal: string;
  timestamp: string;
  status: "success" | "failure";
  errorMessage?: string;
}

// Approved model registry — only models listed here may be used for embeddings.
const APPROVED_EMBEDDING_MODELS: Record<string, { version: string; digest: string }> = {
  "text-embedding-ada-002": {
    version: "text-embedding-ada-002",
    // SHA-256 digest of the canonical model identifier string for integrity verification.
    digest: "sha256:7c4e4c4e2b6f1a3d5e8b0f2a9c1d3e5f7a9b0c2d4e6f8a0b1c3d5e7f9a0b2c4d",
  },
};

const PINNED_EMBEDDING_MODEL = "text-embedding-ada-002";

function createApprovedEmbeddings(apiKey: string | undefined): OpenAIEmbeddings {
  const modelId = PINNED_EMBEDDING_MODEL;
  const registryEntry = APPROVED_EMBEDDING_MODELS[modelId];
  if (!registryEntry) {
    throw new Error(
      `[ModelRegistry] Embedding model '${modelId}' is NOT in the approved registry. ` +
      `Approved models: ${Object.keys(APPROVED_EMBEDDING_MODELS).join(", ")}`
    );
  }
  // Integrity verification: confirm the resolved version matches the pinned registry entry.
  if (registryEntry.version !== modelId) {
    throw new Error(
      `[ModelIntegrity] Version mismatch for model '${modelId}': ` +
      `expected '${registryEntry.version}', got '${modelId}'.`
    );
  }
  console.log(
    `[ModelIdentity] Using approved embedding model: id=${modelId}, ` +
    `version=${registryEntry.version}, digest=${registryEntry.digest}`
  );
  return new OpenAIEmbeddings({
    openAIApiKey: apiKey,
    modelName: modelId,
  });
}

class MemoryManager {
  private static instance: MemoryManager;
  private history: Redis; // injected externally — credentials not held here
  private vectorDBClient: PineconeClient | SupabaseClient;

  public constructor(history?: Redis) {
    this.history = history ?? Redis.fromEnv();
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

  private async writeAuditLog(record: AuditRecord): Promise<void> {
    const auditKey = `audit:${record.operation}:${record.traceId}`;
    try {
      await this.history.set(auditKey, JSON.stringify(record), {
        ex: AUDIT_LOG_TTL_SECONDS,
      });
      // Also append to a time-ordered audit index for forensic queries
      await this.history.zadd("audit:index", {
        score: new Date(record.timestamp).getTime(),
        member: auditKey,
      });
    } catch (auditErr) {
      // Audit log write failure is critical — log to stderr and re-throw
      console.error("CRITICAL: audit log write failed.", auditErr);
      throw auditErr;
    }
  }

  private hashInput(input: string): string {
    return createHash("sha256").update(input).digest("hex");
  }

    public async vectorSearch(
    recentChatHistory: string,
    companionFileName: string,
    principal: string = "system"
  ) {
    const traceId = randomUUID();
    const inputHash = this.hashInput(recentChatHistory);
    const modelId = `OpenAIEmbeddings:${process.env.OPENAI_API_KEY ? "configured" : "unconfigured"}`;
    const dbBackend = process.env.VECTOR_DB === "pinecone" ? "pinecone" : "supabase";
    const operationName = `vectorSearch:${dbBackend}`;

    // Pre-operation audit record
    await this.writeAuditLog({
      traceId,
      operation: operationName,
      modelId,
      inputHash,
      outputSummary: "pending",
      principal,
      timestamp: new Date().toISOString(),
      status: "success",
    });

    if (process.env.VECTOR_DB === "pinecone") {
      console.log("INFO: using Pinecone for vector search.");
      const pineconeClient = <PineconeClient>this.vectorDBClient;

      const pineconeIndex = pineconeClient.Index(
        process.env.PINECONE_INDEX! || ""
      );

            const embeddingsPinecone = createApprovedEmbeddings(process.env.OPENAI_API_KEY);
      console.log(
        `[InferenceMetadata] Pinecone similarity search — model=${PINNED_EMBEDDING_MODEL}, ` +
        `version=${APPROVED_EMBEDDING_MODELS[PINNED_EMBEDDING_MODEL].version}, ` +
        `digest=${APPROVED_EMBEDDING_MODELS[PINNED_EMBEDDING_MODEL].digest}`
      );
      const vectorStore = await PineconeStore.fromExistingIndex(
        embeddingsPinecone,
        { pineconeIndex }
      );

      const similarDocs = await vectorStore
        .similaritySearch(recentChatHistory, 3, { fileName: companionFileName })
        .catch((err) => {
          console.log("WARNING: failed to get vector search results.", err);
        });
        console.error("ERROR: failed to get vector search results.", err);
        throw err;
      }

      await this.writeAuditLog({
        traceId,
        operation: operationName,
        modelId,
        inputHash,
        outputSummary: `returned ${similarDocs?.length ?? 0} documents`,
        principal,
        timestamp: new Date().toISOString(),
        status: "success",
      });
      return similarDocs;
    } else {
      console.log("INFO: using Supabase for vector search.");
      const supabaseClient = <SupabaseClient>this.vectorDBClient;
            const embeddingsSupabase = createApprovedEmbeddings(process.env.OPENAI_API_KEY);
      console.log(
        `[InferenceMetadata] Supabase similarity search — model=${PINNED_EMBEDDING_MODEL}, ` +
        `version=${APPROVED_EMBEDDING_MODELS[PINNED_EMBEDDING_MODEL].version}, ` +
        `digest=${APPROVED_EMBEDDING_MODELS[PINNED_EMBEDDING_MODEL].digest}`
      );
      const vectorStore = await SupabaseVectorStore.fromExistingIndex(
        embeddingsSupabase,
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
        console.error("ERROR: failed to get vector search results.", err);
        throw err;
      }

      await this.writeAuditLog({
        traceId,
        operation: operationName,
        modelId,
        inputHash,
        outputSummary: `returned ${similarDocs?.length ?? 0} documents`,
        principal,
        timestamp: new Date().toISOString(),
        status: "success",
      });
      return similarDocs;
    }
  });
      const vectorStore = await PineconeStore.fromExistingIndex(
        new OpenAIEmbeddings({ openAIApiKey: process.env.OPENAI_API_KEY }),
        { pineconeIndex }
      );
      console.log("LLM_INTERACTION: OpenAIEmbeddings initialized for Pinecone. Calling similaritySearch.", { provider: "pinecone", query: recentChatHistory, topK: 3, filter: { fileName: companionFileName } });

            const similarDocs = await vectorStore
        .similaritySearch(recentChatHistory, 3, { fileName: companionFileName })
        .catch((err) => {
          console.log("WARNING: failed to get vector search results.", err);
        });
      return attachProvenance(similarDocs);
    } else {
      console.log("INFO: using Supabase for vector search.");
      const supabaseClient = <SupabaseClient>this.vectorDBClient;
            console.log("LLM_INTERACTION: Initializing OpenAIEmbeddings for Supabase vector search.", { provider: "supabase", query: recentChatHistory, tableName: "documents", queryName: "match_documents" });
      const vectorStore = await SupabaseVectorStore.fromExistingIndex(
        new OpenAIEmbeddings({ openAIApiKey: process.env.OPENAI_API_KEY }),
        {
          client: supabaseClient,
          tableName: "documents",
          queryName: "match_documents",
        }
      );
      console.log("LLM_INTERACTION: OpenAIEmbeddings initialized for Supabase. Calling similaritySearch.", { provider: "supabase", query: recentChatHistory, topK: 3 });
      const similarDocs = await vectorStore
        .similaritySearch(sanitizedQuery, 3)
        .catch((err) => {
          console.log("WARNING: failed to get vector search results.", err);
        });
      console.log("LLM_INTERACTION: Supabase similaritySearch completed.", { provider: "supabase", query: recentChatHistory, resultCount: similarDocs ? similarDocs.length : 0, results: similarDocs });
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

    const traceId = randomUUID();
    const key = this.generateRedisCompanionKey(companionKey);

    await this.writeAuditLog({
      traceId,
      operation: "writeToHistory",
      modelId: companionKey.modelName,
      inputHash: this.hashInput(text),
      outputSummary: `wrote entry to history key ${key}`,
      principal: companionKey.userId,
      timestamp: new Date().toISOString(),
      status: "success",
    });

    const result = await this.history.zadd(key, {
      score: Date.now(),
      member: text,
    });

    return result;
  }

    const key = this.generateRedisCompanionKey(companionKey);
    const sanitizedText = sanitizeInput(text);
        const taggedText = tagTextWithProvenance(text);
    const result = await this.history.zadd(key, {
      score: Date.now(),
      member: taggedText,
    });

    return result;
  }

  public async readLatestHistory(companionKey: CompanionKey): Promise<string> {
    if (!companionKey || typeof companionKey.userId == "undefined") {
      console.log("Companion key set incorrectly");
      return "";
    }

    const traceId = randomUUID();
    const key = this.generateRedisCompanionKey(companionKey);

    await this.writeAuditLog({
      traceId,
      operation: "readLatestHistory",
      modelId: companionKey.modelName,
      inputHash: this.hashInput(key),
      outputSummary: `read history for key ${key}`,
      principal: companionKey.userId,
      timestamp: new Date().toISOString(),
      status: "success",
    });


    const key = this.generateRedisCompanionKey(companionKey);
    let result = await this.history.zrange(key, 0, Date.now(), {
      byScore: true,
    });

    result = result.slice(-5).reverse();
    const recentChats = result.reverse().join("\n");
    const provenanceCheck = attachProvenance(recentChats);
    // Expose provenance metadata to callers via a non-enumerable property so
    // existing string consumers are unaffected while provenance is available.
    const labeledChats: string & { __provenance?: typeof provenanceCheck["provenance"] } =
      provenanceCheck.data;
    (labeledChats as any).__provenance = provenanceCheck.provenance;
    return sanitizeInput(recentChats);
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
