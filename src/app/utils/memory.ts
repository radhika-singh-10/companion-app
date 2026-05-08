import { Redis } from "@upstash/redis";
import { HuggingFaceInferenceEmbeddings } from "langchain/embeddings/hf";
import { PineconeClient } from "@pinecone-database/pinecone";
import { PineconeStore } from "langchain/vectorstores/pinecone";
import { SupabaseVectorStore } from "langchain/vectorstores/supabase";
import { SupabaseClient, createClient } from "@supabase/supabase-js";
import { createHmac, randomBytes } from "crypto";

export type CompanionKey = {
  companionName: string;
  modelName: string;
  userId: string;
};

const MAX_INPUT_LENGTH = 8192;
const DYNAMIC_CODE_PATTERNS = [
  /\beval\s*\(/i,
  /\bexec\s*\(/i,
  /\bnew\s+Function\s*\(/i,
  /\bsetTimeout\s*\(\s*["'`]/i,
  /\bsetInterval\s*\(\s*["'`]/i,
  /\bimportScripts\s*\(/i,
];

const MALICIOUS_PATTERNS = [
  /^[A-Za-z0-9+/=]{20,}={0,2}$/,
  /(\b(rm|del|format|shutdown|reboot|kill|wget|curl|bash|sh|cmd|powershell)\b)/i,
  /[01@3!$7]/,
  /\[\[.*?\]\]/,
  /<\|.*?\|>/,
  /###\s*(instruction|system|prompt)/i,
  /ignore\s+(previous|above|all)\s+instructions/i,
];

function sanitizeInput(input: string): string {
  if (typeof input !== "string" || input.trim().length === 0) {
    throw new Error("Invalid input: must be a non-empty string.");
  }
  if (input.length > MAX_INPUT_LENGTH) {
    throw new Error(
      `Invalid input: exceeds maximum length of ${MAX_INPUT_LENGTH}.`
    );
  }
  // Strip null bytes and control characters (except newline/tab)
  const sanitized = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  return sanitized;
}

function checkForMaliciousPatterns(input: string): string {
  for (const pattern of MALICIOUS_PATTERNS) {
    if (pattern.test(input)) {
      throw new Error("Input rejected: potentially malicious content detected.");
    }
  }
  return input;
}

function sanitizeKeyComponent(component: string): string {
  return component.replace(/[^a-zA-Z0-9\-_]/g, "");
}

function sanitizeLLMOutput(docs: any[] | undefined): any[] | undefined {
  if (!docs) return docs;
  return docs.filter((doc) => {
    if (!doc || typeof doc.pageContent !== "string") return false;
    for (const pattern of DYNAMIC_CODE_PATTERNS) {
      if (pattern.test(doc.pageContent)) {
        console.log("WARNING: LLM output rejected due to dynamic code execution primitive.");
        return false;
      }
    }
    return true;
  });
}

class MemoryManager {
  private static instance: MemoryManager;
  private vectorDBClient: PineconeClient | SupabaseClient;

  private static getRedis(): Redis {
    return Redis.fromEnv();
  }

  public constructor() {
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
    let sanitizedHistory: string;
    try {
      sanitizedHistory = sanitizeInput(recentChatHistory);
      checkForMaliciousPatterns(sanitizedHistory);
    } catch (e) {
      console.log("WARNING: vectorSearch input rejected.");
      return [];
    }

    if (process.env.VECTOR_DB === "pinecone") {
      console.log("INFO: using Pinecone for vector search.");
      const pineconeClient = <PineconeClient>this.vectorDBClient;

      const pineconeIndex = pineconeClient.Index(
        process.env.PINECONE_INDEX! || ""
      );

      const vectorStore = await PineconeStore.fromExistingIndex(
        new HuggingFaceInferenceEmbeddings({
          apiKey: process.env.HUGGINGFACEHUB_API_KEY,
        }),
        { pineconeIndex }
      );

      const similarDocs = await vectorStore
        .similaritySearch(sanitizedHistory, 3, { fileName: companionFileName })
        .catch((err) => {
          console.log("WARNING: failed to get vector search results.");
        });
      return sanitizeLLMOutput(similarDocs as any[] | undefined);
    } else {
      console.log("INFO: using Supabase for vector search.");
      const supabaseClient = <SupabaseClient>this.vectorDBClient;
      const vectorStore = await SupabaseVectorStore.fromExistingIndex(
        new HuggingFaceInferenceEmbeddings({
          apiKey: process.env.HUGGINGFACEHUB_API_KEY,
        }),
        {
          client: supabaseClient,
          tableName: "documents",
          queryName: "match_documents",
        }
      );
      const similarDocs = await vectorStore
        .similaritySearch(sanitizedHistory, 3)
        .catch((err) => {
          console.log("WARNING: failed to get vector search results.");
        });
      return sanitizeLLMOutput(similarDocs as any[] | undefined);
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
    const secret = process.env.REDIS_KEY_SECRET || "default-secret";
    const safeName = sanitizeKeyComponent(companionKey.companionName);
    const safeModel = sanitizeKeyComponent(companionKey.modelName);
    const safeUser = sanitizeKeyComponent(companionKey.userId);
    const raw = `${safeName}-${safeModel}-${safeUser}`;
    const hmac = createHmac("sha256", secret).update(raw).digest("hex");
    return hmac;
  }

  public async writeToHistory(text: string, companionKey: CompanionKey) {
    if (
      !companionKey ||
      typeof companionKey.userId !== "string" ||
      companionKey.userId.trim().length === 0 ||
      typeof companionKey.companionName !== "string" ||
      companionKey.companionName.trim().length === 0 ||
      typeof companionKey.modelName !== "string" ||
      companionKey.modelName.trim().length === 0
    ) {
      console.log("Companion key set incorrectly");
      return "";
    }

    let sanitizedText: string;
    try {
      sanitizedText = sanitizeInput(text);
    } catch (e) {
      console.log("WARNING: writeToHistory input rejected.");
      return "";
    }

    const key = this.generateRedisCompanionKey(companionKey);
    const result = await MemoryManager.getRedis().zadd(key, {
      score: Date.now(),
      member: sanitizedText,
    });

    return result;
  }

  public async readLatestHistory(companionKey: CompanionKey): Promise<string> {
    if (
      !companionKey ||
      typeof companionKey.userId !== "string" ||
      companionKey.userId.trim().length === 0 ||
      typeof companionKey.companionName !== "string" ||
      companionKey.companionName.trim().length === 0 ||
      typeof companionKey.modelName !== "string" ||
      companionKey.modelName.trim().length === 0
    ) {
      console.log("Companion key set incorrectly");
      return "";
    }

    const key = this.generateRedisCompanionKey(companionKey);
    let result = await MemoryManager.getRedis().zrange(key, 0, Date.now(), {
      byScore: true,
    });

    result = result.slice(-30).reverse();
    const recentChats = result.reverse().join("\n");

    try {
      checkForMaliciousPatterns(recentChats);
    } catch (e) {
      console.log("WARNING: readLatestHistory output rejected due to malicious content.");
      return "";
    }

    return recentChats;
  }

  public async seedChatHistory(
    seedContent: String,
    delimiter: string = "\n",
    companionKey: CompanionKey
  ) {
    let sanitizedSeed: string;
    try {
      sanitizedSeed = sanitizeInput(seedContent as string);
      checkForMaliciousPatterns(sanitizedSeed);
    } catch (e) {
      console.log("WARNING: seedChatHistory input rejected.");
      return;
    }

    const key = this.generateRedisCompanionKey(companionKey);
    if (await MemoryManager.getRedis().exists(key)) {
      console.log("User already has chat history");
      return;
    }

    const content = sanitizedSeed.split(delimiter);
    for (const line of content) {
      const score = parseInt(randomBytes(4).toString("hex"), 16);
      await MemoryManager.getRedis().zadd(key, { score, member: line });
    }
  }
}

export default MemoryManager;