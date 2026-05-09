// Major ref: https://js.langchain.com/docs/modules/indexes/vector_stores/integrations/pinecone
// External systems credentialed by this script (policy limit: 3 max):
//   1. Pinecone  — PINECONE_API_KEY, PINECONE_ENVIRONMENT, PINECONE_INDEX
//   2. OpenAI    — OPENAI_API_KEY
// Total distinct external systems: 2 (within policy limit)
import { PineconeClient } from "@pinecone-database/pinecone";
import dotenv from "dotenv";
import { Document } from "langchain/document";
import { OpenAIEmbeddings } from "langchain/embeddings/openai";
import { PineconeStore } from "langchain/vectorstores/pinecone";
import { CharacterTextSplitter } from "langchain/text_splitter";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import os from "os";

// Audit log configuration
const AUDIT_LOG_PATH = process.env.AUDIT_LOG_PATH || "audit_log.ndjson";
const AUDIT_LOG_RETENTION_DAYS = parseInt(process.env.AUDIT_LOG_RETENTION_DAYS || "365", 10);

function writeAuditRecord(record) {
  try {
    const line = JSON.stringify(record) + "\n";
    fs.appendFileSync(AUDIT_LOG_PATH, line, { encoding: "utf8", flag: "a" });
  } catch (loggingError) {
    // Logging failure must not silently pass — write to stderr and abort
    process.stderr.write(
      `[AUDIT FAILURE] Unable to write audit record: ${loggingError.message}\n` +
      `Intended record: ${JSON.stringify(record)}\n`
    );
    process.exit(1); // Halt execution to preserve forensic integrity
  }
}

function generateTraceId() {
  return crypto.randomUUID();
}

function hashDocuments(docs) {
  const content = docs
    .filter((d) => d !== undefined)
    .map((d) => d.pageContent + JSON.stringify(d.metadata))
    .join("|");
  return crypto.createHash("sha256").update(content, "utf8").digest("hex");
}

dotenv.config({ path: `.env.local` });

/**
 * Sanitizes text before passing it to an AI model.
 * Throws if suspicious/malicious content is detected.
 */
function sanitizeForAI(text, source) {
  // 1. Reject binary / non-printable content (allow common whitespace)
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(text)) {
    throw new Error(`[${source}] Binary or non-printable characters detected. Aborting.`);
  }

  // 2. Strip and warn about zero-width / invisible Unicode characters
  const invisiblePattern = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/g;
  if (invisiblePattern.test(text)) {
    console.warn(`[${source}] Invisible/zero-width characters found and removed.`);
    text = text.replace(invisiblePattern, "");
  }

  // 3. Detect suspiciously long base64-like blobs (potential encoded payloads)
  const base64Pattern = /(?:[A-Za-z0-9+/]{40,}={0,2})/g;
  const base64Matches = text.match(base64Pattern) || [];
  for (const match of base64Matches) {
    try {
      const decoded = Buffer.from(match, "base64").toString("utf8");
      // If the decoded string contains shell-like commands, reject it
      if (/(?:bash|sh|cmd|powershell|eval|exec|system|rm\s+-|wget|curl\s+http|chmod|sudo)/i.test(decoded)) {
        throw new Error(`[${source}] Base64-encoded shell command detected. Aborting.`);
      }
    } catch (e) {
      if (e.message.includes("Aborting")) throw e;
      // Not valid base64 — ignore
    }
  }

  // 4. Detect common shell / OS command patterns
  const shellCommandPattern =
    /(?:^|\s)(?:rm\s+-[rRf]+|wget\s+http|curl\s+http|bash\s+-[ci]|sh\s+-[ci]|eval\s*\(|exec\s*\(|system\s*\(|os\.system|subprocess|__import__|\$\(|`[^`]+`)/im;
  if (shellCommandPattern.test(text)) {
    throw new Error(`[${source}] Shell command pattern detected. Aborting.`);
  }

  // 5. Detect prompt-injection trigger phrases
  const injectionPhrases = [
    /ignore\s+(all\s+)?previous\s+instructions/i,
    /disregard\s+(all\s+)?previous\s+instructions/i,
    /you\s+are\s+now\s+(a\s+)?(?:an?\s+)?(?:evil|malicious|unrestricted|jailbroken)/i,
    /act\s+as\s+(if\s+you\s+are\s+)?(?:an?\s+)?(?:evil|malicious|unrestricted|jailbroken)/i,
    /do\s+anything\s+now/i,
    /DAN\b/,
    /jailbreak/i,
    /override\s+(your\s+)?(?:safety|content)\s+(?:filters?|guidelines?|policy|policies)/i,
  ];
  for (const pattern of injectionPhrases) {
    if (pattern.test(text)) {
      throw new Error(`[${source}] Prompt injection phrase detected (pattern: ${pattern}). Aborting.`);
    }
  }

  // 6. Detect leetspeak obfuscation of dangerous words
  // Normalise common leet substitutions then re-check injection phrases
  const leetNormalized = text
    .replace(/0/g, "o")
    .replace(/1/g, "i")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/@/g, "a")
    .replace(/\$/g, "s");
  for (const pattern of injectionPhrases) {
    if (pattern.test(leetNormalized)) {
      throw new Error(`[${source}] Leetspeak-obfuscated prompt injection detected (pattern: ${pattern}). Aborting.`);
    }
  }

  return text;
}

/**
 * Sanitizes file content to prevent prompt injection attacks.
 * Throws an error if malicious content is detected.
 */
function sanitizeFileContent(content, fileName) {
  // 1. Reject files containing non-printable / invisible characters (except common whitespace)
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(content)) {
    throw new Error(`[SECURITY] File "${fileName}" contains hidden/binary control characters and was rejected.`);
  }

  // 2. Detect zero-width / invisible Unicode characters used to hide text
  if (/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/.test(content)) {
    throw new Error(`[SECURITY] File "${fileName}" contains invisible Unicode characters and was rejected.`);
  }

  // 3. Detect base64-encoded blobs (long runs of base64 chars) that may hide instructions
  if (/[A-Za-z0-9+/]{200,}={0,2}/.test(content)) {
    throw new Error(`[SECURITY] File "${fileName}" contains a suspicious base64-encoded block and was rejected.`);
  }

  // 4. Detect common prompt-injection / jailbreak patterns (case-insensitive)
  const promptInjectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/i,
    /disregard\s+(all\s+)?(previous|prior|above)\s+instructions?/i,
    /forget\s+(all\s+)?(previous|prior|above)\s+instructions?/i,
    /you\s+are\s+now\s+(a|an|the)?\s*(?:different|new|another|evil|unrestricted)/i,
    /act\s+as\s+(a|an|the)?\s*(?:different|new|another|evil|unrestricted|jailbreak)/i,
    /do\s+not\s+follow\s+(your\s+)?(previous\s+)?instructions?/i,
    /override\s+(your\s+)?(previous\s+)?instructions?/i,
    /system\s*:\s*(you\s+are|ignore|forget|disregard)/i,
    /\[INST\]|\[\/?SYS\]|<\|im_start\|>|<\|im_end\|>/i,
    /###\s*(instruction|system|prompt|human|assistant)\s*:/i,
  ];
  for (const pattern of promptInjectionPatterns) {
    if (pattern.test(content)) {
      throw new Error(`[SECURITY] File "${fileName}" contains a suspected prompt-injection pattern and was rejected.`);
    }
  }

  // 5. Detect leetspeak substitutions for common injection keywords
  // Normalise digits/symbols that replace letters, then re-check
  const leetNormalized = content
    .replace(/0/g, "o")
    .replace(/1/g, "i")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/@/g, "a")
    .replace(/\$/g, "s");
  const leetKeywords = [
    /ignore\s+previous\s+instructions?/i,
    /disregard\s+previous\s+instructions?/i,
    /jailbreak/i,
  ];
  for (const pattern of leetKeywords) {
    if (pattern.test(leetNormalized)) {
      throw new Error(`[SECURITY] File "${fileName}" contains suspected leetspeak prompt-injection content and was rejected.`);
    }
  }

  // 6. Detect shell / binary command patterns
  const shellPatterns = [
    /\$\(.*\)/,           // command substitution $()
    /`[^`]+`/,            // backtick execution
    /\bexec\s*\(/i,
    /\beval\s*\(/i,
    /\bsystem\s*\(/i,
    /\bpassthru\s*\(/i,
    /\bshell_exec\s*\(/i,
    /\brm\s+-rf\b/i,
    /\bcurl\s+https?:\/\//i,
    /\bwget\s+https?:\/\//i,
    /\/bin\/(sh|bash|zsh|dash)/,
    /\bpython[23]?\s+-c\b/i,
    /\bnode\s+-e\b/i,
  ];
  for (const pattern of shellPatterns) {
    if (pattern.test(content)) {
      throw new Error(`[SECURITY] File "${fileName}" contains suspected shell/binary command content and was rejected.`);
    }
  }

  return content;
}

const MAX_FILE_SIZE_BYTES = 500_000; // 500 KB limit per file
const MAX_CONTENT_LENGTH = 200_000;  // max characters sent to the model

/**
 * Sanitizes and validates raw file content before sending to the AI model.
 * - Rejects files that exceed the size limit
 * - Strips null bytes and non-printable control characters (except common whitespace)
 * - Rejects empty content after sanitization
 * - Truncates content that exceeds the character limit
 */
function sanitizeAndValidateContent(content, fileName) {
  // 1. Enforce file size limit (byte-level check on the raw string)
  if (Buffer.byteLength(content, "utf8") > MAX_FILE_SIZE_BYTES) {
    throw new Error(
      `File "${fileName}" exceeds the maximum allowed size of ${MAX_FILE_SIZE_BYTES} bytes and will not be indexed.`
    );
  }

  // 2. Strip null bytes and non-printable control characters
  //    Allow: tab (\t), newline (\n), carriage return (\r), and printable Unicode
  // eslint-disable-next-line no-control-regex
  let sanitized = content.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

  // 3. Collapse sequences of whitespace-only lines to a single blank line
  sanitized = sanitized.replace(/(\r?\n){3,}/g, "\n\n").trim();

  // 4. Reject empty content after sanitization
  if (sanitized.length === 0) {
    throw new Error(
      `File "${fileName}" contains no usable content after sanitization and will not be indexed.`
    );
  }

  // 5. Truncate to the maximum allowed character length
  if (sanitized.length > MAX_CONTENT_LENGTH) {
    console.warn(
      `File "${fileName}" content truncated from ${sanitized.length} to ${MAX_CONTENT_LENGTH} characters.`
    );
    sanitized = sanitized.slice(0, MAX_CONTENT_LENGTH);
  }

  return sanitized;
}

const fileNames = fs.readdirSync("companions");
const splitter = new CharacterTextSplitter({
  separator: " ",
  chunkSize: 200,
  chunkOverlap: 50, //TODO: adjust both chunk size and chunk overlap later
});

const langchainDocs = await Promise.all(
  fileNames.map(async (fileName) => {
    if (fileName.endsWith(".txt")) {
      const filePath = path.join("companions", fileName);
      const rawContent = fs.readFileSync(filePath, "utf8");
      // Sanitize and validate content before passing to the AI model
      const fileContent = sanitizeAndValidateContent(rawContent, fileName);
      // get the last section in the doc for background info
      const rawLastSection = fileContent.split("###ENDSEEDCHAT###").slice(-1)[0];
      const lastSection = sanitizeForAI(rawLastSection, fileName);
      const splitDocs = await splitter.createDocuments([lastSection]);
      return splitDocs.map((doc) => {
        return new Document({
          metadata: { fileName },
          pageContent: doc.pageContent,
        });
      });
    }
  })
);

const client = new PineconeClient();
await client.init({
  apiKey: process.env.PINECONE_API_KEY,
  environment: process.env.PINECONE_ENVIRONMENT,
});
const pineconeIndex = client.Index(process.env.PINECONE_INDEX);

// Patterns considered dangerous dynamic code execution primitives
const DANGEROUS_PATTERNS = [
  /\beval\s*\(/,
  /\bexec\s*\(/,
  /\bnew\s+Function\s*\(/,
  /\bFunction\s*\(/,
  /\bsetTimeout\s*\(\s*['"`]/,
  /\bsetInterval\s*\(\s*['"`]/,
];

/**
 * Validates a string value for the presence of dynamic code execution primitives.
 * Throws an error if any dangerous pattern is detected.
 */
function validateForDangerousPatterns(value, context) {
  if (typeof value !== "string") return;
  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.test(value)) {
      throw new Error(
        `Security violation: dynamic code execution primitive detected in ${context}. Pattern: ${pattern}`
      );
    }
  }
}

/**
 * Validates an array of embedding vectors (numbers) returned from the LLM.
 * Embedding vectors should only contain finite numbers.
 */
function validateEmbeddingOutput(embeddings, context) {
  if (!Array.isArray(embeddings)) {
    throw new Error(
      `Security violation: expected an array of embeddings in ${context}, got ${typeof embeddings}`
    );
  }
  for (const embedding of embeddings) {
    if (!Array.isArray(embedding)) {
      throw new Error(
        `Security violation: each embedding must be an array of numbers in ${context}`
      );
    }
    for (const value of embedding) {
      if (typeof value !== "number" || !isFinite(value)) {
        throw new Error(
          `Security violation: embedding contains non-numeric or non-finite value in ${context}: ${value}`
        );
      }
    }
  }
}

/**
 * A sanitizing wrapper around OpenAIEmbeddings that validates LLM output
 * for dynamic code execution primitives before returning embeddings.
 */
class SanitizedOpenAIEmbeddings extends OpenAIEmbeddings {
  async embedDocuments(texts) {
    // Validate input texts before sending to LLM
    for (const text of texts) {
      validateForDangerousPatterns(text, "embedDocuments input");
    }
    const embeddings = await super.embedDocuments(texts);
    // Validate the structure of the returned embeddings
    validateEmbeddingOutput(embeddings, "embedDocuments output");
    return embeddings;
  }

  async embedQuery(text) {
    // Validate input text before sending to LLM
    validateForDangerousPatterns(text, "embedQuery input");
    const embedding = await super.embedQuery(text);
    // Validate the structure of the returned embedding
    validateEmbeddingOutput([embedding], "embedQuery output");
    return embedding;
  }
}

// Validate document pageContent before indexing
const validatedDocs = langchainDocs.flat().filter((doc) => doc !== undefined);
for (const doc of validatedDocs) {
  validateForDangerousPatterns(doc.pageContent, "document pageContent");
}

const docsToIndex = langchainDocs.flat().filter((doc) => doc !== undefined);
console.log(JSON.stringify({
  timestamp: new Date().toISOString(),
  event: "llm_interaction_start",
  model: "OpenAIEmbeddings",
  action: "PineconeStore.fromDocuments",
  documentCount: docsToIndex.length,
  pineconeIndex: process.env.PINECONE_INDEX,
}));

const filteredDocs = langchainDocs.flat().filter((doc) => doc !== undefined);
const traceId = generateTraceId();
const modelIdentifier = "text-embedding-ada-002"; // OpenAIEmbeddings default model
const modelVersion = "v1"; // OpenAI embedding model version label
const principal = process.env.AUDIT_PRINCIPAL || os.userInfo().username || "unknown";
const inputHash = hashDocuments(filteredDocs);
const startTimestamp = new Date().toISOString();

writeAuditRecord({
  traceId,
  event: "ai_action_start",
  action: "generate_embeddings_and_index",
  principal,
  modelIdentifier,
  modelVersion,
  inputDocumentCount: filteredDocs.length,
  inputHash,
  pineconeIndex: process.env.PINECONE_INDEX,
  pineconeEnvironment: process.env.PINECONE_ENVIRONMENT,
  timestamp: startTimestamp,
  retentionDays: AUDIT_LOG_RETENTION_DAYS,
});

try {
  // APPROVED MODEL REGISTRY — pinned embedding model identity
const APPROVED_EMBEDDING_MODEL = "text-embedding-ada-002";
const APPROVED_EMBEDDING_MODEL_VERSION = "1";

const embeddings = new OpenAIEmbeddings({
  openAIApiKey: process.env.OPENAI_API_KEY,
  modelName: APPROVED_EMBEDDING_MODEL,
});

// Model identity logging — satisfies model identity tracking requirement
console.log(
  JSON.stringify({
    event: "embedding_model_resolved",
    model: APPROVED_EMBEDDING_MODEL,
    version: APPROVED_EMBEDDING_MODEL_VERSION,
    registry: "approved",
    timestamp: new Date().toISOString(),
  })
);

await PineconeStore.fromDocuments(
  langchainDocs.flat().filter((doc) => doc !== undefined),
  embeddings,
  {
    pineconeIndex,
  }
);

  writeAuditRecord({
    traceId,
    event: "ai_action_success",
    action: "generate_embeddings_and_index",
    principal,
    modelIdentifier,
    modelVersion,
    inputDocumentCount: filteredDocs.length,
    inputHash,
    pineconeIndex: process.env.PINECONE_INDEX,
    pineconeEnvironment: process.env.PINECONE_ENVIRONMENT,
    startTimestamp,
    endTimestamp: new Date().toISOString(),
    outcome: "success",
    retentionDays: AUDIT_LOG_RETENTION_DAYS,
  });
} catch (actionError) {
  writeAuditRecord({
    traceId,
    event: "ai_action_failure",
    action: "generate_embeddings_and_index",
    principal,
    modelIdentifier,
    modelVersion,
    inputDocumentCount: filteredDocs.length,
    inputHash,
    pineconeIndex: process.env.PINECONE_INDEX,
    pineconeEnvironment: process.env.PINECONE_ENVIRONMENT,
    startTimestamp,
    endTimestamp: new Date().toISOString(),
    outcome: "failure",
    errorMessage: actionError.message,
    retentionDays: AUDIT_LOG_RETENTION_DAYS,
  });
  throw actionError;
}

console.log(JSON.stringify({
  timestamp: new Date().toISOString(),
  event: "llm_interaction_complete",
  model: "OpenAIEmbeddings",
  action: "PineconeStore.fromDocuments",
  documentCount: docsToIndex.length,
  pineconeIndex: process.env.PINECONE_INDEX,
  status: "success",
}));
