// Major ref: https://js.langchain.com/docs/modules/indexes/vector_stores/integrations/pinecone
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

// ---------------------------------------------------------------------------
// Audit helpers
// ---------------------------------------------------------------------------
const AUDIT_LOG_PATH = path.resolve("audit.log");
const MODEL_ID = "text-embedding-ada-002"; // OpenAIEmbeddings default model
const MODEL_VERSION = "002";

/**
 * Appends a single JSON-Lines audit record to the persistent audit log.
 * Each record is written synchronously so it survives process crashes.
 */
function writeAuditRecord(record) {
  const line = JSON.stringify(record) + "\n";
  fs.appendFileSync(AUDIT_LOG_PATH, line, { encoding: "utf8", flag: "a" });
}

/**
 * Returns a SHA-256 hex digest of the serialised document corpus.
 * Used as the input-hash for forensic reproducibility.
 */
function hashDocuments(docs) {
  const serialised = JSON.stringify(
    docs.map((d) => ({ pageContent: d.pageContent, metadata: d.metadata }))
  );
  return crypto.createHash("sha256").update(serialised, "utf8").digest("hex");
}

/**
 * Generates a random UUID-v4 correlation/trace identifier.
 */
function newTraceId() {
  return crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString("hex");
}

// Singapore PII redaction: removes/masks common SG PII categories before indexing
function redactSingaporePII(text) {
  // NRIC/FIN numbers (e.g. S1234567A, T0123456B, F1234567C, G1234567D)
  text = text.replace(/\b[STFG]\d{7}[A-Z]\b/gi, "[REDACTED_NRIC]");

  // Singapore personal mobile numbers (+65 8/9 XXXXXXX or 8/9XXXXXXX)
  text = text.replace(/(\+65[\s-]?)?[89]\d{7}\b/g, "[REDACTED_MOBILE]");

  // Email addresses
  text = text.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, "[REDACTED_EMAIL]");

  // Full names heuristic: two or more capitalised words in sequence (Title Case)
  // This targets patterns like "John Tan Wei Ming" while avoiding sentence starts
  text = text.replace(/\b([A-Z][a-z]+)(\s[A-Z][a-z]+){1,4}\b/g, "[REDACTED_NAME]");

  return text;
}

dotenv.config({ path: `.env.local` });

// Approved foundation model registry — only models listed here may be used for embeddings.
const APPROVED_EMBEDDING_MODELS = Object.freeze([
  "text-embedding-ada-002",
]);

// Pinned model identity — must match an entry in APPROVED_EMBEDDING_MODELS.
const EMBEDDING_MODEL_NAME = "text-embedding-ada-002";
const EMBEDDING_MODEL_VERSION = "text-embedding-ada-002"; // OpenAI does not expose a separate version; the model name is the immutable identifier.

if (!APPROVED_EMBEDDING_MODELS.includes(EMBEDDING_MODEL_NAME)) {
  throw new Error(
    `Model '${EMBEDDING_MODEL_NAME}' is not in the approved model registry. ` +
    `Approved models: ${APPROVED_EMBEDDING_MODELS.join(", ")}`
  );
}

console.log(
  `[model-identity] embedding model='${EMBEDDING_MODEL_NAME}' version='${EMBEDDING_MODEL_VERSION}' approved=true`
);

/**
 * Redacts common PII categories from a string.
 * Covers: email, phone, SSN, credit card, date of birth, and street addresses.
 * @param {string} text
 * @returns {string} text with PII replaced by placeholder tokens
 */
function redactPII(text) {
  // Email addresses
  text = text.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, "[REDACTED_EMAIL]");

  // Phone numbers (various formats: +1-800-555-1234, (800) 555-1234, 800.555.1234, etc.)
  text = text.replace(
    /(\+?1[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}/g,
    "[REDACTED_PHONE]"
  );

  // Social Security Numbers (SSN): 123-45-6789 or 123 45 6789
  text = text.replace(/\b\d{3}[\s\-]\d{2}[\s\-]\d{4}\b/g, "[REDACTED_SSN]");

  // Credit card numbers (16-digit, optionally separated by spaces or dashes)
  text = text.replace(/\b(?:\d{4}[\s\-]?){3}\d{4}\b/g, "[REDACTED_CREDIT_CARD]");

  // Dates of birth (MM/DD/YYYY, MM-DD-YYYY, YYYY-MM-DD)
  text = text.replace(
    /\b(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}|\d{4}[\-]\d{2}[\-]\d{2})\b/g,
    "[REDACTED_DATE]"
  );

  // Street addresses (e.g., 123 Main St, 456 Elm Avenue Apt 7)
  text = text.replace(
    /\b\d+\s+[A-Za-z0-9\s,.']+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Circle|Cir|Way|Place|Pl|Terrace|Ter|Trail|Trl|Parkway|Pkwy|Highway|Hwy)(?:\s+(?:Apt|Suite|Ste|Unit|#)\s*[\w\-]+)?\b/gi,
    "[REDACTED_ADDRESS]"
  );

  // ZIP codes (standalone 5-digit or ZIP+4)
  text = text.replace(/\b\d{5}(?:\-\d{4})?\b/g, "[REDACTED_ZIP]");

  return text;
}

/**
 * Sanitizes text content before passing it to the AI pipeline.
 * Throws if suspicious content is detected; otherwise returns cleaned text.
 */
function sanitizeContent(content, fileName) {
  // 1. Reject binary / shell executable signatures
  if (/^(\x7fELF|MZ|\x89PNG|\xff\xd8\xff)/.test(content)) {
    throw new Error(`[${fileName}] Binary executable content detected — skipping.`);
  }

  // 2. Strip invisible / zero-width characters that can hide prompts
  //    (zero-width space, zero-width non-joiner, zero-width joiner, soft-hyphen, etc.)
  const invisiblePattern = /[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]/g;
  if (invisiblePattern.test(content)) {
    console.warn(`[${fileName}] Invisible/hidden characters detected and stripped.`);
    content = content.replace(invisiblePattern, "");
  }

  // 3. Detect and reject base64-encoded blobs (long runs of base64 chars)
  //    A standalone base64 string of 100+ chars is suspicious.
  const base64Pattern = /(?:[A-Za-z0-9+/]{4}){25,}={0,2}/g;
  if (base64Pattern.test(content)) {
    throw new Error(`[${fileName}] Base64-encoded content detected — possible hidden prompt injection.`);
  }

  // 4. Detect leetspeak substitution patterns used to obfuscate instructions
  //    e.g. "1gnor3", "3x3cut3", "1nstruct10n"
  const leetspeakPattern = /\b(?=[a-z0-9]*[0-9][a-z0-9]*)(?=[a-z0-9]*[a-z][a-z0-9]*)[a-z0-9]{5,}\b/gi;
  const leetspeakMatches = content.match(leetspeakPattern) || [];
  if (leetspeakMatches.length > 5) {
    throw new Error(`[${fileName}] Excessive leetspeak patterns detected — possible obfuscated prompt injection.`);
  }

  // 5. Detect shell / command injection patterns
  const shellPattern = /(?:ignore\s+(?:previous|above|prior)\s+instructions?|system\s*\(|exec\s*\(|eval\s*\(|subprocess|os\.system|rm\s+-rf|curl\s+|wget\s+|base64\s+-d|\|\s*sh|&&\s*sh|;\s*sh\b)/gi;
  if (shellPattern.test(content)) {
    throw new Error(`[${fileName}] Shell command or prompt-override pattern detected — skipping.`);
  }

  // 6. Detect common prompt-injection override phrases
  const injectionPhrases = /(?:disregard\s+(?:all\s+)?(?:previous|prior|above)|new\s+instructions?\s*:|you\s+are\s+now\s+(?:a|an)\s+|act\s+as\s+(?:a|an)\s+|forget\s+(?:everything|all))/gi;
  if (injectionPhrases.test(content)) {
    throw new Error(`[${fileName}] Prompt injection override phrase detected — skipping.`);
  }

  return content;
}

/**
 * Sanitize file content to prevent prompt injection attacks.
 * Throws an error if malicious content is detected.
 */
function sanitizeFileContent(content, fileName) {
  // 1. Strip invisible / zero-width Unicode characters
  // (zero-width space, zero-width non-joiner, zero-width joiner,
  //  left-to-right mark, right-to-left mark, word joiner, etc.)
  const invisibleCharsRegex =
    /[\u200B\u200C\u200D\u200E\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/g;
  const stripped = content.replace(invisibleCharsRegex, "");

  // 2. Detect base64-encoded blobs (long runs of base64 chars)
  const base64BlobRegex = /[A-Za-z0-9+/]{200,}={0,2}/;
  if (base64BlobRegex.test(stripped)) {
    throw new Error(
      `[SECURITY] File "${fileName}" contains a suspicious base64-encoded blob and was rejected.`
    );
  }

  // 3. Detect shell commands / binary-like content
  const shellCommandRegex =
    /(\b(bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess)\b|\$\(|`[^`]*`|\|\s*\w+|;\s*rm\s|;\s*curl\s|;\s*wget\s|\x00)/i;
  if (shellCommandRegex.test(stripped)) {
    throw new Error(
      `[SECURITY] File "${fileName}" contains shell commands or binary content and was rejected.`
    );
  }

  // 4. Detect common prompt-injection / jailbreak keywords
  const promptInjectionRegex =
    /(ignore (all |previous |prior |above |the above |your )?(instructions?|prompts?|rules?|constraints?|guidelines?)|disregard (all |previous |prior |above |the above |your )?(instructions?|prompts?|rules?)|you are now|new persona|act as (an? )?(unrestricted|unfiltered|jailbroken|evil|malicious|DAN)|do anything now|\[system\]|<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>)/i;
  if (promptInjectionRegex.test(stripped)) {
    throw new Error(
      `[SECURITY] File "${fileName}" contains prompt-injection content and was rejected.`
    );
  }

  // 5. Detect leetspeak obfuscation of the word "ignore" (1gn0r3, !gnore, etc.)
  const leetspeakIgnoreRegex = /[1!][g9][n][0o][r][3e]/i;
  if (leetspeakIgnoreRegex.test(stripped)) {
    throw new Error(
      `[SECURITY] File "${fileName}" contains leetspeak obfuscation and was rejected.`
    );
  }

  return stripped;
}

// --- Input sanitization helpers ---
const MAX_FILE_SIZE_BYTES = 500_000; // 500 KB per file
const MAX_CHUNK_LENGTH = 2000;       // characters per chunk sent to the model

/**
 * Sanitize raw text read from a file before it is sent to the LLM.
 * - Rejects files that are too large.
 * - Strips null bytes and non-printable ASCII control characters
 *   (keeps newlines, tabs, and printable Unicode).
 * - Truncates the result to a safe maximum length.
 */
function sanitizeFileContent(content, filePath) {
  if (Buffer.byteLength(content, "utf8") > MAX_FILE_SIZE_BYTES) {
    throw new Error(
      `File "${filePath}" exceeds the maximum allowed size of ${MAX_FILE_SIZE_BYTES} bytes and will not be indexed.`
    );
  }

  // Remove null bytes and ASCII control characters except \t (0x09) and \n (0x0A) and \r (0x0D)
  // eslint-disable-next-line no-control-regex
  const sanitized = content.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

  if (sanitized.trim().length === 0) {
    throw new Error(
      `File "${filePath}" contains no usable text after sanitization.`
    );
  }

  return sanitized;
}

/**
 * Validate and sanitize a single document chunk before indexing.
 * Returns null if the chunk should be discarded.
 */
function sanitizeChunk(pageContent) {
  if (typeof pageContent !== "string") return null;
  // eslint-disable-next-line no-control-regex
  const cleaned = pageContent.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "").trim();
  if (cleaned.length === 0) return null;
  // Truncate chunks that are unexpectedly long
  return cleaned.length > MAX_CHUNK_LENGTH ? cleaned.slice(0, MAX_CHUNK_LENGTH) : cleaned;
}
// --- End sanitization helpers ---

const COMPANIONS_DIR = path.resolve("companions");
const fileNames = fs.readdirSync(COMPANIONS_DIR);
const splitter = new CharacterTextSplitter({
  separator: " ",
  chunkSize: 200,
  chunkOverlap: 50, //TODO: adjust both chunk size and chunk overlap later
});

// Data-minimisation constants
const MAX_CHARS_PER_CHUNK = 500;   // hard cap on individual chunk size
const MAX_CHUNKS_PER_DOC = 20;    // limit total chunks stored per document

// Sensitive-field pattern: drop any line whose key portion matches
const SENSITIVE_LINE_PATTERN =
  /^\s*(email|phone|mobile|address|password|passwd|secret|token|api[_-]?key|ssn|dob|date[_\s]of[_\s]birth|credit[_\s]?card|card[_\s]?number)\s*[=:]/i;

/**
 * Redact lines that appear to carry sensitive field data and
 * truncate the result to a safe maximum length.
 */
function minimiseContent(text) {
  const lines = text.split(/\r?\n/);
  const filtered = lines.filter((line) => !SENSITIVE_LINE_PATTERN.test(line));
  const joined = filtered.join("\n");
  // Hard character ceiling to prevent wholesale injection
  return joined.slice(0, MAX_CHARS_PER_CHUNK * MAX_CHUNKS_PER_DOC);
}

const langchainDocs = await Promise.all(
  fileNames.map(async (fileName) => {
    if (fileName.endsWith(".txt")) {
      const filePath = path.join("companions", fileName);
      const rawContent = fs.readFileSync(filePath, "utf8");
      // Sanitize and validate raw file content before any further processing
      const fileContent = sanitizeFileContent(rawContent, filePath);
      // get the last section in the doc for background info
      const lastSection = fileContent.split("###ENDSEEDCHAT###").slice(-1)[0];
      let sanitizedSection;
      try {
        sanitizedSection = sanitizeContent(lastSection, fileName);
      } catch (err) {
        console.error(`Skipping file due to security check failure: ${err.message}`);
        return undefined;
      }
      const splitDocs = await splitter.createDocuments([sanitizedSection]);
      return splitDocs
        .map((doc) => {
          const cleanedContent = sanitizeChunk(doc.pageContent);
          if (cleanedContent === null) return undefined; // discard empty/invalid chunks
          return new Document({
            metadata: { fileName },
            pageContent: cleanedContent,
          });
        })
        .filter((doc) => doc !== undefined);
    }
  })
);

// External systems accessed: (1) Pinecone, (2) OpenAI — total: 2 (within the 3-system policy limit)
const pineconeConfig = {
  apiKey: process.env.PINECONE_API_KEY,
  environment: process.env.PINECONE_ENVIRONMENT,
  index: process.env.PINECONE_INDEX,
};

const client = new PineconeClient();
await client.init({
  apiKey: pineconeConfig.apiKey,
  environment: pineconeConfig.environment,
});
const pineconeIndex = client.Index(pineconeConfig.index);

const openAIConfig = {
  apiKey: process.env.OPENAI_API_KEY,
};

const embeddings = new OpenAIEmbeddings({
  openAIApiKey: process.env.OPENAI_API_KEY,
  modelName: EMBEDDING_MODEL_NAME,
});

console.log(
  `[indexing-audit] Starting PineconeStore.fromDocuments with ` +
  `model='${EMBEDDING_MODEL_NAME}' version='${EMBEDDING_MODEL_VERSION}' ` +
  `index='${process.env.PINECONE_INDEX}' timestamp='${new Date().toISOString()}'`
);

await PineconeStore.fromDocuments(
  langchainDocs.flat().filter((doc) => doc !== undefined),
  embeddings,
  {
    pineconeIndex,
  }
);

console.log(
  `[indexing-audit] Completed PineconeStore.fromDocuments with ` +
  `model='${EMBEDDING_MODEL_NAME}' version='${EMBEDDING_MODEL_VERSION}' ` +
  `timestamp='${new Date().toISOString()}'`
);
await client.init({
  apiKey: process.env.PINECONE_API_KEY,
  environment: process.env.PINECONE_ENVIRONMENT,
});
const pineconeIndex = client.Index(process.env.PINECONE_INDEX);

// ---------------------------------------------------------------------------
// Audit-wrapped AI-driven indexing operation
// ---------------------------------------------------------------------------
const filteredDocs = langchainDocs.flat().filter((doc) => doc !== undefined);
const traceId = newTraceId();
const inputHash = hashDocuments(filteredDocs);
const principal = `${os.userInfo().username}@${os.hostname()}`;
const startedAt = new Date().toISOString();

// PRE-ACTION audit record — captures intent before execution
writeAuditRecord({
  traceId,
  event: "ai_indexing_started",
  timestamp: startedAt,
  principal,
  action: "PineconeStore.fromDocuments",
  modelId: MODEL_ID,
  modelVersion: MODEL_VERSION,
  inputHash,
  documentCount: filteredDocs.length,
  pineconeIndex: process.env.PINECONE_INDEX,
  pineconeEnvironment: process.env.PINECONE_ENVIRONMENT,
  retentionPolicy: "retain-7-years",
  forensicContext: {
    scriptPath: import.meta.url,
    nodeVersion: process.version,
    pid: process.pid,
  },
});

let indexingOutcome = "unknown";
let indexingError = null;
try {
  await PineconeStore.fromDocuments(
    filteredDocs,
    new OpenAIEmbeddings({ openAIApiKey: process.env.OPENAI_API_KEY }),
    {
      pineconeIndex,
    }
  );
  indexingOutcome = "success";
} catch (err) {
  indexingOutcome = "failure";
  indexingError = err.message ?? String(err);
  throw err; // re-throw so the process exits with a non-zero code
} finally {
  // POST-ACTION audit record — captures outcome for forensic readiness
  writeAuditRecord({
    traceId,
    event: "ai_indexing_completed",
    timestamp: new Date().toISOString(),
    principal,
    action: "PineconeStore.fromDocuments",
    modelId: MODEL_ID,
    modelVersion: MODEL_VERSION,
    inputHash,
    documentCount: filteredDocs.length,
    pineconeIndex: process.env.PINECONE_INDEX,
    pineconeEnvironment: process.env.PINECONE_ENVIRONMENT,
    outcome: indexingOutcome,
    error: indexingError,
    retentionPolicy: "retain-7-years",
    forensicContext: {
      scriptPath: import.meta.url,
      nodeVersion: process.version,
      pid: process.pid,
    },
  });
}
