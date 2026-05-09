// Major ref: https://js.langchain.com/docs/modules/indexes/vector_stores/integrations/pinecone
import { PineconeClient } from "@pinecone-database/pinecone";
import dotenv from "dotenv";
import { Document } from "langchain/document";
import { OpenAIEmbeddings } from "langchain/embeddings/openai";

// Approved model registry — only models listed here may be used for embeddings.
const APPROVED_EMBEDDING_MODELS = Object.freeze([
  "text-embedding-ada-002",
]);

/**
 * Registry-validated wrapper around OpenAIEmbeddings.
 * Enforces:
 *   - model is present in the approved registry allowlist
 *   - an explicit pinned version is always specified (no mutable defaults)
 *   - resolved model identity is logged for audit at instantiation time
 */
function createApprovedEmbeddings({ openAIApiKey, modelName }) {
  if (!modelName) {
    throw new Error(
      `[ModelRegistry] 'modelName' must be explicitly specified — ` +
      `relying on library defaults is not permitted.`
    );
  }
  if (!APPROVED_EMBEDDING_MODELS.includes(modelName)) {
    throw new Error(
      `[ModelRegistry] Model '${modelName}' is NOT in the approved registry. ` +
      `Approved models: ${APPROVED_EMBEDDING_MODELS.join(", ")}`
    );
  }
  // Record resolved model identity for audit purposes.
  console.log(
    `[ModelRegistry] Approved model instantiated — name: '${modelName}', ` +
    `registry: APPROVED_EMBEDDING_MODELS, timestamp: ${new Date().toISOString()}`
  );
  return new OpenAIEmbeddings({ openAIApiKey, modelName });
}
import { PineconeStore } from "langchain/vectorstores/pinecone";
import { CharacterTextSplitter } from "langchain/text_splitter";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import os from "os";

const AUDIT_LOG_PATH = path.resolve("audit_indexPinecone.jsonl");

/**
 * Appends an immutable JSON audit record to the audit log file.
 * Each record is written as a single JSON line (JSONL) for forensic readiness.
 */
function writeAuditRecord(record) {
  const line = JSON.stringify(record) + "\n";
  fs.appendFileSync(AUDIT_LOG_PATH, line, { encoding: "utf8", flag: "a" });
}

dotenv.config({ path: `.env.local` });

/**
 * Detects and redacts Singapore-specific PII from text before indexing.
 * Covered categories:
 *   - NRIC/FIN numbers (e.g. S1234567A, T0123456B, F1234567C, G1234567D)
 *   - Singapore mobile/landline numbers (+65 XXXX XXXX or 8-digit local)
 *   - Singapore postal codes (6-digit, optionally prefixed with "Singapore")
 *   - Singapore/international passport numbers
 *   - Email addresses
 *   - Full names preceded by common salutations (Mr, Mrs, Ms, Dr, Prof)
 * @param {string} text
 * @returns {string} text with PII redacted
 */
function redactSingaporePII(text) {
  // NRIC / FIN  (S/T/F/G followed by 7 digits and a letter)
  text = text.replace(/\b[STFG]\d{7}[A-Z]\b/gi, "[REDACTED_NRIC]");

  // Singapore phone numbers: +65 followed by 8 digits (with optional spaces/dashes)
  text = text.replace(/(?:\+65[\s-]?)?[689]\d{3}[\s-]?\d{4}\b/g, "[REDACTED_PHONE]");

  // Singapore postal codes: optional "Singapore" prefix + 6-digit code
  text = text.replace(/\bSingapore\s+\d{6}\b/gi, "[REDACTED_POSTAL]");
  text = text.replace(/\bS\(\d{6}\)/gi, "[REDACTED_POSTAL]");

  // Passport numbers (alphanumeric, 6–9 chars — covers SG and common foreign formats)
  text = text.replace(/\b[A-Z]{1,2}\d{6,7}[A-Z]?\b/g, (match) => {
    // Avoid re-redacting already-redacted tokens or short codes
    if (match.length < 7) return match;
    return "[REDACTED_PASSPORT]";
  });

  // Email addresses
  text = text.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, "[REDACTED_EMAIL]");

  // Names preceded by salutations
  text = text.replace(/\b(Mr\.?|Mrs\.?|Ms\.?|Miss|Dr\.?|Prof\.?)\s+[A-Z][a-z]+(\s+[A-Z][a-z]+){0,3}/g, "[REDACTED_NAME]");

  return text;
}

/**
 * Redacts common PII patterns from a string.
 * Covers: email addresses, US phone numbers, SSNs, credit card numbers,
 * IPv4 addresses, and patterns that look like full names (Title Case pairs).
 */
function redactPII(text) {
  // Email addresses
  text = text.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, "[REDACTED_EMAIL]");
  // US phone numbers (various formats)
  text = text.replace(/(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}/g, "[REDACTED_PHONE]");
  // Social Security Numbers
  text = text.replace(/\b\d{3}[\s.-]\d{2}[\s.-]\d{4}\b/g, "[REDACTED_SSN]");
  // Credit card numbers (16-digit, optionally grouped)
  text = text.replace(/\b(?:\d{4}[\s.-]?){3}\d{4}\b/g, "[REDACTED_CC]");
  // IPv4 addresses
  text = text.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "[REDACTED_IP]");
  // Full names: two or more consecutive Title Case words (e.g. "John Smith")
  text = text.replace(/\b([A-Z][a-z]+(?:\s[A-Z][a-z]+)+)\b/g, "[REDACTED_NAME]");
  return text;
}

/**
 * Validates file content against prompt injection and malicious command patterns.
 * Throws an error if suspicious content is detected.
 */
function validateContent(content, fileName) {
  // 1. Reject binary / non-printable content (allow common whitespace only)
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(content)) {
    throw new Error(`[SECURITY] Binary or non-printable characters detected in "${fileName}". Skipping.`);
  }

  // 2. Detect invisible / zero-width characters used to hide prompts
  if (/[\u200B-\u200D\uFEFF\u2060\u00AD]/.test(content)) {
    throw new Error(`[SECURITY] Invisible/zero-width characters detected in "${fileName}". Skipping.`);
  }

  // 3. Detect base64-encoded blobs (long runs of base64 chars, >=64 chars)
  if (/[A-Za-z0-9+/]{64,}={0,2}/.test(content)) {
    throw new Error(`[SECURITY] Possible base64-encoded payload detected in "${fileName}". Skipping.`);
  }

  // 4. Detect shell / binary executable commands
  const shellPatterns = [
    /\b(bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess)\s*[\(\[`]/i,
    /\b(curl|wget|nc|ncat|netcat|chmod|chown|sudo|su|rm\s+-rf|mkfifo)\b/i,
    /[|;&`$]\s*(bash|sh|python|perl|ruby|node|php)/i,
    /<script[\s>]/i,
    /javascript:/i,
  ];
  for (const pattern of shellPatterns) {
    if (pattern.test(content)) {
      throw new Error(`[SECURITY] Shell/executable command pattern detected in "${fileName}". Skipping.`);
    }
  }

  // 5. Detect prompt injection keywords
  const injectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /disregard\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /forget\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /you\s+are\s+now\s+(a|an)\s+/i,
    /act\s+as\s+(a|an)\s+/i,
    /new\s+instructions?:/i,
    /system\s*prompt/i,
    /\[INST\]/i,
    /<<SYS>>/i,
  ];
  for (const pattern of injectionPatterns) {
    if (pattern.test(content)) {
      throw new Error(`[SECURITY] Prompt injection keyword detected in "${fileName}". Skipping.`);
    }
  }

  // 6. Detect leetspeak obfuscation (simple heuristic: high ratio of digit-letter substitutions)
  const leetspeakPattern = /[\$3@!0][a-zA-Z]{2,}|[a-zA-Z]{2,}[\$3@!0]/g;
  const leetspeakMatches = content.match(leetspeakPattern) || [];
  const wordCount = content.split(/\s+/).length;
  if (leetspeakMatches.length > 0 && leetspeakMatches.length / wordCount > 0.15) {
    throw new Error(`[SECURITY] Possible leetspeak obfuscation detected in "${fileName}". Skipping.`);
  }

  return true;
}

/**
 * Sanitizes file content to prevent prompt injection attacks.
 * Throws if clearly malicious content is detected; strips invisible characters.
 */
function sanitizeFileContent(content, fileName) {
  // 1. Reject binary/executable content (null bytes or common magic bytes as text)
  if (/\x00/.test(content)) {
    throw new Error(`File "${fileName}" contains binary/null-byte content and was rejected.`);
  }

  // 2. Reject shell command injection patterns
  const shellPatterns = [
    /`[^`]*`/,                        // backtick execution
    /\$\([^)]*\)/,                    // $(command) substitution
    /;\s*(rm|wget|curl|bash|sh|python|perl|ruby|nc|ncat|netcat)\s/i,
    /\|\s*(bash|sh|python|perl|ruby)\s/i,
  ];
  for (const pattern of shellPatterns) {
    if (pattern.test(content)) {
      throw new Error(`File "${fileName}" contains shell command patterns and was rejected.`);
    }
  }

  // 3. Detect and reject base64-encoded blobs (long base64 strings likely encoding hidden prompts)
  const base64Pattern = /(?:[A-Za-z0-9+\/]{40,}={0,2})/g;
  const base64Matches = content.match(base64Pattern) || [];
  for (const match of base64Matches) {
    try {
      const decoded = Buffer.from(match, "base64").toString("utf8");
      // If decoded text contains prompt-injection keywords, reject
      if (/ignore (previous|above|all)|you are now|new instruction|system prompt|disregard/i.test(decoded)) {
        throw new Error(`File "${fileName}" contains a base64-encoded hidden prompt and was rejected.`);
      }
    } catch (e) {
      if (e.message.includes("rejected")) throw e;
      // Not valid base64 or not decodable — skip
    }
  }

  // 4. Detect prompt injection phrases (direct)
  const injectionPhrases = [
    /ignore (previous|all|above|prior) (instructions?|prompts?|context)/i,
    /disregard (previous|all|above|prior) (instructions?|prompts?|context)/i,
    /forget (previous|all|above|prior) (instructions?|prompts?|context)/i,
    /you are now/i,
    /new (role|persona|instructions?|task):/i,
    /\[system\]/i,
    /<<SYS>>/i,
    /<\|system\|>/i,
    /###\s*instruction/i,
    /act as (a |an )?(different|new|another|unrestricted)/i,
    /jailbreak/i,
    /do anything now/i,
    /dan mode/i,
  ];
  for (const pattern of injectionPhrases) {
    if (pattern.test(content)) {
      throw new Error(`File "${fileName}" contains prompt injection phrases and was rejected.`);
    }
  }

  // 5. Detect leetspeak obfuscation of injection keywords
  // Normalize common leet substitutions and re-check
  const leetNormalized = content
    .replace(/0/g, "o")
    .replace(/1/g, "i")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/@/g, "a")
    .replace(/\$/g, "s");
  const leetInjectionPhrases = [
    /ignore (previous|all|above|prior) (instructions?|prompts?|context)/i,
    /disregard (previous|all|above|prior) (instructions?|prompts?|context)/i,
    /you are now/i,
    /jailbreak/i,
    /do anything now/i,
  ];
  for (const pattern of leetInjectionPhrases) {
    if (pattern.test(leetNormalized)) {
      throw new Error(`File "${fileName}" contains leetspeak-obfuscated prompt injection and was rejected.`);
    }
  }

  // 6. Strip invisible/hidden Unicode characters (zero-width spaces, soft hyphens, etc.)
  const sanitized = content
    .replace(/[\u200B-\u200D\uFEFF\u00AD\u2060\u180E\u00A0]/g, " ") // zero-width & invisible chars
    .replace(/[\u202A-\u202E]/g, "")  // Unicode bidirectional override characters
    .replace(/[\u2066-\u2069]/g, ""); // Isolate/override formatting chars

  return sanitized;
}

// --- Input sanitization/validation helpers ---
const MAX_CONTENT_LENGTH = 100_000; // characters

// Patterns that suggest prompt-injection or instruction-override attempts
const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/i,
  /you\s+are\s+now\s+(a|an)?\s*\w+/i,
  /system\s*:\s*(you|your|ignore)/i,
  /<\s*\/?(system|user|assistant)\s*>/i,
  /\[\s*(INST|SYS|SYSTEM)\s*\]/i,
];

/**
 * Sanitizes raw text before it is sent to the AI model.
 * @param {string} text - Raw text content from a file.
 * @param {string} source - Identifier used in error messages (e.g. file name).
 * @returns {string} Sanitized text safe to pass to the embedding model.
 */
function sanitizeAndValidate(text, source) {
  if (typeof text !== "string") {
    throw new Error(`[${source}] Content must be a string.`);
  }

  // 1. Remove null bytes
  let sanitized = text.replace(/\0/g, "");

  // 2. Strip non-printable ASCII control characters (except \t, \n, \r)
  // eslint-disable-next-line no-control-regex
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

  // 3. Enforce maximum length
  if (sanitized.length > MAX_CONTENT_LENGTH) {
    console.warn(
      `[${source}] Content truncated from ${sanitized.length} to ${MAX_CONTENT_LENGTH} characters.`
    );
    sanitized = sanitized.slice(0, MAX_CONTENT_LENGTH);
  }

  // 4. Reject empty content
  if (sanitized.trim().length === 0) {
    throw new Error(`[${source}] Content is empty after sanitization.`);
  }

  // 5. Detect prompt-injection patterns
  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(sanitized)) {
      throw new Error(
        `[${source}] Content rejected: potential prompt-injection pattern detected (${pattern}).`
      );
    }
  }

  return sanitized;
}
// --- End sanitization helpers ---

const COMPANIONS_DIR = path.resolve("companions");
const fileNames = fs.readdirSync(COMPANIONS_DIR);
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
      const fileContent = sanitizeFileContent(rawContent, fileName);
      // get the last section in the doc for background info
      const rawLastSection = fileContent.split("###ENDSEEDCHAT###").slice(-1)[0];
      const lastSection = sanitizeAndValidate(rawLastSection, fileName);
      const splitDocs = await splitter.createDocuments([lastSection]);
      return splitDocs.map((doc) => {
        return new Document({
          metadata: { fileName: path.basename(fileName) },
          pageContent: doc.pageContent,
        });
      });
    }
  })
);

const client = new PineconeClient();
await client.init({
  apiKey: config.pinecone.apiKey,
  environment: config.pinecone.environment,
});
const pineconeIndex = client.Index(config.pinecone.index);

// --- Audit trail setup ---
const MODEL_ID = "text-embedding-ada-002"; // OpenAIEmbeddings default model
const correlationId = crypto.randomUUID();
const principal = process.env.AUDIT_PRINCIPAL || os.userInfo().username || "unknown";
const operationTimestamp = new Date().toISOString();

const filteredDocs = langchainDocs.flat().filter((doc) => doc !== undefined);

// Compute a SHA-256 hash over the concatenated page content of all input documents
const inputHash = crypto
  .createHash("sha256")
  .update(filteredDocs.map((d) => d.pageContent).join("\n"))
  .digest("hex");

// Write the pre-operation audit record
writeAuditRecord({
  event: "AI_INDEXING_STARTED",
  correlationId,
  timestamp: operationTimestamp,
  principal,
  action: "PineconeStore.fromDocuments",
  modelId: MODEL_ID,
  pineconeIndex: process.env.PINECONE_INDEX,
  pineconeEnvironment: process.env.PINECONE_ENVIRONMENT,
  documentCount: filteredDocs.length,
  inputDocumentsHash: inputHash,
});

try {
  await PineconeStore.fromDocuments(
    filteredDocs,
    new OpenAIEmbeddings({ openAIApiKey: config.openai.apiKey }),
    {
      pineconeIndex,
    }
  );

  // Write the post-operation success audit record
  writeAuditRecord({
    event: "AI_INDEXING_COMPLETED",
    correlationId,
    timestamp: new Date().toISOString(),
    principal,
    action: "PineconeStore.fromDocuments",
    modelId: MODEL_ID,
    pineconeIndex: process.env.PINECONE_INDEX,
    documentCount: filteredDocs.length,
    inputDocumentsHash: inputHash,
    status: "SUCCESS",
  });
} catch (err) {
  // Write the failure audit record before re-throwing
  writeAuditRecord({
    event: "AI_INDEXING_FAILED",
    correlationId,
    timestamp: new Date().toISOString(),
    principal,
    action: "PineconeStore.fromDocuments",
    modelId: MODEL_ID,
    pineconeIndex: process.env.PINECONE_INDEX,
    documentCount: filteredDocs.length,
    inputDocumentsHash: inputHash,
    status: "FAILURE",
    error: err.message,
  });
  throw err;
}
