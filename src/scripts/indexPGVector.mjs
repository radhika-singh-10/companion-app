// Call embeding API and insert to supabase
// Ref: https://js.langchain.com/docs/modules/indexes/vector_stores/integrations/supabase

import dotenv from "dotenv";
import { Document } from "langchain/document";
import { OpenAIEmbeddings } from "langchain/embeddings/openai";

// Approved model registry — only models listed here may be used.
const APPROVED_EMBEDDING_MODELS = new Set([
  "text-embedding-ada-002",
]);

const PINNED_EMBEDDING_MODEL = "text-embedding-ada-002";

if (!APPROVED_EMBEDDING_MODELS.has(PINNED_EMBEDDING_MODEL)) {
  throw new Error(
    `Model "${PINNED_EMBEDDING_MODEL}" is not in the approved model registry. ` +
    `Approved models: ${[...APPROVED_EMBEDDING_MODELS].join(", ")}`
  );
}
import { SupabaseVectorStore } from "langchain/vectorstores/supabase";
import { createClient } from "@supabase/supabase-js";
import { CharacterTextSplitter } from "langchain/text_splitter";
import crypto from "crypto";
import os from "os";

import fs from "fs";
import path from "path";

// Redact common PII patterns from text before indexing
function redactPII(text) {
  // Redact email addresses
  text = text.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, "[REDACTED_EMAIL]");
  // Redact US phone numbers (various formats)
  text = text.replace(/(\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}/g, "[REDACTED_PHONE]");
  // Redact US Social Security Numbers
  text = text.replace(/\b\d{3}[\s.-]\d{2}[\s.-]\d{4}\b/g, "[REDACTED_SSN]");
  // Redact credit card numbers (16-digit, optionally grouped)
  text = text.replace(/\b(?:\d{4}[\s.-]?){3}\d{4}\b/g, "[REDACTED_CC]");
  // Redact IP addresses
  text = text.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "[REDACTED_IP]");
  return text;
}

/**
 * Sanitize file content to prevent prompt injection and malicious payloads.
 * Throws an error if suspicious content is detected.
 */
function sanitizeFileContent(content, fileName) {
  // 1. Reject binary / non-printable content (allow common whitespace only)
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(content)) {
    throw new Error(`[SECURITY] Binary or non-printable characters detected in ${fileName}`);
  }

  // 2. Detect invisible / zero-width characters used to hide prompts
  if (/[\u200B-\u200D\uFEFF\u2060\u00AD]/.test(content)) {
    throw new Error(`[SECURITY] Invisible/zero-width characters detected in ${fileName}`);
  }

  // 3. Detect base64-encoded blobs (long runs of base64 chars)
  if (/[A-Za-z0-9+/]{200,}={0,2}/.test(content)) {
    throw new Error(`[SECURITY] Possible base64-encoded payload detected in ${fileName}`);
  }

  // 4. Detect common shell commands / executable patterns
  const shellPatterns = [
    /\b(bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess)\s*[({[]/i,
    /\b(curl|wget|nc|ncat|netcat|chmod|chown|sudo|su\b)/i,
    /<script[\s>]/i,
    /\$\([^)]*\)/,   // $(command)
    /`[^`]+`/,       // backtick execution
  ];
  for (const pattern of shellPatterns) {
    if (pattern.test(content)) {
      throw new Error(`[SECURITY] Shell command or executable pattern detected in ${fileName}`);
    }
  }

  // 5. Detect prompt-injection keywords targeting LLM system prompts
  const injectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /disregard\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /forget\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /you\s+are\s+now\s+(a|an)\s+/i,
    /act\s+as\s+(a|an)\s+/i,
    /new\s+instructions?:/i,
    /system\s*prompt/i,
    /\[INST\]/i,
    /<\|im_start\|>/i,
    /###\s*instruction/i,
  ];
  for (const pattern of injectionPatterns) {
    if (pattern.test(content)) {
      throw new Error(`[SECURITY] Prompt injection pattern detected in ${fileName}`);
    }
  }

  // 6. Detect leetspeak obfuscation (simple heuristic: high ratio of digit-letter substitutions)
  const leetspeakPattern = /(?:[i1][g9][n][o0][r][e3]|[s5][y][s5][t][e3][m]|[e3][x][e3][c])/i;
  if (leetspeakPattern.test(content)) {
    throw new Error(`[SECURITY] Possible leetspeak obfuscation detected in ${fileName}`);
  }

  // 7. Reject files that are unreasonably large (> 1 MB) to prevent resource exhaustion
  if (content.length > 1_000_000) {
    throw new Error(`[SECURITY] File ${fileName} exceeds maximum allowed size of 1 MB`);
  }

  return content;
}

dotenv.config({ path: `.env.local` });

// Validate required credentials are supplied via environment variables only
const REQUIRED_ENV_VARS = ["SUPABASE_URL", "SUPABASE_PRIVATE_KEY", "OPENAI_API_KEY"];
for (const envVar of REQUIRED_ENV_VARS) {
  if (!process.env[envVar]) {
    throw new Error(`Missing required environment variable: ${envVar}. Credentials must be provided via environment variables, not hardcoded.`);
  }
}

const MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024; // 1 MB limit per file
const MAX_CONTENT_LENGTH = 100_000; // max characters after extraction

/**
 * Sanitizes and validates raw file content before sending to the AI model.
 * @param {string} content - Raw string content read from disk.
 * @param {string} fileName - File name used for error context.
 * @returns {string} - Sanitized content safe to pass to the embedding model.
 */
function sanitizeAndValidateContent(content, fileName) {
  if (typeof content !== "string") {
    throw new Error(`[${fileName}] File content must be a string.`);
  }

  // Remove null bytes
  let sanitized = content.replace(/\0/g, "");

  // Strip non-printable ASCII control characters (except common whitespace: \t, \n, \r)
  // eslint-disable-next-line no-control-regex
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

  // Collapse sequences of more than 3 consecutive newlines to reduce noise
  sanitized = sanitized.replace(/\n{3,}/g, "\n\n");

  // Trim leading/trailing whitespace
  sanitized = sanitized.trim();

  if (sanitized.length === 0) {
    throw new Error(`[${fileName}] File content is empty after sanitization.`);
  }

  if (sanitized.length > MAX_CONTENT_LENGTH) {
    throw new Error(
      `[${fileName}] Sanitized content exceeds maximum allowed length of ${MAX_CONTENT_LENGTH} characters.`
    );
  }

  return sanitized;
}

/**
 * Redacts Singapore-specific PII from text before indexing.
 * Covers: NRIC/FIN numbers, SingPass identifiers, Singapore phone numbers,
 * Singapore postal codes, Singapore addresses, and general PII (email, generic IDs).
 */
function redactSingaporePII(text) {
  // NRIC Number: S/T/F/G followed by 7 digits and a letter (e.g. S1234567D)
  text = text.replace(/\b[STFG]\d{7}[A-Z]\b/gi, "[REDACTED_NRIC]");

  // FIN Number: same format as NRIC but starting with F or G
  // (already covered above, but explicit pattern for clarity)
  text = text.replace(/\b[FG]\d{7}[A-Z]\b/gi, "[REDACTED_FIN]");

  // SingPass Identifier: typically an NRIC used as a SingPass login,
  // but also catch patterns like "SingPass ID: SXXXXXXXX"
  text = text.replace(/(singpass\s*(id|identifier|login|user)?\s*[:\-]?\s*)[STFG]\d{7}[A-Z]/gi, "$1[REDACTED_SINGPASS_ID]");

  // Singapore phone numbers: +65 followed by 8 digits, or local 8-digit numbers starting with 6, 8, or 9
  text = text.replace(/(\+65[\s\-]?)?\b[689]\d{7}\b/g, "[REDACTED_SG_PHONE]");

  // Singapore postal codes: 6-digit codes (Singapore uses 6-digit postal codes)
  text = text.replace(/\bSingapore\s+\d{6}\b/gi, "Singapore [REDACTED_POSTAL_CODE]");
  text = text.replace(/\b(postal\s*code|zip\s*code)?\s*\d{6}\b/gi, "[REDACTED_POSTAL_CODE]");

  // Email addresses
  text = text.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, "[REDACTED_EMAIL]");

  // Singapore UEN (Unique Entity Number): 9-10 alphanumeric characters
  text = text.replace(/\b\d{8,9}[A-Z]\b/g, "[REDACTED_UEN]");

  // CPF Account numbers (similar format to NRIC, already covered, but explicit)
  text = text.replace(/(cpf\s*(account|no|number)?\s*[:\-]?\s*)[STFG]\d{7}[A-Z]/gi, "$1[REDACTED_CPF]");

  // Passport numbers (general alphanumeric, 6-9 chars)
  text = text.replace(/(passport\s*(no|number)?\s*[:\-]?\s*)[A-Z0-9]{6,9}\b/gi, "$1[REDACTED_PASSPORT]");

  // Bank account numbers (generic pattern)
  text = text.replace(/(account\s*(no|number)?\s*[:\-]?\s*)\d{7,16}\b/gi, "$1[REDACTED_BANK_ACCOUNT]");

  // Credit/debit card numbers (16-digit groups)
  text = text.replace(/\b(?:\d[ \-]?){13,16}\b/g, "[REDACTED_CARD_NUMBER]");

  return text;
}

const COMPANIONS_DIR = path.resolve("companions");
const MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024; // 1 MB limit
const fileNames = fs.readdirSync(COMPANIONS_DIR);
const splitter = new CharacterTextSplitter({
  separator: " ",
  chunkSize: 200,
  chunkOverlap: 50, //TODO: adjust both chunk size and chunk overlap later
});

// Data-minimisation constants
const MAX_SECTION_CHARS = 8000; // hard cap on injected content size
// Patterns considered sensitive — lines matching these are redacted before embedding
const SENSITIVE_LINE_PATTERN =
  /([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}|(?:api[_\-]?key|secret|token|password|bearer)\s*[:=]\s*\S+)/i;

/**
 * Sanitise a raw companion-file section before it enters the embedding pipeline.
 * - Removes lines that contain sensitive data patterns.
 * - Truncates to MAX_SECTION_CHARS to enforce a size limit.
 * - Trims surrounding whitespace.
 */
function sanitiseSection(raw) {
  const lines = raw.split("\n");
  const filtered = lines
    .filter((line) => !SENSITIVE_LINE_PATTERN.test(line))
    .join("\n");
  return filtered.trim().slice(0, MAX_SECTION_CHARS);
}

/**
 * Sanitizes text content before it is passed to the AI pipeline.
 * Throws or returns null if suspicious content is detected.
 */
function sanitizeContent(text, fileName) {
  // 1. Reject binary content (non-printable characters outside normal whitespace)
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(text)) {
    console.warn(`[SECURITY] Binary/non-printable characters detected in ${fileName}. Skipping.`);
    return null;
  }

  // 2. Strip invisible / zero-width characters (prompt injection via hidden text)
  const invisibleCharsPattern = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/g;
  if (invisibleCharsPattern.test(text)) {
    console.warn(`[SECURITY] Invisible/zero-width characters detected in ${fileName}. Stripping.`);
    text = text.replace(invisibleCharsPattern, "");
  }

  // 3. Detect base64-encoded blobs (long runs of base64 chars)
  if (/(?:[A-Za-z0-9+\/]{40,}={0,2})/.test(text)) {
    console.warn(`[SECURITY] Possible base64-encoded content detected in ${fileName}. Skipping.`);
    return null;
  }

  // 4. Detect shell commands / executable patterns
  const shellPatterns = [
    /\b(bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess)\s*[\(\[`]/i,
    /\b(curl|wget|nc|ncat|netcat|chmod|chown|sudo|su|rm\s+-rf|mkfifo)\b/i,
    /[;&|`$]\s*\w+/,
    /<\s*script[^>]*>/i,
  ];
  for (const pattern of shellPatterns) {
    if (pattern.test(text)) {
      console.warn(`[SECURITY] Shell command/executable pattern detected in ${fileName}. Skipping.`);
      return null;
    }
  }

  // 5. Detect leetspeak obfuscation (e.g. 3x3cut3, 1nj3ct)
  const leetspeakPattern = /\b[a-z0-9]*[013456789][a-z0-9]*[013456789][a-z0-9]*\b/i;
  const leetspeakWords = text.match(/\b\w{4,}\b/g) || [];
  const suspiciousLeet = leetspeakWords.filter(
    (w) => leetspeakPattern.test(w) && /[013456789]/.test(w) && /[a-zA-Z]/.test(w)
  );
  if (suspiciousLeet.length > 5) {
    console.warn(`[SECURITY] Possible leetspeak obfuscation detected in ${fileName}. Skipping.`);
    return null;
  }

  // 6. Detect prompt injection keywords
  const injectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /disregard\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /you\s+are\s+now\s+(a|an)?\s*\w+/i,
    /act\s+as\s+(a|an)?\s*\w+/i,
    /new\s+instructions?:/i,
    /system\s*prompt/i,
    /jailbreak/i,
    /\[INST\]/i,
    /<\|im_start\|>/i,
  ];
  for (const pattern of injectionPatterns) {
    if (pattern.test(text)) {
      console.warn(`[SECURITY] Prompt injection keyword detected in ${fileName}. Skipping.`);
      return null;
    }
  }

  return text;
}

const EMBEDDING_MODEL = "text-embedding-ada-002";
const EMBEDDING_PROVIDER = "openai";
const CONTENT_ORIGIN = "companions-seed-chat";
const AI_GENERATED_LABEL = "ai-generated-embedding";

const langchainDocs = await Promise.all(
  fileNames.map(async (fileName) => {
    if (fileName.endsWith(".txt")) {
      const filePath = path.join("companions", fileName);
            const fileContent = fs.readFileSync(filePath, "utf8");
      const lastSection = fileContent.split("###ENDSEEDCHAT###").slice(-1)[0];
      const redactedSection = redactSingaporePII(lastSection);
      const splitDocs = await splitter.createDocuments([redactedSection]);
      const indexedAt = new Date().toISOString();
      return splitDocs.map((doc) => {
        return new Document({
          metadata: {
            fileName,
            // AI provenance metadata
            aiGenerated: true,
            contentLabel: AI_GENERATED_LABEL,
            embeddingModel: EMBEDDING_MODEL,
            embeddingProvider: EMBEDDING_PROVIDER,
            contentOrigin: CONTENT_ORIGIN,
            indexedAt,
          },
          pageContent: doc.pageContent,
        });
      });
    }
  })
);
      const fileContent = fs.readFileSync(filePath, "utf8");
      const lastSection = fileContent.split("###ENDSEEDCHAT###").slice(-1)[0];

      const sanitized = sanitizeContent(lastSection, fileName);
      if (sanitized === null) {
        console.warn(`[SECURITY] Skipping file due to policy violation: ${fileName}`);
        return [];
      }

      const splitDocs = await splitter.createDocuments([sanitized]);
      return splitDocs.map((doc) => {
        return new Document({
          metadata: { fileName },
          pageContent: doc.pageContent,
        });
      });
    }
  })
);

      // Validate file size before reading full content
      const fileStat = fs.statSync(filePath);
      if (fileStat.size > MAX_FILE_SIZE_BYTES) {
        throw new Error(
          `[${fileName}] File size (${fileStat.size} bytes) exceeds the maximum allowed size of ${MAX_FILE_SIZE_BYTES} bytes.`
        );
      }

      const rawContent = fs.readFileSync(filePath, "utf8");

      // Sanitize and validate before any further processing or AI model calls
      const fileContent = sanitizeAndValidateContent(rawContent, fileName);

      const rawSection = fileContent.split("###ENDSEEDCHAT###").slice(-1)[0];
      const lastSection = sanitiseSection(rawSection);
      if (!lastSection) return []; // nothing left after sanitisation — skip file
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

const auth = {
  detectSessionInUrl: false,
  persistSession: false,
  autoRefreshToken: false,
};

const client = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_PRIVATE_KEY,
  { auth }
);

// Sanitization helper: validates that an embedding vector is safe
function sanitizeEmbedding(embedding, context = "") {
  if (!Array.isArray(embedding)) {
    throw new Error(`[LLM Output Validation] Embedding is not an array. Context: ${context}`);
  }
  for (const value of embedding) {
    if (typeof value !== "number" || !isFinite(value)) {
      throw new Error(
        `[LLM Output Validation] Embedding contains a non-finite or non-numeric value: ${value}. Context: ${context}`
      );
    }
  }
  // Guard against dynamic code execution primitives smuggled in the serialized form
  const serialized = JSON.stringify(embedding);
  const dangerousPatterns = [
    /\beval\s*\(/,
    /\bexec\s*\(/,
    /\bFunction\s*\(/,
    /\bnew\s+Function\b/,
    /\bsetTimeout\s*\(/,
    /\bsetInterval\s*\(/,
    /\bimport\s*\(/,
    /\brequire\s*\(/,
  ];
  for (const pattern of dangerousPatterns) {
    if (pattern.test(serialized)) {
      throw new Error(
        `[LLM Output Validation] Dangerous code execution primitive detected in embedding output. Pattern: ${pattern}. Context: ${context}`
      );
    }
  }
  return embedding;
}

// Wrap OpenAIEmbeddings to intercept and validate all returned vectors
class SafeOpenAIEmbeddings extends OpenAIEmbeddings {
  async embedDocuments(texts) {
    const embeddings = await super.embedDocuments(texts);
    if (!Array.isArray(embeddings)) {
      throw new Error("[LLM Output Validation] embedDocuments did not return an array.");
    }
    return embeddings.map((emb, i) => sanitizeEmbedding(emb, `embedDocuments[${i}]`));
  }

  async embedQuery(text) {
    const embedding = await super.embedQuery(text);
    return sanitizeEmbedding(embedding, `embedQuery('${text.slice(0, 40)}...')`);
  }
}

// ── Audit / forensic setup ──────────────────────────────────────────────────
const AUDIT_LOG_PATH = "audit.log";

function appendAuditLog(record) {
  const line = JSON.stringify(record) + "\n";
  fs.appendFileSync(AUDIT_LOG_PATH, line, "utf8");
  console.log("[AUDIT]", line.trim());
}

const filteredDocs = langchainDocs.flat().filter((doc) => doc !== undefined);

// Build forensic context before the AI-driven operation
const traceId = crypto.randomUUID();
const modelIdentifier = "text-embedding-ada-002"; // OpenAIEmbeddings default
const modelVersion = "openai/text-embedding-ada-002@v2";
const principal = os.userInfo().username;
const sourceFiles = [...new Set(filteredDocs.map((d) => d.metadata?.fileName).filter(Boolean))];
const inputPayload = filteredDocs.map((d) => d.pageContent).join("\n");
const inputHash = crypto.createHash("sha256").update(inputPayload, "utf8").digest("hex");
const operationStartTs = new Date().toISOString();
const startTime = Date.now();

const auditRecordStart = {
  traceId,
  event: "embedding_operation_start",
  timestamp: operationStartTs,
  principal,
  model: modelIdentifier,
  modelVersion,
  inputHash,
  documentCount: filteredDocs.length,
  sourceFiles,
  targetTable: "documents",
  supabaseUrl: process.env.SUPABASE_URL,
};
appendAuditLog(auditRecordStart);
// ────────────────────────────────────────────────────────────────────────────

try {
  await SupabaseVectorStore.fromDocuments(
    filteredDocs,
    new OpenAIEmbeddings({
    openAIApiKey: process.env.OPENAI_API_KEY,
    modelName: PINNED_EMBEDDING_MODEL, // explicit version pin — never rely on SDK default
  }),
    {
      client,
      tableName: "documents",
    }
  );

  // Audit: successful completion
  appendAuditLog({
    traceId,
    event: "embedding_operation_success",
    timestamp: new Date().toISOString(),
    principal,
    model: modelIdentifier,
    modelVersion,
    inputHash,
    documentCount: filteredDocs.length,
    sourceFiles,
    targetTable: "documents",
    durationMs: Date.now() - startTime,
  });
} catch (err) {
  // Audit: failure with error context for forensic reconstruction
  appendAuditLog({
    traceId,
    event: "embedding_operation_failure",
    timestamp: new Date().toISOString(),
    principal,
    model: modelIdentifier,
    modelVersion,
    inputHash,
    documentCount: filteredDocs.length,
    sourceFiles,
    targetTable: "documents",
    durationMs: Date.now() - startTime,
    error: err.message,
  });
  throw err;
}
