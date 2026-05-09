// Call embeding API and insert to supabase
// Ref: https://js.langchain.com/docs/modules/indexes/vector_stores/integrations/supabase

// ---------------------------------------------------------------------------
// Approved model registry – only models listed here may be instantiated.
// Pin each entry to an immutable model identifier supplied by the provider.
// ---------------------------------------------------------------------------
const APPROVED_EMBEDDING_MODELS = new Set([
  "text-embedding-3-small",   // OpenAI stable release, 2024-01
  "text-embedding-3-large",   // OpenAI stable release, 2024-01
  "text-embedding-ada-002",   // OpenAI stable release, 2022-12
]);

// The single source-of-truth model identifier used throughout this script.
const EMBEDDING_MODEL_ID = "text-embedding-3-small";

if (!APPROVED_EMBEDDING_MODELS.has(EMBEDDING_MODEL_ID)) {
  throw new Error(
    `Model "${EMBEDDING_MODEL_ID}" is not in the approved registry. ` +
    `Approved models: ${[...APPROVED_EMBEDDING_MODELS].join(", ")}`
  );
}

import dotenv from "dotenv";
import { Document } from "langchain/document";
import { OpenAIEmbeddings } from "langchain/embeddings/openai";
import { SupabaseVectorStore } from "langchain/vectorstores/supabase";
import { createClient } from "@supabase/supabase-js";
import { CharacterTextSplitter } from "langchain/text_splitter";
import crypto from "crypto";

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Resolve the absolute path of the allowed base directory
const COMPANIONS_BASE_DIR = path.resolve(__dirname, "../../companions");

// ---------------------------------------------------------------------------
// Audit logging helpers
// ---------------------------------------------------------------------------
const AUDIT_LOG_FILE = "audit_index_pgvector.jsonl";
const MODEL_ID = "text-embedding-ada-002"; // OpenAI default embedding model
const RETENTION_DAYS = 90;                 // Operator-defined retention period

function writeAuditRecord(record) {
  const line = JSON.stringify(record) + "\n";
  fs.appendFileSync(AUDIT_LOG_FILE, line, "utf8");
  console.log("[AUDIT]", JSON.stringify(record));
}

function hashContent(content) {
  return crypto.createHash("sha256").update(content).digest("hex");
}
// ---------------------------------------------------------------------------

/**
 * Scans text for Singapore PII categories and redacts them.
 * Categories covered:
 *   - NRIC/FIN numbers (e.g. S1234567A, T0012345B, F1234567C, G1234567D)
 *   - Singapore mobile numbers (+65 8/9 XXXXXXX or local 8/9XXXXXXX)
 *   - Personal email addresses
 *   - Passport numbers (generic alphanumeric)
 *   - Dates of birth (common formats)
 *   - Postal codes (6-digit Singapore postal codes)
 *   - Full name heuristic (Title + Capitalised words)
 * Throws an error listing detected PII types so the file is not indexed.
 */
function scanAndRedactSingaporePII(text) {
  const piiPatterns = [
    {
      name: "NRIC/FIN Number",
      pattern: /\b[STFG]\d{7}[A-Z]\b/gi,
    },
    {
      name: "Singapore Mobile Number",
      pattern: /(?:\+65[\s-]?)?[89]\d{3}[\s-]?\d{4}\b/g,
    },
    {
      name: "Personal Email Address",
      pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
    },
    {
      name: "Passport Number",
      pattern: /\b[A-Z]{1,2}\d{6,9}\b/g,
    },
    {
      name: "Date of Birth",
      pattern: /\b(?:\d{1,2}[\/-]\d{1,2}[\/-]\d{2,4}|\d{4}[\/-]\d{2}[\/-]\d{2})\b/g,
    },
    {
      name: "Singapore Postal Code",
      pattern: /\bSingapore\s+\d{6}\b/gi,
    },
    {
      name: "Full Name (Title + Name)",
      pattern: /\b(?:Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3}\b/g,
    },
  ];

  const detectedTypes = [];
  let redacted = text;

  for (const { name, pattern } of piiPatterns) {
    if (pattern.test(redacted)) {
      detectedTypes.push(name);
    }
    // Reset lastIndex for global patterns after test()
    pattern.lastIndex = 0;
    redacted = redacted.replace(pattern, `[REDACTED-${name.replace(/\s+/g, "_").toUpperCase()}]`);
  }

  if (detectedTypes.length > 0) {
    throw new Error(
      `Singapore PII detected in file content. Detected categories: ${detectedTypes.join(", ")}. ` +
      `File will not be indexed. Please remove PII before re-running this script.`
    );
  }

  return redacted;
}

/**
 * Redacts common PII categories from a string.
 * Categories covered: email, phone number, SSN, credit card,
 * street address, date of birth, and IP address.
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

  // Credit card numbers (16 digits, optionally separated by spaces or dashes)
  text = text.replace(/\b(?:\d{4}[\s\-]?){3}\d{4}\b/g, "[REDACTED_CC]");

  // Street addresses (e.g., 123 Main St, 456 Elm Avenue)
  text = text.replace(
    /\b\d{1,5}\s+[A-Za-z0-9\s,.']+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Circle|Cir|Trail|Tr|Terrace|Ter)\b[.,]?/gi,
    "[REDACTED_ADDRESS]"
  );

  // Dates of birth (MM/DD/YYYY, DD-MM-YYYY, YYYY-MM-DD)
  text = text.replace(
    /\b(?:\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}|\d{4}[\/\-]\d{1,2}[\/\-]\d{1,2})\b/g,
    "[REDACTED_DOB]"
  );

  // IP addresses (IPv4)
  text = text.replace(
    /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    "[REDACTED_IP]"
  );

  return text;
}

/**
 * Sanitizes and validates file content before passing it to the AI pipeline.
 * Throws an error if suspicious content is detected.
 */
function sanitizeFileContent(content, fileName) {
  const MAX_FILE_SIZE = 500_000; // 500 KB limit

  // 1. Enforce maximum size
  if (content.length > MAX_FILE_SIZE) {
    throw new Error(`[Security] File "${fileName}" exceeds maximum allowed size.`);
  }

  // 2. Reject binary content (null bytes indicate binary/executable data)
  if (content.includes("\x00")) {
    throw new Error(`[Security] File "${fileName}" contains binary/null-byte content and was rejected.`);
  }

  // 3. Strip invisible and zero-width characters (prompt injection via hidden text)
  const invisibleCharsPattern = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/g;
  if (invisibleCharsPattern.test(content)) {
    console.warn(`[Security] File "${fileName}" contained invisible/zero-width characters. Stripping them.`);
    content = content.replace(invisibleCharsPattern, "");
  }

  // 4. Reject base64-encoded blobs (long base64 strings may encode hidden instructions)
  const base64Pattern = /(?:[A-Za-z0-9+\/]{60,}={0,2})/g;
  if (base64Pattern.test(content)) {
    throw new Error(`[Security] File "${fileName}" contains suspected base64-encoded content and was rejected.`);
  }

  // 5. Reject shell command patterns
  const shellCommandPattern = /(?:bash|sh|cmd|powershell|exec|eval|system|popen|subprocess|os\.system|`[^`]+`|\$\([^)]+\))/i;
  if (shellCommandPattern.test(content)) {
    throw new Error(`[Security] File "${fileName}" contains suspected shell command patterns and was rejected.`);
  }

  // 6. Reject common prompt injection / jailbreak patterns (including leetspeak variants)
  const promptInjectionPattern = /(?:ignore\s+(all\s+)?previous\s+instructions?|you\s+are\s+now|disregard\s+(all\s+)?prior|act\s+as\s+(a\s+)?(?:an?\s+)?(?:evil|unrestricted|jailbroken|DAN)|system\s*:\s*you|<\s*script\s*>|\[INST\]|\[\[\s*system|1gnor3|1nstruct10n|pr0mpt)/i;
  if (promptInjectionPattern.test(content)) {
    throw new Error(`[Security] File "${fileName}" contains suspected prompt injection or leetspeak patterns and was rejected.`);
  }

  return content;
}

/**
 * Sanitizes file content to prevent prompt injection attacks.
 * Throws an error if malicious content is detected.
 */
function sanitizeFileContent(content, fileName) {
  // 1. Reject files containing non-printable / invisible characters (except normal whitespace)
  // Zero-width spaces, soft hyphens, bidirectional overrides, etc.
  const invisibleCharPattern = /[\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00A0]/g;
  if (invisibleCharPattern.test(content)) {
    throw new Error(`[SECURITY] File "${fileName}" contains invisible/hidden characters that may indicate a prompt injection attempt.`);
  }

  // 2. Detect base64-encoded blobs (long runs of base64 chars) that could hide instructions
  const base64Pattern = /(?:[A-Za-z0-9+\/]{40,}={0,2})/g;
  const base64Matches = content.match(base64Pattern) || [];
  for (const match of base64Matches) {
    try {
      const decoded = Buffer.from(match, "base64").toString("utf8");
      // If the decoded string looks like readable text with injection keywords, reject it
      if (/ignore|disregard|system|prompt|instruction|assistant|user|role|jailbreak/i.test(decoded)) {
        throw new Error(`[SECURITY] File "${fileName}" contains base64-encoded content with suspicious instructions.`);
      }
    } catch (e) {
      if (e.message.startsWith("[SECURITY]")) throw e;
      // Not valid base64 text — ignore decode errors
    }
  }

  // 3. Detect leetspeak patterns used to obfuscate injection commands
  // e.g. "1gnor3", "d1sr3g4rd", "syst3m"
  const leetspeakInjectionPattern = /(?:1gn[o0]r[e3]|d[i1]sr[e3]g[a4]rd|[s5]y[s5]t[e3]m|[p9]r[o0]m[p9]t|[j]4[i1]lb[r]34k)/i;
  if (leetspeakInjectionPattern.test(content)) {
    throw new Error(`[SECURITY] File "${fileName}" contains leetspeak obfuscation that may indicate a prompt injection attempt.`);
  }

  // 4. Detect common prompt injection / jailbreak instruction patterns
  const injectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)/i,
    /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)/i,
    /forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)/i,
    /you\s+are\s+now\s+(a|an|the)\s+/i,
    /act\s+as\s+(a|an|the)\s+/i,
    /pretend\s+(you\s+are|to\s+be)\s+/i,
    /\[\s*system\s*\]/i,
    /<\s*system\s*>/i,
    /###\s*system/i,
    /new\s+instructions?\s*:/i,
    /override\s+(system|instructions?|prompt)/i,
    /jailbreak/i,
    /do\s+anything\s+now/i,
    /DAN\s+mode/i,
  ];
  for (const pattern of injectionPatterns) {
    if (pattern.test(content)) {
      throw new Error(`[SECURITY] File "${fileName}" contains suspicious prompt injection instructions matching pattern: ${pattern}`);
    }
  }

  // 5. Detect binary content / shell commands embedded in the file
  // Check for null bytes (binary indicator)
  if (content.includes("\x00")) {
    throw new Error(`[SECURITY] File "${fileName}" contains null bytes indicating binary content.`);
  }
  // Check for common shell command patterns
  const shellCommandPattern = /(?:bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess)\s*[\(\-]/i;
  if (shellCommandPattern.test(content)) {
    throw new Error(`[SECURITY] File "${fileName}" contains shell command patterns that may indicate malicious content.`);
  }
  // Check for shebang lines
  if (/^#!\s*\/(?:bin|usr)\//m.test(content)) {
    throw new Error(`[SECURITY] File "${fileName}" contains a shebang line indicating an embedded executable script.`);
  }

  // 6. Strip any remaining suspicious HTML/script tags that could carry injections
  const strippedContent = content
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<[^>]+>/g, "");

  return strippedContent;
}

// Sanitize and validate text before sending to LLM
const MAX_CHUNK_LENGTH = 10000; // max characters per chunk

function sanitizeAndValidate(text) {
  if (typeof text !== "string") {
    throw new Error("Document content must be a string.");
  }
  // Remove null bytes and non-printable control characters (except common whitespace)
  let sanitized = text.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  // Trim excessive whitespace
  sanitized = sanitized.trim();
  // Validate that content is not empty after sanitization
  if (sanitized.length === 0) {
    throw new Error("Document content is empty after sanitization.");
  }
  // Truncate if exceeding maximum allowed length
  if (sanitized.length > MAX_CHUNK_LENGTH) {
    sanitized = sanitized.slice(0, MAX_CHUNK_LENGTH);
  }
  return sanitized;
}

dotenv.config({ path: `.env.local` });

// Validate that only the expected external-system credentials are present
function getRequiredEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

// External system credentials (2 systems: Supabase, OpenAI)
const SUPABASE_URL = getRequiredEnv("SUPABASE_URL");
const SUPABASE_PRIVATE_KEY = getRequiredEnv("SUPABASE_PRIVATE_KEY");
const OPENAI_API_KEY = getRequiredEnv("OPENAI_API_KEY");

const fileNames = fs.readdirSync(COMPANIONS_BASE_DIR);
const splitter = new CharacterTextSplitter({
  separator: " ",
  chunkSize: 200,
  chunkOverlap: 50, //TODO: adjust both chunk size and chunk overlap later
});

// Data minimisation: maximum characters allowed from the knowledge section per file.
const MAX_SECTION_CHARS = 4000;

/**
 * Minimise raw section content before embedding:
 *  - Remove lines beginning with '#' (headings / directives / metadata markers)
 *  - Remove lines beginning with '---' (separator markers)
 *  - Collapse excessive whitespace
 *  - Hard-cap total length to MAX_SECTION_CHARS
 */
function minimiseSection(raw) {
  const allowedLines = raw
    .split("\n")
    .filter((line) => {
      const trimmed = line.trim();
      if (trimmed.startsWith("#")) return false;   // strip directive/metadata lines
      if (trimmed.startsWith("---")) return false;  // strip separator markers
      return true;
    })
    .join("\n")
    .trim();
  // Hard cap to prevent unbounded content injection
  return allowedLines.slice(0, MAX_SECTION_CHARS);
}

const langchainDocs = await Promise.all(
  fileNames.map(async (fileName) => {
    if (fileName.endsWith(".txt")) {
      const filePath = path.join("companions", fileName);
      const rawContent = fs.readFileSync(filePath, "utf8");
      const fileContent = sanitizeFileContent(rawContent, fileName);
      const rawSection = fileContent.split("###ENDSEEDCHAT###").slice(-1)[0];
      const lastSection = minimiseSection(rawSection);
      if (!lastSection) return undefined; // nothing left after minimisation — skip file
      const splitDocs = await splitter.createDocuments([lastSection]);
      return splitDocs
        .map((doc) => {
          try {
            const sanitizedContent = sanitizeAndValidate(doc.pageContent);
            return new Document({
              metadata: { fileName },
              pageContent: sanitizedContent,
            });
          } catch (err) {
            console.warn(`Skipping chunk from ${fileName}: ${err.message}`);
            return undefined;
          }
        })
        .filter((doc) => doc !== undefined);
    }
  })
);

const auth = {
  detectSessionInUrl: false,
  persistSession: false,
  autoRefreshToken: false,
};

const client = createClient(
  SUPABASE_URL,
  SUPABASE_PRIVATE_KEY,
  { auth }
);

// Dangerous dynamic code execution primitives to detect in LLM output
const DANGEROUS_PATTERNS = [
  /\beval\s*\(/i,
  /\bexec\s*\(/i,
  /\bnew\s+Function\s*\(/i,
  /\bsetTimeout\s*\(\s*['"`]/i,
  /\bsetInterval\s*\(\s*['"`]/i,
  /\bsubprocess\b/i,
  /\bspawn\s*\(/i,
  /\bexecSync\s*\(/i,
  /\bexecFile\s*\(/i,
  /\brequire\s*\(\s*['"`]child_process/i,
  /\bimport\s*\(\s*['"`]child_process/i,
  /\bProcessBuilder\b/i,
  /\bRuntime\.getRuntime\b/i,
];

/**
 * Validates that a string value does not contain dynamic code execution primitives.
 * Throws an error if any dangerous pattern is detected.
 * @param {string} value - The string to validate.
 * @param {string} context - A label for error messages.
 */
function validateNoCodeExecution(value, context = "LLM output") {
  if (typeof value !== "string") return;
  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.test(value)) {
      throw new Error(
        `Security violation: Dangerous code execution primitive detected in ${context}. Pattern: ${pattern}`
      );
    }
  }
}

/**
 * Sanitizes a string by removing characters that are not expected in
 * normal text or embedding metadata (keeps alphanumeric, punctuation, whitespace).
 * @param {string} value
 * @returns {string}
 */
function sanitizeString(value) {
  if (typeof value !== "string") return value;
  // Strip null bytes and non-printable control characters (except common whitespace)
  return value.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
}

/**
 * Validates and sanitizes an array of embedding vectors returned by the LLM.
 * Embeddings should be arrays of finite numbers only.
 * @param {number[][]} embeddings
 * @returns {number[][]}
 */
function validateAndSanitizeEmbeddings(embeddings) {
  if (!Array.isArray(embeddings)) {
    throw new Error("Security violation: LLM embeddings output is not an array.");
  }
  return embeddings.map((embedding, i) => {
    if (!Array.isArray(embedding)) {
      throw new Error(
        `Security violation: Embedding at index ${i} is not an array.`
      );
    }
    return embedding.map((value, j) => {
      if (typeof value !== "number" || !isFinite(value)) {
        throw new Error(
          `Security violation: Non-numeric or non-finite value detected in embedding[${i}][${j}]: ${value}`
        );
      }
      return value;
    });
  });
}

// Wrap OpenAIEmbeddings to intercept and validate/sanitize LLM output
class ValidatedOpenAIEmbeddings extends OpenAIEmbeddings {
  async embedDocuments(texts) {
    // Validate input texts before sending to LLM
    for (const text of texts) {
      validateNoCodeExecution(text, "embedDocuments input");
    }
    const embeddings = await super.embedDocuments(texts);
    // Validate and sanitize the LLM embedding output
    return validateAndSanitizeEmbeddings(embeddings);
  }

  async embedQuery(text) {
    validateNoCodeExecution(text, "embedQuery input");
    const embedding = await super.embedQuery(text);
    if (!Array.isArray(embedding)) {
      throw new Error("Security violation: LLM query embedding output is not an array.");
    }
    const [validated] = validateAndSanitizeEmbeddings([embedding]);
    return validated;
  }
}

// Validate and sanitize documents before passing to the vector store
const docsToIndex = langchainDocs.flat().filter((doc) => doc !== undefined).map((doc) => {
  // Validate page content for dangerous patterns
  validateNoCodeExecution(doc.pageContent, "document pageContent");
  // Sanitize page content
  const sanitizedContent = sanitizeString(doc.pageContent);
  // Validate and sanitize metadata values
  const sanitizedMetadata = {};
  for (const [key, val] of Object.entries(doc.metadata || {})) {
    validateNoCodeExecution(String(val), `document metadata[${key}]`);
    sanitizedMetadata[key] = typeof val === "string" ? sanitizeString(val) : val;
  }
  return new Document({
    metadata: sanitizedMetadata,
    pageContent: sanitizedContent,
  });
});

// ---------------------------------------------------------------------------
// Audit: pre-action decision record
// ---------------------------------------------------------------------------
const traceId = crypto.randomUUID();          // correlation ID for this run
const principal = process.env.USER || process.env.USERNAME || "ci-service";
const docsToIndex = langchainDocs.flat().filter((doc) => doc !== undefined);
const inputHash = hashContent(
  docsToIndex.map((d) => d.pageContent).join("\n")
);

writeAuditRecord({
  event: "embedding_index_start",
  traceId,
  timestamp: new Date().toISOString(),
  principal,
  model: MODEL_ID,
  modelVersion: "latest",          // pin to a specific version in production
  tableName: "documents",
  documentCount: docsToIndex.length,
  inputHash,
  retentionPolicy: {
    retentionDays: RETENTION_DAYS,
    rotationRule: "delete-after-retention-period",
    note: "Operator must enforce retention/rotation on the 'documents' table.",
  },
});

// ---------------------------------------------------------------------------
// AI-driven action: generate embeddings and insert into vector store
// ---------------------------------------------------------------------------
try {
  await SupabaseVectorStore.fromDocuments(
    docsToIndex,
    new OpenAIEmbeddings({ openAIApiKey: OPENAI_API_KEY }),
    {
      client,
      tableName: "documents",
    }
  );

  // Audit: post-action completion record
  writeAuditRecord({
    event: "embedding_index_complete",
    traceId,
    timestamp: new Date().toISOString(),
    principal,
    model: MODEL_ID,
    tableName: "documents",
    documentCount: docsToIndex.length,
    inputHash,
    outcome: "success",
  });
} catch (err) {
  // Audit: failure record preserves causal chain
  writeAuditRecord({
    event: "embedding_index_error",
    traceId,
    timestamp: new Date().toISOString(),
    principal,
    model: MODEL_ID,
    tableName: "documents",
    documentCount: docsToIndex.length,
    inputHash,
    outcome: "failure",
    error: err.message,
  });
  throw err;
}
