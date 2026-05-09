// Call embeding API and insert to supabase
// Ref: https://js.langchain.com/docs/modules/indexes/vector_stores/integrations/supabase

import dotenv from "dotenv";
import { Document } from "langchain/document";
import { OpenAIEmbeddings } from "langchain/embeddings/openai";
import { SupabaseVectorStore } from "langchain/vectorstores/supabase";
import { createClient } from "@supabase/supabase-js";
import { CharacterTextSplitter } from "langchain/text_splitter";
import { createHash, randomUUID } from "crypto";
import os from "os";

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

// ---------------------------------------------------------------------------
// Audit logging helpers
// ---------------------------------------------------------------------------
const AUDIT_LOG_PATH = path.resolve("audit.log");
// Retention policy: audit log entries MUST be retained for a minimum of 90 days.
// Rotate / archive the file externally (e.g. logrotate) with `rotate 90` and
// `dateext` so that each rotated file is kept for at least 90 days before
// deletion. Do NOT truncate this file programmatically.

/**
 * Append a structured JSON audit record to the persistent audit log file
 * and echo it to stdout so that log-shipping agents can also capture it.
 *
 * @param {object} record - Arbitrary key/value audit fields.
 */
function writeAuditRecord(record) {
  const entry = JSON.stringify(record) + "\n";
  // Append-only write — never truncate.
  fs.appendFileSync(AUDIT_LOG_PATH, entry, { encoding: "utf8", flag: "a" });
  process.stdout.write("[AUDIT] " + entry);
}

/**
 * Compute a SHA-256 hex digest of the serialised document array so that the
 * exact input to the embedding model can be verified later.
 *
 * @param {Document[]} docs
 * @returns {string} hex digest
 */
function hashDocuments(docs) {
  const serialised = JSON.stringify(
    docs.map((d) => ({ pageContent: d.pageContent, metadata: d.metadata }))
  );
  return createHash("sha256").update(serialised, "utf8").digest("hex");
}

/**
 * Redacts common PII categories from a string.
 * Categories covered: email, phone number, SSN, credit card,
 * date of birth, IP address, and street address patterns.
 */
function redactPII(text) {
  // Email addresses
  text = text.replace(
    /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
    "[REDACTED_EMAIL]"
  );

  // Phone numbers (various formats: +1-800-555-1234, (800) 555-1234, 800.555.1234, etc.)
  text = text.replace(
    /(\+?1[\s.-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}/g,
    "[REDACTED_PHONE]"
  );

  // US Social Security Numbers (SSN): 123-45-6789 or 123 45 6789
  text = text.replace(
    /\b\d{3}[\s\-]\d{2}[\s\-]\d{4}\b/g,
    "[REDACTED_SSN]"
  );

  // Credit card numbers (16-digit, optionally separated by spaces or dashes)
  text = text.replace(
    /\b(?:\d{4}[\s\-]?){3}\d{4}\b/g,
    "[REDACTED_CREDIT_CARD]"
  );

  // Dates of birth (MM/DD/YYYY, MM-DD-YYYY, YYYY-MM-DD)
  text = text.replace(
    /\b(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}|\d{4}[\-]\d{2}[\-]\d{2})\b/g,
    "[REDACTED_DATE]"
  );

  // IPv4 addresses
  text = text.replace(
    /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    "[REDACTED_IP]"
  );

  // Street addresses (e.g., 123 Main St, 456 Elm Avenue, Apt 7)
  text = text.replace(
    /\b\d+\s+[A-Za-z0-9\s,.'#\-]+(Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Circle|Cir|Way|Place|Pl|Terrace|Ter)(\s+(Apt|Suite|Ste|Unit|#)\s*[\w\-]+)?\b/gi,
    "[REDACTED_ADDRESS]"
  );

  return text;
}

/**
 * Sanitizes file content to prevent prompt injection attacks.
 * Checks for: invisible/hidden characters, base64-encoded payloads,
 * leetspeak, suspicious instruction phrases, and binary/shell commands.
 */
function sanitizeFileContent(content, fileName) {
  // 1. Reject files containing non-printable / invisible control characters
  //    (excluding normal whitespace: tab, newline, carriage return)
  const invisibleCharsRegex = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u200B\u200C\u200D\u200E\u200F\uFEFF]/g;
  if (invisibleCharsRegex.test(content)) {
    throw new Error(
      `[SECURITY] File "${fileName}" contains invisible/control characters that may indicate a hidden prompt injection attempt. Skipping.`
    );
  }

  // 2. Detect suspiciously long base64-encoded strings (>100 chars of base64)
  const base64Regex = /(?:[A-Za-z0-9+\/]{4}){25,}(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?/g;
  if (base64Regex.test(content)) {
    throw new Error(
      `[SECURITY] File "${fileName}" contains what appears to be a base64-encoded payload. Skipping.`
    );
  }

  // 3. Detect common leetspeak substitution patterns used to obfuscate instructions
  //    e.g. "1gnor3", "4ct", "3x3cut3", "1nstruct"
  const leetspeakRegex = /\b(?:[a-z]*[0-9][a-z0-9]*){3,}\b/gi;
  const leetspeakMatches = content.match(leetspeakRegex) || [];
  if (leetspeakMatches.length > 5) {
    throw new Error(
      `[SECURITY] File "${fileName}" contains excessive leetspeak patterns that may indicate obfuscated prompt injection. Skipping.`
    );
  }

  // 4. Detect suspicious prompt-injection instruction phrases
  const suspiciousPhrasesRegex = /\b(?:ignore\s+(?:all\s+)?(?:previous|above|prior|earlier)\s+instructions?|disregard\s+(?:all\s+)?(?:previous|above|prior|earlier)\s+instructions?|forget\s+(?:all\s+)?(?:previous|above|prior|earlier)\s+instructions?|you\s+are\s+now\s+(?:a|an)\s+|act\s+as\s+(?:a|an)\s+|pretend\s+(?:you\s+are|to\s+be)\s+|your\s+new\s+(?:role|persona|instructions?|task)\s+(?:is|are)|system\s*:\s*you\s+are|<\s*system\s*>|\[\s*system\s*\]|###\s*system|new\s+instructions?\s*:|override\s+instructions?|jailbreak|prompt\s+injection)/gi;
  if (suspiciousPhrasesRegex.test(content)) {
    throw new Error(
      `[SECURITY] File "${fileName}" contains suspicious prompt-injection phrases. Skipping.`
    );
  }

  // 5. Detect shell commands or binary-like sequences
  const shellCommandRegex = /(?:(?:^|\s)(?:\/bin\/|sudo\s|chmod\s|chown\s|curl\s|wget\s|bash\s|sh\s|exec\s|eval\s|rm\s+-rf|nc\s+|ncat\s+|python\s+-c|perl\s+-e|ruby\s+-e)|\$\([^)]{0,100}\)|`[^`]{0,100}`|\|\s*(?:bash|sh|zsh|python|perl|ruby))/gim;
  if (shellCommandRegex.test(content)) {
    throw new Error(
      `[SECURITY] File "${fileName}" contains shell commands or binary sequences. Skipping.`
    );
  }

  return content;
}

dotenv.config({ path: `.env.local` });

// Maximum allowed file size in bytes (e.g. 1 MB)
const MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024;

/**
 * Sanitizes and validates raw text content before it is sent to the AI model.
 * @param {string} content - Raw text read from a file.
 * @param {string} fileName - File name used for error context.
 * @returns {string} Sanitized content.
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

  // Collapse sequences of more than 5 consecutive newlines to prevent prompt injection via whitespace
  sanitized = sanitized.replace(/(\r?\n){5,}/g, "\n\n");

  // Trim leading/trailing whitespace
  sanitized = sanitized.trim();

  if (sanitized.length === 0) {
    throw new Error(`[${fileName}] File content is empty after sanitization.`);
  }

  return sanitized;
}

const fileNames = fs.readdirSync("companions");
const splitter = new CharacterTextSplitter({
  separator: " ",
  chunkSize: 200,
  chunkOverlap: 50, //TODO: adjust both chunk size and chunk overlap later
});

// Maximum characters allowed from the last section to prevent full-document injection
const MAX_SECTION_CHARS = 2000;

// Sensitive field patterns to redact before embedding
const SENSITIVE_LINE_PATTERN = /(?:password|secret|token|api[_\-]?key|private[_\-]?key|email|ssn|credit[_\-]?card|bearer)/i;

/**
 * Minimise and sanitise a document section before embedding:
 * - Removes lines containing sensitive field indicators
 * - Caps total length to MAX_SECTION_CHARS
 */
function sanitiseSection(raw) {
  const lines = raw.split(/\r?\n/);
  const filtered = lines.filter((line) => !SENSITIVE_LINE_PATTERN.test(line));
  const joined = filtered.join("\n").trim();
  return joined.slice(0, MAX_SECTION_CHARS);
}

/**
 * Sanitizes document content before passing it to the AI embedding pipeline.
 * Defends against prompt injection, hidden instructions, base64 payloads,
 * invisible characters, leetspeak obfuscation, and shell command patterns.
 */
function sanitizeContent(text) {
  if (typeof text !== "string") {
    throw new Error("Content must be a string.");
  }

  const MAX_LENGTH = 100_000;
  if (text.length > MAX_LENGTH) {
    throw new Error(`Content exceeds maximum allowed length of ${MAX_LENGTH} characters.`);
  }

  // Reject content with binary / non-printable characters (except common whitespace)
  // Allow: tab (\x09), newline (\x0A), carriage return (\x0D), and printable ASCII/Unicode
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(text)) {
    throw new Error("Content contains binary or non-printable control characters.");
  }

  // Strip zero-width and invisible Unicode characters (common in hidden-prompt attacks)
  // U+200B ZERO WIDTH SPACE, U+200C/D ZERO WIDTH NON-JOINER/JOINER, U+FEFF BOM, etc.
  let sanitized = text.replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/g, "");

  // Detect base64-encoded blocks (>=40 chars of base64 alphabet) and reject
  if (/(?:[A-Za-z0-9+/]{40,}={0,2})/.test(sanitized)) {
    throw new Error("Content contains suspected base64-encoded payload.");
  }

  // Detect shell command patterns
  const shellPatterns = [
    /\b(bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess)\s*[\(\[{]/i,
    /`[^`]{1,200}`/,                          // backtick command substitution
    /\$\([^)]{1,200}\)/,                      // $(...) command substitution
    /;\s*(rm|wget|curl|chmod|chown|sudo|su|nc|ncat|netcat|python|perl|ruby|php)\b/i,
    /\|\s*(bash|sh|python|perl|ruby|php|nc)\b/i,
  ];
  for (const pattern of shellPatterns) {
    if (pattern.test(sanitized)) {
      throw new Error("Content contains suspected shell command pattern.");
    }
  }

  // Detect prompt injection / role-hijacking phrases (case-insensitive)
  const injectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /disregard\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /forget\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /you\s+are\s+now\s+(a|an|the)\s+/i,
    /act\s+as\s+(a|an|the)\s+/i,
    /pretend\s+(you\s+are|to\s+be)\s+/i,
    /new\s+instructions?\s*:/i,
    /system\s*:\s*(you|your|ignore)/i,
    /\[INST\]/i,
    /<\|im_start\|>/i,
    /###\s*instruction/i,
  ];
  for (const pattern of injectionPatterns) {
    if (pattern.test(sanitized)) {
      throw new Error("Content contains suspected prompt injection directive.");
    }
  }

  // Detect common leetspeak obfuscation of dangerous keywords
  // Normalise digits/symbols that substitute letters, then re-check shell patterns
  const leetNormalized = sanitized
    .replace(/0/g, "o")
    .replace(/1/g, "i")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/@/g, "a")
    .replace(/\$/g, "s");

  const leetDangerousKeywords = /\b(exec|eval|system|bash|sh|cmd|powershell|wget|curl|chmod|sudo)\b/i;
  if (leetDangerousKeywords.test(leetNormalized)) {
    throw new Error("Content contains suspected obfuscated dangerous keyword.");
  }

  return sanitized;
}

const langchainDocs = await Promise.all(
  fileNames.map(async (fileName) => {
    if (fileName.endsWith(".txt")) {
      const filePath = path.join("companions", fileName);
      const rawContent = fs.readFileSync(filePath, "utf8");
      const fileContent = redactPII(rawContent);
      const lastSection = fileContent.split("###ENDSEEDCHAT###").slice(-1)[0];

      let safeSection;
      try {
        safeSection = sanitizeContent(lastSection);
      } catch (err) {
        console.error(`Skipping file "${fileName}" due to safety violation: ${err.message}`);
        return undefined;
      }

      const splitDocs = await splitter.createDocuments([safeSection]);
      return splitDocs.map((doc) => {
        return new Document({
          metadata: { fileName },
          pageContent: doc.pageContent,
        });
      });
    }
  })
);
      const rawContent = fs.readFileSync(filePath, "utf8");

      // Enforce maximum file size
      const fileStat = fs.statSync(filePath);
      if (fileStat.size > MAX_FILE_SIZE_BYTES) {
        throw new Error(`[${fileName}] File exceeds maximum allowed size of ${MAX_FILE_SIZE_BYTES} bytes.`);
      }

      // Sanitize and validate the raw file content before any further processing
      const fileContent = sanitizeAndValidateContent(rawContent, fileName);

      const rawSection = fileContent.split("###ENDSEEDCHAT###").slice(-1)[0];
      const lastSection = sanitiseSection(rawSection);
      if (!lastSection) return undefined;
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
  SUPABASE_URL,
  SUPABASE_PRIVATE_KEY,
  { auth }
);

// Sanitization: patterns indicating dynamic code execution primitives
const DANGEROUS_PATTERNS = [
  /\beval\s*\(/i,
  /\bexec\s*\(/i,
  /\bnew\s+Function\s*\(/i,
  /\bsetTimeout\s*\(\s*['"`]/i,
  /\bsetInterval\s*\(\s*['"`]/i,
  /\bimport\s*\(/i,
  /\brequire\s*\(/i,
  /\bprocess\.binding\s*\(/i,
  /\bchild_process/i,
  /\bvm\.runInThisContext\s*\(/i,
  /\bvm\.runInNewContext\s*\(/i,
];

function sanitizeLLMOutput(text) {
  if (typeof text !== "string") return text;
  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(
        `Dangerous code execution primitive detected in LLM output: ${pattern}`
      );
    }
  }
  return text;
}

function sanitizeDocuments(docs) {
  return docs.map((doc) => {
    if (!doc) return doc;
    const sanitizedContent = sanitizeLLMOutput(doc.pageContent);
    return new Document({
      metadata: doc.metadata,
      pageContent: sanitizedContent,
    });
  });
}

// Wrap OpenAIEmbeddings to validate output before use
class SanitizedOpenAIEmbeddings extends OpenAIEmbeddings {
  async embedDocuments(texts) {
    const embeddings = await super.embedDocuments(texts);
    // Validate that embeddings are numeric arrays (not strings with code)
    for (const embedding of embeddings) {
      if (!Array.isArray(embedding)) {
        throw new Error("LLM embedding output is not a valid array.");
      }
      for (const value of embedding) {
        if (typeof value !== "number" || !isFinite(value)) {
          throw new Error(
            "LLM embedding output contains non-numeric or non-finite value."
          );
        }
      }
    }
    return embeddings;
  }

  async embedQuery(text) {
    const embedding = await super.embedQuery(text);
    if (!Array.isArray(embedding)) {
      throw new Error("LLM embedding query output is not a valid array.");
    }
    for (const value of embedding) {
      if (typeof value !== "number" || !isFinite(value)) {
        throw new Error(
          "LLM embedding query output contains non-numeric or non-finite value."
        );
      }
    }
    return embedding;
  }
}

const rawDocs = langchainDocs.flat().filter((doc) => doc !== undefined);
const sanitizedDocs = sanitizeDocuments(rawDocs);

// ---------------------------------------------------------------------------
// Audit-logged embedding + vector-store insertion
// ---------------------------------------------------------------------------
const filteredDocs = langchainDocs.flat().filter((doc) => doc !== undefined);

// Correlation ID ties every log entry for this run together for end-to-end
// reconstruction of the decision chain.
const correlationId = randomUUID();

// Capture the principal executing this script.
const principal = os.userInfo().username || process.env.USER || "unknown";

// Model metadata — keep in sync with the OpenAIEmbeddings constructor below.
const MODEL_ID = "text-embedding-ada-002";
const MODEL_VERSION = "v1"; // OpenAI does not expose a numeric version via the JS SDK.

// Hash the input so the exact corpus can be verified forensically.
const inputHash = hashDocuments(filteredDocs);

// --- Decision audit record: BEFORE action ---
writeAuditRecord({
  correlationId,
  event: "AI_ACTION_INITIATED",
  timestamp: new Date().toISOString(),
  principal,
  action: "SupabaseVectorStore.fromDocuments",
  modelId: MODEL_ID,
  modelVersion: MODEL_VERSION,
  inputDocumentCount: filteredDocs.length,
  inputHash,
  targetTable: "documents",
  retentionPolicyDays: 90,
});

let actionOutcome = "SUCCESS";
let actionError = null;

try {
  // Approved model registry — only models listed here are permitted.
const APPROVED_EMBEDDING_MODELS = Object.freeze({
  "text-embedding-ada-002": "openai/text-embedding-ada-002",
});

// Pinned model identity — must match an entry in APPROVED_EMBEDDING_MODELS.
const PINNED_EMBEDDING_MODEL = "text-embedding-ada-002";

// Integrity check: verify the pinned model is in the approved registry before
// any API call is made.  Throws at startup rather than silently using an
// unapproved or mutable default.
if (!Object.prototype.hasOwnProperty.call(APPROVED_EMBEDDING_MODELS, PINNED_EMBEDDING_MODEL)) {
  throw new Error(
    `Model identity verification failed: "${PINNED_EMBEDDING_MODEL}" is not in the approved model registry. ` +
    `Approved models: ${Object.keys(APPROVED_EMBEDDING_MODELS).join(", ")}`
  );
}

console.log(
  `[model-registry] Using approved embedding model: ${APPROVED_EMBEDDING_MODELS[PINNED_EMBEDDING_MODEL]}`
);

await SupabaseVectorStore.fromDocuments(
  langchainDocs.flat().filter((doc) => doc !== undefined),
  new OpenAIEmbeddings({
    openAIApiKey: process.env.OPENAI_API_KEY,
    modelName: PINNED_EMBEDDING_MODEL, // explicit version pin — no mutable library default
  }),
  {
    client,
    tableName: "documents",
  }
);
} catch (err) {
  actionOutcome = "FAILURE";
  actionError = err instanceof Error ? err.message : String(err);
  throw err; // re-throw so the process exits with a non-zero code
} finally {
  // --- Decision audit record: AFTER action (success or failure) ---
  writeAuditRecord({
    correlationId,
    event: "AI_ACTION_COMPLETED",
    timestamp: new Date().toISOString(),
    principal,
    action: "SupabaseVectorStore.fromDocuments",
    modelId: MODEL_ID,
    modelVersion: MODEL_VERSION,
    inputDocumentCount: filteredDocs.length,
    inputHash,
    targetTable: "documents",
    outcome: actionOutcome,
    error: actionError,
    retentionPolicyDays: 90,
  });
}
