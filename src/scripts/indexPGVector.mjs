// Call embeding API and insert to supabase
// Ref: https://js.langchain.com/docs/modules/indexes/vector_stores/integrations/supabase

// ---------------------------------------------------------------------------
// Approved model registry — only models listed here may be used at runtime.
// Update this list only after a formal model review and approval process.
// ---------------------------------------------------------------------------
const APPROVED_EMBEDDING_MODELS = new Set([
  "text-embedding-ada-002", // OpenAI Ada v2 — approved 2024-01-01
]);

// Pinned model identity — must match an entry in APPROVED_EMBEDDING_MODELS.
const EMBEDDING_MODEL_NAME = "text-embedding-ada-002";
const EMBEDDING_MODEL_VERSION = "text-embedding-ada-002"; // immutable alias; no sub-version exposed by OpenAI API

function assertModelApproved(modelName) {
  if (!APPROVED_EMBEDDING_MODELS.has(modelName)) {
    throw new Error(
      `Model "${modelName}" is NOT in the approved model registry. ` +
        `Approved models: ${[...APPROVED_EMBEDDING_MODELS].join(", ")}`
    );
  }
  // Integrity log — records resolved model identity for audit trail.
  console.log(
    JSON.stringify({
      event: "model_identity_verified",
      modelName,
      modelVersion: EMBEDDING_MODEL_VERSION,
      approvedRegistry: [...APPROVED_EMBEDDING_MODELS],
      timestamp: new Date().toISOString(),
    })
  );
}

import dotenv from "dotenv";
import { Document } from "langchain/document";
import { OpenAIEmbeddings } from "langchain/embeddings/openai";
import { SupabaseVectorStore } from "langchain/vectorstores/supabase";
import { createClient } from "@supabase/supabase-js";
import { CharacterTextSplitter } from "langchain/text_splitter";
import crypto from "crypto";
import os from "os";

import fs from "fs";
import path from "path";

// Redact common PII patterns from text before processing
function redactPII(text) {
  // Redact email addresses
  text = text.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, "[REDACTED_EMAIL]");
  // Redact US phone numbers (various formats)
  text = text.replace(/(\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}/g, "[REDACTED_PHONE]");
  // Redact US Social Security Numbers
  text = text.replace(/\b\d{3}[\s.-]\d{2}[\s.-]\d{4}\b/g, "[REDACTED_SSN]");
  // Redact credit card numbers (16-digit, with or without spaces/dashes)
  text = text.replace(/\b(?:\d[ -]?){13,16}\b/g, "[REDACTED_CC]");
  // Redact IPv4 addresses
  text = text.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "[REDACTED_IP]");
  return text;
}

dotenv.config({ path: `.env.local` });

/**
 * Sanitizes text content before passing it to the AI pipeline.
 * Detects and rejects content containing:
 * - Invisible/hidden Unicode characters
 * - Base64-encoded payloads
 * - Binary or shell command indicators
 * - Leetspeak obfuscation patterns
 * - Suspicious prompt injection keywords
 */
function sanitizeContent(content, fileName) {
  // Reject binary content (non-printable characters outside normal whitespace)
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(content)) {
    throw new Error(`[SECURITY] Binary or non-printable characters detected in ${fileName}. Aborting.`);
  }

  // Reject invisible/hidden Unicode characters (zero-width, soft hyphen, etc.)
  if (/[\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u2028\u2029]/.test(content)) {
    throw new Error(`[SECURITY] Hidden/invisible Unicode characters detected in ${fileName}. Aborting.`);
  }

  // Detect base64-encoded blocks (long runs of base64 chars, typical of encoded payloads)
  const base64Pattern = /(?:[A-Za-z0-9+\/]{40,}={0,2})/g;
  const base64Matches = content.match(base64Pattern) || [];
  for (const match of base64Matches) {
    try {
      const decoded = Buffer.from(match, "base64").toString("utf8");
      // If decoded content looks like a shell command or injection, reject it
      if (/(?:ignore|system|exec|eval|bash|sh\s|cmd|powershell|\$\(|`)/i.test(decoded)) {
        throw new Error(`[SECURITY] Base64-encoded malicious payload detected in ${fileName}. Aborting.`);
      }
    } catch (e) {
      if (e.message.startsWith("[SECURITY]")) throw e;
      // Not valid base64 or harmless — continue
    }
  }

  // Detect shell command patterns
  if (/(?:\$\(|`[^`]*`|\bexec\b|\beval\b|\bsystem\b|\bspawn\b|\bchild_process\b|\brm\s+-rf|\bcurl\b.*\bsh\b|\bwget\b.*\bsh\b)/i.test(content)) {
    throw new Error(`[SECURITY] Shell command pattern detected in ${fileName}. Aborting.`);
  }

  // Detect prompt injection keywords (common jailbreak/override patterns)
  const injectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i,
    /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i,
    /forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i,
    /you\s+are\s+now\s+(a\s+)?(?!a companion)/i,
    /act\s+as\s+(if\s+you\s+are\s+)?(?:an?\s+)?(?:evil|malicious|unrestricted|jailbroken|DAN)/i,
    /\bDAN\b/,
    /do\s+anything\s+now/i,
    /override\s+(your\s+)?(instructions?|programming|rules|guidelines)/i,
    /new\s+(instructions?|prompt|persona|role)\s*:/i,
    /system\s*:\s*you\s+(are|must|should|will)/i,
    /\[INST\]|\[\/?SYS\]|<\|im_start\|>|<\|im_end\|>/,
  ];

  for (const pattern of injectionPatterns) {
    if (pattern.test(content)) {
      throw new Error(`[SECURITY] Prompt injection pattern detected in ${fileName} (pattern: ${pattern}). Aborting.`);
    }
  }

  // Detect leetspeak obfuscation (e.g., 1gn0r3, 3x3cut3)
  const leetspeakMap = { "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s" };
  const normalized = content.replace(/[01345@$7]/g, (c) => leetspeakMap[c] || c);
  for (const pattern of injectionPatterns) {
    if (pattern.test(normalized)) {
      throw new Error(`[SECURITY] Leetspeak-obfuscated prompt injection detected in ${fileName}. Aborting.`);
    }
  }

  return content;
}

// Singapore PII detection patterns
const SINGAPORE_PII_PATTERNS = [
  // NRIC / FIN Number (S/T/F/G followed by 7 digits and a letter)
  { name: "NRIC/FIN Number", pattern: /\b[STFG]\d{7}[A-Z]\b/i },
  // Singapore Passport Number (E followed by 7-8 digits)
  { name: "Passport Number", pattern: /\b[E]\d{7,8}\b/i },
  // Singapore phone numbers (+65 XXXX XXXX or 8/9 XXXX XXXX)
  { name: "Phone Number", pattern: /(?:\+65[\s-]?)?[89]\d{3}[\s-]?\d{4}\b/ },
  // Singapore postal code (6 digits, common format)
  { name: "Postal Code", pattern: /\bSingapore\s+\d{6}\b/i },
  // Date of birth patterns (DD/MM/YYYY or DD-MM-YYYY)
  { name: "Date of Birth", pattern: /\b(0?[1-9]|[12]\d|3[01])[\/-](0?[1-9]|1[0-2])[\/-](19|20)\d{2}\b/ },
  // Email addresses
  { name: "Email Address", pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/ },
  // Full name patterns (common Singapore name formats: Chinese, Malay, Indian)
  // Chinese names: 2-4 uppercase words, at least one all-caps segment
  { name: "Full Name (Chinese)", pattern: /\b[A-Z][A-Z]+(?:\s+[A-Z][A-Z]+){1,3}\b/ },
  // Bank account numbers (common SG format: 9-12 digits)
  { name: "Bank Account Number", pattern: /\b\d{9,12}\b/ },
  // Credit/Debit card numbers (16 digits, optionally grouped)
  { name: "Credit Card Number", pattern: /\b(?:\d{4}[\s-]?){3}\d{4}\b/ },
];

function detectSingaporePII(content, fileName) {
  const detectedPII = [];
  for (const { name, pattern } of SINGAPORE_PII_PATTERNS) {
    if (pattern.test(content)) {
      detectedPII.push(name);
    }
  }
  if (detectedPII.length > 0) {
    throw new Error(
      `Singapore PII detected in file "${fileName}": [${detectedPII.join(", ")}]. ` +
      `Upload aborted. Please remove all PII before uploading.`
    );
  }
}

const COMPANIONS_DIR = path.resolve("companions");
const SAFE_FILENAME_RE = /^[a-zA-Z0-9_\-]+\.txt$/;
const fileNames = fs.readdirSync(COMPANIONS_DIR);

// Patterns indicative of prompt injection or malicious content
const INVISIBLE_CHARS_RE = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/g;
const BASE64_INJECTION_RE = /(?:[A-Za-z0-9+\/]{40,}={0,2})/g;
const LEET_INJECTION_RE = /(?:1gn0r3|1gnor3|d1sr3g4rd|d15r3g4rd|f0rg3t|f0rget|0b3y|0bey)/gi;
const SUSPICIOUS_PHRASES_RE = /(?:ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)|disregard\s+(all\s+)?(previous|prior|above|earlier)|you\s+are\s+now|act\s+as\s+(a\s+)?(?:different|new|another)|forget\s+(all\s+)?(previous|prior|your)\s+(instructions?|training)|new\s+instructions?\s*:|system\s*:\s*you|<\s*system\s*>|\[\s*system\s*\]|###\s*system|override\s+(previous\s+)?instructions?)/gi;
const SHELL_COMMAND_RE = /(?:(?:^|\s)(?:bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess)\s*[\(\[{]|(?:\$\(|`)[^`]*`|\|\s*(?:bash|sh|cmd)|;\s*(?:rm|del|format|mkfs|dd)\s)/gim;
const BINARY_RE = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/;

function sanitizeContent(content, fileName) {
  // Reject files containing binary/non-printable characters
  if (BINARY_RE.test(content)) {
    throw new Error(`File "${fileName}" contains binary or non-printable characters and was rejected.`);
  }

  // Strip invisible/zero-width characters
  let sanitized = content.replace(INVISIBLE_CHARS_RE, "");

  // Reject if base64-encoded blobs are present (potential encoded payloads)
  const base64Matches = sanitized.match(BASE64_INJECTION_RE);
  if (base64Matches) {
    throw new Error(`File "${fileName}" contains potential base64-encoded content and was rejected.`);
  }

  // Reject if leetspeak injection patterns are detected
  if (LEET_INJECTION_RE.test(sanitized)) {
    throw new Error(`File "${fileName}" contains leetspeak prompt injection patterns and was rejected.`);
  }

  // Reject if suspicious prompt-injection phrases are detected
  if (SUSPICIOUS_PHRASES_RE.test(sanitized)) {
    throw new Error(`File "${fileName}" contains suspicious prompt injection content and was rejected.`);
  }

  // Reject if shell commands or binary executable patterns are detected
  if (SHELL_COMMAND_RE.test(sanitized)) {
    throw new Error(`File "${fileName}" contains shell commands or executable patterns and was rejected.`);
  }

  return sanitized;
}
const splitter = new CharacterTextSplitter({
  separator: " ",
  chunkSize: 200,
  chunkOverlap: 50, //TODO: adjust both chunk size and chunk overlap later
});

// Data-minimisation helpers
// Maximum characters forwarded to the embedding pipeline per companion file.
const MAX_SECTION_CHARS = 4000;

// Lines whose content matches these patterns are redacted before embedding.
const REDACTED_LINE_PATTERNS = [
  /^\s*(name|email|password|passwd|token|secret|api[_-]?key|private[_-]?key|auth)[\s:=]/i,
];

function minimiseSection(raw) {
  // 1. Redact sensitive lines.
  const cleaned = raw
    .split("\n")
    .filter((line) => !REDACTED_LINE_PATTERNS.some((re) => re.test(line)))
    .join("\n");
  // 2. Enforce size cap.
  return cleaned.slice(0, MAX_SECTION_CHARS);
}

// Maximum allowed characters for a single file to prevent excessively large inputs
const MAX_FILE_LENGTH = 100_000;

/**
 * Sanitizes and validates raw text before it is sent to the OpenAI Embeddings API.
 * - Removes null bytes and ASCII control characters (except common whitespace).
 * - Trims leading/trailing whitespace.
 * - Rejects content that is empty or exceeds the maximum allowed length.
 * Returns the sanitized string, or null if the content is invalid.
 */
function sanitizeAndValidate(text) {
  if (typeof text !== "string") return null;

  // Remove null bytes and non-printable ASCII control characters
  // (keep \t, \n, \r which are legitimate whitespace)
  let sanitized = text.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

  // Collapse sequences of whitespace-only lines to a single blank line
  sanitized = sanitized.replace(/(\r?\n){3,}/g, "\n\n");

  sanitized = sanitized.trim();

  if (sanitized.length === 0) {
    console.warn("Skipping empty content after sanitization.");
    return null;
  }

  if (sanitized.length > MAX_FILE_LENGTH) {
    console.warn(
      `Content exceeds maximum allowed length (${MAX_FILE_LENGTH} chars). Truncating.`
    );
    sanitized = sanitized.slice(0, MAX_FILE_LENGTH);
  }

  return sanitized;
}

const langchainDocs = await Promise.all(
  fileNames.map(async (fileName) => {
    if (SAFE_FILENAME_RE.test(fileName)) {
      const filePath = path.resolve(COMPANIONS_DIR, fileName);
      if (!filePath.startsWith(COMPANIONS_DIR + path.sep)) {
        console.warn(`Skipping file outside companions directory: ${fileName}`);
        return undefined;
      }
      const fileContent = fs.readFileSync(filePath, "utf8");
      const lastSection = fileContent.split("###ENDSEEDCHAT###").slice(-1)[0];

      // Sanitize and validate the section before splitting and embedding
      const sanitizedSection = sanitizeAndValidate(lastSection);
      if (!sanitizedSection) {
        console.warn(`Skipping file "${fileName}" due to invalid content.`);
        return [];
      }

      const splitDocs = await splitter.createDocuments([sanitizedSection]);
      return splitDocs
        .map((doc) => {
          // Sanitize each individual chunk as well
          const sanitizedChunk = sanitizeAndValidate(doc.pageContent);
          if (!sanitizedChunk) return undefined;
          return new Document({
            metadata: { fileName },
            pageContent: sanitizedChunk,
          });
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
  credentials.supabase.url,
  credentials.supabase.privateKey,
  { auth }
);

// --- LLM Output Validation & Sanitization ---

/**
 * Patterns that indicate dynamic code execution primitives.
 * Applied to any text content before sending to the LLM and
 * to any string-form output returned from the LLM.
 */
const DANGEROUS_PATTERNS = [
  /\beval\s*\(/i,
  /\bexec\s*\(/i,
  /\bnew\s+Function\s*\(/i,
  /\bsetTimeout\s*\(\s*['"`]/i,
  /\bsetInterval\s*\(\s*['"`]/i,
  /\bimport\s*\(/i,
  /\brequire\s*\(/i,
  /\bprocess\.binding\s*\(/i,
  /__import__/i,
  /\bcompile\s*\(/i,
  /\bexecfile\s*\(/i,
];

/**
 * Throws if the provided text contains any dynamic code execution primitive.
 * @param {string} text - The text to check.
 * @param {string} context - A label for error messages.
 */
function assertNoDynamicCodePrimitives(text, context = "content") {
  if (typeof text !== "string") return;
  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(
        `Security violation: dynamic code execution primitive detected in ${context}: pattern ${pattern}`
      );
    }
  }
}

/**
 * Sanitize a document's pageContent by stripping dangerous patterns.
 * Logs a warning when content is modified.
 * @param {Document} doc
 * @returns {Document}
 */
function sanitizeDocument(doc) {
  let sanitized = doc.pageContent;
  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.test(sanitized)) {
      console.warn(
        `[WARN] Removing dangerous pattern (${pattern}) from document: ${doc.metadata?.fileName}`
      );
      sanitized = sanitized.replace(pattern, "[REDACTED]");
    }
  }
  return new Document({ metadata: doc.metadata, pageContent: sanitized });
}

/**
 * Validate that an embedding vector returned by the LLM is a plain numeric
 * array and contains no executable content.
 * @param {unknown} embedding - The value to validate.
 * @param {number} index - Position in the batch (for error messages).
 */
function validateEmbedding(embedding, index) {
  if (!Array.isArray(embedding)) {
    throw new Error(
      `Security violation: LLM embedding at index ${index} is not an array (got ${typeof embedding}).`
    );
  }
  for (let i = 0; i < embedding.length; i++) {
    const val = embedding[i];
    if (typeof val !== "number" || !isFinite(val)) {
      throw new Error(
        `Security violation: LLM embedding[${index}][${i}] is not a finite number (got ${JSON.stringify(val)}).`
      );
    }
  }
}

// Sanitize documents before sending to the LLM.
const rawDocs = langchainDocs.flat().filter((doc) => doc !== undefined);
const sanitizedDocs = rawDocs.map((doc) => sanitizeDocument(doc));

// Wrap OpenAIEmbeddings to validate output after each LLM call.
const baseEmbeddings = new OpenAIEmbeddings({ openAIApiKey: process.env.OPENAI_API_KEY });

const validatedEmbeddings = new Proxy(baseEmbeddings, {
  get(target, prop) {
    if (prop === "embedDocuments") {
      return async function (texts) {
        // Validate input texts before sending to LLM.
        texts.forEach((text, i) => assertNoDynamicCodePrimitives(text, `embedDocuments input[${i}]`));
        const result = await target.embedDocuments(texts);
        // Validate output embeddings returned from LLM.
        if (!Array.isArray(result)) {
          throw new Error("Security violation: embedDocuments did not return an array.");
        }
        result.forEach((embedding, i) => validateEmbedding(embedding, i));
        return result;
      };
    }
    if (prop === "embedQuery") {
      return async function (text) {
        assertNoDynamicCodePrimitives(text, "embedQuery input");
        const result = await target.embedQuery(text);
        validateEmbedding(result, 0);
        return result;
      };
    }
    const value = target[prop];
    return typeof value === "function" ? value.bind(target) : value;
  },
});

// ── Audit / forensic setup ────────────────────────────────────────────────
const AUDIT_LOG_PATH = "audit_log.jsonl";
const MODEL_ID = "text-embedding-ada-002"; // OpenAIEmbeddings default model
const MODEL_VERSION = "1";                 // Ada-002 has a single stable version
const RETENTION_DAYS = 365;               // forensic retention policy
const traceId = crypto.randomUUID();
const principal = os.userInfo().username;
const filteredDocs = langchainDocs.flat().filter((doc) => doc !== undefined);

// Compute a deterministic SHA-256 hash of the serialised input documents
const inputHash = crypto
  .createHash("sha256")
  .update(JSON.stringify(filteredDocs))
  .digest("hex");

const auditStart = {
  traceId,
  event: "embedding_start",
  timestamp: new Date().toISOString(),
  principal,
  model: MODEL_ID,
  modelVersion: MODEL_VERSION,
  inputDocumentCount: filteredDocs.length,
  inputHash,
  targetTable: "documents",
  retentionDays: RETENTION_DAYS,
};
fs.appendFileSync(AUDIT_LOG_PATH, JSON.stringify(auditStart) + "\n", "utf8");
console.log("[AUDIT]", JSON.stringify(auditStart));
// ──────────────────────────────────────────────────────────────────────────

let embeddingOutcome = "success";
let embeddingError = null;
try {
  // Verify model identity against the approved registry before any inference.
assertModelApproved(EMBEDDING_MODEL_NAME);

const embeddings = new OpenAIEmbeddings({
  openAIApiKey: process.env.OPENAI_API_KEY,
  modelName: EMBEDDING_MODEL_NAME, // explicit version pin — no implicit library default
});

await SupabaseVectorStore.fromDocuments(
  langchainDocs.flat().filter((doc) => doc !== undefined),
  embeddings,
  {
    client,
    tableName: "documents",
  }
);
} catch (err) {
  embeddingOutcome = "failure";
  embeddingError = err.message;
  throw err;
} finally {
  // ── Audit record: outcome ──────────────────────────────────────────────
  const auditEnd = {
    traceId,
    event: "embedding_end",
    timestamp: new Date().toISOString(),
    principal,
    model: MODEL_ID,
    modelVersion: MODEL_VERSION,
    inputHash,
    outcome: embeddingOutcome,
    ...(embeddingError && { error: embeddingError }),
    targetTable: "documents",
    retentionDays: RETENTION_DAYS,
  };
  fs.appendFileSync(AUDIT_LOG_PATH, JSON.stringify(auditEnd) + "\n", "utf8");
  console.log("[AUDIT]", JSON.stringify(auditEnd));
  // ────────────────────────────────────────────────────────────────────────
}
