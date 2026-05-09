// Call embeding API and insert to supabase
// Ref: https://js.langchain.com/docs/modules/indexes/vector_stores/integrations/supabase

import dotenv from "dotenv";
import { Document } from "langchain/document";
import { OpenAIEmbeddings } from "langchain/embeddings/openai";
import { SupabaseVectorStore } from "langchain/vectorstores/supabase";
import { createClient } from "@supabase/supabase-js";
import { CharacterTextSplitter } from "langchain/text_splitter";
import { createHash, randomUUID } from "crypto";
import { createWriteStream } from "fs";

import fs from "fs";
import path from "path";

// Audit logger — appends structured JSON audit records to audit.log
const auditLogStream = createWriteStream("audit.log", { flags: "a" });
function writeAuditRecord(record) {
  const entry = JSON.stringify({ ...record, logged_at: new Date().toISOString() });
  auditLogStream.write(entry + "\n");
  console.log("[AUDIT]", entry);
}

dotenv.config({ path: `.env.local` });

// This script uses credentials for exactly 2 external systems:
// 1. Supabase (SUPABASE_URL + SUPABASE_PRIVATE_KEY)
// 2. OpenAI (OPENAI_API_KEY)
// No additional external system credentials are loaded or used.
const { SUPABASE_URL, SUPABASE_PRIVATE_KEY, OPENAI_API_KEY } = process.env;
if (!SUPABASE_URL || !SUPABASE_PRIVATE_KEY || !OPENAI_API_KEY) {
  throw new Error("Missing required credentials: SUPABASE_URL, SUPABASE_PRIVATE_KEY, OPENAI_API_KEY");
}

/**
 * Sanitizes file content to prevent prompt injection attacks.
 * Checks for and removes/rejects hidden prompts, invisible characters,
 * base64-encoded content, leetspeak, suspicious instructions, and shell commands.
 */
function sanitizeContent(content) {
  // Remove invisible/zero-width characters often used to hide prompts
  // eslint-disable-next-line no-control-regex
  const invisibleCharsRegex = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u00AD\u200B-\u200F\u2028\u2029\uFEFF\uFFF9-\uFFFC]/g;
  let sanitized = content.replace(invisibleCharsRegex, "");

  // Detect and reject base64-encoded blocks that could hide instructions
  const base64BlockRegex = /(?:[A-Za-z0-9+\/]{40,}={0,2})/g;
  const base64Matches = sanitized.match(base64BlockRegex) || [];
  for (const match of base64Matches) {
    try {
      const decoded = Buffer.from(match, "base64").toString("utf8");
      // If decoded content looks like text instructions, strip the base64 block
      if (/ignore|prompt|instruction|system|assistant|user|role|jailbreak/i.test(decoded)) {
        console.warn("[SECURITY] Removed suspicious base64-encoded content from file.");
        sanitized = sanitized.replace(match, "");
      }
    } catch (_) {
      // Not valid base64, ignore
    }
  }

  // Detect suspicious prompt injection patterns (case-insensitive)
  const injectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)/i,
    /you\s+are\s+now\s+(a|an)?\s*[a-z]+/i,
    /act\s+as\s+(a|an)?\s*[a-z]+/i,
    /pretend\s+(you\s+are|to\s+be)/i,
    /disregard\s+(all\s+)?(previous|prior|above)/i,
    /new\s+instructions?\s*:/i,
    /system\s*:\s*(you|your|ignore)/i,
    /\[system\]/i,
    /\[user\]/i,
    /\[assistant\]/i,
    /<\s*system\s*>/i,
    /<\s*prompt\s*>/i,
    /jailbreak/i,
    /do\s+anything\s+now/i,
    /DAN\b/,
  ];

  for (const pattern of injectionPatterns) {
    if (pattern.test(sanitized)) {
      console.warn(`[SECURITY] Suspicious prompt injection pattern detected and removed: ${pattern}`);
      sanitized = sanitized.replace(pattern, "");
    }
  }

  // Detect leetspeak substitutions for common injection keywords
  const leetspeakPatterns = [
    /1gn[o0]r[e3]/i,       // ignore
    /[i1]n5truct[i1][o0]n/i, // instruction
    /5y5t[e3]m/i,          // system
    /pr[o0]mpt/i,
  ];
  for (const pattern of leetspeakPatterns) {
    if (pattern.test(sanitized)) {
      console.warn(`[SECURITY] Leetspeak injection pattern detected and removed: ${pattern}`);
      sanitized = sanitized.replace(pattern, "");
    }
  }

  // Detect shell/binary command patterns
  const shellPatterns = [
    /\$\([^)]*\)/g,          // $(command)
    /`[^`]+`/g,              // `command`
    /\b(rm|chmod|chown|wget|curl|bash|sh|python|perl|ruby|exec|eval|nc|netcat|nmap)\s+/i,
    /\/bin\//i,
    /\/etc\//i,
    /\/dev\//i,
    /&&|\|\||;\s*\w/,        // shell chaining
  ];
  for (const pattern of shellPatterns) {
    if (pattern.test(sanitized)) {
      console.warn(`[SECURITY] Shell/binary command pattern detected and removed: ${pattern}`);
      sanitized = sanitized.replace(pattern, "");
    }
  }

  // Strip any remaining HTML/XML tags that could be used for prompt structuring
  sanitized = sanitized.replace(/<[^>]{0,200}>/g, "");

  return sanitized.trim();
}

// --- Input sanitization & validation helpers ---

const MAX_FILE_SIZE_BYTES = 500_000; // 500 KB hard limit per file
const MAX_CONTENT_LENGTH = 200_000;  // character limit after reading

/**
 * Sanitize raw text before it is sent to the LLM / embeddings API.
 * - Removes ASCII control characters (except newline/tab)
 * - Collapses runs of whitespace to a single space
 * - Trims leading/trailing whitespace
 * - Strips common prompt-injection trigger phrases
 */
function sanitizeText(text) {
  if (typeof text !== "string") return "";

  // Remove ASCII control characters except \t (0x09) and \n (0x0A)
  let sanitized = text.replace(/[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]/g, "");

  // Strip null bytes
  sanitized = sanitized.replace(/\0/g, "");

  // Collapse excessive whitespace (but preserve single newlines for readability)
  sanitized = sanitized.replace(/[ \t]+/g, " ");
  sanitized = sanitized.replace(/\n{3,}/g, "\n\n");

  // Remove common prompt-injection patterns (case-insensitive)
  const injectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
    /disregard\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
    /you\s+are\s+now\s+(?:a|an)\s+/gi,
    /act\s+as\s+(?:a|an)\s+/gi,
    /system\s*:\s*/gi,
    /<\s*script[^>]*>/gi,
  ];
  for (const pattern of injectionPatterns) {
    sanitized = sanitized.replace(pattern, "");
  }

  return sanitized.trim();
}

/**
 * Validate that the sanitized content is acceptable for embedding.
 * Throws an error if validation fails.
 */
function validateContent(content, fileName) {
  if (!content || content.trim().length === 0) {
    throw new Error(`Validation failed for "${fileName}": content is empty after sanitization.`);
  }
  if (content.length > MAX_CONTENT_LENGTH) {
    throw new Error(
      `Validation failed for "${fileName}": content length (${content.length}) exceeds maximum allowed (${MAX_CONTENT_LENGTH}).`
    );
  }
}

// --- End helpers ---

// Sanitize content to prevent prompt injection attacks
function sanitizeContent(content) {
  // Reject binary/non-printable content (allow common whitespace: tab, newline, carriage return)
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(content)) {
    throw new Error("File contains binary or non-printable characters and will not be processed.");
  }

  // Detect and reject invisible/zero-width characters used to hide prompts
  if (/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/.test(content)) {
    throw new Error("File contains invisible or zero-width characters and will not be processed.");
  }

  // Detect base64-encoded blocks that could hide encoded instructions
  const base64Pattern = /(?:[A-Za-z0-9+\/]{40,}={0,2})/g;
  if (base64Pattern.test(content)) {
    throw new Error("File contains suspected base64-encoded content and will not be processed.");
  }

  // Detect common shell command patterns
  const shellCommandPattern = /\b(bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess|os\.system|rm\s+-rf|wget|curl\s+.*http|chmod|chown|sudo|nc\s+|netcat|\|\s*sh|&&\s*sh)\b/i;
  if (shellCommandPattern.test(content)) {
    throw new Error("File contains suspected shell commands and will not be processed.");
  }

  // Detect common prompt injection trigger phrases
  const injectionPattern = /\b(ignore (previous|all|above|prior)|disregard (previous|all|above|prior)|forget (previous|all|above|prior)|new instruction|system prompt|you are now|act as|jailbreak|do anything now|dan mode|override (previous|all|above|prior)|bypass|pretend (you are|to be)|roleplay as)\b/i;
  if (injectionPattern.test(content)) {
    throw new Error("File contains suspected prompt injection phrases and will not be processed.");
  }

  // Detect leetspeak patterns (e.g., 1gn0r3, 3x3cut3)
  const leetspeakPattern = /\b[a-z0-9]*[013457@$!][a-z0-9]*[013457@$!][a-z0-9]*\b/i;
  const leetspeakWords = content.match(/\b\w+\b/g) || [];
  const suspiciousLeet = leetspeakWords.filter(w => leetspeakPattern.test(w) && w.length > 4);
  if (suspiciousLeet.length > 5) {
    throw new Error("File contains suspected leetspeak-encoded content and will not be processed.");
  }

  return content.trim();
}

/**
 * Redacts common PII categories from a string.
 * Categories covered: email, phone number, SSN, credit card, IP address,
 * and simple US street address patterns.
 */
function redactPII(text) {
  // Email addresses
  text = text.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, "[REDACTED_EMAIL]");

  // Phone numbers (various US/international formats)
  text = text.replace(
    /(\+?1[\s.-]?)?(\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}/g,
    "[REDACTED_PHONE]"
  );

  // US Social Security Numbers (SSN)
  text = text.replace(/\b\d{3}[\s.-]\d{2}[\s.-]\d{4}\b/g, "[REDACTED_SSN]");

  // Credit card numbers (13–16 digit sequences, optionally separated by spaces/dashes)
  text = text.replace(
    /\b(?:\d[ -]?){13,16}\b/g,
    "[REDACTED_CC]"
  );

  // IPv4 addresses
  text = text.replace(
    /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    "[REDACTED_IP]"
  );

  // Simple US street address pattern (e.g. "123 Main St", "456 Elm Avenue")
  text = text.replace(
    /\b\d{1,5}\s+[A-Za-z0-9\s,.#]+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b[.,]?/gi,
    "[REDACTED_ADDRESS]"
  );

  // US ZIP codes (standalone 5-digit or ZIP+4)
  text = text.replace(/\b\d{5}(?:-\d{4})?\b/g, "[REDACTED_ZIP]");

  return text;
}

// Singapore PII redaction utility
// Redacts common Singapore PII categories before indexing
function redactSingaporePII(text) {
  // Redact Singapore NRIC/FIN numbers (e.g. S1234567A, T0123456B, F1234567C, G1234567D)
  text = text.replace(/\b[STFG]\d{7}[A-Z]\b/gi, "[REDACTED_NRIC]");

  // Redact email addresses
  text = text.replace(
    /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
    "[REDACTED_EMAIL]"
  );

  // Redact Singapore mobile numbers:
  // Local format: 8/9 followed by 7 digits, optionally prefixed with +65 or 65
  text = text.replace(
    /(?:\+65|\b65)?\s*[89]\d{3}\s*\d{4}\b/g,
    "[REDACTED_MOBILE]"
  );

  // Redact full names heuristic: sequences of 2-4 capitalised words
  // (common in Singapore: Chinese, Malay, Indian, Western names)
  text = text.replace(
    /\b([A-Z][a-z]+(\s[A-Z][a-z]+){1,3})\b/g,
    "[REDACTED_NAME]"
  );

  return text;
}

const COMPANIONS_DIR = path.resolve("companions");
const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB limit
const fileNames = fs.readdirSync(COMPANIONS_DIR);
const splitter = new CharacterTextSplitter({
  separator: " ",
  chunkSize: 200,
  chunkOverlap: 50, //TODO: adjust both chunk size and chunk overlap later
});

// Maximum characters allowed from the last section of any companion file.
// Enforces a hard size limit to prevent over-broad context injection.
const MAX_SECTION_CHARS = 4000;

/**
 * Minimise raw companion-file content before it is embedded:
 *  - Remove lines that begin with '#' (metadata / instruction markers).
 *  - Remove lines that begin with '---' (front-matter separators).
 *  - Collapse runs of blank lines to a single blank line.
 *  - Enforce the hard character cap.
 */
function minimiseContent(raw) {
  const allowedLines = raw
    .split("\n")
    .filter((line) => {
      const trimmed = line.trim();
      // Drop metadata markers and system-instruction lines
      if (trimmed.startsWith("#")) return false;
      if (trimmed.startsWith("---")) return false;
      return true;
    });

  // Collapse consecutive blank lines
  const collapsed = [];
  let prevBlank = false;
  for (const line of allowedLines) {
    const isBlank = line.trim() === "";
    if (isBlank && prevBlank) continue;
    collapsed.push(line);
    prevBlank = isBlank;
  }

  const joined = collapsed.join("\n").trim();
  // Hard character cap — never store more than MAX_SECTION_CHARS characters
  return joined.slice(0, MAX_SECTION_CHARS);
}

const langchainDocs = await Promise.all(
  fileNames.map(async (fileName) => {
    if (fileName.endsWith(".txt")) {
      const filePath = path.join("companions", fileName);
      // Validate file size before reading
      const fileStat = fs.statSync(filePath);
      if (fileStat.size > MAX_FILE_SIZE_BYTES) {
        console.warn(`Skipping "${fileName}": file size (${fileStat.size} bytes) exceeds limit.`);
        return undefined;
      }

      const rawContent = fs.readFileSync(filePath, "utf8");

      // Extract the relevant section, then sanitize and validate
      const rawSection = rawContent.split("###ENDSEEDCHAT###").slice(-1)[0];
      const lastSection = sanitizeText(rawSection);
      validateContent(lastSection, fileName);

      const splitDocs = await splitter.createDocuments([lastSection]);
      return splitDocs.map((doc) => {
        return new Document({
          metadata: { fileName },
          pageContent: doc.pageContent.trim().slice(0, 500),
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

// --- LLM Output Validation & Sanitization Helpers ---

/**
 * Patterns for dynamic code execution primitives that must never appear
 * in LLM output (embeddings metadata, text responses, etc.).
 */
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
  /__proto__/gi,
  /constructor\s*\[/gi,
];

/**
 * Throws if the string contains any dynamic code execution primitive.
 */
function assertNoCodeExecution(str, context = "LLM output") {
  if (typeof str !== "string") return;
  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.test(str)) {
      throw new Error(
        `Security violation: dynamic code execution primitive detected in ${context}: ${pattern}`
      );
    }
  }
}

/**
 * Sanitize a document's pageContent by removing dangerous patterns.
 * Returns a new Document with cleaned content.
 */
function sanitizeDocument(doc) {
  let content = doc.pageContent;
  assertNoCodeExecution(content, `document pageContent (file: ${doc.metadata?.fileName})`);
  // Strip dangerous patterns as an extra defensive measure
  for (const pattern of DANGEROUS_PATTERNS) {
    content = content.replace(pattern, "[REDACTED]");
  }
  return new Document({ metadata: doc.metadata, pageContent: content });
}

/**
 * Validate that an embedding vector returned by the LLM is a plain
 * array of finite numbers — not executable code or a poisoned payload.
 */
function validateEmbeddingVector(vector, index = 0) {
  if (!Array.isArray(vector)) {
    throw new Error(
      `Security violation: embedding at index ${index} is not an array.`
    );
  }
  for (let i = 0; i < vector.length; i++) {
    const val = vector[i];
    if (typeof val !== "number" || !isFinite(val)) {
      throw new Error(
        `Security violation: embedding[${index}][${i}] is not a finite number: ${val}`
      );
    }
  }
}

/**
 * Wraps an OpenAIEmbeddings instance so that every vector returned
 * by the LLM is validated before use.
 */
function createValidatedEmbeddings(embeddingsInstance) {
  const originalEmbedDocuments = embeddingsInstance.embedDocuments.bind(embeddingsInstance);
  const originalEmbedQuery = embeddingsInstance.embedQuery.bind(embeddingsInstance);

  embeddingsInstance.embedDocuments = async function (texts) {
    // Sanitize texts before sending to LLM
    texts.forEach((t, i) => assertNoCodeExecution(t, `embedDocuments input[${i}]`));
    const vectors = await originalEmbedDocuments(texts);
    // Validate LLM output
    if (!Array.isArray(vectors)) {
      throw new Error("Security violation: embedDocuments did not return an array.");
    }
    vectors.forEach((vec, i) => validateEmbeddingVector(vec, i));
    return vectors;
  };

  embeddingsInstance.embedQuery = async function (text) {
    assertNoCodeExecution(text, "embedQuery input");
    const vector = await originalEmbedQuery(text);
    validateEmbeddingVector(vector, 0);
    return vector;
  };

  return embeddingsInstance;
}

// --- Sanitize documents before passing to LLM ---
const rawDocs = langchainDocs.flat().filter((doc) => doc !== undefined);
const sanitizedDocs = rawDocs.map((doc) => sanitizeDocument(doc));

// --- Create embeddings instance with output validation ---
const validatedEmbeddings = createValidatedEmbeddings(
  new OpenAIEmbeddings({ openAIApiKey: process.env.OPENAI_API_KEY })
);

try {
  // ── Audit: pre-action record ────────────────────────────────────────────────
const traceId = randomUUID();                          // correlation ID linking all steps
const modelId = "text-embedding-ada-002";              // OpenAI embedding model identifier
const modelVersion = "v1";                             // model version label
const principal = process.env.AUDIT_PRINCIPAL ?? process.env.USER ?? "unknown"; // who triggered this
const filteredDocs = langchainDocs.flat().filter((doc) => doc !== undefined);

// Build a deterministic hash of all input document content for data-lineage tracking
const inputHash = createHash("sha256")
  .update(filteredDocs.map((d) => d.pageContent).join("\n"))
  .digest("hex");

const sourceFiles = [...new Set(filteredDocs.map((d) => d.metadata?.fileName).filter(Boolean))];

writeAuditRecord({
  event: "embedding_and_storage_start",
  trace_id: traceId,
  timestamp: new Date().toISOString(),
  principal,
  model_id: modelId,
  model_version: modelVersion,
  input_document_count: filteredDocs.length,
  input_content_hash: inputHash,
  source_files: sourceFiles,
  target_table: "documents",
  supabase_url: process.env.SUPABASE_URL,
});

let actionOutcome = "success";
let actionError = null;
try {
  // Approved model registry: only these pinned model identifiers are permitted.
const APPROVED_EMBEDDING_MODELS = new Set([
  "text-embedding-ada-002",
]);

// Pinned model identifier — must match an entry in APPROVED_EMBEDDING_MODELS.
const EMBEDDING_MODEL_NAME = "text-embedding-ada-002";

// Registry allowlist check: abort if the model is not in the approved registry.
if (!APPROVED_EMBEDDING_MODELS.has(EMBEDDING_MODEL_NAME)) {
  throw new Error(
    `Model '${EMBEDDING_MODEL_NAME}' is not in the approved model registry. ` +
    `Permitted models: ${[...APPROVED_EMBEDDING_MODELS].join(", ")}`
  );
}

console.log(`[registry-check] Using approved, pinned embedding model: ${EMBEDDING_MODEL_NAME}`);

await SupabaseVectorStore.fromDocuments(
  langchainDocs.flat().filter((doc) => doc !== undefined),
  new OpenAIEmbeddings({
    openAIApiKey: process.env.OPENAI_API_KEY,
    modelName: EMBEDDING_MODEL_NAME, // explicit version pin
  }),
  {
    client,
    tableName: "documents",
  }
);
} catch (err) {
  actionOutcome = "failure";
  actionError = err?.message ?? String(err);
  throw err;  // re-throw so the process exits with a non-zero code
} finally {
  // ── Audit: post-action record ──────────────────────────────────────────────
  writeAuditRecord({
    event: "embedding_and_storage_end",
    trace_id: traceId,
    timestamp: new Date().toISOString(),
    principal,
    model_id: modelId,
    model_version: modelVersion,
    input_document_count: filteredDocs.length,
    input_content_hash: inputHash,
    source_files: sourceFiles,
    target_table: "documents",
    outcome: actionOutcome,
    error: actionError,
  });
  auditLogStream.end();
}
} catch (err) {
  console.error("Failed to index documents:", err.message);
  process.exit(1);
}
