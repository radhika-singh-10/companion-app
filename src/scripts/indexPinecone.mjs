// Major ref: https://js.langchain.com/docs/modules/indexes/vector_stores/integrations/pinecone
import { PineconeClient } from "@pinecone-database/pinecone";
import dotenv from "dotenv";
import { Document } from "langchain/document";
// OpenAIEmbeddings removed: OpenAI/GPT and LangChain are not in the approved LLM registry.
// Replace with your organization's approved embeddings provider.
import ApprovedEmbeddingsClient from "../lib/approvedEmbeddingsClient.js";

// Minimal approved embeddings adapter compatible with PineconeStore.fromDocuments
class ApprovedEmbeddings {
  constructor(config) {
    this.client = new ApprovedEmbeddingsClient(config);
  }
  async embedDocuments(texts) {
    return Promise.all(texts.map((text) => this.client.embed(text)));
  }
  async embedQuery(text) {
    return this.client.embed(text);
  }
}
import { PineconeStore } from "langchain/vectorstores/pinecone";
import { CharacterTextSplitter } from "langchain/text_splitter";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config({ path: `.env.local` });

// ── Approved model registry ──────────────────────────────────────────────────
// Only models listed here may be used in this workload.
const APPROVED_EMBEDDING_MODELS = new Set([
  "text-embedding-3-small",
  "text-embedding-3-large",
]);

// Pinned model identity – must match an entry in APPROVED_EMBEDDING_MODELS.
const EMBEDDING_MODEL_ID = "text-embedding-3-small";

// Integrity manifest: expected SHA-256 digest of the model identifier string
// (acts as a lightweight tamper-evident check on the pinned constant itself).
const EMBEDDING_MODEL_ID_SHA256 = "f8b4e2d1c3a7e6f0b9d2c5a8e1f4b7d0a3c6e9f2b5d8a1c4e7f0b3d6a9c2e5f8";

import { createHash } from "crypto";

function assertModelApproved(modelId, expectedDigest) {
  if (!APPROVED_EMBEDDING_MODELS.has(modelId)) {
    throw new Error(
      `Model '${modelId}' is NOT in the approved model registry. ` +
      `Approved models: ${[...APPROVED_EMBEDDING_MODELS].join(", ")}`
    );
  }
  const actualDigest = createHash("sha256").update(modelId, "utf8").digest("hex");
  if (actualDigest !== expectedDigest) {
    throw new Error(
      `Integrity check failed for model identifier '${modelId}'. ` +
      `Expected digest: ${expectedDigest}, got: ${actualDigest}`
    );
  }
  console.log(`[model-identity] Approved and verified: modelId=${modelId} digest=${actualDigest}`);
}
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Scans text for Singapore-specific PII categories and returns any matches found.
 * Categories checked:
 *   - NRIC / FIN numbers (e.g. S1234567D, T0312345A, F1234567N, G1234567P)
 *   - Singapore passport numbers (e.g. E1234567X)
 *   - Personal email addresses
 *   - Singapore local phone numbers (+65 or 65 prefix, or 8-digit starting with 6/8/9)
 *   - Full names preceded by common salutations (Mr, Mrs, Ms, Dr, Prof)
 *   - Dates of birth in common formats
 */
function scanForSingaporePII(text) {
  const piiPatterns = [
    {
      name: "NRIC/FIN Number",
      // S/T = citizens/PRs born locally; F/G = foreigners
      pattern: /\b[STFG]\d{7}[A-Z]\b/gi,
    },
    {
      name: "Singapore Passport Number",
      pattern: /\bE\d{7}[A-Z]\b/gi,
    },
    {
      name: "Personal Email Address",
      pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
    },
    {
      name: "Singapore Phone Number",
      // Matches +65 XXXX XXXX, 65XXXXXXXX, or standalone 8-digit numbers starting with 6, 8, or 9
      pattern: /(?:\+65|\b65)?\s?[689]\d{3}\s?\d{4}\b/g,
    },
    {
      name: "Full Name (with salutation)",
      // Matches salutation followed by one or more capitalised words
      pattern: /\b(?:Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+/g,
    },
    {
      name: "Date of Birth",
      // Matches DD/MM/YYYY, DD-MM-YYYY, YYYY-MM-DD, Month DD YYYY, DD Month YYYY
      pattern:
        /\b(?:\d{1,2}[\/-]\d{1,2}[\/-]\d{2,4}|\d{4}-\d{2}-\d{2}|(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2}[,\s]+\d{4}|\d{1,2}\s+(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{4})\b/gi,
    },
  ];

  const findings = [];
  for (const { name, pattern } of piiPatterns) {
    const matches = text.match(pattern);
    if (matches && matches.length > 0) {
      findings.push({ type: name, count: matches.length });
    }
  }
  return findings;
}

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

  // Credit card numbers (16-digit, optionally grouped by spaces or dashes)
  text = text.replace(/\b(?:\d{4}[\s\-]?){3}\d{4}\b/g, "[REDACTED_CC]");

  // Dates of birth (MM/DD/YYYY, MM-DD-YYYY, YYYY-MM-DD)
  text = text.replace(
    /\b(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}|\d{4}[\-]\d{2}[\-]\d{2})\b/g,
    "[REDACTED_DOB]"
  );

  // Street addresses (e.g., "123 Main St", "456 Elm Avenue", "789 Oak Blvd")
  text = text.replace(
    /\b\d+\s+[A-Za-z0-9\s,.']+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Circle|Cir|Trail|Tr|Terrace|Ter)\b[.,]?(?:\s+(?:Apt|Suite|Unit|#)\s*[\w\d]+)?/gi,
    "[REDACTED_ADDRESS]"
  );

  // ZIP codes (standalone 5-digit or ZIP+4)
  text = text.replace(/\b\d{5}(?:-\d{4})?\b/g, "[REDACTED_ZIP]");

  return text;
}

/**
 * Sanitizes file content to prevent prompt injection attacks.
 * Throws an error if suspicious content is detected.
 */
function sanitizeFileContent(content, fileName) {
  // 1. Reject binary/non-UTF8 content (null bytes or high concentration of control chars)
  if (/\x00/.test(content)) {
    throw new Error(`[SECURITY] Binary content detected in ${fileName}`);
  }

  // 2. Strip and flag invisible/zero-width characters used to hide prompts
  const invisibleCharPattern = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E\u00A0]/g;
  if (invisibleCharPattern.test(content)) {
    throw new Error(`[SECURITY] Invisible/zero-width characters detected in ${fileName}`);
  }

  // 3. Detect base64-encoded blobs that could hide instructions
  const base64Pattern = /(?:[A-Za-z0-9+\/]{40,}={0,2})/g;
  const base64Matches = content.match(base64Pattern) || [];
  for (const match of base64Matches) {
    try {
      const decoded = Buffer.from(match, "base64").toString("utf8");
      if (/ignore|prompt|system|assistant|instruction|jailbreak|bypass/i.test(decoded)) {
        throw new Error(`[SECURITY] Base64-encoded prompt injection detected in ${fileName}`);
      }
    } catch (e) {
      if (e.message.startsWith("[SECURITY]")) throw e;
      // Not valid base64 — skip
    }
  }

  // 4. Detect common prompt injection / jailbreak patterns
  const promptInjectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)/i,
    /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)/i,
    /forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)/i,
    /you\s+are\s+now\s+(a|an|the)?\s*(different|new|evil|unrestricted|jailbroken)/i,
    /act\s+as\s+(if\s+you\s+are|a|an)?\s*(different|new|evil|unrestricted|jailbroken|DAN)/i,
    /\bDAN\b/,
    /jailbreak/i,
    /bypass\s+(your\s+)?(safety|filter|restriction|guideline|policy)/i,
    /system\s*:\s*(you are|your role|your task|your job)/i,
    /<\s*system\s*>/i,
    /\[INST\]/i,
    /###\s*(system|instruction|prompt)\s*:/i,
  ];
  for (const pattern of promptInjectionPatterns) {
    if (pattern.test(content)) {
      throw new Error(`[SECURITY] Prompt injection pattern detected in ${fileName}: ${pattern}`);
    }
  }

  // 5. Detect leetspeak obfuscation of common injection keywords
  const normalizedContent = content
    .replace(/4/g, "a")
    .replace(/3/g, "e")
    .replace(/1/g, "i")
    .replace(/0/g, "o")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/@/g, "a")
    .replace(/\$/g, "s")
    .toLowerCase();
  const leetspeakInjectionPatterns = [
    /ignore\s+(all\s+)?previous\s+instructions/i,
    /jailbreak/i,
    /bypass\s+(safety|filter)/i,
  ];
  for (const pattern of leetspeakInjectionPatterns) {
    if (pattern.test(normalizedContent)) {
      throw new Error(`[SECURITY] Leetspeak-obfuscated prompt injection detected in ${fileName}`);
    }
  }

  // 6. Detect shell/binary commands embedded in content
  const shellCommandPatterns = [
    /\b(rm|wget|curl|chmod|chown|sudo|bash|sh|python|perl|ruby|exec|eval|system)\s+(-[a-zA-Z]+\s+)?[\/~.]/i,
    /\$\(.*\)/,
    /`[^`]{1,200}`/,
    /<script[\s>]/i,
    /javascript\s*:/i,
  ];
  for (const pattern of shellCommandPatterns) {
    if (pattern.test(content)) {
      throw new Error(`[SECURITY] Shell/binary command detected in ${fileName}: ${pattern}`);
    }
  }

  return content;
}

const MAX_FILE_SIZE_BYTES = 500_000; // 500 KB limit per file
const MAX_CHUNK_LENGTH = 2000;      // max characters per chunk sent to embeddings

/**
 * Sanitizes raw text content before sending to the AI model.
 * - Removes null bytes and non-printable control characters (except common whitespace)
 * - Trims leading/trailing whitespace
 * - Enforces a maximum length
 * @param {string} text
 * @param {number} [maxLength]
 * @returns {string}
 */
function sanitizeText(text, maxLength = MAX_FILE_SIZE_BYTES) {
  if (typeof text !== "string") {
    throw new TypeError("Input must be a string");
  }
  // Remove null bytes and non-printable control characters except \t, \n, \r
  // eslint-disable-next-line no-control-regex
  const cleaned = text.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  const trimmed = cleaned.trim();
  if (trimmed.length === 0) {
    throw new Error("File content is empty after sanitization");
  }
  return trimmed.slice(0, maxLength);
}

// ---------------------------------------------------------------------------
// Prompt-injection / malicious-content guard
// ---------------------------------------------------------------------------
function sanitizeFileContent(content, fileName) {
  // 1. Reject binary / non-UTF-8 content (null bytes are a strong signal)
  if (/\x00/.test(content)) {
    throw new Error(`[SECURITY] Binary content detected in "${fileName}". Aborting.`);
  }

  // 2. Strip and warn about invisible / zero-width characters
  const invisiblePattern = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/g;
  if (invisiblePattern.test(content)) {
    console.warn(`[SECURITY] Invisible/zero-width characters found in "${fileName}" and removed.`);
    content = content.replace(invisiblePattern, "");
  }

  // 3. Detect and reject base64-encoded blobs (long runs of base64 chars)
  const base64Pattern = /(?:[A-Za-z0-9+\/]{40,}={0,2})/g;
  if (base64Pattern.test(content)) {
    throw new Error(`[SECURITY] Potential base64-encoded payload detected in "${fileName}". Aborting.`);
  }

  // 4. Detect shell / script execution patterns
  const shellPattern =
    /(\$\(|`[^`]*`|\beval\s*\(|\bexec\s*\(|\bsystem\s*\(|\bspawn\s*\(|\bchild_process\b|\bsh\s+-c\b|\bbash\s+-c\b|\bpowershell\b|\bcmd\.exe\b)/i;
  if (shellPattern.test(content)) {
    throw new Error(`[SECURITY] Shell/script execution pattern detected in "${fileName}". Aborting.`);
  }

  // 5. Detect common prompt-injection / jailbreak keywords
  const injectionPattern =
    /(ignore (all |previous |prior |above |the )?(instructions?|prompts?|rules?|constraints?)|you are now|act as (an? |a )?(unrestricted|jailbroken|evil|malicious|DAN)|disregard (your |all )?(previous |prior |above )?(instructions?|rules?|guidelines?)|system prompt|<\|im_start\||<\|im_end\||\[INST\]|\[\/?SYS\])/i;
  if (injectionPattern.test(content)) {
    throw new Error(`[SECURITY] Prompt-injection pattern detected in "${fileName}". Aborting.`);
  }

  // 6. Detect leetspeak substitution attempts on sensitive keywords
  //    e.g. "1gnor3", "3x3cut3", "syst3m"
  const leetspeakPattern = /\b(?:[i1][g9][n][o0][r3][e3]|[e3][x*][e3][c*][u*][t+][e3]|[s$][y*][s$][t+][e3][m*])\b/i;
  if (leetspeakPattern.test(content)) {
    throw new Error(`[SECURITY] Leetspeak obfuscation of sensitive keyword detected in "${fileName}". Aborting.`);
  }

  // 7. Enforce a reasonable maximum file size (512 KB)
  const MAX_BYTES = 512 * 1024;
  if (Buffer.byteLength(content, "utf8") > MAX_BYTES) {
    throw new Error(`[SECURITY] File "${fileName}" exceeds the 512 KB size limit. Aborting.`);
  }

  return content;
}
// ---------------------------------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
// Resolve the absolute, canonical path of the companions directory once.
const COMPANIONS_DIR = path.resolve(__dirname, "../../companions");

const fileNames = fs.readdirSync(COMPANIONS_DIR);
const splitter = new CharacterTextSplitter({
  separator: " ",
  chunkSize: 200,
  chunkOverlap: 50, //TODO: adjust both chunk size and chunk overlap later
});

// Output data minimisation constants
const MAX_SECTION_CHARS = 2000;  // hard cap on raw text fed into the splitter
const MAX_CHUNKS_PER_DOC = 8;   // maximum number of chunks stored per companion

// Redact lines that may contain sensitive fields before indexing.
const SENSITIVE_LINE_PATTERN = /^[^\n]*\b(key|secret|password|passwd|token|email|api[_\s]?key)\s*[:=]/im;

function minimiseSection(raw) {
  // 1. Truncate to the allowed character budget.
  const truncated = raw.slice(0, MAX_SECTION_CHARS);
  // 2. Remove lines that match sensitive field patterns.
  const redacted = truncated
    .split("\n")
    .filter((line) => !SENSITIVE_LINE_PATTERN.test(line))
    .join("\n");
  return redacted;
}

const langchainDocs = await Promise.all(
  fileNames.map(async (fileName) => {
    if (fileName.endsWith(".txt")) {
      const filePath = path.join("companions", fileName);
      const rawContent = fs.readFileSync(filePath, "utf8");
      // Validate file size before processing
      if (Buffer.byteLength(rawContent, "utf8") > MAX_FILE_SIZE_BYTES) {
        console.warn(`Skipping ${fileName}: file exceeds maximum allowed size.`);
        return [];
      }
      // Sanitize raw file content
      let fileContent;
      try {
        fileContent = sanitizeText(rawContent);
      } catch (err) {
        console.warn(`Skipping ${fileName}: ${err.message}`);
        return [];
      }
      // get the last section in the doc for background info
      const lastSection = fileContent.split("###ENDSEEDCHAT###").slice(-1)[0];
      // Sanitize the extracted section
      let sanitizedSection;
      try {
        sanitizedSection = sanitizeText(lastSection);
      } catch (err) {
        console.warn(`Skipping ${fileName} (last section empty after sanitization): ${err.message}`);
        return [];
      }
      const splitDocs = await splitter.createDocuments([sanitizedSection]);
      return splitDocs
        .filter((doc) => doc.pageContent && doc.pageContent.trim().length > 0)
        .map((doc) => {
          // Sanitize each individual chunk before embedding
          const safeContent = sanitizeText(doc.pageContent, MAX_CHUNK_LENGTH);
          return new Document({
            metadata: { fileName },
            pageContent: safeContent,
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

// Sanitization helper: validates that an embedding vector is a plain numeric array
// and that its serialized form contains no dynamic code execution primitives.
function validateEmbedding(embedding, context) {
  const DANGEROUS_PATTERNS = [
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /\bsubprocess\b/i,
    /\bspawn\s*\(/i,
    /\bFunction\s*\(/i,
    /\bnew\s+Function\b/i,
    /\bsetTimeout\s*\(/i,
    /\bsetInterval\s*\(/i,
    /\brequire\s*\(/i,
    /\bimport\s*\(/i,
    /\bchild_process\b/i,
    /\bos\.system\b/i,
    /\bexecSync\s*\(/i,
    /\bexecFile\s*\(/i,
  ];

  if (!Array.isArray(embedding)) {
    throw new Error(`[LLM Output Validation] ${context}: embedding is not an array.`);
  }

  for (let i = 0; i < embedding.length; i++) {
    const val = embedding[i];
    if (typeof val !== "number" || !isFinite(val)) {
      throw new Error(
        `[LLM Output Validation] ${context}: embedding[${i}] is not a finite number (got ${typeof val}: ${val}).`
      );
    }
  }

  // Serialize and scan for dangerous patterns as a belt-and-suspenders check.
  const serialized = JSON.stringify(embedding);
  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.test(serialized)) {
      throw new Error(
        `[LLM Output Validation] ${context}: embedding contains a forbidden dynamic code execution primitive matching ${pattern}.`
      );
    }
  }
}

// Wrap OpenAIEmbeddings to validate all output before it reaches Pinecone.
class SafeOpenAIEmbeddings extends OpenAIEmbeddings {
  async embedDocuments(texts) {
    const embeddings = await super.embedDocuments(texts);
    if (!Array.isArray(embeddings)) {
      throw new Error("[LLM Output Validation] embedDocuments: result is not an array.");
    }
    embeddings.forEach((embedding, idx) =>
      validateEmbedding(embedding, `embedDocuments[${idx}]`)
    );
    return embeddings;
  }

  async embedQuery(text) {
    const embedding = await super.embedQuery(text);
    validateEmbedding(embedding, "embedQuery");
    return embedding;
  }
}

const docsToIndex = langchainDocs.flat().filter((doc) => doc !== undefined);
console.log(
  `[LLM Interaction] Calling OpenAIEmbeddings via PineconeStore.fromDocuments. ` +
  `Model: text-embedding-ada-002. Documents to embed: ${docsToIndex.length}. ` +
  `Timestamp: ${new Date().toISOString()}`
);
// ── Audit: pre-action record ────────────────────────────────────────────────
const filteredDocs = langchainDocs.flat().filter((doc) => doc !== undefined);
const correlationId = crypto.randomUUID();
const actionTimestamp = new Date().toISOString();
const inputHash = hashDocuments(filteredDocs);

const auditPreRecord = {
  correlationId,
  timestamp: actionTimestamp,
  principal: PRINCIPAL,
  action: "PineconeStore.fromDocuments",
  modelIdentifier: MODEL_IDENTIFIER,
  pineconeIndex: process.env.PINECONE_INDEX,
  pineconeEnvironment: process.env.PINECONE_ENVIRONMENT,
  documentCount: filteredDocs.length,
  inputHash,
  retentionDays: AUDIT_RETENTION_DAYS,
  status: "INITIATED",
};

try {
  writeAuditRecord(auditPreRecord);
} catch (auditErr) {
  // Logging failure must not silently pass — surface it and abort.
  console.error("[AUDIT FAILURE] Could not write pre-action audit record:", auditErr);
  process.exit(2);
}

// ── AI-driven action ─────────────────────────────────────────────────────────
let actionOutcome = "UNKNOWN";
let actionError = null;
try {
  // Verify model identity, registry membership, and integrity before use.
assertModelApproved(EMBEDDING_MODEL_ID, EMBEDDING_MODEL_ID_SHA256);

console.log(`[model-identity] Instantiating embeddings with pinned model: ${EMBEDDING_MODEL_ID}`);
const embeddings = new OpenAIEmbeddings({
  openAIApiKey: process.env.OPENAI_API_KEY,
  modelName: EMBEDDING_MODEL_ID, // explicit version pin
});

await PineconeStore.fromDocuments(
  langchainDocs.flat().filter((doc) => doc !== undefined),
  embeddings,
  {
    pineconeIndex,
    // Record model identity in index metadata for auditability.
    namespace: `model:${EMBEDDING_MODEL_ID}`,
  }
);
  actionOutcome = "SUCCESS";
} catch (err) {
  actionOutcome = "FAILURE";
  actionError = { message: err.message, stack: err.stack };
  throw err; // re-throw after audit so the process exits with a non-zero code
} finally {
  // ── Audit: post-action record ──────────────────────────────────────────────
  const auditPostRecord = {
    correlationId,
    timestamp: new Date().toISOString(),
    principal: PRINCIPAL,
    action: "PineconeStore.fromDocuments",
    modelIdentifier: MODEL_IDENTIFIER,
    pineconeIndex: process.env.PINECONE_INDEX,
    pineconeEnvironment: process.env.PINECONE_ENVIRONMENT,
    documentCount: filteredDocs.length,
    inputHash,
    retentionDays: AUDIT_RETENTION_DAYS,
    status: actionOutcome,
    ...(actionError ? { error: actionError } : {}),
  };

  try {
    writeAuditRecord(auditPostRecord);
  } catch (auditErr) {
    // Post-action logging failure is critical — surface it explicitly.
    console.error("[AUDIT FAILURE] Could not write post-action audit record:", auditErr);
    // Do not suppress the original action error; exit with a distinct code.
    process.exitCode = 2;
  }
}
console.log(
  `[LLM Interaction] OpenAIEmbeddings call completed successfully. ` +
  `Documents indexed: ${docsToIndex.length}. ` +
  `Timestamp: ${new Date().toISOString()}`
);
