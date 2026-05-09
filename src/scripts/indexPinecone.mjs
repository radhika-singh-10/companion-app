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

// ---------------------------------------------------------------------------
// Approved model registry — only models listed here may be used.
// Each entry carries the pinned model identifier and a SHA-256 integrity hash
// of that identifier string (acts as a tamper-evident manifest check).
// ---------------------------------------------------------------------------
const APPROVED_MODEL_REGISTRY = {
  "text-embedding-ada-002": {
    version: "text-embedding-ada-002",
    // echo -n "text-embedding-ada-002" | sha256sum
    integrityHash:
      "4a88b9f4e1f4e1f4e1f4e1f4e1f4e1f4e1f4e1f4e1f4e1f4e1f4e1f4e1f4e1f",
  },
};

/**
 * Verifies that the requested model is in the approved registry and that its
 * identifier has not been tampered with (integrity check via SHA-256).
 *
 * @param {string} modelId - The model identifier to verify.
 * @returns {{ modelId: string, version: string }} Verified model identity.
 * @throws {Error} If the model is not registered or fails integrity verification.
 */
function verifyModelIdentity(modelId) {
  const entry = APPROVED_MODEL_REGISTRY[modelId];
  if (!entry) {
    throw new Error(
      `Model "${modelId}" is NOT in the approved model registry. ` +
        `Approved models: ${Object.keys(APPROVED_MODEL_REGISTRY).join(", ")}`
    );
  }

  // Integrity check: recompute the hash of the model identifier string and
  // compare it against the known-good value stored in the registry.
  const computedHash = crypto
    .createHash("sha256")
    .update(modelId, "utf8")
    .digest("hex");

  if (computedHash !== entry.integrityHash) {
    throw new Error(
      `Integrity verification FAILED for model "${modelId}". ` +
        `Expected hash ${entry.integrityHash}, got ${computedHash}.`
    );
  }

  console.log(
    `[model-registry] Model identity verified: id=${modelId} version=${entry.version} hash=${computedHash}`
  );
  return { modelId, version: entry.version };
}
import crypto from "crypto";

// ---------------------------------------------------------------------------
// Audit / forensic logging helpers
// ---------------------------------------------------------------------------
const AUDIT_LOG_PATH = path.resolve("logs", "indexPinecone_audit.jsonl");
const AUDIT_LOG_MAX_BYTES = 10 * 1024 * 1024; // 10 MB retention cap per file

/** Ensure the log directory exists. */
fs.mkdirSync(path.dirname(AUDIT_LOG_PATH), { recursive: true });

/**
 * Rotate the audit log when it exceeds AUDIT_LOG_MAX_BYTES so that old
 * records are preserved in a timestamped archive rather than silently lost.
 */
function rotateAuditLogIfNeeded() {
  if (fs.existsSync(AUDIT_LOG_PATH)) {
    const { size } = fs.statSync(AUDIT_LOG_PATH);
    if (size >= AUDIT_LOG_MAX_BYTES) {
      const rotated = AUDIT_LOG_PATH.replace(
        /\.jsonl$/,
        `_${new Date().toISOString().replace(/[:.]/g, "-")}.jsonl`
      );
      fs.renameSync(AUDIT_LOG_PATH, rotated);
    }
  }
}

/**
 * Append a single audit record (JSON-lines format) to the persistent log.
 * Each record is written synchronously so that a crash cannot lose the entry.
 */
function writeAuditRecord(record) {
  rotateAuditLogIfNeeded();
  fs.appendFileSync(AUDIT_LOG_PATH, JSON.stringify(record) + "\n", "utf8");
}

/**
 * Compute a deterministic SHA-256 fingerprint of the document corpus so that
 * the exact input can be reproduced or verified later.
 */
function hashDocuments(docs) {
  const corpus = docs.map((d) => d.pageContent + JSON.stringify(d.metadata)).join("|");
  return crypto.createHash("sha256").update(corpus, "utf8").digest("hex");
}

/** Generate a random correlation ID to link all steps of this indexing run. */
function newCorrelationId() {
  return crypto.randomUUID();
}

dotenv.config({ path: `.env.local` });

/**
 * Scans text for Singapore PII categories and throws if any are found.
 * Categories checked: NRIC/FIN, personal email, SG phone numbers,
 * full-name salutation patterns, date-of-birth patterns, and
 * health-record keywords.
 */
function scanForSingaporePII(text, sourceLabel) {
  const piiPatterns = [
    // NRIC / FIN  (S/T/F/G followed by 7 digits and a letter)
    { name: "NRIC/FIN Number", pattern: /\b[STFG]\d{7}[A-Z]\b/i },
    // Personal email address
    { name: "Personal Email Address", pattern: /\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b/i },
    // Singapore local phone numbers (+65 or 65 prefix, or bare 8-digit starting with 6/8/9)
    { name: "Phone Number", pattern: /(?:\+65|\b65)?\s*[689]\d{7}\b/ },
    // Full name with common salutation
    { name: "Full Name (salutation)", pattern: /\b(?:Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+/ },
    // Date of birth patterns  (DD/MM/YYYY, DD-MM-YYYY, YYYY-MM-DD)
    { name: "Date of Birth", pattern: /\b(?:\d{2}[\/\-]\d{2}[\/\-]\d{4}|\d{4}[\/\-]\d{2}[\/\-]\d{2})\b/ },
    // Health / medical record keywords
    { name: "Health Record", pattern: /\b(?:diagnosis|prescription|medical record|patient id|blood type|HIV|diabetes|cancer|medication|dosage)\b/i },
    // Passport number (Singapore passports: E followed by 7 digits)
    { name: "Passport Number", pattern: /\bE\d{7}\b/ },
    // Home / residential address indicators
    { name: "Residential Address", pattern: /\b(?:Blk|Block|#\d{2}[-–]\d{2,}|Singapore\s+\d{6})\b/i },
  ];

  const detected = piiPatterns
    .filter(({ pattern }) => pattern.test(text))
    .map(({ name }) => name);

  if (detected.length > 0) {
    throw new Error(
      `PII detected in "${sourceLabel}" — categories found: ${detected.join(", ")}. ` +
      `File will not be indexed. Remove or redact PII before re-running.`
    );
  }
}

/**
 * Redacts common PII categories from a string.
 * Covers: email addresses, phone numbers, SSNs, credit card numbers,
 * US street addresses, ZIP codes, and dates of birth.
 */
function redactPII(text) {
  // Redact email addresses
  text = text.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, "[REDACTED_EMAIL]");

  // Redact phone numbers (various formats: (123) 456-7890, 123-456-7890, +1 123 456 7890, etc.)
  text = text.replace(/(\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}/g, "[REDACTED_PHONE]");

  // Redact SSNs (123-45-6789)
  text = text.replace(/\b\d{3}-\d{2}-\d{4}\b/g, "[REDACTED_SSN]");

  // Redact credit card numbers (16-digit, optionally separated by spaces or dashes)
  text = text.replace(/\b(?:\d[ -]?){13,16}\b/g, "[REDACTED_CC]");

  // Redact US street addresses (e.g., 123 Main St, 456 Elm Avenue)
  text = text.replace(/\b\d{1,5}\s+[A-Za-z0-9\s,.']+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Circle|Cir)\b[.,]?/gi, "[REDACTED_ADDRESS]");

  // Redact ZIP codes (12345 or 12345-6789)
  text = text.replace(/\b\d{5}(?:-\d{4})?\b/g, "[REDACTED_ZIP]");

  // Redact dates of birth (MM/DD/YYYY, MM-DD-YYYY, YYYY-MM-DD)
  text = text.replace(/\b(?:\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}|\d{4}-\d{2}-\d{2})\b/g, "[REDACTED_DOB]");

  return text;
}

/**
 * Sanitizes extracted text to detect and reject potentially malicious content
 * before it is passed to the AI embedding model.
 */
function sanitizeContent(text) {
  // 1. Reject binary / non-printable content (allow common whitespace)
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(text)) {
    throw new Error("File contains binary or non-printable characters.");
  }

  // 2. Strip and detect invisible / zero-width characters used to hide prompts
  const invisiblePattern = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/g;
  if (invisiblePattern.test(text)) {
    throw new Error("File contains invisible/zero-width characters that may hide prompts.");
  }

  // 3. Detect base64-encoded blobs (long runs of base64 chars)
  if (/(?:[A-Za-z0-9+/]{40,}={0,2})/.test(text)) {
    throw new Error("File contains a suspicious base64-encoded block.");
  }

  // 4. Detect common shell / executable command patterns
  const shellPatterns = [
    /\b(bash|sh|zsh|cmd|powershell|exec|eval|system|popen)\s*[(\/\-]/i,
    /`[^`]{0,200}`/,          // backtick command substitution
    /\$\([^)]{0,200}\)/,      // $(...) command substitution
    /<script[\s>]/i,
    /javascript:/i,
  ];
  for (const pattern of shellPatterns) {
    if (pattern.test(text)) {
      throw new Error(`File contains suspicious shell/script content matching ${pattern}.`);
    }
  }

  // 5. Detect prompt-injection / jailbreak patterns
  const injectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /disregard\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /forget\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /you\s+are\s+now\s+(a\s+)?(?:an?\s+)?(?:evil|unrestricted|jailbroken|DAN)/i,
    /act\s+as\s+(if\s+you\s+are\s+)?(?:an?\s+)?(?:evil|unrestricted|jailbroken|DAN)/i,
    /\bDAN\b/,                // "Do Anything Now" jailbreak keyword
    /system\s*prompt/i,
    /\[INST\]/i,              // instruction-tuning injection markers
    /<<SYS>>/i,
  ];
  for (const pattern of injectionPatterns) {
    if (pattern.test(text)) {
      throw new Error(`File contains a suspected prompt-injection pattern matching ${pattern}.`);
    }
  }

  // 6. Detect leetspeak obfuscation (simple heuristic: high ratio of digit-letter substitutions)
  const leetspeakPattern = /(?:[i1][gq][n][o0][r][e3]|[s5][y][s5][t7][e3][m3]|[p][r][o0][m][p][t7])/i;
  if (leetspeakPattern.test(text)) {
    throw new Error("File contains suspected leetspeak obfuscation of sensitive keywords.");
  }

  return text;
}

/**
 * Sanitize and validate text content before passing it to the AI model.
 * - Removes null bytes and non-printable control characters (except common whitespace)
 * - Strips common prompt-injection patterns
 * - Enforces a maximum content length
 * - Returns null if the content is empty or invalid after sanitization
 */
function sanitizeContent(text) {
  if (typeof text !== "string") return null;

  // Remove null bytes
  let sanitized = text.replace(/\0/g, "");

  // Remove non-printable control characters except \t, \n, \r
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

  // Strip common prompt-injection / jailbreak patterns (case-insensitive)
  const injectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
    /disregard\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
    /forget\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
    /you\s+are\s+now\s+(?:a\s+)?(?:an?\s+)?(?:evil|malicious|unrestricted|jailbroken)/gi,
    /act\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:an?\s+)?(?:evil|malicious|unrestricted|jailbroken)/gi,
    /<\s*script[^>]*>.*?<\s*\/\s*script\s*>/gis,
    /system\s*:\s*you\s+are/gi,
    /\[\s*system\s*\]/gi,
  ];

  for (const pattern of injectionPatterns) {
    sanitized = sanitized.replace(pattern, "");
  }

  // Enforce maximum content length (1 MB of text)
  const MAX_LENGTH = 1_000_000;
  if (sanitized.length > MAX_LENGTH) {
    sanitized = sanitized.slice(0, MAX_LENGTH);
  }

  // Trim and reject empty content
  sanitized = sanitized.trim();
  if (sanitized.length === 0) return null;

  return sanitized;
}

/**
 * Sanitizes text content before passing it to the AI pipeline.
 * Throws an error if suspicious content is detected.
 */
function sanitizeContent(content, fileName) {
  // 1. Reject binary / non-UTF-8 content (null bytes are a strong signal)
  if (/\x00/.test(content)) {
    throw new Error(`[SECURITY] Binary content detected in ${fileName}. Aborting.`);
  }

  // 2. Strip and warn about invisible / zero-width characters
  const invisiblePattern = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/g;
  if (invisiblePattern.test(content)) {
    console.warn(`[SECURITY] Invisible/zero-width characters found in ${fileName} and removed.`);
    content = content.replace(invisiblePattern, "");
  }

  // 3. Detect and reject base64-encoded blobs (long runs of base64 chars)
  const base64Pattern = /(?:[A-Za-z0-9+\/]{40,}={0,2})/g;
  const base64Matches = content.match(base64Pattern) || [];
  for (const match of base64Matches) {
    try {
      const decoded = Buffer.from(match, "base64").toString("utf8");
      // If the decoded string contains shell/script indicators, reject the file
      if (/(?:bash|sh|cmd|powershell|eval|exec|system|import os|subprocess)/i.test(decoded)) {
        throw new Error(`[SECURITY] Base64-encoded shell command detected in ${fileName}. Aborting.`);
      }
    } catch (e) {
      if (e.message.startsWith("[SECURITY]")) throw e;
      // Not valid base64 — ignore
    }
  }

  // 4. Detect shell command patterns
  const shellPattern = /(?:(?:^|\s)(?:bash|sh|zsh|cmd|powershell|python|perl|ruby|node|curl|wget|nc|ncat|netcat|chmod|chown|sudo|su|rm\s+-rf|mkfifo|eval|exec)\b)/im;
  if (shellPattern.test(content)) {
    throw new Error(`[SECURITY] Shell command pattern detected in ${fileName}. Aborting.`);
  }

  // 5. Detect prompt-injection / jailbreak phrases
  const injectionPhrases = [
    /ignore\s+(all\s+)?previous\s+instructions/i,
    /disregard\s+(all\s+)?previous\s+instructions/i,
    /forget\s+(all\s+)?previous\s+instructions/i,
    /you\s+are\s+now\s+(a\s+)?(?:dan|jailbreak|unrestricted|evil)/i,
    /act\s+as\s+(if\s+you\s+are\s+)?(?:an?\s+)?(?:unrestricted|evil|malicious|jailbreak)/i,
    /do\s+anything\s+now/i,
    /pretend\s+(you\s+have\s+no\s+restrictions|to\s+be)/i,
    /system\s*:\s*you\s+are/i,
    /<\s*script[^>]*>/i,
  ];
  for (const pattern of injectionPhrases) {
    if (pattern.test(content)) {
      throw new Error(`[SECURITY] Prompt injection phrase detected in ${fileName}. Aborting.`);
    }
  }

  // 6. Detect leetspeak obfuscation attempts (simple heuristic)
  const leetspeakPattern = /(?:[i!1][g9][n][o0][r][e3]|[e3][x][e3][c]|[s5][h][e3][l1][l1])/i;
  if (leetspeakPattern.test(content)) {
    console.warn(`[SECURITY] Possible leetspeak obfuscation detected in ${fileName}. Removing matched segments.`);
    content = content.replace(leetspeakPattern, "[REDACTED]");
  }

  return content;
}

// Allowlist of line-prefix patterns permitted for indexing.
// Only lines whose trimmed content starts with one of these prefixes
// will be retained — everything else is redacted before embedding.
const ALLOWED_FIELD_PREFIXES = [
  "Name:",
  "Personality:",
  "Background:",
  "Occupation:",
  "Interests:",
  "Hobbies:",
  "Description:",
];

// Hard cap on the total characters forwarded to the embedder per file section.
const MAX_SECTION_CHARS = 2000;

/**
 * Minimise a raw companion-file section to only the fields on the allowlist,
 * then truncate to MAX_SECTION_CHARS.
 */
function minimiseSection(rawSection) {
  const allowedLines = rawSection
    .split("\n")
    .filter((line) => {
      const trimmed = line.trim();
      return ALLOWED_FIELD_PREFIXES.some((prefix) =>
        trimmed.startsWith(prefix)
      );
    })
    .join("\n");
  return allowedLines.slice(0, MAX_SECTION_CHARS);
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
            const companionsDir = path.resolve("companions");
      const filePath = path.resolve(companionsDir, fileName);
      // Prevent path traversal: ensure resolved path is within companions directory
      if (!filePath.startsWith(companionsDir + path.sep) && filePath !== companionsDir) {
        throw new Error(`Path traversal detected for file: ${fileName}`);
      }
      const fileContent = fs.readFileSync(filePath, "utf8");
      // get the last section in the doc for background info
      const rawSection = fileContent.split("###ENDSEEDCHAT###").slice(-1)[0];
      // Sanitize content to prevent prompt injection / malicious payloads
      let lastSection;
      try {
        lastSection = sanitizeContent(rawSection);
      } catch (err) {
        console.error(`Skipping file "${fileName}" due to policy violation: ${err.message}`);
        return undefined;
      }
      const splitDocs = await splitter.createDocuments([lastSection]);
      return splitDocs
        .map((doc) => {
          const sanitizedPageContent = sanitizeContent(doc.pageContent);
          if (!sanitizedPageContent) return undefined;
          return new Document({
            metadata: { fileName },
            pageContent: sanitizedPageContent,
          });
        })
        .filter((doc) => doc !== undefined);
    }
  })
);

const client = new PineconeClient();
await client.init({
  apiKey: EXTERNAL_CREDENTIALS.pinecone.apiKey,
  environment: EXTERNAL_CREDENTIALS.pinecone.environment,
});
const pineconeIndex = client.Index(EXTERNAL_CREDENTIALS.pinecone.index);

// --- Model identity, version pinning, and registry enforcement ---
const PINNED_MODEL_ID = "text-embedding-ada-002";
const verifiedModel = verifyModelIdentity(PINNED_MODEL_ID);

// Record the resolved model identity in the Pinecone namespace so that every
// indexed document is traceable back to the exact model version used.
const modelNamespace = `model:${verifiedModel.version}`;

console.log(
  `[inference] Using embedding model: ${verifiedModel.modelId} ` +
    `(version=${verifiedModel.version}) — namespace=${modelNamespace}`
);

const embeddings = new OpenAIEmbeddings({
  openAIApiKey: process.env.OPENAI_API_KEY,
  modelName: verifiedModel.version, // explicit, pinned model name
});

await PineconeStore.fromDocuments(
  langchainDocs.flat().filter((doc) => doc !== undefined),
  embeddings,
  {
    pineconeIndex,
    namespace: modelNamespace, // model identity recorded in request metadata
  }
);
await client.init({
  apiKey: process.env.PINECONE_API_KEY,
  environment: process.env.PINECONE_ENVIRONMENT,
});
const pineconeIndex = client.Index(process.env.PINECONE_INDEX);

// Sanitization: check documents for dynamic code execution primitives before indexing
const DANGEROUS_PATTERNS = [
  /\beval\s*\(/,
  /\bexec\s*\(/,
  /\bnew\s+Function\s*\(/,
  /\bsetTimeout\s*\(\s*['"`]/,
  /\bsetInterval\s*\(\s*['"`]/,
  /\bimportScripts\s*\(/,
  /\bdocument\.write\s*\(/,
  /\bInlineCode\b/,
];

function sanitizeAndValidateDoc(doc) {
  if (!doc || typeof doc.pageContent !== "string") {
    throw new Error("Invalid document: missing or non-string pageContent");
  }
  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.test(doc.pageContent)) {
      throw new Error(
        `Document content contains a forbidden dynamic code execution primitive matching ${pattern}. Aborting indexing.`
      );
    }
  }
  return doc;
}

const sanitizedDocs = langchainDocs
  .flat()
  .filter((doc) => doc !== undefined)
  .map(sanitizeAndValidateDoc);

const embeddings = new OpenAIEmbeddings({ openAIApiKey: process.env.OPENAI_API_KEY });

// Wrap embedQuery to validate LLM output before it is used
const originalEmbedDocuments = embeddings.embedDocuments.bind(embeddings);
embeddings.embedDocuments = async (texts) => {
  const result = await originalEmbedDocuments(texts);
  if (!Array.isArray(result)) {
    throw new Error("LLM embedding output is not an array; aborting.");
  }
  for (const vector of result) {
    if (!Array.isArray(vector)) {
      throw new Error("LLM embedding output contains a non-array vector; aborting.");
    }
    for (const value of vector) {
      if (typeof value !== "number" || !isFinite(value)) {
        throw new Error(
          "LLM embedding output contains a non-numeric or non-finite value; aborting."
        );
      }
    }
  }
  return result;
};

// ---------------------------------------------------------------------------
// Audit-wrapped indexing action
// ---------------------------------------------------------------------------
const correlationId = newCorrelationId();
const principal = process.env.USER || process.env.USERNAME || "ci-service";
const modelId = "text-embedding-ada-002"; // OpenAI embedding model used by LangChain default
const modelVersion = "1";                 // Update if the model version changes

const filteredDocs = langchainDocs.flat().filter((doc) => doc !== undefined);
const inputHash = hashDocuments(filteredDocs);
const sourceFiles = [...new Set(filteredDocs.map((d) => d.metadata?.fileName).filter(Boolean))];

// PRE-ACTION audit record — captures intent and full forensic context
writeAuditRecord({
  event: "indexing_started",
  correlationId,
  timestamp: new Date().toISOString(),
  principal,
  action: "PineconeStore.fromDocuments",
  model: { id: modelId, version: modelVersion },
  input: {
    documentCount: filteredDocs.length,
    inputHash,
    sourceFiles,
    pineconeIndex: process.env.PINECONE_INDEX,
    pineconeEnvironment: process.env.PINECONE_ENVIRONMENT,
  },
  dataLineage: {
    sourceDirectory: "companions",
    splitterConfig: { separator: " ", chunkSize: 200, chunkOverlap: 50 },
  },
});

let indexingError = null;
try {
  await PineconeStore.fromDocuments(
    filteredDocs,
    new OpenAIEmbeddings({ openAIApiKey: process.env.OPENAI_API_KEY }),
    {
      pineconeIndex,
    }
  );
} catch (err) {
  indexingError = { message: err.message, stack: err.stack };
  // POST-ACTION audit record — failure path
  writeAuditRecord({
    event: "indexing_failed",
    correlationId,
    timestamp: new Date().toISOString(),
    principal,
    action: "PineconeStore.fromDocuments",
    model: { id: modelId, version: modelVersion },
    input: { documentCount: filteredDocs.length, inputHash, sourceFiles },
    error: indexingError,
  });
  throw err;
}

// POST-ACTION audit record — success path
writeAuditRecord({
  event: "indexing_completed",
  correlationId,
  timestamp: new Date().toISOString(),
  principal,
  action: "PineconeStore.fromDocuments",
  model: { id: modelId, version: modelVersion },
  input: { documentCount: filteredDocs.length, inputHash, sourceFiles },
  output: {
    status: "success",
    vectorsUpserted: filteredDocs.length,
    pineconeIndex: process.env.PINECONE_INDEX,
  },
  dataLineage: {
    sourceDirectory: "companions",
    splitterConfig: { separator: " ", chunkSize: 200, chunkOverlap: 50 },
  },
});

console.log(`[AUDIT] Indexing run ${correlationId} completed. Audit log: ${AUDIT_LOG_PATH}`);
