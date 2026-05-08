// Call embeding API and insert to supabase
// Ref: https://js.langchain.com/docs/modules/indexes/vector_stores/integrations/supabase

// CREDENTIAL AUDIT:
// External systems accessed by this script:
//   1. Supabase (SUPABASE_URL, SUPABASE_PRIVATE_KEY)
//   2. HuggingFace (HUGGINGFACEHUB_API_KEY)
// This script is within the approved 2-system credential limit.
// Any additional credential environment variables will cause a runtime error.

import dotenv from "dotenv";
import { Document } from "langchain/document";
import { HuggingFaceInferenceEmbeddings } from "langchain/embeddings/hf";
import { SupabaseVectorStore } from "langchain/vectorstores/supabase";
import { createClient } from "@supabase/supabase-js";
import { CharacterTextSplitter } from "langchain/text_splitter";

import fs from "fs";
import path from "path";

dotenv.config({ path: `.env.local` });

// Guard against credential sprawl: only approved env vars for external systems are allowed
const disallowedCredentialEnvVars = [
  "OPENAI_API_KEY",
  "PINECONE_API_KEY",
  "STEAMSHIP_API_KEY",
  "ANTHROPIC_API_KEY",
  "COHERE_API_KEY",
  "AI21_API_KEY",
  "REPLICATE_API_KEY",
];
for (const envVar of disallowedCredentialEnvVars) {
  if (process.env[envVar]) {
    throw new Error(
      `Credential sprawl detected: unexpected environment variable '${envVar}' is set. ` +
        `This script is only permitted to access Supabase and HuggingFace.`
    );
  }
}

// --- Sanitization and validation utilities ---

const MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024; // 1 MB limit

/**
 * Sanitize and validate file content before passing to the embedding pipeline.
 * - Enforces max file size
 * - Strips null bytes and non-printable control characters
 * - Trims excessive whitespace
 * - Validates non-empty content
 */
function sanitizeFileContent(content, fileName) {
  if (Buffer.byteLength(content, "utf8") > MAX_FILE_SIZE_BYTES) {
    throw new Error(
      `File '${fileName}' exceeds maximum allowed size of ${MAX_FILE_SIZE_BYTES} bytes.`
    );
  }

  // Strip null bytes and non-printable control characters (except \t, \n, \r)
  let sanitized = content.replace(/\0/g, "").replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

  // Trim excessive whitespace
  sanitized = sanitized.replace(/[ \t]+/g, " ").trim();

  if (!sanitized || sanitized.length === 0) {
    throw new Error(`File '${fileName}' is empty after sanitization.`);
  }

  return sanitized;
}

/**
 * Check for hidden/invisible characters, base64-encoded prompts, leetspeak,
 * suspicious instruction patterns, and binary/shell command content.
 * Strips or rejects content that triggers these checks.
 */
function sanitizeForMaliciousContent(content, fileName) {
  // Remove zero-width and other invisible Unicode characters
  let sanitized = content.replace(
    /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E\u00A0]/g,
    ""
  );

  // Detect and reject base64-encoded payloads (long base64 strings)
  const base64Pattern = /(?:[A-Za-z0-9+/]{40,}={0,2})/g;
  if (base64Pattern.test(sanitized)) {
    console.warn(
      `Warning: Possible base64-encoded content detected in '${fileName}'. Stripping.`
    );
    sanitized = sanitized.replace(/(?:[A-Za-z0-9+/]{40,}={0,2})/g, "[REDACTED_BASE64]");
  }

  // Detect leetspeak patterns (simple heuristic)
  const leetspeakPattern = /(\b\w*[013457@$!]\w*\b){4,}/i;
  if (leetspeakPattern.test(sanitized)) {
    console.warn(
      `Warning: Possible leetspeak content detected in '${fileName}'. Stripping.`
    );
    sanitized = sanitized.replace(leetspeakPattern, "[REDACTED_LEETSPEAK]");
  }

  // Detect suspicious prompt injection keywords
  const suspiciousPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
    /you\s+are\s+now\s+(a|an)\s+/gi,
    /disregard\s+(all\s+)?(previous|prior|above)/gi,
    /system\s*:\s*(you|your|ignore)/gi,
    /\bjailbreak\b/gi,
    /\bprompt\s+injection\b/gi,
    /\bact\s+as\s+(a|an)\b/gi,
    /\bforget\s+(all\s+)?(previous|prior|above)\b/gi,
    /\bdo\s+not\s+follow\b/gi,
    /\boverride\s+(all\s+)?(previous|prior|above)\b/gi,
  ];
  for (const pattern of suspiciousPatterns) {
    if (pattern.test(sanitized)) {
      console.warn(
        `Warning: Suspicious prompt injection pattern detected in '${fileName}'. Stripping.`
      );
      sanitized = sanitized.replace(pattern, "[REDACTED_INJECTION]");
    }
  }

  // Detect binary/shell command content
  const shellCommandPattern = /(\b(bash|sh|cmd|powershell|exec|eval|subprocess|os\.system|popen|system\(|rm\s+-rf|wget|curl\s+http|chmod|chown|sudo|nc\s+-|netcat)\b)/gi;
  if (shellCommandPattern.test(sanitized)) {
    console.warn(
      `Warning: Possible shell/binary command content detected in '${fileName}'. Stripping.`
    );
    sanitized = sanitized.replace(shellCommandPattern, "[REDACTED_CMD]");
  }

  return sanitized;
}

/**
 * Redact common PII patterns from content.
 */
function redactPII(content) {
  let redacted = content;

  // Email addresses
  redacted = redacted.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, "[REDACTED_EMAIL]");

  // Phone numbers (international and US formats)
  redacted = redacted.replace(/(\+?(\d[\s\-.]?){7,14}\d)/g, "[REDACTED_PHONE]");

  // SSNs (US)
  redacted = redacted.replace(/\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g, "[REDACTED_SSN]");

  // Credit card numbers (basic pattern)
  redacted = redacted.replace(/\b(?:\d[ \-]?){13,16}\b/g, "[REDACTED_CC]");

  // IP addresses
  redacted = redacted.replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, "[REDACTED_IP]");

  // Full names (simple heuristic: Title Case sequences of 2-3 words)
  redacted = redacted.replace(/\b([A-Z][a-z]+\s){1,2}[A-Z][a-z]+\b/g, "[REDACTED_NAME]");

  return redacted;
}

/**
 * Redact Singapore-specific PII from content.
 */
function redactSingaporePII(content) {
  let redacted = content;

  // NRIC/FIN numbers (e.g., S1234567A, T0123456B, F1234567C, G1234567D)
  redacted = redacted.replace(/\b[STFG]\d{7}[A-Z]\b/gi, "[REDACTED_NRIC]");

  // Singapore phone numbers (8-digit starting with 6, 8, or 9)
  redacted = redacted.replace(/\b(?:\+65[\s\-]?)?[689]\d{7}\b/g, "[REDACTED_SG_PHONE]");

  // Singapore postal codes (6-digit)
  redacted = redacted.replace(/\b\d{6}\b/g, "[REDACTED_SG_POSTAL]");

  // Passport numbers (generic: letter(s) followed by digits)
  redacted = redacted.replace(/\b[A-Z]{1,2}\d{6,9}\b/g, "[REDACTED_PASSPORT]");

  return redacted;
}

/**
 * Check LLM output (document content) for dynamic code execution primitives.
 */
function sanitizeLLMOutput(content) {
  const dangerousPatterns = [
    /\beval\s*\(/gi,
    /\bexec\s*\(/gi,
    /\bsubprocess\b/gi,
    /\bnew\s+Function\s*\(/gi,
    /\bsetTimeout\s*\(\s*["'`]/gi,
    /\bsetInterval\s*\(\s*["'`]/gi,
    /\bFunction\s*\(\s*["'`]/gi,
    /\bos\.system\s*\(/gi,
    /\bchild_process\b/gi,
    /\brequire\s*\(\s*["'`]child_process["'`]\s*\)/gi,
  ];

  let sanitized = content;
  for (const pattern of dangerousPatterns) {
    if (pattern.test(sanitized)) {
      console.warn(
        `Warning: Dynamic code execution primitive detected in LLM output. Sanitizing.`
      );
      sanitized = sanitized.replace(pattern, "[REDACTED_CODE_EXEC]");
    }
  }
  return sanitized;
}

/**
 * Apply all sanitization steps to file content.
 */
function applyAllSanitization(content, fileName) {
  let result = sanitizeFileContent(content, fileName);
  result = sanitizeForMaliciousContent(result, fileName);
  result = redactPII(result);
  result = redactSingaporePII(result);
  result = sanitizeLLMOutput(result);
  return result;
}

/**
 * Sanitize a file name and verify it stays within the base directory.
 */
function safeResolvePath(baseDir, fileName) {
  const resolvedBase = path.resolve(baseDir);
  const resolvedFile = path.resolve(baseDir, fileName);
  if (!resolvedFile.startsWith(resolvedBase + path.sep) && resolvedFile !== resolvedBase) {
    throw new Error(
      `Path traversal detected: file '${fileName}' resolves outside the base directory.`
    );
  }
  return resolvedFile;
}

// --- Main script ---

const companionsDir = "companions";
const fileNames = fs.readdirSync(companionsDir);
const splitter = new CharacterTextSplitter({
  separator: " ",
  chunkSize: 200,
  chunkOverlap: 50, //TODO: adjust both chunk size and chunk overlap later
});

const langchainDocs = await Promise.all(
  fileNames.map(async (fileName) => {
    if (fileName.endsWith(".txt")) {
      // Sanitize and validate file path to prevent path traversal
      const filePath = safeResolvePath(companionsDir, fileName);
      const rawContent = fs.readFileSync(filePath, "utf8");

      // Apply all sanitization steps to file content
      const sanitizedContent = applyAllSanitization(rawContent, fileName);

      const lastSection = sanitizedContent.split("###ENDSEEDCHAT###").slice(-1)[0];
      const splitDocs = await splitter.createDocuments([lastSection]);
      return splitDocs.map((doc) => {
        // Sanitize LLM output (document page content) before indexing
        const sanitizedPageContent = sanitizeLLMOutput(doc.pageContent);
        return new Document({
          metadata: { fileName },
          pageContent: sanitizedPageContent,
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

// Validate and sanitize all documents before passing to the vector store
const validatedDocs = langchainDocs
  .flat()
  .filter((doc) => doc !== undefined)
  .map((doc) => {
    const sanitizedContent = sanitizeLLMOutput(doc.pageContent);
    return new Document({
      metadata: doc.metadata,
      pageContent: sanitizedContent,
    });
  });

await SupabaseVectorStore.fromDocuments(
  validatedDocs,
  new HuggingFaceInferenceEmbeddings({
    apiKey: process.env.HUGGINGFACEHUB_API_KEY,
  }),
  {
    client,
    tableName: "documents",
  }
);