// Major ref: https://js.langchain.com/docs/modules/indexes/vector_stores/integrations/pinecone
import { PineconeClient } from "@pinecone-database/pinecone";
import dotenv from "dotenv";
import { Document } from "langchain/document";
import { HuggingFaceInferenceEmbeddings } from "langchain/embeddings/hf";
import { PineconeStore } from "langchain/vectorstores/pinecone";
import { CharacterTextSplitter } from "langchain/text_splitter";
import fs from "fs";
import path from "path";

dotenv.config({ path: `.env.local` });

// --- Credential guard ---
const pineconeConfig = {
  apiKey: process.env.PINECONE_API_KEY,
  environment: process.env.PINECONE_ENVIRONMENT,
  index: process.env.PINECONE_INDEX,
};

if (!pineconeConfig.apiKey || !pineconeConfig.environment || !pineconeConfig.index) {
  throw new Error("Missing required Pinecone credentials: PINECONE_API_KEY, PINECONE_ENVIRONMENT, PINECONE_INDEX must all be set.");
}

if (!process.env.HUGGINGFACEHUB_API_KEY) {
  throw new Error("Missing required credential: HUGGINGFACEHUB_API_KEY must be set.");
}

// --- Sanitization and validation ---
const MAX_CONTENT_LENGTH = 100000;

const PROMPT_INJECTION_PATTERNS = [
  /^\s*(system|instruction|prompt)\s*:/im,
  /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i,
  /you\s+are\s+now\s+/i,
  /disregard\s+(all\s+)?(previous|prior|above)/i,
  /forget\s+(all\s+)?(previous|prior|above)/i,
  /new\s+instructions?\s*:/i,
  /override\s+(previous|prior|all)/i,
];

const BASE64_PATTERN = /(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/;

const LEETSPEAK_PATTERN = /(\b\w*[013@$!][013@$!]\w*\b.*){3,}/i;

const SHELL_COMMAND_PATTERNS = [
  /\b(rm\s+-rf|chmod\s+[0-7]{3,4}|curl\s+http|wget\s+http|bash\s+-c|sh\s+-c|exec\s+|eval\s*\(|system\s*\(|popen\s*\()\b/i,
  /\x7fELF/,
  /MZ\x90\x00/,
];

const INVISIBLE_UNICODE_PATTERN = /[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad]/;

const MALICIOUS_PHRASES = [
  /act\s+as\s+(if\s+you\s+are|a\s+)/i,
  /jailbreak/i,
  /DAN\s+mode/i,
  /developer\s+mode/i,
  /do\s+anything\s+now/i,
];

// Singapore-specific PII patterns
const NRIC_FIN_PATTERN = /\b[STFGM]\d{7}[A-Z]\b/i;
const SG_PHONE_PATTERN = /(\+65[\s-]?)?[689]\d{3}[\s-]?\d{4}\b/;
const PASSPORT_PATTERN_SG = /\b[A-Z]\d{7}[A-Z]?\b/;
const DOB_PATTERN = /\b(0?[1-9]|[12]\d|3[01])[\/\-](0?[1-9]|1[0-2])[\/\-](19|20)\d{2}\b/;

// General PII patterns
const SSN_PATTERN = /\b\d{3}-\d{2}-\d{4}\b/g;
const EMAIL_PATTERN = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g;
const PHONE_PATTERN = /(\+?1[\s.-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b/g;
const CREDIT_CARD_PATTERN = /\b(?:\d[ -]?){13,16}\b/g;
const ADDRESS_PATTERN = /\b\d{1,5}\s+\w+(\s+\w+){0,3}\s+(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b/gi;
const GENERAL_PASSPORT_PATTERN = /\b[A-Z]{1,2}\d{6,9}\b/g;

function redactPII(content) {
  let redacted = content;
  redacted = redacted.replace(SSN_PATTERN, "[REDACTED_SSN]");
  redacted = redacted.replace(EMAIL_PATTERN, "[REDACTED_EMAIL]");
  redacted = redacted.replace(PHONE_PATTERN, "[REDACTED_PHONE]");
  redacted = redacted.replace(CREDIT_CARD_PATTERN, "[REDACTED_CC]");
  redacted = redacted.replace(ADDRESS_PATTERN, "[REDACTED_ADDRESS]");
  redacted = redacted.replace(GENERAL_PASSPORT_PATTERN, "[REDACTED_PASSPORT]");
  return redacted;
}

function containsSingaporePII(content) {
  if (NRIC_FIN_PATTERN.test(content)) return { found: true, type: "NRIC/FIN" };
  if (SG_PHONE_PATTERN.test(content)) return { found: true, type: "SG phone number" };
  if (PASSPORT_PATTERN_SG.test(content)) return { found: true, type: "passport number" };
  if (DOB_PATTERN.test(content)) return { found: true, type: "date of birth" };
  return { found: false };
}

function sanitizeContent(content, fileName) {
  // Strip null bytes and non-printable control characters (keep newlines/tabs)
  let sanitized = content.replace(/\0/g, "").replace(/[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "");

  // Strip invisible/hidden Unicode characters
  if (INVISIBLE_UNICODE_PATTERN.test(sanitized)) {
    sanitized = sanitized.replace(/[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad]/g, "");
  }

  // Enforce maximum content length
  if (sanitized.length > MAX_CONTENT_LENGTH) {
    throw new Error(`Content in ${fileName} exceeds maximum allowed length of ${MAX_CONTENT_LENGTH} characters.`);
  }

  // Reject base64-encoded payloads
  if (BASE64_PATTERN.test(sanitized)) {
    throw new Error(`Suspicious base64-encoded content detected in ${fileName}. Skipping.`);
  }

  // Reject leetspeak obfuscation patterns
  if (LEETSPEAK_PATTERN.test(sanitized)) {
    throw new Error(`Suspicious leetspeak obfuscation detected in ${fileName}. Skipping.`);
  }

  // Reject shell commands or binary signatures
  for (const pattern of SHELL_COMMAND_PATTERNS) {
    if (pattern.test(sanitized)) {
      throw new Error(`Suspicious shell command or binary content detected in ${fileName}. Skipping.`);
    }
  }

  // Reject prompt-injection patterns
  for (const pattern of PROMPT_INJECTION_PATTERNS) {
    if (pattern.test(sanitized)) {
      throw new Error(`Prompt injection pattern detected in ${fileName}. Skipping.`);
    }
  }

  // Reject malicious phrases
  for (const pattern of MALICIOUS_PHRASES) {
    if (pattern.test(sanitized)) {
      throw new Error(`Malicious content pattern detected in ${fileName}. Skipping.`);
    }
  }

  return sanitized;
}

function validateAndSanitizeSection(lastSection, fileName) {
  // Strip null bytes and non-printable control characters
  let sanitized = lastSection.replace(/\0/g, "").replace(/[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "");

  // Enforce maximum content length
  if (sanitized.length > MAX_CONTENT_LENGTH) {
    throw new Error(`Section in ${fileName} exceeds maximum allowed length.`);
  }

  // Reject prompt-injection patterns
  for (const pattern of PROMPT_INJECTION_PATTERNS) {
    if (pattern.test(sanitized)) {
      throw new Error(`Prompt injection pattern detected in section of ${fileName}.`);
    }
  }

  return sanitized;
}

// --- Path traversal validation ---
const baseCompanionsDir = path.resolve("companions");

const fileNames = fs.readdirSync("companions");
const splitter = new CharacterTextSplitter({
  separator: " ",
  chunkSize: 200,
  chunkOverlap: 50, //TODO: adjust both chunk size and chunk overlap later
});

const langchainDocs = await Promise.all(
  fileNames.map(async (fileName) => {
    if (fileName.endsWith(".txt")) {
      // Path traversal validation
      const resolvedPath = path.resolve(baseCompanionsDir, fileName);
      if (!resolvedPath.startsWith(baseCompanionsDir + path.sep) && resolvedPath !== baseCompanionsDir) {
        console.warn(`Path traversal detected for file: ${fileName}. Skipping.`);
        return undefined;
      }

      // Validate filename does not contain path traversal sequences
      if (fileName.includes("..") || fileName.includes("/") || fileName.includes("\\")) {
        console.warn(`Invalid filename detected: ${fileName}. Skipping.`);
        return undefined;
      }

      const filePath = resolvedPath;
      let fileContent;
      try {
        fileContent = fs.readFileSync(filePath, "utf8");
      } catch (err) {
        console.warn(`Failed to read file ${fileName}: ${err.message}. Skipping.`);
        return undefined;
      }

      // Sanitize file content (malicious content, shell commands, etc.)
      let sanitizedFileContent;
      try {
        sanitizedFileContent = sanitizeContent(fileContent, fileName);
      } catch (err) {
        console.warn(err.message);
        return undefined;
      }

      // Singapore PII detection — skip file if PII found
      const sgPiiResult = containsSingaporePII(sanitizedFileContent);
      if (sgPiiResult.found) {
        console.warn(`Singapore PII detected (${sgPiiResult.type}) in ${fileName}. Skipping file.`);
        return undefined;
      }

      // Redact general PII before processing
      const redactedContent = redactPII(sanitizedFileContent);

      // get the last section in the doc for background info
      const lastSection = redactedContent.split("###ENDSEEDCHAT###").slice(-1)[0];

      // Validate and sanitize the section before passing to embeddings
      let validatedSection;
      try {
        validatedSection = validateAndSanitizeSection(lastSection, fileName);
      } catch (err) {
        console.warn(err.message);
        return undefined;
      }

      const splitDocs = await splitter.createDocuments([validatedSection]);
      return splitDocs.map((doc) => {
        return new Document({
          metadata: { fileName },
          pageContent: doc.pageContent,
        });
      });
    }
  })
);

const client = new PineconeClient();
await client.init({
  apiKey: pineconeConfig.apiKey,
  environment: pineconeConfig.environment,
});
const pineconeIndex = client.Index(pineconeConfig.index);

await PineconeStore.fromDocuments(
  langchainDocs.flat().filter((doc) => doc !== undefined),
  new HuggingFaceInferenceEmbeddings({ apiKey: process.env.HUGGINGFACEHUB_API_KEY }),
  {
    pineconeIndex,
  }
);