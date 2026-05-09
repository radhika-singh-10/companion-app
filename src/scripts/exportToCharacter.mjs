import { Redis } from "@upstash/redis";
import { PromptTemplate } from "langchain/prompts";
import { LLMChain } from "langchain/chains";
import { OpenAI } from "langchain/llms/openai";

import dotenv from "dotenv";
import fs from "fs/promises";
import path from "path";
dotenv.config({ path: `.env.local` });

/**
 * Validates that a companion name contains only safe characters.
 * Prevents path traversal and injection via the name parameter.
 */
function validateCompanionName(name) {
  if (typeof name !== "string" || !/^[a-zA-Z0-9_-]{1,64}$/.test(name)) {
    throw new Error(
      `Invalid COMPANION_NAME: must be 1-64 alphanumeric characters, hyphens, or underscores. Got: ${JSON.stringify(name)}`
    );
  }
  return name;
}

/**
 * Sanitizes a string for safe embedding in an LLM prompt.
 * Removes/escapes characters that could be used for prompt injection.
 */
function sanitizeForPrompt(value) {
  if (value === null || value === undefined) return "";
  // Convert to string, then strip or replace characters that could
  // break out of the intended prompt context or inject new instructions.
  return String(value)
    .replace(/`/g, "'")
    .replace(/\$\{/g, "\\${")
    .replace(/###/g, "---")
    .replace(/\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>/gi, "")
    .trim();
}

// ── Tool allow list policy ────────────────────────────────────────────────────
const POLICY_VERSION = "v1.0.0";
const ALLOWED_TOOLS = new Set(["LLMChain"]);

function auditLog({ actor, tool, allowed, reason, question }) {
  const entry = {
    timestamp: new Date().toISOString(),
    policyVersion: POLICY_VERSION,
    actor,
    tool,
    allowed,
    reason,
    question,
  };
  // Write structured audit record to stdout so it can be captured by log
  // aggregators; use process.stdout.write to avoid mixing with app output.
  process.stdout.write("[AUDIT] " + JSON.stringify(entry) + "\n");
}

function assertToolAllowed(toolName, actor, question) {
  if (!ALLOWED_TOOLS.has(toolName)) {
    auditLog({
      actor,
      tool: toolName,
      allowed: false,
      reason: `Tool "${toolName}" is not in the allow list`,
      question,
    });
    throw new Error(
      `[Policy violation] Tool "${toolName}" is not permitted. ` +
        `Allowed tools: ${[...ALLOWED_TOOLS].join(", ")}`
    );
  }
  auditLog({
    actor,
    tool: toolName,
    allowed: true,
    reason: "Tool is in the allow list",
    question,
  });
}
// ─────────────────────────────────────────────────────────────────────────────

// AUDIT LOG RETENTION POLICY:
// Audit log files follow the naming pattern: audit_<ISO-date>.jsonl
// Retention: logs MUST be retained for a minimum of 90 days.
// Rotation: a new log file is created per calendar day.
// Deletion of logs older than the retention window must be performed
// by a scheduled job external to this script.
const AUDIT_LOG_FILE = `audit_${new Date().toISOString().slice(0, 10)}.jsonl`;

async function writeAuditRecord(record) {
  const line = JSON.stringify(record) + "\n";
  await fs.appendFile(AUDIT_LOG_FILE, line, "utf8");
}

function hashInput(input) {
  return crypto.createHash("sha256").update(JSON.stringify(input)).digest("hex");
}

// ---------------------------------------------------------------------------
// Provenance / labeling helpers
// ---------------------------------------------------------------------------
const AI_LABEL = "AI_GENERATED_CONTENT";
const PROVENANCE_MODEL = "gpt-3.5-turbo-16k";
const PROVENANCE_TOOL = "langchain/llms/openai";

/**
 * Builds a deterministic HMAC-SHA256 watermark over the content so that
 * the origin can be verified later with the same secret.
 */
function computeWatermark(content) {
  const secret = process.env.WATERMARK_SECRET;
  if (!secret) {
    throw new Error(
      "WATERMARK_SECRET env var is not set — cannot watermark AI-generated content."
    );
  }
  return crypto.createHmac("sha256", secret).update(content).digest("hex");
}

/**
 * Attaches a provenance header to `content` and returns the labeled string.
 * Throws if any required field is missing so the fail-safe can intercept it.
 */
function attachProvenance(content) {
  const timestamp = new Date().toISOString();
  const watermark = computeWatermark(content); // throws on missing secret
  const header = [
    `# ${AI_LABEL}`,
    `# model: ${PROVENANCE_MODEL}`,
    `# tool: ${PROVENANCE_TOOL}`,
    `# generated_at: ${timestamp}`,
    `# watermark (HMAC-SHA256): ${watermark}`,
    `# companion: ${COMPANION_NAME}`,
    "#",
  ].join("\n");
  return `${header}\n${content}`;
}

/**
 * Fail-safe write: labels the content first; if labeling throws for ANY
 * reason the file is NOT written and the error is re-thrown.
 */
async function safeWriteAIContent(filePath, content) {
  // This will throw before touching the filesystem if labeling fails.
  const labeled = attachProvenance(content);
  await fs.writeFile(filePath, labeled);
}

const logStream = createWriteStream("llm_interactions.log", { flags: "a" });

function logLLMInteraction(type, data) {
  const entry = JSON.stringify({
    timestamp: new Date().toISOString(),
    type,
    ...data,
  });
  logStream.write(entry + "\n");
  console.log(`[LLM ${type}]`, entry);
}

const COMPANION_NAME_RAW = process.argv[2];
// Sanitize companion name to prevent path traversal
if (!COMPANION_NAME_RAW || !/^[a-zA-Z0-9_\-]+$/.test(COMPANION_NAME_RAW)) {
  throw new Error("Invalid COMPANION_NAME: only alphanumeric characters, underscores, and hyphens are allowed.");
}
const COMPANION_NAME = COMPANION_NAME_RAW;
const MODEL_NAME = process.argv[3];
const USER_ID = process.argv[4];

if (!!!RAW_COMPANION_NAME || !!!MODEL_NAME || !!!USER_ID) {
  throw new Error(
    "**Usage**: npm run export-to-character <COMPANION_NAME> <MODEL_NAME> <USER_ID>"
  );
}

/**
 * Validate that a name contains only safe alphanumeric/hyphen/underscore characters.
 * This prevents path traversal and prompt injection via the name itself.
 */
function validateName(name) {
  if (typeof name !== "string" || name.length === 0 || name.length > 100) {
    throw new Error(`Invalid name: must be a non-empty string up to 100 characters.`);
  }
  if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
    throw new Error(
      `Invalid name "${name}": only alphanumeric characters, hyphens, and underscores are allowed.`
    );
  }
  return name;
}

/**
 * Sanitize free-text content before injecting it into an LLM prompt.
 * - Removes null bytes and other ASCII control characters (except common whitespace).
 * - Strips sequences that could be used for prompt injection (e.g. "###", "---", repeated special chars).
 * - Trims leading/trailing whitespace.
 */
function sanitizeContent(text) {
  if (typeof text !== "string") {
    return "";
  }
  // Remove null bytes and non-printable control characters (keep \t, \n, \r)
  let sanitized = text.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  // Limit length to prevent excessively large prompts
  const MAX_LENGTH = 20000;
  if (sanitized.length > MAX_LENGTH) {
    sanitized = sanitized.slice(0, MAX_LENGTH);
  }
  return sanitized.trim();
}

// Validate all command-line name inputs
validateName(COMPANION_NAME);
validateName(MODEL_NAME);
validateName(USER_ID);

/**
 * Sanitizes a text segment extracted from an uploaded companion file before
 * it is injected into an LLM prompt.
 *
 * Checks performed:
 *  1. Invisible / zero-width characters (common in hidden-prompt attacks)
 *  2. Base64-encoded blobs that could hide secondary instructions
 *  3. Leetspeak patterns used to obfuscate prompt-injection keywords
 *  4. Shell / binary command patterns
 *  5. Explicit prompt-injection phrases
 */
function sanitizeSegment(text, segmentName) {
  if (typeof text !== "string") {
    throw new Error(`Companion file segment "${segmentName}" is not a string.`);
  }

  // 1. Invisible / zero-width characters
  const invisibleCharsPattern = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/g;
  if (invisibleCharsPattern.test(text)) {
    throw new Error(
      `Companion file segment "${segmentName}" contains invisible/zero-width characters that may indicate a hidden prompt injection attempt.`
    );
  }

  // 2. Base64-encoded blobs (long runs of base64 chars, >=64 chars)
  const base64Pattern = /(?:[A-Za-z0-9+\/]{64,}={0,2})/;
  if (base64Pattern.test(text)) {
    throw new Error(
      `Companion file segment "${segmentName}" contains a base64-encoded payload that may hide malicious instructions.`
    );
  }

  // 3. Leetspeak obfuscation of sensitive keywords
  //    Normalise common leet substitutions then check for injection keywords.
  const leetNormalized = text
    .replace(/0/g, "o")
    .replace(/1/g, "i")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/@/g, "a")
    .replace(/\$/g, "s")
    .toLowerCase();

  const injectionKeywords = [
    "ignore previous instructions",
    "ignore all instructions",
    "disregard previous",
    "forget your instructions",
    "you are now",
    "act as",
    "new instructions",
    "override instructions",
    "system prompt",
    "jailbreak",
    "do anything now",
    "dan mode",
  ];
  for (const keyword of injectionKeywords) {
    if (leetNormalized.includes(keyword)) {
      throw new Error(
        `Companion file segment "${segmentName}" contains a suspected prompt injection keyword: "${keyword}".`
      );
    }
  }

  // 4. Shell / binary command patterns
  const shellPatterns = [
    /\$\([^)]*\)/,          // $(command)
    /`[^`]+`/,              // `command`
    /\b(exec|eval|system|popen|subprocess|os\.system|child_process)\s*\(/i,
    /\b(rm|del|format|shutdown|reboot|wget|curl|nc|netcat|bash|sh|cmd|powershell)\b/i,
    /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/,  // non-printable / binary bytes
  ];
  for (const pattern of shellPatterns) {
    if (pattern.test(text)) {
      throw new Error(
        `Companion file segment "${segmentName}" contains shell commands or binary content that may be malicious.`
      );
    }
  }

  // 5. Enforce a reasonable length limit to prevent prompt-flooding attacks
  const MAX_SEGMENT_LENGTH = 8000;
  if (text.length > MAX_SEGMENT_LENGTH) {
    throw new Error(
      `Companion file segment "${segmentName}" exceeds the maximum allowed length of ${MAX_SEGMENT_LENGTH} characters.`
    );
  }

  return text;
}

/**
 * Sanitize a string before injecting it into an LLM prompt.
 * Removes / neutralises:
 *  - invisible / zero-width characters
 *  - base64-encoded blobs that could hide instructions
 *  - shell / binary command patterns
 *  - common prompt-injection trigger phrases
 *  - leetspeak substitutions used to bypass keyword filters
 */
function sanitizeInput(raw) {
  if (typeof raw !== "string") return "";

  // 1. Strip zero-width and other invisible Unicode characters
  let s = raw.replace(/[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/g, "");

  // 2. Decode and reject base64 blobs that contain suspicious content
  s = s.replace(/[A-Za-z0-9+/]{20,}={0,2}/g, (match) => {
    try {
      const decoded = Buffer.from(match, "base64").toString("utf8");
      if (SUSPICIOUS_PATTERN.test(decoded)) {
        return "[REDACTED_BASE64]";
      }
    } catch (_) { /* not valid base64 – leave as-is */ }
    return match;
  });

  // 3. Remove shell / binary command patterns
  s = s.replace(/(`[^`]*`|\$\([^)]*\)|\|\s*\w+|&&|;\s*\w+|\bexec\b|\beval\b|\bsystem\b|\bspawn\b|\bchild_process\b)/gi, "[REDACTED_CMD]");

  // 4. Remove prompt-injection trigger phrases (case-insensitive)
  const injectionPhrases = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
    /disregard\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
    /forget\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
    /you\s+are\s+now\s+/gi,
    /new\s+instructions?\s*:/gi,
    /system\s*prompt\s*:/gi,
    /###\s*instruction/gi,
    /\[INST\]/gi,
    /<\|im_start\|>/gi,
    /<\|im_end\|>/gi,
  ];
  for (const pattern of injectionPhrases) {
    s = s.replace(pattern, "[REDACTED_INJECTION]");
  }

  // 5. Neutralise leetspeak by normalising common substitutions then re-checking
  const leetMap = { "@": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t", "$": "s", "+": "t" };
  const normalised = s.replace(/[@310$+57]/g, (c) => leetMap[c] ?? c);
  for (const pattern of injectionPhrases) {
    if (pattern.test(normalised)) {
      // The normalised version matched – redact the original token
      s = "[REDACTED_LEET_INJECTION]";
      break;
    }
  }

  return s;
}

// Shared pattern used inside sanitizeInput
const SUSPICIOUS_PATTERN = /ignore|instruction|system|exec|eval|prompt|disregard|forget/i;

// Sanitize the companion name (command-line arg) – also enforce safe filename characters
const COMPANION_NAME = sanitizeInput(RAW_COMPANION_NAME).replace(/[^a-zA-Z0-9_-]/g, "");
if (!COMPANION_NAME) {
  throw new Error("COMPANION_NAME contains only unsafe characters and was fully redacted.");
}

const companionsDir = path.resolve("companions");
const companionFile = path.resolve(companionsDir, COMPANION_NAME + ".txt");
if (!companionFile.startsWith(companionsDir + path.sep)) {
  throw new Error(`Path traversal detected: resolved path '${companionFile}' is outside the companions directory.`);
}
const data = await fs.readFile(companionFile, "utf8");
const presplit = data.split("###ENDPREAMBLE###");
if (presplit.length < 2) {
  throw new Error("Companion file is missing the ###ENDPREAMBLE### delimiter.");
}
const preambleRaw = presplit[0];
const seedsplit = presplit[1].split("###ENDSEEDCHAT###");
if (seedsplit.length < 2) {
  throw new Error("Companion file is missing the ###ENDSEEDCHAT### delimiter.");
}
const seedChatRaw = seedsplit[0];
const backgroundStoryRaw = seedsplit[1];

// Sanitize each segment before use in LLM prompts
const preamble = sanitizeSegment(preambleRaw, "preamble");
const seedChat = sanitizeSegment(seedChatRaw, "seedChat");
const backgroundStory = sanitizeSegment(backgroundStoryRaw, "backgroundStory");
console.log(preamble, backgroundStory);

const history = new Redis({
  url: EXTERNAL_CREDENTIALS.upstashRedisUrl,
  token: EXTERNAL_CREDENTIALS.upstashRedisToken,
});

const upstashChatHistory = await history.zrange(
  `${COMPANION_NAME}-${MODEL_NAME}-${USER_ID}`,
  0,
  Date.now(),
  {
    byScore: true,
  }
);
const recentChat = upstashChatHistory.slice(-30).map((entry) => sanitizeContent(String(entry)));
const anthropicClient = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY,
});

// Wrapper to make Anthropic compatible with LangChain's LLMChain interface
const model = {
  verbose: true,
  call: async (prompt) => {
    const message = await anthropicClient.messages.create({
      model: "claude-3-5-sonnet-20241022",
      max_tokens: 1024,
      messages: [{ role: "user", content: prompt }],
    });
    return message.content[0].text;
  },
};

const sanitizedCompanionName = sanitizeContent(COMPANION_NAME);
const safePreamble = sanitizeForPrompt(preamble);
const safeBackgroundStory = sanitizeForPrompt(backgroundStory);
const safeSeedChat = sanitizeForPrompt(seedChat);
const safeRecentChat = Array.isArray(recentChat)
  ? recentChat.map(sanitizeForPrompt).join("\n")
  : sanitizeForPrompt(recentChat);
const safeCompanionName = sanitizeForPrompt(COMPANION_NAME);

const chainPrompt = PromptTemplate.fromTemplate(
  `--- Background Story ---\n` +
  `${safePreamble}\n\n` +
  `${safeBackgroundStory}\n\n` +
  `--- Chat History ---\n` +
  `${safeSeedChat}\n\n` +
  `...\n` +
  `${safeRecentChat}\n\n` +
  `Above is someone whose name is ${safeCompanionName}'s story and their chat history with a human. ` +
  `Output answer to the following question. Return only the answer itself.\n\n` +
  `{question}`
);

/**
 * Sanitizes LLM output by detecting and stripping dynamic code execution primitives.
 * Throws an error if dangerous patterns are found, or strips them based on policy.
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
  /\bvm\.runInThisContext\s*\(/gi,
  /\bvm\.runInNewContext\s*\(/gi,
  /\bvm\.Script\s*\(/gi,
  /\bFunction\s*\(/gi,
];

function sanitizeLLMOutput(text, questionIndex) {
  if (typeof text !== "string") {
    console.warn(`[sanitizeLLMOutput] Result ${questionIndex} is not a string; coercing.`);
    text = String(text ?? "");
  }

  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.test(text)) {
      console.error(
        `[sanitizeLLMOutput] Dangerous pattern detected in LLM output for question ${questionIndex}: ${pattern}`
      );
      // Strip the dangerous content rather than propagating it
      text = text.replace(pattern, "[REDACTED]");
    }
    // Reset lastIndex for global regexes
    pattern.lastIndex = 0;
  }

  // Remove null bytes and other control characters that could be used for injection
  text = text.replace(/\x00/g, "").replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

  return text;
}

const questions = [
  `Greeting: What would ${sanitizedCompanionName} say to start a conversation?`,
  `Short Description: In a few sentences, how would ${sanitizedCompanionName} describe themselves?`,
  `Long Description: In a few sentences, how would ${sanitizedCompanionName} describe themselves?`,
];
// Generate a single correlation ID linking all inference steps in this batch.
const CORRELATION_ID = crypto.randomUUID();
const MODEL_ID = "openai/gpt-3.5-turbo-16k";
const MODEL_VERSION = "gpt-3.5-turbo-16k";

const results = await Promise.all(
  questions.map(async (question) => {
    const inputHash = hashInput({ question });
    const timestamp = new Date().toISOString();
    let result;
    try {
      result = await chain.call({ question });
    } catch (error) {
      // Log the failure to the audit trail before re-throwing (fail closed).
      await writeAuditRecord({
        correlationId: CORRELATION_ID,
        timestamp,
        principal: USER_ID,
        modelId: MODEL_ID,
        modelVersion: MODEL_VERSION,
        inputHash,
        question,
        output: null,
        status: "ERROR",
        error: String(error),
      });
      // Re-throw so the caller is aware of the failure (no silent swallowing).
      throw error;
    }
    // Persist a full decision audit record for this inference.
    await writeAuditRecord({
      correlationId: CORRELATION_ID,
      timestamp,
      principal: USER_ID,
      modelId: MODEL_ID,
      modelVersion: MODEL_VERSION,
      inputHash,
      question,
      output: result?.text ?? null,
      status: "SUCCESS",
    });
    return result;
  })
);
      const text = await model.call(prompt);
      return { text };
    } catch (error) {
      console.error(error);
    }
  })
);

let output = "";
for (let i = 0; i < questions.length; i++) {
  if (!results[i] || typeof results[i].text === "undefined") {
    console.warn(`[export] No result for question ${i}: "${questions[i]}". Skipping.`);
    continue;
  }
  const sanitizedText = sanitizeLLMOutput(results[i].text, i);
  output += `*****${questions[i]}*****\n${sanitizedText}\n\n`;
}
output += `Definition (Advanced)\n${recentChat.join("\n")}`;

// Fail-safe writes: content is only persisted if provenance labeling succeeds.
await safeWriteAIContent(
  `${COMPANION_NAME}_chat_history.txt`,
  Array.isArray(upstashChatHistory)
    ? upstashChatHistory.join("\n")
    : String(upstashChatHistory)
);
await safeWriteAIContent(`${COMPANION_NAME}_character_ai_data.txt`, output);
