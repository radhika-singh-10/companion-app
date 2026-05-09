import { Redis } from "@upstash/redis";
import { PromptTemplate } from "langchain/prompts";
import { LLMChain } from "langchain/chains";
import { OpenAI } from "langchain/llms/openai";

import dotenv from "dotenv";
import fs from "fs/promises";
dotenv.config({ path: `.env.local` });

// ── Approved Model Registry ──────────────────────────────────────────────────
// Only models listed here may be used. Each entry carries an immutable
// version pin (snapshot date suffix) so the exact model weights are fixed
// server-side and cannot silently change.
const APPROVED_MODEL_REGISTRY = {
  // mutable alias  →  immutable pinned identifier
  "gpt-3.5-turbo-16k": "gpt-3.5-turbo-16k-0613",
};

function resolveModel(requestedName) {
  const pinned = APPROVED_MODEL_REGISTRY[requestedName];
  if (!pinned) {
    throw new Error(
      `Model "${requestedName}" is NOT in the approved model registry. ` +
      `Approved models: ${Object.keys(APPROVED_MODEL_REGISTRY).join(", ")}`
    );
  }
  return pinned;
}
// ─────────────────────────────────────────────────────────────────────────────

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Sanitize a string for safe interpolation into LLM prompts
function sanitizeForPrompt(value) {
  if (typeof value !== "string") return String(value);
  // Remove sequences commonly used for prompt injection
  return value
    .replace(/###/g, "")
    .replace(/SYSTEM:/gi, "")
    .replace(/IGNORE/gi, "")
    .replace(/[`<>]/g, "");
}

// ── Tool Allow List Policy ────────────────────────────────────────────────────
const POLICY_VERSION = "1.0.0";

// Only these exact chain types are permitted to be constructed and called.
const ALLOWED_CHAIN_TYPES = new Set(["LLMChain"]);

// Only questions whose prefix matches one of these approved intents may be sent
// to the LLM.  Any runtime-constructed question that does not match is denied.
const ALLOWED_QUESTION_PREFIXES = [
  "Greeting:",
  "Short Description:",
  "Long Description:",
];

// ── Structured Audit Logger ───────────────────────────────────────────────────
function auditLog(entry) {
  // Write a structured JSON record to stdout so it can be captured by any
  // log-aggregation pipeline (CloudWatch, Datadog, Splunk, etc.).
  process.stdout.write(
    JSON.stringify({
      timestamp: new Date().toISOString(),
      policyVersion: POLICY_VERSION,
      actor: USER_ID ?? "unknown",
      companion: COMPANION_NAME ?? "unknown",
      ...entry,
    }) + "\n"
  );
}

// ── Input Sanitiser ───────────────────────────────────────────────────────────
// Strip characters that could be used for prompt-injection before interpolating
// external data into the prompt template.
function sanitize(value) {
  if (typeof value !== "string") return String(value ?? "");
  // Remove template-literal placeholders and common injection markers.
  return value
    .replace(/\$\{[^}]*\}/g, "")
    .replace(/[<>]/g, "")
    .trim();
}

// ── Chain Allow-List Guard ────────────────────────────────────────────────────
function assertChainAllowed(chainType) {
  if (!ALLOWED_CHAIN_TYPES.has(chainType)) {
    auditLog({
      event: "CHAIN_DENIED",
      chainType,
      reason: `Chain type '${chainType}' is not in the allow list`,
    });
    throw new Error(
      `Policy violation: chain type '${chainType}' is not permitted.`
    );
  }
  auditLog({ event: "CHAIN_ALLOWED", chainType });
}

// ── Question Allow-List Guard ─────────────────────────────────────────────────
function assertQuestionAllowed(question) {
  const allowed = ALLOWED_QUESTION_PREFIXES.some((prefix) =>
    question.trimStart().startsWith(prefix)
  );
  if (!allowed) {
    auditLog({
      event: "TOOL_INVOCATION_DENIED",
      question,
      reason: "Question prefix not in allow list",
      allowedPrefixes: ALLOWED_QUESTION_PREFIXES,
    });
    throw new Error(
      `Policy violation: question '${question}' is not in the approved allow list.`
    );
  }
  auditLog({ event: "TOOL_INVOCATION_ALLOWED", question });
}

const LLM_LOG_FILE = "llm_interaction_log.jsonl";
const llmLogStream = createWriteStream(LLM_LOG_FILE, { flags: "a" });

function logLLMInteraction(entry) {
  const record = { timestamp: new Date().toISOString(), ...entry };
  llmLogStream.write(JSON.stringify(record) + "\n");
}

// ---------------------------------------------------------------------------
// Prompt-injection sanitization
// ---------------------------------------------------------------------------
const BASE64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

// Patterns that indicate shell commands, binary payloads, or injection attempts
const SHELL_CMD_RE = /(?:^|\s)(?:rm\s+-rf|chmod|chown|wget|curl|bash|sh\s+-c|exec|eval|system|passthru|popen|subprocess|os\.system|__import__|\$\(|`[^`]*`)/i;

// Leetspeak substitution map (common replacements)
const LEET_MAP = { '0':'o','1':'i','3':'e','4':'a','5':'s','7':'t','@':'a','$':'s','!':'i' };
const LEET_RE = /[013457@$!]/g;

// Invisible / zero-width characters
const INVISIBLE_RE = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/g;

// Suspicious prompt-injection keywords
const INJECTION_KEYWORDS_RE = /(?:ignore\s+(?:previous|above|all)\s+instructions?|disregard\s+(?:previous|above|all)|you\s+are\s+now|act\s+as\s+(?:a|an)?\s*(?:different|new|evil|unrestricted)|jailbreak|do\s+anything\s+now|dan\s+mode|developer\s+mode|system\s+prompt|<\s*script|<\s*img|<\s*svg|javascript\s*:)/i;

function decodeLeet(str) {
  return str.replace(LEET_RE, (ch) => LEET_MAP[ch] || ch);
}

function isBase64Payload(str) {
  // Only flag strings that are long enough to be meaningful encoded payloads
  const trimmed = str.trim();
  return trimmed.length >= 20 && BASE64_RE.test(trimmed);
}

function sanitizeInput(value, fieldName) {
  if (typeof value !== 'string') {
    throw new Error(`Sanitization error: ${fieldName} must be a string.`);
  }

  // 1. Strip invisible / zero-width characters
  let sanitized = value.replace(INVISIBLE_RE, '');

  // 2. Reject base64-encoded payloads (line-by-line check)
  for (const line of sanitized.split('\n')) {
    if (isBase64Payload(line)) {
      throw new Error(
        `Security violation: ${fieldName} contains a base64-encoded payload. Aborting.`
      );
    }
  }

  // 3. Check for shell / binary commands
  if (SHELL_CMD_RE.test(sanitized)) {
    throw new Error(
      `Security violation: ${fieldName} contains shell or binary commands. Aborting.`
    );
  }

  // 4. Check for injection keywords in the raw value
  if (INJECTION_KEYWORDS_RE.test(sanitized)) {
    throw new Error(
      `Security violation: ${fieldName} contains prompt-injection keywords. Aborting.`
    );
  }

  // 5. Check for injection keywords after leetspeak normalisation
  const deLeeted = decodeLeet(sanitized);
  if (INJECTION_KEYWORDS_RE.test(deLeeted)) {
    throw new Error(
      `Security violation: ${fieldName} contains leetspeak-obfuscated prompt-injection content. Aborting.`
    );
  }

  return sanitized;
}
// ---------------------------------------------------------------------------

const RAW_COMPANION_NAME = process.argv[2];
// Validate COMPANION_NAME: only allow alphanumeric characters, hyphens, and underscores
if (RAW_COMPANION_NAME && !/^[a-zA-Z0-9_-]+$/.test(RAW_COMPANION_NAME)) {
  throw new Error(
    "Invalid COMPANION_NAME: only alphanumeric characters, hyphens, and underscores are allowed."
  );
}
const COMPANION_NAME = RAW_COMPANION_NAME;
const MODEL_NAME = process.argv[3];
const USER_ID = process.argv[4];

// Sanitize command-line argument used in the prompt
try {
  sanitizeInput(COMPANION_NAME, 'COMPANION_NAME');
} catch (err) {
  throw new Error(`Invalid COMPANION_NAME argument: ${err.message}`);
}

if (!!!COMPANION_NAME || !!!MODEL_NAME || !!!USER_ID) {
  throw new Error(
    "**Usage**: npm run export-to-character <COMPANION_NAME> <MODEL_NAME> <USER_ID>"
  );
}

// Validate COMPANION_NAME: only allow alphanumeric characters, hyphens, and underscores
// to prevent path traversal and prompt injection via the name.
const SAFE_NAME_PATTERN = /^[a-zA-Z0-9_-]{1,64}$/;
if (!SAFE_NAME_PATTERN.test(COMPANION_NAME)) {
  throw new Error(
    "Invalid COMPANION_NAME: must contain only alphanumeric characters, hyphens, or underscores (max 64 chars)."
  );
}
if (!SAFE_NAME_PATTERN.test(MODEL_NAME)) {
  throw new Error(
    "Invalid MODEL_NAME: must contain only alphanumeric characters, hyphens, or underscores (max 64 chars)."
  );
}
// Validate USER_ID: only allow alphanumeric characters, hyphens, and underscores
const SAFE_ID_PATTERN = /^[a-zA-Z0-9_|-]{1,128}$/;
if (!SAFE_ID_PATTERN.test(USER_ID)) {
  throw new Error(
    "Invalid USER_ID: must contain only alphanumeric characters, hyphens, pipes, or underscores (max 128 chars)."
  );
}

/**
 * Sanitize a string for safe inclusion in an LLM prompt.
 * - Removes null bytes and control characters.
 * - Strips sequences that could be used to inject fake prompt sections
 *   (e.g. lines that start with "###" which is the section delimiter used in the prompt).
 * - Truncates to maxLength characters.
 */
function sanitizeForPrompt(value, maxLength = 4000) {
  if (typeof value !== "string") {
    value = String(value);
  }
  // Remove null bytes and ASCII control characters (except newline/tab)
  value = value.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  // Neutralize lines that start with ### to prevent fake section injection
  value = value.replace(/^(\s*###)/gm, "# #");
  // Truncate
  if (value.length > maxLength) {
    value = value.slice(0, maxLength) + "[TRUNCATED]";
  }
  return value;
}

// ---------------------------------------------------------------------------
// Sanitization helpers – guard against prompt-injection via uploaded files
// ---------------------------------------------------------------------------

/**
 * Strip invisible / zero-width Unicode characters that are commonly used to
 * hide injected instructions from human reviewers.
 */
function stripInvisibleChars(text) {
  // Zero-width space, zero-width non-joiner, zero-width joiner, word joiner,
  // soft hyphen, left-to-right / right-to-left marks, BOM, etc.
  return text.replace(
    /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u00AD\u200B-\u200F\u2028\u2029\u202A-\u202E\u2060-\u206F\uFEFF]/g,
    ""
  );
}

/**
 * Return true when the string contains a suspicious base64-encoded blob
 * (≥ 40 contiguous base64 characters).  Attackers encode instructions in
 * base64 to bypass keyword filters.
 */
function containsBase64Blob(text) {
  return /[A-Za-z0-9+/]{40,}={0,2}/.test(text);
}

/**
 * Return true when the string looks like it contains shell / binary commands
 * that should never appear in a character description file.
 */
function containsShellOrBinaryPatterns(text) {
  const patterns = [
    /\$\([^)]*\)/,          // $(command)
    /`[^`]+`/,              // `command`
    /\b(eval|exec|system|popen|subprocess|os\.system)\s*\(/i,
    /\b(curl|wget|nc|ncat|bash|sh|cmd\.exe|powershell)\b/i,
    /[\x00-\x08\x0E-\x1F]/, // raw control bytes
  ];
  return patterns.some((re) => re.test(text));
}

/**
 * Normalise common leetspeak substitutions so that keyword checks below
 * cannot be trivially bypassed with "1gnore", "sy5tem", etc.
 */
function normalizeLeetspeak(text) {
  return text
    .replace(/0/g, "o")
    .replace(/1/g, "i")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/@/g, "a")
    .replace(/\$/g, "s");
}

/**
 * Return true when the (normalised) text contains known prompt-injection
 * trigger phrases.
 */
function containsInjectionPhrases(text) {
  const normalized = normalizeLeetspeak(text.toLowerCase());
  const phrases = [
    "ignore previous instructions",
    "ignore all previous",
    "disregard previous",
    "forget previous instructions",
    "override previous",
    "new instructions:",
    "system prompt:",
    "system:",
    "you are now",
    "act as",
    "pretend you are",
    "pretend to be",
    "roleplay as",
    "jailbreak",
    "dan mode",
    "developer mode",
    "prompt injection",
    "<|im_start|>",
    "<|im_end|>",
    "<|endoftext|>",
    "### instruction",
    "### system",
    "[system]",
    "[inst]",
  ];
  return phrases.some((phrase) => normalized.includes(phrase));
}

/**
 * Run all checks on a single field extracted from the companion file.
 * Throws an Error (halting the script) if any check fails.
 */
function sanitizeField(fieldName, raw) {
  const cleaned = stripInvisibleChars(raw);

  if (containsBase64Blob(cleaned)) {
    throw new Error(
      `Security violation in companion file – field "${fieldName}" contains a ` +
        `base64-encoded blob which may hide injected instructions.`
    );
  }

  if (containsShellOrBinaryPatterns(cleaned)) {
    throw new Error(
      `Security violation in companion file – field "${fieldName}" contains ` +
        `shell or binary command patterns.`
    );
  }

  if (containsInjectionPhrases(cleaned)) {
    throw new Error(
      `Security violation in companion file – field "${fieldName}" contains ` +
        `prompt-injection trigger phrases.`
    );
  }

  return cleaned;
}
// ---------------------------------------------------------------------------

// Resolve the companions directory and the target file path, then verify the
// resolved path is strictly within the companions directory to prevent traversal.
const companionsDir = path.resolve(__dirname, "../../companions");
const resolvedFilePath = path.resolve(companionsDir, COMPANION_NAME + ".txt");
if (!resolvedFilePath.startsWith(companionsDir + path.sep)) {
  throw new Error("Path traversal detected: invalid COMPANION_NAME.");
}
const data = await fs.readFile(resolvedFilePath, "utf8");
const presplit = data.split("###ENDPREAMBLE###");
const preamble = sanitizeInput(presplit[0], 'preamble');
const seedsplit = presplit[1].split("###ENDSEEDCHAT###");
const seedChat = sanitizeInput(seedsplit[0], 'seedChat');
const backgroundStory = sanitizeInput(seedsplit[1], 'backgroundStory');
console.log(preamble, backgroundStory);

if (!process.env.UPSTASH_REDIS_REST_URL || !process.env.UPSTASH_REDIS_REST_TOKEN) {
  throw new Error("Missing required credentials: UPSTASH_REDIS_REST_URL or UPSTASH_REDIS_REST_TOKEN");
}
const history = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

const upstashChatHistory = await history.zrange(
  `${COMPANION_NAME}-${MODEL_NAME}-${USER_ID}`,
  0,
  Date.now(),
  {
    byScore: true,
  }
);
const recentChat = upstashChatHistory
  .slice(-30)
  .map((entry) => sanitizeForPrompt(String(entry), 500));
const model = new Replicate({
  model: "a16z-infra/llama-2-13b-chat:df7690f1994d94e96ad9d568eac121aecf97b2d03a56cafbd2b7c1be93b7d5d",
  apiKey: process.env.REPLICATE_API_TOKEN,
});
model.verbose = true;

// Join sanitized recentChat entries for prompt interpolation
const sanitizedRecentChatText = recentChat.join("\n");

// Sanitize all external data before interpolating into the prompt to prevent
// prompt-injection attacks from file or Redis content.
const safePreamble = sanitize(preamble);
const safeBackgroundStory = sanitize(backgroundStory);
const safeSeedChat = sanitize(seedChat);
const safeRecentChat = Array.isArray(recentChat)
  ? recentChat.map(sanitize).join("\n")
  : sanitize(recentChat);
const safeCompanionName = sanitize(COMPANION_NAME);

// Sanitize all user-controlled values before embedding them in the prompt
const safePreamble = sanitizeForPrompt(preamble);
const safeBackgroundStory = sanitizeForPrompt(backgroundStory);
const safeSeedChat = sanitizeForPrompt(seedChat);
const safeRecentChat = Array.isArray(recentChat)
  ? recentChat.map(sanitizeForPrompt).join("\n")
  : sanitizeForPrompt(String(recentChat));
const safeCompanionName = sanitizeForPrompt(COMPANION_NAME);

const chainPrompt = PromptTemplate.fromTemplate(`
  ### Background Story: 
  ${safePreamble}
  
  ${safeBackgroundStory}

  ### Chat history: 
  ${safeSeedChat}

  ...
  ${safeRecentChat}

  
  Above is someone whose name is ${safeCompanionName}'s story and their chat history with a human. Output answer to the following question. Return only the answer itself 
  
  {question}`);

// Enforce chain allow list before constructing the chain.
assertChainAllowed("LLMChain");
const chain = new LLMChain({
  llm: model,
  prompt: chainPrompt,
});
const questions = [
  `Greeting: What would ${safeCompanionName} say to start a conversation?`,
  `Short Description: In a few sentences, how would ${safeCompanionName} describe themselves?`,
  `Long Description: In a few sentences, how would ${safeCompanionName} describe themselves?`,
];
const results = await Promise.all(
  questions.map(async (question) => {
    try {
      const result = await chain.call({ question });
      // Attach resolved model identity to every inference result for audit.
      result._auditModelId = RESOLVED_MODEL_ID;
      result._auditTimestamp = new Date().toISOString();
      console.log(
        `[AUDIT] inference | model=${RESOLVED_MODEL_ID}` +
        ` | timestamp=${result._auditTimestamp}` +
        ` | question="${question.substring(0, 60)}..."`
      );
      return result;
    } catch (error) {
      console.error(error);
    }
  })
);
      const result = await chain.call({ question });
      auditLog({ event: "TOOL_INVOCATION_SUCCESS", question });
      return result;
    } catch (error) {
      // Structured audit log for failures (includes policy denials).
      auditLog({
        event: "TOOL_INVOCATION_ERROR",
        question,
        error: error?.message ?? String(error),
      });
      // Re-throw policy violations so the process exits with a non-zero code.
      if (error?.message?.startsWith("Policy violation")) throw error;
    }
  })
);
      const result = await chain.call({ question });
      logLLMInteraction({ type: "response", input: { question }, output: result.text });
      return result;
    } catch (error) {
      logLLMInteraction({ type: "error", input: { question }, error: error.message });
      console.error(error);
    }
  })
);

/**
 * Sanitize LLM output by detecting dynamic code execution primitives.
 * Throws if dangerous patterns are found; otherwise returns the sanitized text.
 */
function sanitizeLLMOutput(text) {
  if (typeof text !== "string") {
    throw new Error("LLM output is not a string.");
  }

  // Patterns that indicate dynamic code execution primitives
  const dangerousPatterns = [
    /\beval\s*\(/,
    /\bexec\s*\(/,
    /\bexecSync\s*\(/,
    /\bspawn\s*\(/,
    /\bspawnSync\s*\(/,
    /\bsubprocess\b/,
    /\bnew\s+Function\s*\(/,
    /\bsetTimeout\s*\(\s*['"`]/,
    /\bsetInterval\s*\(\s*['"`]/,
    /\brequire\s*\(/,
    /\bimport\s*\(/,
    /\bchild_process\b/,
    /\bvm\.run/,
    /\bvm\.Script\b/,
    /\bprocess\.binding\b/,
  ];

  for (const pattern of dangerousPatterns) {
    if (pattern.test(text)) {
      throw new Error(
        `LLM output contains a forbidden dynamic code execution primitive matching pattern: ${pattern}. Output rejected.`
      );
    }
  }

  // Strip any non-printable / control characters (except common whitespace)
  const sanitized = text.replace(/[^\x09\x0A\x0D\x20-\x7E\u00A0-\uFFFF]/g, "");

  return sanitized;
}

// Prepend audit header so the output file itself records model provenance.
let output = `# AUDIT HEADER\n# model_id=${RESOLVED_MODEL_ID}\n# generated_at=${new Date().toISOString()}\n\n`;
for (let i = 0; i < questions.length; i++) {
  output += `*****${questions[i]}*****\n${results[i].text}\n\n`;
} catch (err) {
    console.error(`Sanitization failed for question "${questions[i]}": ${err.message}`);
    safeText = "[REDACTED: unsafe content detected in LLM output]";
  }
  output += `*****${questions[i]}*****\n${safeText}\n\n`;
}
output += `Definition (Advanced)\n${recentChat.join("\n")}`;

// Use safeCompanionName for output filenames to avoid path injection in filenames
await fs.writeFile(`${safeCompanionName}_chat_history.txt`, upstashChatHistory);
await fs.writeFile(`${safeCompanionName}_character_ai_data.txt`, output);
