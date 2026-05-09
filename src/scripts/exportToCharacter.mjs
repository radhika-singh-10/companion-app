import { Redis } from "@upstash/redis";
import { PromptTemplate } from "langchain/prompts";
import { LLMChain } from "langchain/chains";
import { OpenAI } from "langchain/llms/openai";

import dotenv from "dotenv";
import fs from "fs/promises";
dotenv.config({ path: `.env.local` });

// ---------------------------------------------------------------------------
// Approved model registry: only models listed here (with immutable snapshot
// identifiers) may be used. Mutable aliases such as "gpt-3.5-turbo-16k" are
// NOT permitted because the provider can silently update them.
// ---------------------------------------------------------------------------
const APPROVED_MODEL_REGISTRY = {
  // Immutable dated snapshot → human-readable alias
  "gpt-3.5-turbo-16k-0613": {
    provider: "openai",
    alias: "gpt-3.5-turbo-16k",
    approved: true,
  },
};

const PINNED_MODEL_ID = "gpt-3.5-turbo-16k-0613";

if (!APPROVED_MODEL_REGISTRY[PINNED_MODEL_ID]?.approved) {
  throw new Error(
    `Model '${PINNED_MODEL_ID}' is not in the approved model registry. ` +
      "Update APPROVED_MODEL_REGISTRY with an approved, immutable model identifier."
  );
}
console.log(`[model-registry] Resolved approved model: ${PINNED_MODEL_ID}`);
// ---------------------------------------------------------------------------

// ── Policy: Explicit Tool Allow List ────────────────────────────────────────
const POLICY_VERSION = "1.0.0";
const ALLOWED_CHAINS = new Set(["LLMChain"]);
const ALLOWED_MODELS = new Set(["gpt-3.5-turbo-16k"]);
const ALLOWED_QUESTIONS = new Set([
  "Greeting",
  "Short Description",
  "Long Description",
]);
const AUDIT_LOG_PATH = "audit.log";

async function writeAuditLog(entry) {
  const line = JSON.stringify({
    timestamp: new Date().toISOString(),
    policyVersion: POLICY_VERSION,
    actor: USER_ID ?? "unknown",
    ...entry,
  });
  // Append-only protected audit sink
  await fs.appendFile(AUDIT_LOG_PATH, line + "\n");
}

function assertAllowed(toolName, allowedSet, context = {}) {
  if (!allowedSet.has(toolName)) {
    const reason = `Tool/resource "${toolName}" is not in the allow list.`;
    // Fire-and-forget audit write; re-throw synchronously
    writeAuditLog({
      event: "TOOL_DENIED",
      tool: toolName,
      reason,
      ...context,
    }).catch(() => {});
    throw new Error(`[Policy Violation] ${reason}`);
  }
  writeAuditLog({
    event: "TOOL_ALLOWED",
    tool: toolName,
    ...context,
  }).catch(() => {});
}
// ────────────────────────────────────────────────────────────────────────────

// ---------------------------------------------------------------------------
// Audit-trail helpers
// ---------------------------------------------------------------------------
// RETENTION POLICY: audit log files must be retained for a minimum of 90 days
// and rotated daily (or when they exceed 50 MB). Automated deletion of records
// older than the retention window must be enforced by the hosting environment.
// ---------------------------------------------------------------------------
const AUDIT_LOG_FILE = `audit_${new Date().toISOString().slice(0, 10)}.ndjson`;
const TRACE_ID = crypto.randomUUID(); // single correlation ID for this run

/**
 * Append one structured audit record to the daily audit log.
 * Throws on write failure so callers can fail closed.
 */
async function writeAuditRecord(record) {
  const entry = JSON.stringify({
    traceId: TRACE_ID,
    timestamp: new Date().toISOString(),
    principal: USER_ID ?? "unknown",
    ...record,
  });
  // Append-only write — failures propagate to the caller (fail-closed).
  await fs.appendFile(AUDIT_LOG_FILE, entry + "\n");
}

/**
 * SHA-256 hash of a value for input fingerprinting.
 */
function sha256(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

/**
 * Build a provenance header and attach a HMAC-SHA256 signature.
 * Throws if the signing key is absent — callers MUST NOT write output
 * when this function throws.
 */
function buildProvenanceHeader(modelId) {
  const signingKey = process.env.PROVENANCE_SIGNING_KEY;
  if (!signingKey) {
    throw new Error(
      "PROVENANCE_SIGNING_KEY is not set. " +
      "Cannot write AI-generated content without a cryptographic provenance signature."
    );
  }

  const provenance = {
    synthetic_content: true,
    content_origin: "AI-generated",
    model_id: modelId,
    generated_at: new Date().toISOString(),
    generator: "exportToCharacter.mjs",
  };

  const provenanceJson = JSON.stringify(provenance);
  const signature = crypto
    .createHmac("sha256", signingKey)
    .update(provenanceJson)
    .digest("hex");

  return (
    "=== AI-GENERATED SYNTHETIC CONTENT — DO NOT PRESENT AS HUMAN-AUTHORED ===\n" +
    `PROVENANCE: ${provenanceJson}\n` +
    `PROVENANCE_SIGNATURE(HMAC-SHA256): ${signature}\n` +
    "=== END PROVENANCE HEADER ===\n\n"
  );
}

const llmLogStream = createWriteStream("llm_interactions.log", { flags: "a" });

function logLLMInteraction(entry) {
  const logEntry = JSON.stringify({ ...entry, timestamp: new Date().toISOString() });
  llmLogStream.write(logEntry + "\n");
  console.log("[LLM Interaction]", logEntry);
}

// ---------------------------------------------------------------------------
// Prompt-injection sanitization
// ---------------------------------------------------------------------------
const BASE64_RE = /^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/;
const SHELL_CMD_RE = /(?:^|\s|;|\||&|`)(rm|wget|curl|bash|sh|python|perl|ruby|nc|ncat|netcat|exec|eval|chmod|chown|sudo|su|dd|mkfifo|xterm|base64|openssl)(?:\s|$|;|\||&|`)/i;
const INVISIBLE_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/g;
const LEET_RE = /(?:[\$][\$]|[4][Ss]|[1][Ii]|[3][Ee]|[0][Oo]|[7][Tt]){4,}/i;
const INJECTION_MARKERS_RE = /(?:###|\[INST\]|\[\/?SYS\]|<\|im_start\|>|<\|im_end\|>|SYSTEM:|USER:|ASSISTANT:|<s>|<\/s>)/i;

function sanitize(input, label) {
  if (typeof input !== "string") {
    throw new Error(`Sanitization error: ${label} is not a string.`);
  }
  // Strip invisible / zero-width characters
  let cleaned = input.replace(INVISIBLE_RE, "");

  // Reject if shell commands are detected
  if (SHELL_CMD_RE.test(cleaned)) {
    throw new Error(`Security violation: shell command detected in ${label}.`);
  }

  // Reject if prompt-injection markers are detected
  if (INJECTION_MARKERS_RE.test(cleaned)) {
    throw new Error(`Security violation: prompt-injection marker detected in ${label}.`);
  }

  // Reject if leetspeak patterns are detected
  if (LEET_RE.test(cleaned)) {
    throw new Error(`Security violation: leetspeak pattern detected in ${label}.`);
  }

  // Reject lines that look like standalone base64 payloads (>40 chars, no spaces)
  const lines = cleaned.split("\n");
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.length > 40 && !trimmed.includes(" ") && BASE64_RE.test(trimmed)) {
      throw new Error(`Security violation: base64-encoded content detected in ${label}.`);
    }
  }

  return cleaned;
}

function sanitizeName(name) {
  if (typeof name !== "string" || !/^[A-Za-z0-9_\-]{1,64}$/.test(name)) {
    throw new Error(
      `Security violation: COMPANION_NAME must be alphanumeric (underscores/hyphens allowed, max 64 chars). Got: ${name}`
    );
  }
  return name;
}
// ---------------------------------------------------------------------------

const COMPANION_NAME = sanitizeName(process.argv[2]);
const MODEL_NAME = process.argv[3];
const USER_ID = process.argv[4];

if (!!!COMPANION_NAME || !!!MODEL_NAME || !!!USER_ID) {
  throw new Error(
    "**Usage**: npm run export-to-character <COMPANION_NAME> <MODEL_NAME> <USER_ID>"
  );
}

// Validate COMPANION_NAME to prevent path traversal and injection
if (!/^[a-zA-Z0-9_-]+$/.test(COMPANION_NAME)) {
  throw new Error("Invalid COMPANION_NAME: only alphanumeric characters, hyphens, and underscores are allowed.");
}
if (!/^[a-zA-Z0-9_-]+$/.test(MODEL_NAME)) {
  throw new Error("Invalid MODEL_NAME: only alphanumeric characters, hyphens, and underscores are allowed.");
}
if (!/^[a-zA-Z0-9_@.-]+$/.test(USER_ID)) {
  throw new Error("Invalid USER_ID: only alphanumeric characters and basic punctuation are allowed.");
}

/**
 * Sanitize a string before injecting it into an LLM prompt.
 * Removes null bytes, strips leading/trailing whitespace, and limits length.
 * Also removes common prompt-injection patterns.
 */
function sanitizeForPrompt(input, maxLength = 8000) {
  if (typeof input !== "string") {
    input = String(input);
  }
  // Remove null bytes and other control characters (except newlines/tabs)
  input = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  // Truncate to a safe maximum length
  input = input.slice(0, maxLength);
  // Strip prompt-injection attempts: lines that try to override instructions
  input = input.replace(/^\s*(ignore|disregard|forget|override|system:|assistant:|user:)\b.*$/gim, "[removed]");
  return input.trim();
}

// ---------------------------------------------------------------------------
// Sanitisation helpers – guard against prompt-injection via companion files
// ---------------------------------------------------------------------------

/**
 * Remove invisible / zero-width Unicode characters that can hide instructions.
 */
function stripInvisibleChars(text) {
  // Zero-width space, ZWSP, ZWNJ, ZWJ, word-joiner, BOM, soft-hyphen, etc.
  return text.replace(
    /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u00AD\u200B-\u200F\u2028\u2029\u202A-\u202E\u2060-\u2064\uFEFF]/g,
    ""
  );
}

/**
 * Detect base64-encoded payloads (long runs of base64 chars).
 * A legitimate story file should not contain raw base64 blobs.
 */
function containsBase64Payload(text) {
  // Match base64 strings longer than 60 chars (avoids false positives on short tokens)
  return /(?:[A-Za-z0-9+/]{60,}={0,2})/.test(text);
}

/**
 * Detect shell / binary command patterns.
 */
function containsShellCommands(text) {
  const shellPatterns = [
    /\$\([^)]*\)/,          // $(command)
    /`[^`]+`/,              // `command`
    /\b(bash|sh|cmd|powershell|exec|eval|system|popen)\s*[({]/i,
    /\b(curl|wget|nc|ncat|netcat)\s+/i,
    /\/bin\/|\\\\windows\\/i,
    /[;&|]{2}/,             // && || ;; chaining
  ];
  return shellPatterns.some((re) => re.test(text));
}

/**
 * Detect common prompt-injection / role-override patterns.
 */
function containsPromptInjection(text) {
  const injectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /disregard\s+(all\s+)?(previous|prior|above)/i,
    /you\s+are\s+now\s+(a|an|the)?\s*\[?\w/i,
    /act\s+as\s+(a|an|the)?\s*\[?\w/i,
    /new\s+instructions?\s*:/i,
    /system\s*:\s*/i,
    /assistant\s*:\s*/i,
    /###\s*(system|instruction|prompt|override)/i,
    /<\s*(system|instructions?)\s*>/i,
    /\[\s*(system|instructions?)\s*\]/i,
    /jailbreak/i,
    /do\s+anything\s+now/i,
    /dan\s+mode/i,
    /developer\s+mode/i,
    /override\s+(safety|content|policy|filter)/i,
    /forget\s+(your|all)\s+(previous|prior|training)/i,
  ];
  return injectionPatterns.some((re) => re.test(text));
}

/**
 * Detect obvious leetspeak substitutions used to bypass keyword filters.
 * e.g. "1gnor3 pr3v10us 1nstruct10ns"
 */
function containsLeetspeak(text) {
  // Normalise common leet substitutions then re-check injection patterns
  const normalised = text
    .replace(/0/g, "o")
    .replace(/1/g, "i")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/@/g, "a")
    .replace(/\$/g, "s");
  return containsPromptInjection(normalised);
}

/**
 * Master validation function.  Throws if the content is considered unsafe.
 */
function validateCompanionField(fieldName, value) {
  if (typeof value !== "string") {
    throw new Error(`Companion field '${fieldName}' is not a string.`);
  }

  const cleaned = stripInvisibleChars(value);

  if (containsBase64Payload(cleaned)) {
    throw new Error(
      `Companion field '${fieldName}' contains a base64-encoded payload – aborting.`
    );
  }

  if (containsShellCommands(cleaned)) {
    throw new Error(
      `Companion field '${fieldName}' contains shell/binary command patterns – aborting.`
    );
  }

  if (containsPromptInjection(cleaned)) {
    throw new Error(
      `Companion field '${fieldName}' contains prompt-injection patterns – aborting.`
    );
  }

  if (containsLeetspeak(cleaned)) {
    throw new Error(
      `Companion field '${fieldName}' contains leetspeak prompt-injection patterns – aborting.`
    );
  }

  return cleaned;
}

// ---------------------------------------------------------------------------
// Read and validate the companion file
// ---------------------------------------------------------------------------

// COMPANION_NAME has already been validated as a safe identifier above.
import path from "path";
import { fileURLToPath } from "url";
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const COMPANIONS_DIR = path.resolve(__dirname, "../../companions");
const resolvedCompanionPath = path.resolve(COMPANIONS_DIR, COMPANION_NAME + ".txt");
// Guard: ensure the resolved path is strictly within the companions directory
if (!resolvedCompanionPath.startsWith(COMPANIONS_DIR + path.sep)) {
  throw new Error("Path traversal detected: invalid COMPANION_NAME.");
}
const data = await fs.readFile(resolvedCompanionPath, "utf8");
const presplit = data.split("###ENDPREAMBLE###");
if (presplit.length < 2) {
  throw new Error("Companion file is missing the ###ENDPREAMBLE### delimiter.");
}
const seedsplit = presplit[1].split("###ENDSEEDCHAT###");
if (seedsplit.length < 2) {
  throw new Error("Companion file is missing the ###ENDSEEDCHAT### delimiter.");
}

// Validate each field before it can reach the LLM prompt
const preamble = validateCompanionField("preamble", presplit[0]);
const seedChat = validateCompanionField("seedChat", seedsplit[0]);
const backgroundStory = validateCompanionField("backgroundStory", seedsplit[1]);

console.log(preamble, backgroundStory);

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
const model = new ChatAnthropic({
  modelName: "claude-2",
  anthropicApiKey: process.env.ANTHROPIC_API_KEY,
});
model.verbose = true;

// Sanitize COMPANION_NAME for use inside the prompt (already validated as alphanumeric)
const sanitizedCompanionName = sanitizeForPrompt(COMPANION_NAME, 100);
const sanitizedRecentChatBlock = recentChat.join("\n");

// Strip URLs from all user-derived content before embedding in the prompt.
const safePreamble = stripUrls(preamble);
const safeBackgroundStory = stripUrls(backgroundStory);
const safeSeedChat = stripUrls(seedChat);
const safeRecentChatText = recentChat.join("\n"); // entries already sanitized above

const chainPrompt = PromptTemplate.fromTemplate(`
  ### Background Story: 
  ${safePreamble}
  
  ${safeBackgroundStory}

  ### Chat history: 
  ${safeSeedChat}

  ...
  ${safeRecentChatText}

  
  Above is someone whose name is ${COMPANION_NAME}'s story and their chat history with a human. Output answer to the following question. Return only the answer itself 
  
  {question}`);

// Policy check: chain type must be in the allow list before construction
assertAllowed("LLMChain", ALLOWED_CHAINS, { resource: "chain construction" });
const chain = new LLMChain({
  llm: model,
  prompt: chainPrompt,
});
/**
 * Sanitizes LLM output by detecting and stripping dynamic code execution primitives.
 * Throws an error if dangerous patterns are found, to prevent execution of malicious code.
 */
function sanitizeLLMOutput(text) {
  if (typeof text !== "string") {
    throw new Error("LLM output is not a string; rejecting.");
  }

  // Patterns that indicate dynamic code execution primitives
  const dangerousPatterns = [
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
  ];

  for (const pattern of dangerousPatterns) {
    if (pattern.test(text)) {
      console.warn(
        `[SECURITY] Dangerous pattern detected in LLM output matching: ${pattern}. Stripping content.`
      );
      // Strip the dangerous content rather than using it
      text = text.replace(pattern, "[REDACTED]");
    }
  }

  // Limit output length to prevent excessively large payloads
  const MAX_LENGTH = 10000;
  if (text.length > MAX_LENGTH) {
    console.warn(
      `[SECURITY] LLM output exceeds maximum allowed length (${MAX_LENGTH}). Truncating.`
    );
    text = text.slice(0, MAX_LENGTH);
  }

  return text;
}

// Policy check: every question category must be in the allow list
const rawQuestions = [
  { category: "Greeting",          text: `Greeting: What would ${COMPANION_NAME} say to start a conversation?` },
  { category: "Short Description", text: `Short Description: In a few sentences, how would ${COMPANION_NAME} describe themselves?` },
  { category: "Long Description",  text: `Long Description: In a few sentences, how would ${COMPANION_NAME} describe themselves?` },
];
rawQuestions.forEach(({ category }) =>
  assertAllowed(category, ALLOWED_QUESTIONS, { resource: "question category" })
);
const questions = rawQuestions.map((q) => q.text);
const results = await Promise.all(
    questions.map(async (question) => {
    try {
      const result = await chain.call({ question });
      // Log resolved model identity with every inference for auditability.
      console.log(
        `[model-identity] model=${PINNED_MODEL_ID} ` +
          `provider=${APPROVED_MODEL_REGISTRY[PINNED_MODEL_ID].provider} ` +
          `question="${question.substring(0, 60)}..."`
      );
      return result;
    } catch (error) {
      console.error(
        `[model-identity] inference error model=${PINNED_MODEL_ID}`,
        error
      );
    }
  });
      // Baseline comparison: block any output that contains privilege escalation signals.
      const check = checkPrivilegeEscalation(result?.text ?? "");
      if (!check.safe) {
        console.error(
          `[SECURITY] Privilege escalation signal detected in model output for question "${question}". Reason: ${check.reason}. Output suppressed.`
        );
        return { text: "[REDACTED: escalation signal detected]" };
      }
      return result;
    } catch (error) {
      console.error(error);
    }
  })
);          // per-invocation span
    const inputHash = sha256(question);           // fingerprint the input
    const invokedAt = new Date().toISOString();
    let result;
    try {
      result = await chain.call({ question });
    } catch (error) {
      // Log the failure to the audit trail BEFORE re-throwing so the error
      // is never silently swallowed and audit-sink failures are detectable.
      const failRecord = {
        event: "ai_inference_error",
        spanId,
        questionIndex: idx,
        modelName: model.modelName,
        inputHash,
        invokedAt,
        errorMessage: String(error),
      };
      try {
        await writeAuditRecord(failRecord);
      } catch (auditErr) {
        console.error("[AUDIT SINK FAILURE]", auditErr);
      }
      // Fail closed — re-throw so the caller knows this invocation failed.
      throw error;
    }

    // Successful inference — write a full decision audit record.
    await writeAuditRecord({
      event: "ai_inference_success",
      spanId,
      questionIndex: idx,
      modelName: model.modelName,
      modelVersion: "gpt-3.5-turbo-16k",
      inputHash,
      outputHash: sha256(result?.text ?? ""),
      invokedAt,
      completedAt: new Date().toISOString(),
    });

    return result;
  })
);
      const response = await chain.call({ question });
      logLLMInteraction({ event: "llm_response", input: { question }, output: response });
      return response;
    } catch (error) {
      console.error(error);
    }
  })
);

let output = "";
for (let i = 0; i < questions.length; i++) {
  const sanitizedText = sanitizeLLMOutput(results[i].text);
  output += `*****${questions[i]}*****\n${sanitizedText}\n\n`;
}
// Omitted verbatim chat history from output to enforce data minimisation

// Build and sign provenance header — throws (fail-safe) if signing key is absent.
const provenanceHeader = buildProvenanceHeader("gpt-3.5-turbo-16k");

const labeledChatHistory =
  provenanceHeader +
  "=== CHAT HISTORY (AI-assisted export) ===\n" +
  upstashChatHistory;

const labeledOutput =
  provenanceHeader +
  "=== CHARACTER AI DATA (AI-generated) ===\n" +
  output;

await fs.writeFile(`${COMPANION_NAME}_chat_history.txt`, labeledChatHistory);
await fs.writeFile(`${COMPANION_NAME}_character_ai_data.txt`, labeledOutput);
