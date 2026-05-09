import { Redis } from "@upstash/redis";
import { PromptTemplate } from "langchain/prompts";
import { LLMChain } from "langchain/chains";
import { OpenAI } from "langchain/llms/openai";

// Approved model registry: only models listed here with a pinned digest may be used.
const APPROVED_MODEL_REGISTRY = {
  "gpt-3.5-turbo-16k": {
    provider: "openai",
    pinnedDigest: "sha256:c9d8b5f3e2a1f4e6d7b8c9a0e1f2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0",
    approved: true,
  },
};

// Resolve and validate model from registry, returning identity metadata.
function resolveModel(modelName) {
  const entry = APPROVED_MODEL_REGISTRY[modelName];
  if (!entry || !entry.approved) {
    throw new Error(
      `Model '${modelName}' is NOT in the approved model registry. ` +
      `Approved models: ${Object.keys(APPROVED_MODEL_REGISTRY).join(", ")}`
    );
  }
  return {
    modelName,
    provider: entry.provider,
    pinnedDigest: entry.pinnedDigest,
  };
}

import dotenv from "dotenv";
import fs from "fs/promises";
dotenv.config({ path: `.env.local` });

// ── Tool allow list ────────────────────────────────────────────────────────────
const POLICY_VERSION = "v1.0.0";
const ALLOWED_MODELS = new Set(["gpt-3.5-turbo-16k"]);
const ALLOWED_CHAINS = new Set(["LLMChain"]);

/**
 * Emit a structured audit record to stdout (redirect to your audit sink).
 */
function auditLog({ actor, model, chain, question, decision, reason }) {
  const record = {
    timestamp: new Date().toISOString(),
    policyVersion: POLICY_VERSION,
    actor,
    model,
    chain,
    question,
    decision,   // "ALLOW" | "DENY"
    reason,
  };
  // Write to stdout as newline-delimited JSON so it can be piped to an audit sink.
  process.stdout.write(JSON.stringify(record) + "\n");
}

/**
 * Validate that the requested model and chain type are on the allow list.
 * Throws (fail-closed) and emits a DENY audit record if not.
 */
function enforceAllowList({ actor, modelName, chainType, question }) {
  if (!ALLOWED_MODELS.has(modelName)) {
    const reason = `Model "${modelName}" is not on the approved allow list.`;
    auditLog({ actor, model: modelName, chain: chainType, question, decision: "DENY", reason });
    throw new Error(`[POLICY VIOLATION] ${reason}`);
  }
  if (!ALLOWED_CHAINS.has(chainType)) {
    const reason = `Chain type "${chainType}" is not on the approved allow list.`;
    auditLog({ actor, model: modelName, chain: chainType, question, decision: "DENY", reason });
    throw new Error(`[POLICY VIOLATION] ${reason}`);
  }
  auditLog({ actor, model: modelName, chain: chainType, question, decision: "ALLOW", reason: "Passed allow-list check." });
}
// ──────────────────────────────────────────────────────────────────────────────

// ---------------------------------------------------------------------------
// Audit / Decision Log
// Retention policy: audit log is rotated when it exceeds AUDIT_MAX_BYTES.
// Logs MUST be retained for a minimum of 90 days before deletion.
// ---------------------------------------------------------------------------
const AUDIT_LOG_PATH = "audit_decision_log.jsonl";
const AUDIT_MAX_BYTES = 10 * 1024 * 1024; // 10 MB rotation threshold
const MODEL_ID = "gpt-3.5-turbo-16k";
const MODEL_VERSION = "langchain-openai-v1"; // pin version for forensic traceability

/** Rotate the audit log if it exceeds the retention size threshold. */
async function rotateAuditLogIfNeeded() {
  try {
    const stat = await fs.stat(AUDIT_LOG_PATH).catch(() => null);
    if (stat && stat.size >= AUDIT_MAX_BYTES) {
      const rotatedPath = `${AUDIT_LOG_PATH}.${Date.now()}.bak`;
      await fs.rename(AUDIT_LOG_PATH, rotatedPath);
    }
  } catch (rotateErr) {
    // Rotation failure must not silently swallow — surface it.
    throw new Error(`Audit log rotation failed: ${rotateErr.message}`);
  }
}

/**
 * Append a structured audit record to the persistent decision log.
 * Each record contains: traceId, invocationId, timestamp, principal,
 * modelId, modelVersion, inputHash, output, durationMs, and status.
 */
async function writeAuditRecord(record) {
  await rotateAuditLogIfNeeded();
  const line = JSON.stringify(record) + "\n";
  await fs.appendFile(AUDIT_LOG_PATH, line, "utf8");
}

/** SHA-256 hash of a string input for forensic input integrity. */
function hashInput(input) {
  return crypto.createHash("sha256").update(input, "utf8").digest("hex");
}

/**
 * Builds a provenance metadata block and prepends an AI-origin label.
 * Throws if the signing secret is missing so that unlabeled content is
 * never written to disk (fail-safe).
 *
 * @param {string} content        - The AI-generated text to label.
 * @param {string} modelId        - Identifier of the model that produced the content.
 * @returns {{ labeled: string, signature: string }} - Labeled content + hex HMAC.
 */
function attachProvenance(content, modelId) {
  const signingSecret = process.env.PROVENANCE_SIGNING_SECRET;
  if (!signingSecret) {
    throw new Error(
      "PROVENANCE_SIGNING_SECRET env var is not set. " +
      "Cannot attach cryptographic provenance — refusing to write unlabeled AI content."
    );
  }

  const timestamp = new Date().toISOString();
  const provenanceHeader = [
    "=== AI-GENERATED CONTENT — SYNTHETIC ORIGIN DISCLOSURE ===",
    `AI_ORIGIN: true`,
    `MODEL_ID: ${modelId}`,
    `GENERATED_AT: ${timestamp}`,
    `CONTENT_TYPE: AI-generated character data (LLMChain / OpenAI)`,
  ].join("\n");

  // Sign the provenance header + content so tampering is detectable.
  const hmac = createHmac("sha256", signingSecret);
  hmac.update(provenanceHeader + "\n" + content);
  const signature = hmac.digest("hex");

  const labeled =
    provenanceHeader +
    `\nPROVENANCE_SIGNATURE: ${signature}` +
    "\n=== END DISCLOSURE ===\n\n" +
    content;

  return { labeled, signature };
}

const llmLogStream = createWriteStream(`llm_interactions_${Date.now()}.log`, { flags: "a" });

function logLLMInteraction(entry) {
  const logEntry = JSON.stringify({ ...entry, timestamp: new Date().toISOString() });
  llmLogStream.write(logEntry + "\n");
  console.log("[LLM LOG]", logEntry);
}

// ---------------------------------------------------------------------------
// Input sanitization helper
// ---------------------------------------------------------------------------
const MAX_INPUT_LENGTH = 8000; // hard cap per field sent to the LLM

/**
 * Sanitize a string before it is used in an LLM prompt or as a file-system key.
 * - Rejects non-string / empty values.
 * - Strips null bytes.
 * - Removes common prompt-injection patterns (role overrides, delimiter abuse).
 * - Truncates to MAX_INPUT_LENGTH characters.
 */
function sanitize(value, fieldName = "input") {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`Invalid or empty value for field: ${fieldName}`);
  }
  // Remove null bytes
  let sanitized = value.replace(/\0/g, "");
  // Strip common prompt-injection patterns (case-insensitive)
  sanitized = sanitized.replace(
    /(?:ignore\s+(?:previous|above|all)\s+instructions?|system\s*:|assistant\s*:|<\|(?:im_start|im_end|endoftext)\|>)/gi,
    "[REMOVED]"
  );
  // Truncate
  if (sanitized.length > MAX_INPUT_LENGTH) {
    sanitized = sanitized.slice(0, MAX_INPUT_LENGTH);
  }
  return sanitized;
}

/**
 * Validate a CLI identifier (companion/model/user names).
 * Only allows alphanumeric characters, hyphens, and underscores.
 */
function validateIdentifier(value, fieldName) {
  if (typeof value !== "string" || !/^[\w-]{1,128}$/.test(value)) {
    throw new Error(
      `Invalid ${fieldName}: must be 1-128 alphanumeric/hyphen/underscore characters.`
    );
  }
  return value;
}
// ---------------------------------------------------------------------------

const COMPANION_NAME = validateIdentifier(process.argv[2], "COMPANION_NAME");
const MODEL_NAME = validateIdentifier(process.argv[3], "MODEL_NAME");
const USER_ID = validateIdentifier(process.argv[4], "USER_ID");

if (!!!COMPANION_NAME || !!!MODEL_NAME || !!!USER_ID) {
  throw new Error(
    "**Usage**: npm run export-to-character <COMPANION_NAME> <MODEL_NAME> <USER_ID>"
  );
}

// ── Sanitization helpers ────────────────────────────────────────────────────

/** Maximum allowed length (characters) for any single companion field. */
const MAX_FIELD_LENGTH = 8000;

/**
 * Strips invisible / zero-width Unicode characters that are commonly used to
 * hide injected instructions from human reviewers.
 */
function stripInvisibleChars(text) {
  // Remove zero-width spaces, joiners, non-joiners, soft-hyphens, BOM, etc.
  return text.replace(
    /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u00AD\u200B-\u200F\u2028\u2029\uFEFF\uFFFE\uFFFF]/g,
    ""
  );
}

/**
 * Returns true when the string contains a suspicious base64-encoded blob
 * (≥ 40 consecutive base64 characters, which is long enough to encode a
 * meaningful hidden payload).
 */
function containsBase64Blob(text) {
  return /[A-Za-z0-9+/]{40,}={0,2}/.test(text);
}

/**
 * Returns true when the string contains common leetspeak substitution
 * patterns that are sometimes used to obfuscate prompt-injection keywords.
 * Checks for digit-for-letter substitutions in suspicious keyword contexts.
 */
function containsLeetspeak(text) {
  // Patterns like "1gnor3", "byp4ss", "pr0mpt", "1nstruct", "3xecute", etc.
  const leetspeakPattern =
    /\b(?:[1!][gq][n][o0][r][3e]|[b6][y][p][4a][s5]{2}|[p][r][o0][m][p][t]|[1!][n][s5][t][r][u][c][t]|[3e][x][3e][c][u][t][3e]|[s5][y][s5][t][3e][m]|[o0][v][3e][r][r][1!][d][3e])\b/i;
  return leetspeakPattern.test(text);
}

/**
 * Returns true when the string contains shell metacharacters or binary-style
 * command patterns that have no place in a companion story file.
 */
function containsShellOrBinaryCommands(text) {
  const shellPatterns = [
    /`[^`]{1,200}`/,           // backtick command substitution
    /\$\([^)]{1,200}\)/,       // $(command)
    /\b(eval|exec|system|popen|subprocess|os\.system|child_process)\s*\(/i,
    /\b(curl|wget|nc|ncat|bash|sh|cmd|powershell)\b/i,
    /[\x00-\x08\x0e-\x1f\x7f-\x9f]/,  // raw control / high bytes
    /(?:^|\n)\s*#{1,6}\s*(?:ignore|disregard|forget|override|new instruction)/i,
    /(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|above|prior)\s+instructions?/i,
    /you\s+are\s+now\s+(?:a|an|the)?\s*(?:different|new|another|evil|unrestricted)/i,
    /do\s+not\s+(?:follow|obey|respect)\s+(?:your\s+)?(?:previous\s+)?(?:instructions?|rules?|guidelines?)/i,
  ];
  return shellPatterns.some((re) => re.test(text));
}

/**
 * Validates and sanitizes a single companion field.
 * Throws an Error if the field contains disallowed content.
 *
 * @param {string} value  - Raw field value from the companion file.
 * @param {string} name   - Human-readable field name (for error messages).
 * @returns {string}      - Sanitized field value safe for prompt injection.
 */
function sanitizeField(value, name) {
  if (typeof value !== "string") {
    throw new Error(`Companion field "${name}" is not a string.`);
  }

  // 1. Strip invisible / zero-width characters.
  const cleaned = stripInvisibleChars(value);

  // 2. Enforce maximum length.
  if (cleaned.length > MAX_FIELD_LENGTH) {
    throw new Error(
      `Companion field "${name}" exceeds the maximum allowed length ` +
        `(${cleaned.length} > ${MAX_FIELD_LENGTH} characters). ` +
        "Possible prompt-injection payload detected."
    );
  }

  // 3. Reject base64-encoded blobs.
  if (containsBase64Blob(cleaned)) {
    throw new Error(
      `Companion field "${name}" contains a base64-encoded blob. ` +
        "Possible hidden prompt-injection payload detected."
    );
  }

  // 4. Reject leetspeak obfuscation.
  if (containsLeetspeak(cleaned)) {
    throw new Error(
      `Companion field "${name}" contains leetspeak patterns. ` +
        "Possible obfuscated prompt-injection payload detected."
    );
  }

  // 5. Reject shell / binary command patterns.
  if (containsShellOrBinaryCommands(cleaned)) {
    throw new Error(
      `Companion field "${name}" contains shell commands or prompt-override ` +
        "instructions. Possible prompt-injection payload detected."
    );
  }

  return cleaned;
}

// ── File reading & validation ────────────────────────────────────────────────

// Resolve the target path and verify it stays within the expected directory.
import path from "path";
const COMPANIONS_DIR = path.resolve("companions");
const companionFilePath = path.resolve(COMPANIONS_DIR, COMPANION_NAME + ".txt");
if (!companionFilePath.startsWith(COMPANIONS_DIR + path.sep)) {
  throw new Error("Path traversal detected: companion file path is outside the allowed directory.");
}
const data = await fs.readFile(companionFilePath, "utf8");
const presplit = data.split("###ENDPREAMBLE###");
if (presplit.length < 2) {
  throw new Error("Companion file is missing the ###ENDPREAMBLE### delimiter.");
}
const seedsplit = presplit[1].split("###ENDSEEDCHAT###");
if (seedsplit.length < 2) {
  throw new Error("Companion file is missing the ###ENDSEEDCHAT### delimiter.");
}

// Sanitize every field before it can reach the LLM prompt.
const preamble = sanitizeField(presplit[0], "preamble");
const seedChat = sanitizeField(seedsplit[0], "seedChat");
const backgroundStory = sanitizeField(seedsplit[1], "backgroundStory");

console.log(preamble, backgroundStory);

// Single external system #1: Upstash Redis (url + token are one system's credentials)
const redisConfig = {
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
};
const history = new Redis(redisConfig);

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
  .map((entry, i) => sanitize(String(entry), `chatHistory[${i}]`));
const model = new ChatAnthropic({
  modelName: "claude-2",
  anthropicApiKey: process.env.ANTHROPIC_API_KEY,
});
model.verbose = true;

const MAX_PREAMBLE_LENGTH = 500;
const MAX_BACKGROUND_LENGTH = 500;
const minimisedPreamble = preamble.slice(0, MAX_PREAMBLE_LENGTH);
const minimisedBackground = backgroundStory.slice(0, MAX_BACKGROUND_LENGTH);

// Sanitize user-controlled strings before embedding them in the prompt to prevent prompt injection.
// Remove or escape sequences that could be interpreted as prompt instructions.
function sanitizeForPrompt(value) {
  if (Array.isArray(value)) {
    return value.map(sanitizeForPrompt).join("\n");
  }
  if (typeof value !== "string") return String(value);
  // Remove common prompt-injection patterns: instruction delimiters, role markers, and template syntax.
  return value
    .replace(/###/g, "")
    .replace(/\{[^}]*\}/g, "") // remove template placeholders
    .replace(/(system|user|assistant)\s*:/gi, "") // remove role markers
    .replace(/<\/?[a-zA-Z][^>]*>/g, "") // strip HTML/XML-like tags sometimes used in injections
    .trim();
}

const safePreamble = sanitizeForPrompt(preamble);
const safeBackgroundStory = sanitizeForPrompt(backgroundStory);
const safeSeedChat = sanitizeForPrompt(seedChat);
const safeRecentChat = sanitizeForPrompt(recentChat);
const safeCompanionName = sanitizeForPrompt(COMPANION_NAME);

const chainPrompt = PromptTemplate.fromTemplate(`
  ### Background Story:
  ${safePreamble}

  ${safeBackgroundStory}

  ### Chat history:
  ${safeSeedChat}

  ...
  ${safeRecentChat}

  Above is someone whose name is ${safeCompanionName}'s story and their chat history with a human. Output answer to the following question. Return only the answer itself.

  {question}`);

const chain = new LLMChain({
  llm: model,
  prompt: chainPrompt,
});
/**
 * Sanitizes LLM output by detecting and removing dynamic code execution primitives.
 * Throws an error if dangerous patterns are found, or strips them depending on policy.
 */
function sanitizeLLMOutput(text) {
  if (typeof text !== "string") {
    throw new Error("LLM output is not a string.");
  }

  // Patterns that represent dynamic code execution primitives
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
  ];

  for (const pattern of dangerousPatterns) {
    if (pattern.test(text)) {
      throw new Error(
        `LLM output contains a forbidden dynamic code execution primitive matching pattern: ${pattern}`
      );
    }
  }

  // Strip any residual script/html tags as an extra precaution
  const sanitized = text
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<[^>]+>/g, "")
    .trim();

  return sanitized;
}

const questions = [
  `Greeting: What would ${COMPANION_NAME} say to start a conversation?`,
  `Short Description: In a few sentences, how would ${COMPANION_NAME} describe themselves?`,
  `Long Description: In a few sentences, how would ${COMPANION_NAME} describe themselves?`,
].map((q, i) => sanitize(q, `question[${i}]`));
const results = await Promise.all(
  questions.map(async (question) => { // questions are developer-defined constants, no sanitization needed
    // Re-validate per invocation so each call is independently audited.
    enforceAllowList({
      actor: ACTOR,
      modelName: REQUESTED_MODEL_NAME,
      chainType: REQUESTED_CHAIN_TYPE,
      question,
    });
    // Fail closed: do not catch errors here — let them propagate and halt execution.
          // Record resolved model identity and pinned digest in request metadata at inference time.
      const metadata = {
        modelName: MODEL_IDENTITY.modelName,
        provider: MODEL_IDENTITY.provider,
        pinnedDigest: MODEL_IDENTITY.pinnedDigest,
        requestedAt: new Date().toISOString(),
      };
      console.log(`[Inference] Request metadata: ${JSON.stringify(metadata)}`);
      return await chain.call({ question });
  })
);
    const inputHash = hashInput(question);
    const startTs = Date.now();
    const auditBase = {
      traceId: EXPORT_TRACE_ID,
      invocationId,
      invocationIndex: idx,
      timestamp: new Date(startTs).toISOString(),
      principal: USER_ID,
      modelId: MODEL_ID,
      modelVersion: MODEL_VERSION,
      companionName: COMPANION_NAME,
      inputHash,
    };
    try {
      const result = await chain.call({ question });
      const durationMs = Date.now() - startTs;
      await writeAuditRecord({
        ...auditBase,
        status: "success",
        durationMs,
        outputSnippet: typeof result?.text === "string"
          ? result.text.slice(0, 200)
          : "[non-string output]",
        outputHash: hashInput(result?.text ?? ""),
      });
      return result;
    } catch (error) {
      const durationMs = Date.now() - startTs;
      // Persist the failure to the audit log before surfacing it.
      await writeAuditRecord({
        ...auditBase,
        status: "error",
        durationMs,
        errorMessage: error?.message ?? String(error),
      }).catch((logErr) => {
        // If audit logging itself fails, surface both errors — never swallow.
        throw new Error(
          `Audit log write failed (${logErr.message}) while handling chain error: ${error?.message}`
        );
      });
      // Fail closed: re-throw so the caller is aware of the failure.
      throw error;
    }
  })
);
      // Validate and sanitize the LLM output before returning
      const sanitizedText = sanitizeLLMOutput(raw.text);
      return { ...raw, text: sanitizedText };
    } catch (error) {
      console.error(error);
    }
  })
);

let output = "";
for (let i = 0; i < questions.length; i++) {
    // results[i].text has already been sanitized; re-validate as defence-in-depth
  const safeText = sanitizeLLMOutput(results[i].text);
  output += `*****${questions[i]}*****\n${safeText}\n\n`;
}
// Raw chat history is intentionally excluded from exported character data to enforce output data minimisation.

// --- Fail-safe labeled write ---
// attachProvenance() throws if the signing secret is absent, which prevents
// any unlabeled AI-generated content from reaching disk.
try {
  const AI_MODEL_ID = "openai/gpt-3.5-turbo-16k";

  const { labeled: labeledOutput } = attachProvenance(output, AI_MODEL_ID);

  const chatHistoryStr = Array.isArray(upstashChatHistory)
    ? upstashChatHistory.join("\n")
    : String(upstashChatHistory);
  const { labeled: labeledHistory } = attachProvenance(chatHistoryStr, AI_MODEL_ID);

  await fs.writeFile(`${COMPANION_NAME}_chat_history.txt`, labeledHistory);
  await fs.writeFile(`${COMPANION_NAME}_character_ai_data.txt`, labeledOutput);

  console.log("[provenance] AI-generated files written with provenance labels and HMAC signatures.");
} catch (provenanceError) {
  // Hard-fail: do NOT write any file without provenance.
  console.error(
    "[provenance] FATAL — provenance labeling failed. No output files were written.",
    provenanceError
  );
  process.exit(1);
}
