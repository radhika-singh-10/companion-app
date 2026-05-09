import { Redis } from "@upstash/redis";
import { PromptTemplate } from "langchain/prompts";
import { LLMChain } from "langchain/chains";
import { OpenAI } from "langchain/llms/openai";

import dotenv from "dotenv";
import fs from "fs/promises";
dotenv.config({ path: `.env.local` });

// ── Tool allow list policy ────────────────────────────────────────────────────
const POLICY_VERSION = "v1.0.0";

/**
 * Explicit allow list of tool/chain identifiers that agents are permitted to
 * invoke.  Any capability NOT present here is denied by default.
 */
const TOOL_ALLOW_LIST = new Set([
  "LLMChain:character-export",
]);

/**
 * Per-role scoping: maps a USER_ID prefix (or exact ID) to the subset of
 * allowed tools that role may use.  Falls back to an empty set (deny-all)
 * when the user is not recognised.
 */
const ROLE_TOOL_SCOPE = {
  // Example: admin users may use all allowed tools.
  admin: new Set(["LLMChain:character-export"]),
  // Default authenticated users get the same set here; tighten as needed.
  default: new Set(["LLMChain:character-export"]),
};

/**
 * Structured audit logger.  Writes a JSON line to stdout so that log
 * aggregators (CloudWatch, Datadog, etc.) can ingest and alert on it.
 */
function auditLog({ actor, tool, allowed, reason, question }) {
  const entry = {
    timestamp: new Date().toISOString(),
    policyVersion: POLICY_VERSION,
    actor,
    tool,
    allowed,
    reason,
    question: question ?? null,
  };
  // Use process.stdout so the record is never swallowed by console filtering.
  process.stdout.write(JSON.stringify(entry) + "\n");
}

/**
 * Checks whether `userId` is permitted to invoke `toolId`.
 * Throws a structured error (and emits an audit-deny record) when denied.
 */
function enforceToolAllowList(userId, toolId, question) {
  // 1. Global allow-list check.
  if (!TOOL_ALLOW_LIST.has(toolId)) {
    const reason = `Tool '${toolId}' is not on the global allow list.`;
    auditLog({ actor: userId, tool: toolId, allowed: false, reason, question });
    throw new Error(`[POLICY DENIED] ${reason}`);
  }

  // 2. Per-role / per-user scoping.
  // Derive a simple role from the USER_ID (extend this logic as needed).
  const role = userId.startsWith("admin:") ? "admin" : "default";
  const roleScope = ROLE_TOOL_SCOPE[role] ?? new Set();

  if (!roleScope.has(toolId)) {
    const reason =
      `User '${userId}' (role: ${role}) is not permitted to invoke '${toolId}'.`;
    auditLog({ actor: userId, tool: toolId, allowed: false, reason, question });
    throw new Error(`[POLICY DENIED] ${reason}`);
  }

  // 3. Allowed — emit audit record.
  auditLog({
    actor: userId,
    tool: toolId,
    allowed: true,
    reason: "Tool invocation permitted by allow list.",
    question,
  });
}

// ---------------------------------------------------------------------------
// Audit-trail helpers
// ---------------------------------------------------------------------------
const AUDIT_LOG_PATH = "ai_decision_audit.jsonl";
// Retention: rotate the audit log when it exceeds MAX_AUDIT_BYTES (default 10 MB).
const MAX_AUDIT_BYTES = parseInt(process.env.AUDIT_LOG_MAX_BYTES ?? String(10 * 1024 * 1024), 10);

async function rotateAuditLogIfNeeded() {
  try {
    const stat = await fs.stat(AUDIT_LOG_PATH).catch(() => null);
    if (stat && stat.size >= MAX_AUDIT_BYTES) {
      const rotatedPath = `${AUDIT_LOG_PATH}.${Date.now()}.bak`;
      await fs.rename(AUDIT_LOG_PATH, rotatedPath);
    }
  } catch (rotateErr) {
    // Rotation failure must not suppress the primary audit write.
    process.stderr.write(`[AUDIT ROTATION ERROR] ${rotateErr}\n`);
  }
}

async function writeAuditEntry(entry) {
  await rotateAuditLogIfNeeded();
  const line = JSON.stringify(entry) + "\n";
  await fs.appendFile(AUDIT_LOG_PATH, line, "utf8");
}

function sha256(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

// Session-level correlation ID — links every chain.call() in this run.
const TRACE_ID = crypto.randomUUID();

/**
 * Builds a provenance metadata block, signs it with HMAC-SHA256,
 * and returns the full provenance header string.
 * Throws if the PROVENANCE_HMAC_SECRET env var is missing.
 */
function buildProvenanceHeader(modelName, companionName, userId) {
  const secret = process.env.PROVENANCE_HMAC_SECRET;
  if (!secret) {
    throw new Error(
      "PROVENANCE_HMAC_SECRET environment variable is required for content provenance signing."
    );
  }
  const provenance = {
    content_origin: "AI_GENERATED",
    model_identifier: modelName,
    generation_timestamp: new Date().toISOString(),
    companion_name: companionName,
    user_id: userId,
    generator: "OpenAI GPT via LangChain",
  };
  const provenanceJson = JSON.stringify(provenance, null, 2);
  const signature = crypto
    .createHmac("sha256", secret)
    .update(provenanceJson)
    .digest("hex");

  return [
    "=== SYNTHETIC CONTENT NOTICE ===",
    "This file contains AI-generated content. It does not represent real events,",
    "statements, or opinions of any real person.",
    "=== PROVENANCE METADATA ===",
    provenanceJson,
    `=== PROVENANCE SIGNATURE (HMAC-SHA256) ===`,
    signature,
    "=== END PROVENANCE HEADER ===",
    "",
  ].join("\n");
}

const LLM_INTERACTION_LOG = `${new Date().toISOString().replace(/[:.]/g, "-")}_llm_interactions.log`;
const logStream = createWriteStream(LLM_INTERACTION_LOG, { flags: "a" });

function logLLMInteraction(entry) {
  const record = JSON.stringify({ timestamp: new Date().toISOString(), ...entry });
  logStream.write(record + "\n");
  console.log("[LLM Interaction]", record);
}

// ---------------------------------------------------------------------------
// Input sanitization helpers
// ---------------------------------------------------------------------------

/**
 * Validates a simple identifier: only alphanumeric characters, hyphens, and
 * underscores are allowed.  Throws if the value is absent or contains
 * unexpected characters.
 */
function validateIdentifier(value, name) {
  if (!value || typeof value !== "string") {
    throw new Error(`${name} is required.`);
  }
  if (!/^[a-zA-Z0-9_-]+$/.test(value)) {
    throw new Error(
      `${name} contains invalid characters. Only alphanumeric characters, hyphens, and underscores are allowed.`
    );
  }
  return value;
}

/**
 * Sanitizes free-form text that will be interpolated into an LLM prompt.
 * - Removes ASCII control characters (except ordinary whitespace).
 * - Collapses runs of whitespace-only lines to a single blank line.
 * - Trims leading/trailing whitespace.
 */
function sanitizeText(text) {
  if (typeof text !== "string") return "";
  return text
    // Strip ASCII control characters except \t, \n, \r
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
    // Collapse 3+ consecutive blank lines into two
    .replace(/(\r?\n){3,}/g, "\n\n")
    .trim();
}

// ---------------------------------------------------------------------------
// Validate command-line arguments
// ---------------------------------------------------------------------------

const COMPANION_NAME = validateIdentifier(process.argv[2], "COMPANION_NAME");
const MODEL_NAME     = validateIdentifier(process.argv[3], "MODEL_NAME");
const USER_ID        = validateIdentifier(process.argv[4], "USER_ID");

if (!COMPANION_NAME || !MODEL_NAME || !USER_ID) {
  throw new Error(
    "**Usage**: npm run export-to-character <COMPANION_NAME> <MODEL_NAME> <USER_ID>"
  );
}

// COMPANION_NAME has already been validated as a safe identifier, so the
// path cannot escape the companions/ directory.
// --- Security: sanitize companion file content before LLM injection ---
function sanitizeCompanionContent(content, label) {
  // 1. Reject binary / non-printable characters (allow common whitespace)
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/.test(content)) {
    throw new Error(`Security violation in ${label}: binary or non-printable characters detected.`);
  }

  // 2. Strip and reject zero-width / invisible Unicode characters
  const invisiblePattern = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E\u00A0]/;
  if (invisiblePattern.test(content)) {
    throw new Error(`Security violation in ${label}: invisible or zero-width characters detected.`);
  }

  // 3. Detect base64-encoded blobs (long runs of base64 chars)
  if (/(?:[A-Za-z0-9+/]{40,}={0,2})/.test(content)) {
    throw new Error(`Security violation in ${label}: possible base64-encoded payload detected.`);
  }

  // 4. Detect shell commands / command injection patterns
  const shellPatterns = [
    /`[^`]*`/,                        // backtick execution
    /\$\([^)]*\)/,                    // $(...) subshell
    /;\s*(rm|curl|wget|bash|sh|python|perl|ruby|nc|ncat|netcat)\b/i,
    /\|\s*(bash|sh|python|perl|ruby)\b/i,
    /&&\s*(rm|curl|wget|bash|sh)\b/i,
  ];
  for (const pattern of shellPatterns) {
    if (pattern.test(content)) {
      throw new Error(`Security violation in ${label}: shell command pattern detected.`);
    }
  }

  // 5. Detect common prompt-injection / jailbreak phrases
  const injectionPatterns = [
    /ignore (all )?(previous|prior|above) instructions?/i,
    /disregard (all )?(previous|prior|above) instructions?/i,
    /forget (all )?(previous|prior|above) instructions?/i,
    /you are now (in )?developer mode/i,
    /act as (an? )?(unrestricted|unfiltered|jailbroken|DAN)/i,
    /do anything now/i,
    /system prompt/i,
    /\[INST\]/i,
    /<\|im_start\|>/i,
    /###\s*instruction/i,
    /override (safety|content|moderation)/i,
  ];
  for (const pattern of injectionPatterns) {
    if (pattern.test(content)) {
      throw new Error(`Security violation in ${label}: prompt injection pattern detected.`);
    }
  }

  // 6. Detect leetspeak obfuscation (simple heuristic: high ratio of digit-letter substitutions)
  const leetMatches = content.match(/[0-9](?=[a-zA-Z])|[a-zA-Z](?=[0-9])/g) || [];
  const wordCount = content.split(/\s+/).length;
  if (leetMatches.length > 0 && leetMatches.length / wordCount > 3) {
    throw new Error(`Security violation in ${label}: possible leetspeak obfuscation detected.`);
  }

  return content.trim();
}

// Validate COMPANION_NAME to prevent path traversal
if (!/^[a-zA-Z0-9_-]+$/.test(COMPANION_NAME)) {
  throw new Error("Invalid COMPANION_NAME: only alphanumeric characters, hyphens, and underscores are allowed.");
}

// Additional path traversal guard: resolve the target path and confirm it stays within the companions directory.
import path from 'path';
import { fileURLToPath } from 'url';
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const companionsDir = path.resolve(__dirname, '../../companions');
const targetPath = path.resolve(companionsDir, COMPANION_NAME + '.txt');
if (!targetPath.startsWith(companionsDir + path.sep) && targetPath !== companionsDir) {
  throw new Error('Invalid COMPANION_NAME: path traversal detected.');
}
const data = await fs.readFile(targetPath, 'utf8');
const presplit = data.split("###ENDPREAMBLE###");
if (presplit.length < 2) {
  throw new Error("Companion file is missing ###ENDPREAMBLE### delimiter.");
}
const seedsplit = presplit[1].split("###ENDSEEDCHAT###");
if (seedsplit.length < 2) {
  throw new Error("Companion file is missing ###ENDSEEDCHAT### delimiter.");
}
const preamble = sanitizeCompanionContent(presplit[0], "preamble");
const seedChat = sanitizeCompanionContent(seedsplit[0], "seedChat");
const backgroundStory = sanitizeCompanionContent(seedsplit[1], "backgroundStory");
console.log(preamble, backgroundStory);

// Redis credentials are consolidated into a single config object sourced from env
const redisConfig = JSON.parse(
  process.env.UPSTASH_REDIS_CONFIG ||
  JSON.stringify({
    url: process.env.UPSTASH_REDIS_REST_URL,
    token: process.env.UPSTASH_REDIS_REST_TOKEN,
  })
);
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
  .map((entry) => sanitizeText(String(entry)));
const model = new Anthropic({
  modelName: "claude-2",
  anthropicApiKey: process.env.ANTHROPIC_API_KEY,
});
model.verbose = true;

// Minimise: truncate preamble and backgroundStory before injecting into the prompt
const MAX_PREAMBLE_LENGTH = 500;
const MAX_BACKGROUND_LENGTH = 500;
const truncatedPreamble = preamble.slice(0, MAX_PREAMBLE_LENGTH);
const truncatedBackground = backgroundStory.slice(0, MAX_BACKGROUND_LENGTH);
const sanitisedChatBlock = sanitisedChat.join("\n");

const chainPrompt = PromptTemplate.fromTemplate(`
  ### Background Story: 
  ${truncatedPreamble}
  
  ${truncatedBackground}

  ### Chat history: 
  ${seedChat}

  ...
  ${sanitisedChatBlock}

  
  Above is someone whose name is ${COMPANION_NAME}'s story and their chat history with a human. Output answer to the following question. Return only the answer itself 
  
  {question}`);

const chain = new LLMChain({
  llm: model,
  prompt: chainPrompt,
});
/**
 * Sanitizes LLM output by detecting and removing dynamic code execution primitives.
 * Throws an error if dangerous patterns are found, or strips them based on policy.
 */
function sanitizeLLMOutput(text) {
  if (typeof text !== "string") {
    throw new Error("LLM output is not a string; rejecting.");
  }

  // Patterns that indicate dynamic code execution primitives
  const dangerousPatterns = [
    /\beval\s*\(/gi,
    /\bexec\s*\(/gi,
    /\bexecSync\s*\(/gi,
    /\bspawn\s*\(/gi,
    /\bspawnSync\s*\(/gi,
    /\bsubprocess\b/gi,
    /\bnew\s+Function\s*\(/gi,
    /\bsetTimeout\s*\(\s*['"`]/gi,
    /\bsetInterval\s*\(\s*['"`]/gi,
    /\brequire\s*\(/gi,
    /\bimport\s*\(/gi,
    /\bprocess\.binding\s*\(/gi,
    /\bvm\.runInThisContext\s*\(/gi,
    /\bvm\.runInNewContext\s*\(/gi,
    /\bvm\.Script\b/gi,
  ];

  const detectedPatterns = dangerousPatterns
    .filter((pattern) => pattern.test(text))
    .map((pattern) => pattern.toString());

  if (detectedPatterns.length > 0) {
    throw new Error(
      `LLM output contains dangerous code execution primitives: ${detectedPatterns.join(", ")}. Output rejected.`
    );
  }

  // Strip any non-printable or control characters (except common whitespace)
  const sanitized = text.replace(/[^\x09\x0A\x0D\x20-\x7E\u00A0-\uFFFF]/g, "");

  return sanitized;
}

const questions = [
  `Greeting: What would ${COMPANION_NAME} say to start a conversation?`,
  `Short Description: In a few sentences, how would ${COMPANION_NAME} describe themselves?`,
  `Long Description: In a few sentences, how would ${COMPANION_NAME} describe themselves?`,
];
const results = await Promise.all(
  questions.map(async (question, invocationIndex) => {
    const invokedAt = new Date().toISOString();
    const inputHash = sha256(question);
    let chainResult;
    try {
      chainResult = await chain.call({ question });
    } catch (error) {
      // Fail-closed: log the error to the persistent audit trail, then re-throw
      // so execution does NOT continue silently with an undefined result.
      const errorEntry = {
        traceId: TRACE_ID,
        invocationIndex,
        modelName: model.modelName,
        principal: USER_ID,
        companionName: COMPANION_NAME,
        invokedAt,
        completedAt: new Date().toISOString(),
        inputHash,
        question,
        status: "error",
        errorMessage: String(error),
        errorStack: error?.stack ?? null,
      };
      await writeAuditEntry(errorEntry);
      throw error; // re-throw — do not silently continue
    }
    const completedAt = new Date().toISOString();
    const auditEntry = {
      traceId: TRACE_ID,
      invocationIndex,
      modelName: model.modelName,
      principal: USER_ID,
      companionName: COMPANION_NAME,
      invokedAt,
      completedAt,
      inputHash,
      outputHash: sha256(chainResult?.text ?? ""),
      status: "success",
    };
    await writeAuditEntry(auditEntry);
    return chainResult;
  })
);
    try {
      const result = await chain.call({ question });
      logLLMInteraction({ event: "llm_response", input: { question }, output: result });
      return result;
    } catch (error) {
      logLLMInteraction({ event: "llm_error", input: { question }, error: error.message });
      console.error(error);
    }
  })
);

// Build and sign provenance header — throws if signing is not possible,
// which prevents any unlabeled content from being written (fail-safe).
const provenanceHeader = buildProvenanceHeader(
  "gpt-3.5-turbo-16k",
  COMPANION_NAME,
  USER_ID
);

let output = `[MODEL IDENTITY] Generated with approved model: ${RESOLVED_MODEL_ID}\n\n`;
for (let i = 0; i < questions.length; i++) {
  output += `*****${questions[i]}*****\n${results[i].text}\n\n`;
}
output += `Definition (Advanced)\n${sanitisedChat.join("\n")}`;

// Prepend provenance header to both output files.
const labeledCharacterData = provenanceHeader + output;
const labeledChatHistory =
  provenanceHeader + JSON.stringify(upstashChatHistory, null, 2);

try {
  await fs.writeFile(
    `${COMPANION_NAME}_chat_history.txt`,
    labeledChatHistory
  );
} catch (writeError) {
  console.error(
    "[PROVENANCE FAIL-SAFE] Failed to write labeled chat history. Aborting to prevent unlabeled output.",
    writeError
  );
  process.exit(1);
}

try {
  await fs.writeFile(
    `${COMPANION_NAME}_character_ai_data.txt`,
    labeledCharacterData
  );
} catch (writeError) {
  console.error(
    "[PROVENANCE FAIL-SAFE] Failed to write labeled character AI data. Aborting to prevent unlabeled output.",
    writeError
  );
  process.exit(1);
}
