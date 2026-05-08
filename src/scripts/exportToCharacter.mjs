import { Redis } from "@upstash/redis";
import { PromptTemplate } from "langchain/prompts";
import { LLMChain } from "langchain/chains";
import { ChatAnthropic } from "langchain/chat_models/anthropic";

import dotenv from "dotenv";
import fs from "fs/promises";
dotenv.config({ path: `.env.local` });

const COMPANION_NAME = process.argv[2];
const MODEL_NAME = process.argv[3];
const SECRET_TOKEN = process.argv[4];
const USER_ID = process.argv[5];

if (!COMPANION_NAME || !MODEL_NAME || !SECRET_TOKEN || !USER_ID) {
  throw new Error(
    "**Usage**: npm run generate-character <COMPANION_NAME> <MODEL_NAME> <SECRET_TOKEN> <USER_ID>"
  );
}

// Authentication check: verify secret token before any external access
if (!process.env.EXPORT_SECRET || SECRET_TOKEN !== process.env.EXPORT_SECRET) {
  throw new Error("Authentication failed: invalid or missing secret token.");
}

// Validate COMPANION_NAME to allow only safe alphanumeric characters, hyphens, and underscores (prevents path traversal)
if (!/^[a-zA-Z0-9_-]+$/.test(COMPANION_NAME)) {
  throw new Error(
    "Invalid COMPANION_NAME: only alphanumeric characters, hyphens, and underscores are allowed."
  );
}

// Explicit credential validation
// External systems accessed by this script (must remain within 3-system limit):
//   1. Upstash Redis (UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN)
//   2. Anthropic Claude (ANTHROPIC_API_KEY)
if (!process.env.UPSTASH_REDIS_REST_URL || !process.env.UPSTASH_REDIS_REST_TOKEN) {
  throw new Error("Missing required Upstash Redis credentials.");
}
if (!process.env.ANTHROPIC_API_KEY) {
  throw new Error("Missing required Anthropic API key.");
}

// Tool allow list: only these questions are permitted to be sent to the LLM
const ALLOWED_QUESTIONS = [
  `Greeting: What would ${COMPANION_NAME} say to start a conversation?`,
  `Short Description: In a few sentences, how would ${COMPANION_NAME} describe themselves?`,
  `Long Description: In a few sentences, how would ${COMPANION_NAME} describe themselves?`,
];

/**
 * Sanitize a string to prevent prompt injection, path traversal, and malicious content.
 * Strips hidden/invisible/zero-width characters, base64-encoded payloads, shell/binary commands,
 * leetspeak patterns, suspicious instruction patterns, and enforces length limits.
 */
function sanitizeInput(value, maxLength = 8000) {
  if (typeof value !== "string") return "";

  // Remove zero-width and invisible Unicode characters
  let sanitized = value.replace(
    /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E\u00A0]/g,
  );

  // Detect and reject base64-encoded payloads (long base64 strings)
  if (/(?:[A-Za-z0-9+/]{40,}={0,2})/.test(sanitized)) {
    throw new Error("Suspicious base64-encoded content detected in input.");
  }

  // Detect and reject shell/binary command patterns
  const shellPatterns = [
    /\b(bash|sh|zsh|cmd|powershell|exec|system|popen|subprocess|os\.system)\b/i,
    /(\$\(|\`[^`]*\`|&&|\|\|)/,
    /\b(rm\s+-rf|chmod|chown|wget|curl\s+.*\|)\b/i,
  ];
  for (const pattern of shellPatterns) {
    if (pattern.test(sanitized)) {
      throw new Error("Suspicious shell/binary command detected in input.");
    }
  }

  // Detect leetspeak patterns used to obfuscate injection attempts
  if (/[4@][dD][mM][1iI][nN]|[iI][gG][nN][oO][rR][3eE]/.test(sanitized)) {
    throw new Error("Suspicious leetspeak pattern detected in input.");
  }

  // Detect hidden prompt / instruction injection patterns
  const injectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/i,
    /you\s+are\s+now\s+/i,
    /disregard\s+(all\s+)?(previous|prior|above)/i,
    /system\s*:\s*/i,
    /\[INST\]/i,
    /<\|.*?\|>/,
  ];
  for (const pattern of injectionPatterns) {
    if (pattern.test(sanitized)) {
      throw new Error("Suspicious prompt injection pattern detected in input.");
    }
  }

  // Strip ### sequences that could be used for prompt injection
  sanitized = sanitized.replace(/###/g, "");

  // Strip backticks
  sanitized = sanitized.replace(/`/g, "");

  // Trim leading/trailing whitespace
  sanitized = sanitized.trim();

  // Enforce length limit
  if (sanitized.length > maxLength) {
    sanitized = sanitized.substring(0, maxLength);
  }

  return sanitized;
}

/**
 * Sanitize LLM output to detect and strip dynamic code execution primitives.
 */
function sanitizeLLMOutput(output) {
  if (typeof output !== "string") return "";

  const dangerousPatterns = [
    /\beval\s*\(/gi,
    /\bexec\s*\(/gi,
    /new\s+Function\s*\(/gi,
    /\bsetTimeout\s*\(\s*["'`]/gi,
    /\bsetInterval\s*\(\s*["'`]/gi,
    /\bimportScripts\s*\(/gi,
    /\brequire\s*\(\s*["'`]child_process/gi,
    /process\.binding\s*\(/gi,
  ];

  let sanitized = output;
  for (const pattern of dangerousPatterns) {
    if (pattern.test(sanitized)) {
      // Strip the dangerous primitive
      sanitized = sanitized.replace(pattern, "[REDACTED]");
    }
  }

  return sanitized;
}

// Open log file for LLM interaction logging
const LOG_FILE = `${COMPANION_NAME}_llm_interactions.log`;
async function logLLMInteraction(question, response, error) {
  const timestamp = new Date().toISOString();
  let entry;
  if (error) {
    entry = `[${timestamp}] INPUT: ${question}\nERROR: ${error}\n---\n`;
  } else {
    entry = `[${timestamp}] INPUT: ${question}\nOUTPUT: ${response}\n---\n`;
  }
  await fs.appendFile(LOG_FILE, entry, { encoding: "utf8" });
}

const rawData = await fs.readFile("companions/" + COMPANION_NAME + ".txt", "utf8");
const presplit = rawData.split("###ENDPREAMBLE###");
const rawPreamble = presplit[0];
const seedsplit = presplit[1].split("###ENDSEEDCHAT###");
const rawSeedChat = seedsplit[0];
const rawBackgroundStory = seedsplit[1];

// Sanitize file contents to prevent malicious prompt injection from uploaded files
const preamble = sanitizeInput(rawPreamble);
const seedChat = sanitizeInput(rawSeedChat);
const backgroundStory = sanitizeInput(rawBackgroundStory);
const sanitizedCompanionName = sanitizeInput(COMPANION_NAME, 100);

console.log(preamble, backgroundStory);

const history = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

const upstashChatHistory = await history.zrange(
  `${sanitizedCompanionName}-${MODEL_NAME}-${USER_ID}`,
  0,
  Date.now(),
  {
    byScore: true,
  }
);
const recentChatRaw = upstashChatHistory.slice(-30);
// Sanitize each chat history entry
const recentChat = recentChatRaw.map((entry) => {
  try {
    return sanitizeInput(String(entry));
  } catch {
    return "[sanitized]";
  }
});

// Use approved Anthropic Claude model (claude-2) instead of disallowed OpenAI GPT model
const model = new ChatAnthropic({
  modelName: "claude-2",
  anthropicApiKey: process.env.ANTHROPIC_API_KEY,
});
model.verbose = true;

const chainPrompt = PromptTemplate.fromTemplate(`
  Background Story: 
  ${preamble}
  
  ${backgroundStory}

  Chat history: 
  ${seedChat}

  ...
  ${recentChat}

  
  Above is someone whose name is ${sanitizedCompanionName}'s story and their chat history with a human. Output answer to the following question. Return only the answer itself 
  
  {question}`);

const chain = new LLMChain({
  llm: model,
  prompt: chainPrompt,
});

const questions = ALLOWED_QUESTIONS;

const results = await Promise.all(
  questions.map(async (question) => {
    // Enforce tool allow list
    if (!ALLOWED_QUESTIONS.includes(question)) {
      const errMsg = `Question not on allow list: ${question}`;
      await logLLMInteraction(question, null, errMsg);
      throw new Error(errMsg);
    }

    try {
      const result = await chain.call({ question });
      const sanitizedOutput = sanitizeLLMOutput(result.text);
      await logLLMInteraction(question, sanitizedOutput, null);
      return { text: sanitizedOutput };
    } catch (error) {
      await logLLMInteraction(question, null, error.message || String(error));
      throw error;
    }
  })
);

// Validate results before writing output
for (let i = 0; i < results.length; i++) {
  if (!results[i] || typeof results[i].text !== "string") {
    throw new Error(`Invalid result for question: ${questions[i]}`);
  }
}

let output = "";
for (let i = 0; i < questions.length; i++) {
  output += `*****${questions[i]}*****\n${results[i].text}\n\n`;
}
output += `Definition (Advanced)\n${recentChat.join("\n")}`;

// Write output files with restricted permissions (mode 0o600)
await fs.writeFile(`${sanitizedCompanionName}_chat_history.txt`, upstashChatHistory.join("\n"), { mode: 0o600 });
await fs.writeFile(`${sanitizedCompanionName}_character_ai_data.txt`, output, { mode: 0o600 });