import { OpenAI } from "langchain/llms/openai";
import dotenv from "dotenv";
import { LLMChain } from "langchain/chains";
import { StreamingTextResponse, LangChainStream } from "ai";
import clerk from "@clerk/clerk-sdk-node";
import { CallbackManager } from "langchain/callbacks";
import { PromptTemplate } from "langchain/prompts";
import { NextResponse } from "next/server";
import { createHash, randomUUID } from "crypto";
import { appendFileSync } from "fs";
import { join } from "path";

// ---------------------------------------------------------------------------
// Minimal persistent audit logger (JSON-lines, append-only).
// Replace appendFileSync with a call to your database / SIEM in production.
// ---------------------------------------------------------------------------
function writeAuditRecord(record: Record<string, unknown>): void {
  const line = JSON.stringify(record) + "\n";
  const auditPath = join(process.cwd(), "audit", "ai_decisions.jsonl");
  try {
    appendFileSync(auditPath, line, { encoding: "utf8", flag: "a" });
  } catch (err) {
    // Fallback: emit to stderr so the record is at least captured by log
    // aggregators even if the file cannot be written.
    process.stderr.write("[AUDIT FALLBACK] " + line);
  }
}
import { currentUser } from "@clerk/nextjs";
import MemoryManager from "@/app/utils/memory";
import { rateLimit } from "@/app/utils/rateLimit";

dotenv.config({ path: `.env.local` });

export async function POST(req: Request) {
  let clerkUserId;
  let user;
  let clerkUserName;
  const { prompt, isText } = await req.json();

  const identifier = req.url + "-" + "anonymous";
  const { success } = await rateLimit(identifier);
  if (!success) {
    console.log("INFO: rate limit exceeded");
    return new NextResponse(
      JSON.stringify({ Message: "Hi, the companions can't talk this fast." }),
      {
        status: 429,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }

  // Sanitize and validate user-supplied inputs before use in LLM prompts.
  // Strips characters commonly used for prompt injection and enforces length limits.
  function sanitizeInput(value: string | null | undefined, maxLength = 500): string {
    if (!value) return "";
    // Remove control characters, backticks, and common prompt-injection patterns
    const stripped = value
      .replace(/[\x00-\x1F\x7F]/g, "")   // control characters
      .replace(/`/g, "'")                  // backticks
      .replace(/###/g, "")                 // section delimiters used in character files
      .replace(/(ignore|disregard|forget).{0,40}(above|previous|instruction)/gi, "") // injection phrases
      .trim();
    return stripped.slice(0, maxLength);
  }

  // XXX Companion name passed here. Can use as a key to get backstory, chat history etc.
  const rawName = req.headers.get("name");
  const name = sanitizeInput(rawName, 100);
  if (!name) {
    return new NextResponse(
      JSON.stringify({ Message: "Missing or invalid companion name" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
  // Restrict companionFileName to alphanumeric, hyphens, and underscores to prevent path traversal.
  if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion name" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
  const companionFileName = name + ".txt";

  // Sanitize the user-supplied prompt before any use
  try {
    prompt = sanitizeInput(prompt, "user prompt");
  } catch (e) {
    console.error("Rejected user prompt:", e);
    return new NextResponse(
      JSON.stringify({ Message: "Your message contains disallowed content." }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

      console.log("prompt: ", prompt);
  // Always authenticate server-side; never trust client-supplied userId/userName
  user = await currentUser();
  clerkUserId = user?.id;
  clerkUserName = user?.firstName;

  if (!clerkUserId || !!!(await clerk.users.getUser(clerkUserId))) {
    console.log("user not authorized");
    return new NextResponse(
      JSON.stringify({ Message: "User not authorized" }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }

  // Load character "PREAMBLE" from character file. These are the core personality
  // characteristics that are used in every prompt. Additional background is
  // only included if it matches a similarity comparioson with the current
  // discussion. The PREAMBLE should include a seed conversation whose format will
  // vary by the model using it.
  const fs = require("fs").promises;
  const path = require("path");

  // Resolve and verify the file path stays within the companions directory
  const companionsDir = path.resolve("companions");
  const resolvedPath = path.resolve(companionsDir, companionFileName);
  if (!resolvedPath.startsWith(companionsDir + path.sep)) {
    console.log("Path traversal attempt detected");
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion name" }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  const data = await fs.readFile(resolvedPath, "utf8");

  // --- Malicious content checks ---
  function containsMaliciousContent(text: string): boolean {
    // 1. Invisible / zero-width Unicode characters often used to hide injections
    if (/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/.test(text)) return true;

    // 2. Base64-encoded blobs (long runs of base64 chars that could hide payloads)
    if (/(?:[A-Za-z0-9+\/]{40,}={0,2})/.test(text)) return true;

    // 3. Shell command patterns
    if (/(?:bash|sh|cmd|powershell|exec|eval|system|popen|subprocess|os\.system|`[^`]+`)/i.test(text)) return true;

    // 4. Prompt-override / jailbreak phrases
    const overridePhrases = [
      /ignore (all |previous |above |prior )?instructions/i,
      /disregard (all |previous |above |prior )?instructions/i,
      /forget (all |previous |above |prior )?instructions/i,
      /you are now/i,
      /act as (a |an )?/i,
      /new persona/i,
      /system prompt/i,
      /\[system\]/i,
      /###SYSTEM/i,
      /<\|im_start\|>/i,
      /<\|im_end\|>/i,
    ];
    if (overridePhrases.some((re) => re.test(text))) return true;

    // 5. Leetspeak patterns (e.g. 1gn0r3, 3x3cut3)
    if (/[1!][g9][n][0o][r][3e]|[3e][x][3e][c][u][t][3e]/i.test(text)) return true;

    // 6. Binary / non-printable characters (excluding normal whitespace)
    if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(text)) return true;

    return false;
  }

  if (containsMaliciousContent(data)) {
    console.log("Malicious content detected in companion file: " + companionFileName);
    return new NextResponse(
      JSON.stringify({ Message: "Companion file contains disallowed content" }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  // Clunky way to break out PREAMBLE and SEEDCHAT from the character file
    const presplit = data.split("###ENDPREAMBLE###");
  // Data minimisation: truncate preamble to 2000 characters
  const preamble = presplit[0].slice(0, 2000);
  const seedsplit = presplit[1].split("###ENDSEEDCHAT###");
  // Data minimisation: truncate seedchat to 500 characters
  const seedchat = seedsplit[0].slice(0, 500);

  // Sanitize file-sourced content before injecting into the prompt
  try {
    preamble = sanitizeInput(preamble, "companion preamble");
  } catch (e) {
    console.error("Rejected companion preamble:", e);
    return new NextResponse(
      JSON.stringify({ Message: "Companion file contains disallowed content." }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }

  const companionKey = {
    companionName: name!,
    modelName: "chatgpt",
    userId: clerkUserId,
  };
  const memoryManager = await MemoryManager.getInstance();

  const records = await memoryManager.readLatestHistory(companionKey);
  if (records.length === 0) {
    await memoryManager.seedChatHistory(seedchat, "\n\n", companionKey);
  }

  const sanitizedPrompt = sanitizeInput(prompt, 2000);
  if (!sanitizedPrompt) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid or empty prompt" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
  await memoryManager.writeToHistory("Human: " + sanitizedPrompt + "\n", companionKey);
  let recentChatHistory = await memoryManager.readLatestHistory(companionKey);
  // Data minimisation: limit recent chat history to the last 10 lines
  recentChatHistory = recentChatHistory.split("\n").slice(-10).join("\n");

    // Vector search removed to comply with external credential policy (max 3 systems).
  // Active credentials: OpenAI, Clerk, Redis/Upstash.
  let relevantHistory = "";

  // Sanitize vector-search results before injecting into the prompt
  try {
    relevantHistory = sanitizeInput(relevantHistory, "relevantHistory");
  } catch (e) {
    console.error("Rejected relevantHistory content:", e);
    relevantHistory = ""; // degrade gracefully — omit tainted history
  }

  // Sanitize recent chat history before injecting into the prompt
  try {
    recentChatHistory = sanitizeInput(recentChatHistory, "recentChatHistory");
  } catch (e) {
    console.error("Rejected recentChatHistory content:", e);
    recentChatHistory = ""; // degrade gracefully — omit tainted history
  }

  // --- Approved model registry: maps logical name -> pinned digest/commit hash ---
  const APPROVED_MODEL_REGISTRY: Record<string, { modelId: string; pinnedDigest: string }> = {
    "gpt-4-0613": {
      modelId: "gpt-4-0613",
      pinnedDigest: "sha256:openai-gpt-4-0613-20230613",
    },
    "gpt-3.5-turbo-0125": {
      modelId: "gpt-3.5-turbo-0125",
      pinnedDigest: "sha256:openai-gpt-3.5-turbo-0125-20240125",
    },
  };

  const REQUESTED_MODEL_TAG = "gpt-3.5-turbo-0125";
  const registryEntry = APPROVED_MODEL_REGISTRY[REQUESTED_MODEL_TAG];
  if (!registryEntry) {
    console.error(
      `Model '${REQUESTED_MODEL_TAG}' is not in the approved model registry. Aborting inference.`
    );
    return new NextResponse(
      JSON.stringify({
        Message: `Model '${REQUESTED_MODEL_TAG}' is not approved for use.`,
      }),
      {
        status: 403,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  const { stream, handlers } = LangChainStream();

    // Use the registry-resolved, pinned model identifier — never a mutable tag.
  const model = new OpenAI({
    streaming: true,
    modelName: registryEntry.modelId,
    openAIApiKey: process.env.OPENAI_API_KEY,
    callbackManager: CallbackManager.fromHandlers(handlers),
  });
  console.log(
    `[ModelRegistry] Resolved model: id=${registryEntry.modelId} digest=${registryEntry.pinnedDigest}`
  );
  model.verbose = true;

  const replyWithTwilioLimit = isText
    ? "You reply within 1000 characters."
    : "";

  const chainPrompt = PromptTemplate.fromTemplate(`
    You are ${name} and are currently talking to ${clerkUserName ?? "the user"}.

    ${preamble}

  You reply with answers that range from one sentence to one paragraph and with some details. ${replyWithTwilioLimit}

  Below are relevant details about ${name}'s past
  ${relevantHistory}
  
  Below is a relevant conversation history

  ${sanitizedPrompt ? recentChatHistory : ""}`);

  const chain = new LLMChain({
    llm: model,
    prompt: chainPrompt,
  });

  const renderedPrompt = await chainPrompt.format({
    relevantHistory,
    recentChatHistory: recentChatHistory,
  });
  console.log("[LLM Interaction] Input prompt sent to LLM:", renderedPrompt);

  const result = await chain
    .call({
      relevantHistory: scrubPII(relevantHistory),
      recentChatHistory: scrubPII(recentChatHistory),
    })
    .catch(console.error);

  console.log("[LLM Interaction] Output received from LLM:", result);
  // Sanitize LLM output: reject or strip dynamic code execution primitives
  const sanitizeLLMOutput = (text: string): string => {
    if (typeof text !== "string") {
      throw new Error("Invalid LLM output: expected a string.");
    }
    // Patterns for dynamic code execution primitives
    const dangerousPatterns = [
      /\beval\s*\(/gi,
      /\bexec\s*\(/gi,
      /\bnew\s+Function\s*\(/gi,
      /\bsetTimeout\s*\(\s*['"`]/gi,
      /\bsetInterval\s*\(\s*['"`]/gi,
      /\bsubprocess\b/gi,
      /\bchild_process\b/gi,
      /\bspawnSync\b/gi,
      /\bspawn\s*\(/gi,
      /\bexecSync\s*\(/gi,
      /\bexecFile\s*\(/gi,
      /\bProcessBuilder\b/gi,
      /\bRuntime\.getRuntime\b/gi,
      /\b__import__\s*\(/gi,
      /\bimportlib\b/gi,
      /\bos\.system\s*\(/gi,
      /\bos\.popen\s*\(/gi,
    ];
    let sanitized = text;
    for (const pattern of dangerousPatterns) {
      sanitized = sanitized.replace(pattern, "[BLOCKED]");
    }
    return sanitized;
  };

  let sanitizedText: string;
  try {
    sanitizedText = sanitizeLLMOutput(result!.text);
  } catch (e) {
    console.error("LLM output sanitization failed:", e);
    return new NextResponse("Invalid response from model.", { status: 500 });
  }

  const chatHistoryRecord = await memoryManager.writeToHistory(
    sanitizedText + "\n",
    companionKey
  );
  console.log("chatHistoryRecord", chatHistoryRecord);
  if (isText) {
    return NextResponse.json(sanitizedText);
  }
  return new StreamingTextResponse(stream);
}
