import { ChatAnthropic } from "langchain/chat_models/anthropic";
import dotenv from "dotenv";
import { LLMChain } from "langchain/chains";
import { StreamingTextResponse, LangChainStream } from "ai";
import clerk from "@clerk/clerk-sdk-node";
import { CallbackManager } from "langchain/callbacks";
import { PromptTemplate } from "langchain/prompts";
import { NextResponse } from "next/server";
import { currentUser } from "@clerk/nextjs";
import MemoryManager from "@/app/utils/memory";
import { rateLimit } from "@/app/utils/rateLimit";
import crypto from "crypto";

dotenv.config({ path: `.env.local` });

// Explicit tool allow list
const ALLOWED_TOOLS: string[] = [];

function validateTools(requestedTools: string[]): boolean {
  if (requestedTools.length === 0) {
    console.log("INFO: tool validation passed — no tools requested (tool-free invocation permitted)");
    return true;
  }
  for (const tool of requestedTools) {
    if (!ALLOWED_TOOLS.includes(tool)) {
      console.log(`INFO: tool validation failed — unauthorized tool requested: ${tool}`);
      return false;
    }
  }
  return true;
}

function sanitizeInput(input: string, maxLength: number = 4000): string {
  // Strip control characters (except newlines and tabs)
  let sanitized = input.replace(/[^\x09\x0A\x0D\x20-\x7E\u00A0-\uFFFF]/g, "");

  // Remove hidden/invisible unicode characters
  sanitized = sanitized.replace(/[\u200B-\u200D\uFEFF\u00AD]/g, "");

  // Detect and strip base64-encoded blobs (long base64 strings)
  sanitized = sanitized.replace(/(?:[A-Za-z0-9+/]{40,}={0,2})/g, "[REDACTED_BASE64]");

  // Strip shell/binary command patterns
  const shellPatterns = [
    /\b(eval|exec|system|popen|subprocess|os\.system|child_process|spawn|execSync|execFile)\s*\(/gi,
    /`[^`]*`/g,
    /\$\([^)]*\)/g,
    /;\s*(rm|ls|cat|wget|curl|bash|sh|python|node|perl|ruby)\b/gi,
  ];
  for (const pattern of shellPatterns) {
    sanitized = sanitized.replace(pattern, "[REDACTED_CMD]");
  }

  // Strip prompt injection keywords
  const injectionPatterns = [
    /ignore\s+(previous|above|prior)\s+instructions?/gi,
    /disregard\s+(previous|above|prior)\s+instructions?/gi,
    /forget\s+(previous|above|prior)\s+instructions?/gi,
    /you\s+are\s+now\s+/gi,
    /act\s+as\s+if\s+/gi,
    /pretend\s+(you\s+are|to\s+be)\s+/gi,
    /jailbreak/gi,
    /prompt\s+injection/gi,
  ];
  for (const pattern of injectionPatterns) {
    sanitized = sanitized.replace(pattern, "[REDACTED_INJECTION]");
  }

  // Strip leetspeak injection patterns
  sanitized = sanitized.replace(/[i!1][g9][n][o0][r][e3]/gi, "[REDACTED]");

  // Enforce length limit
  if (sanitized.length > maxLength) {
    sanitized = sanitized.substring(0, maxLength);
  }

  return sanitized;
}

function sanitizeName(name: string): string {
  // Allow only alphanumeric characters, hyphens, and underscores
  return name.replace(/[^a-zA-Z0-9_-]/g, "");
}

function sanitizeLLMOutput(output: string): string {
  // Check for dynamic code execution primitives
  const dangerousPatterns = [
    /\beval\s*\(/gi,
    /\bexec\s*\(/gi,
    /\bsubprocess\b/gi,
    /\bos\.system\s*\(/gi,
    /\bchild_process\b/gi,
    /\bspawn\s*\(/gi,
    /\bexecSync\s*\(/gi,
    /\bexecFile\s*\(/gi,
    /\bFunction\s*\(/gi,
    /\bnew\s+Function\b/gi,
    /\bsetTimeout\s*\(\s*["'`]/gi,
    /\bsetInterval\s*\(\s*["'`]/gi,
  ];

  let sanitized = output;
  for (const pattern of dangerousPatterns) {
    sanitized = sanitized.replace(pattern, "[REDACTED_DANGEROUS_CODE]");
  }

  return sanitized;
}

function validateCompanionFile(content: string): boolean {
  // Check for hidden/invisible characters
  if (/[\u200B-\u200D\uFEFF\u00AD]/.test(content)) {
    console.log("INFO: companion file validation failed — hidden characters detected");
    return false;
  }

  // Check for base64-encoded payloads
  if (/(?:[A-Za-z0-9+/]{60,}={0,2})/.test(content)) {
    console.log("INFO: companion file validation failed — base64 payload detected");
    return false;
  }

  // Check for shell/binary commands
  if (/\b(eval|exec|system|popen|subprocess|os\.system|child_process|spawn|execSync|execFile)\s*\(/.test(content)) {
    console.log("INFO: companion file validation failed — shell command detected");
    return false;
  }

  // Check for explicit prompt-injection keywords
  const injectionPatterns = [
    /ignore\s+(previous|above|prior)\s+instructions?/gi,
    /disregard\s+(previous|above|prior)\s+instructions?/gi,
    /forget\s+(previous|above|prior)\s+instructions?/gi,
    /jailbreak/gi,
    /prompt\s+injection/gi,
  ];
  for (const pattern of injectionPatterns) {
    if (pattern.test(content)) {
      console.log("INFO: companion file validation failed — prompt injection keyword detected");
      return false;
    }
  }

  // Check for leetspeak injection patterns
  if (/[i!1][g9][n][o0][r][e3]/gi.test(content)) {
    console.log("INFO: companion file validation failed — leetspeak injection detected");
    return false;
  }

  return true;
}

function verifyHmacSignature(userId: string, userName: string, signature: string): boolean {
  const secret = process.env.HMAC_SECRET_KEY;
  if (!secret) {
    console.log("INFO: HMAC_SECRET_KEY not configured");
    return false;
  }
  const payload = `${userId}:${userName}`;
  const expected = crypto.createHmac("sha256", secret).update(payload).digest("hex");
  return crypto.timingSafeEqual(Buffer.from(signature, "hex"), Buffer.from(expected, "hex"));
}

export async function POST(req: Request) {
  const { prompt, isText, userId, userName, signature } = await req.json();

  const identifier = req.url + "-" + (userId || "anonymous");
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

  // XXX Companion name passed here. Can use as a key to get backstory, chat history etc.
  const rawName = req.headers.get("name");
  const name = rawName ? sanitizeName(rawName) : null;
  if (!name) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion name" }),
      {
        status: 400,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }
  const companionFileName = name + ".txt";

  // Always use server-side Clerk authentication
  let clerkUserId: string | undefined;
  let clerkUserName: string | undefined | null;

  if (isText) {
    // For text requests, require HMAC signature verification
    if (!userId || !userName || !signature) {
      console.log("INFO: missing identity fields or signature for text request");
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
    if (!verifyHmacSignature(userId, userName, signature)) {
      console.log("INFO: HMAC signature verification failed");
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
    clerkUserId = userId;
    clerkUserName = userName;
  } else {
    const user = await currentUser();
    clerkUserId = user?.id;
    clerkUserName = user?.firstName;
  }

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
  const data = await fs.readFile("companions/" + companionFileName, "utf8");

  // Validate companion file for malicious content
  if (!validateCompanionFile(data)) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion file content" }),
      {
        status: 400,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }

  // Clunky way to break out PREAMBLE and SEEDCHAT from the character file
  const presplit = data.split("###ENDPREAMBLE###");
  const preamble = presplit[0];
  const seedsplit = presplit[1].split("###ENDSEEDCHAT###");
  const seedchat = seedsplit[0];

  // Sanitize prompt input
  const sanitizedPrompt = sanitizeInput(prompt || "", 2000);

  // Validate sanitized inputs for injection attempts
  const sanitizedPreamble = sanitizeInput(preamble, 8000);

  if (!sanitizedPrompt) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid prompt" }),
      {
        status: 400,
        headers: {
          "Content-Type": "application/json",
        },
      }
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

  await memoryManager.writeToHistory("Human: " + sanitizedPrompt + "\n", companionKey);
  let recentChatHistory = await memoryManager.readLatestHistory(companionKey);

  // Removed Pinecone vector search to reduce external system credentials
  let relevantHistory = "";

  const sanitizedRelevantHistory = sanitizeInput(relevantHistory, 4000);
  const sanitizedRecentChatHistory = sanitizeInput(recentChatHistory, 4000);

  const { stream, handlers } = LangChainStream();

  const model = new ChatAnthropic({
    streaming: true,
    modelName: "claude-2",
    anthropicApiKey: process.env.ANTHROPIC_API_KEY,
    callbackManager: CallbackManager.fromHandlers(handlers),
  });

  const replyWithTwilioLimit = isText
    ? "You reply within 1000 characters."
    : "";

  // Validate tools before invoking the LLM chain
  const requestedTools: string[] = [];
  if (!validateTools(requestedTools)) {
    return new NextResponse(
      JSON.stringify({ Message: "Unauthorized tool usage detected" }),
      {
        status: 403,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }

  const chainPrompt = PromptTemplate.fromTemplate(`
    You are ${name} and are currently talking to a user.

    ${sanitizedPreamble}

  You reply with answers that range from one sentence to one paragraph and with some details. ${replyWithTwilioLimit}

  Below are relevant details about ${name}'s past
  ${sanitizedRelevantHistory}
  
  Below is a relevant conversation history

  ${sanitizedRecentChatHistory}`);

  const chain = new LLMChain({
    llm: model,
    prompt: chainPrompt,
  });

  // Log full LLM input before invocation (without PII)
  console.log("INFO: LLM input — name:", name, "| replyWithTwilioLimit:", replyWithTwilioLimit, "| preamble length:", sanitizedPreamble.length, "| relevantHistory length:", sanitizedRelevantHistory.length, "| recentChatHistory length:", sanitizedRecentChatHistory.length);

  const result = await chain
    .call({
      relevantHistory: sanitizedRelevantHistory,
      recentChatHistory: sanitizedRecentChatHistory,
    })
    .catch(console.error);

  if (!result || !result.text) {
    return new NextResponse(
      JSON.stringify({ Message: "No response from model" }),
      {
        status: 500,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }

  // Sanitize LLM output before writing to history or returning to client
  const sanitizedOutput = sanitizeLLMOutput(result.text);

  const chatHistoryRecord = await memoryManager.writeToHistory(
    sanitizedOutput + "\n",
    companionKey
  );
  console.log("chatHistoryRecord", chatHistoryRecord);
  if (isText) {
    return NextResponse.json(sanitizedOutput);
  }
  return new StreamingTextResponse(stream);
}