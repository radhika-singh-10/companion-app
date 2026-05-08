import dotenv from "dotenv";
import { StreamingTextResponse, LangChainStream } from "ai";
import { ChatOpenAI } from "langchain/chat_models/openai";
import { CallbackManager } from "langchain/callbacks";
import clerk from "@clerk/clerk-sdk-node";
import MemoryManager from "@/app/utils/memory";
import { currentUser } from "@clerk/nextjs";
import { NextResponse } from "next/server";
import { rateLimit } from "@/app/utils/rateLimit";

dotenv.config({ path: `.env.local` });

const APPROVED_COMPANION_NAMES = ["Alex", "Evelyn", "Lucky", "Rosie", "Sebastian"];
const POLICY_VERSION = "1.0.0";
const MAX_PROMPT_LENGTH = 4096;

function sanitizeInput(input: string, maxLength: number = MAX_PROMPT_LENGTH): string {
  if (typeof input !== "string") return "";
  // Strip null bytes and control characters
  let sanitized = input.replace(/\0/g, "").replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  // Strip invisible/zero-width characters
  sanitized = sanitized.replace(/[\u200B-\u200D\uFEFF\u00AD]/g, "");
  // Truncate to max length
  if (sanitized.length > maxLength) {
    sanitized = sanitized.slice(0, maxLength);
  }
  return sanitized;
}

function sanitizeForPromptInjection(input: string): string {
  if (typeof input !== "string") return "";
  // Strip newlines and carriage returns that could be used for prompt injection
  let sanitized = input.replace(/[\r\n]+/g, " ");
  // Strip control characters
  sanitized = sanitized.replace(/[\x00-\x1F\x7F]/g, "");
  // Strip invisible characters
  sanitized = sanitized.replace(/[\u200B-\u200D\uFEFF\u00AD]/g, "");
  return sanitized;
}

function sanitizeCompanionName(name: string | null): string | null {
  if (!name) return null;
  // Only allow alphanumeric, hyphens, underscores
  const sanitized = name.replace(/[^a-zA-Z0-9_-]/g, "");
  if (!sanitized || sanitized.length === 0) return null;
  return sanitized;
}

function containsMaliciousPatterns(input: string): boolean {
  const dangerousPatterns = [
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /\bsubprocess\b/i,
    /\bos\.system\b/i,
    /\bspawn\s*\(/i,
    /\brequire\s*\(\s*['"]child_process['"]\s*\)/i,
    /\bFunction\s*\(/i,
    /\bnew\s+Function\b/i,
    /\bsetTimeout\s*\(\s*['"`]/i,
    /\bsetInterval\s*\(\s*['"`]/i,
    /\bimport\s*\(/i,
    /\b__import__\s*\(/i,
    /\bbase64_decode\b/i,
    /\batob\s*\(/i,
    /\bbtoa\s*\(/i,
  ];
  return dangerousPatterns.some((pattern) => pattern.test(input));
}

function sanitizeLLMOutput(output: string): string {
  const dangerousPatterns = [
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /\bsubprocess\b/i,
    /\bos\.system\b/i,
    /\bspawn\s*\(/i,
    /\brequire\s*\(\s*['"]child_process['"]\s*\)/i,
    /\bFunction\s*\(/i,
    /\bnew\s+Function\b/i,
    /\bsetTimeout\s*\(\s*['"`]/i,
    /\bsetInterval\s*\(\s*['"`]/i,
    /\bimport\s*\(/i,
    /\b__import__\s*\(/i,
  ];
  for (const pattern of dangerousPatterns) {
    if (pattern.test(output)) {
      console.error(
        JSON.stringify({
          event: "llm_output_sanitized",
          reason: "dangerous_pattern_detected",
          pattern: pattern.toString(),
          policyVersion: POLICY_VERSION,
          timestamp: new Date().toISOString(),
        })
      );
      return "I'm sorry, I cannot provide that response.";
    }
  }
  return output;
}

export async function POST(request: Request) {
  const { prompt, isText, userId, userName } = await request.json();

  const identifier = request.url + "-" + (userId || "anonymous");
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

  // Always use server-side session authentication regardless of isText flag
  const user = await currentUser();
  const clerkUserId = user?.id;
  const clerkUserName = user?.firstName;

  // If isText and userId supplied, verify it matches the authenticated session user
  if (isText && userId && userId !== clerkUserId) {
    console.error(
      JSON.stringify({
        event: "auth_mismatch",
        reason: "supplied_userId_does_not_match_session",
        policyVersion: POLICY_VERSION,
        timestamp: new Date().toISOString(),
      })
    );
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

  if (!clerkUserId || !!!(await clerk.users.getUser(clerkUserId))) {
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

  // Validate and sanitize companion name from header to prevent path traversal
  const rawName = request.headers.get("name");
  const name = sanitizeCompanionName(rawName);

  if (!name) {
    console.error(
      JSON.stringify({
        event: "companion_validation_failed",
        reason: "invalid_or_empty_name",
        rawName,
        actor: clerkUserId,
        policyVersion: POLICY_VERSION,
        timestamp: new Date().toISOString(),
      })
    );
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion name." }),
      {
        status: 400,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }

  // Validate companion name against allow list
  if (!APPROVED_COMPANION_NAMES.includes(name)) {
    console.error(
      JSON.stringify({
        event: "companion_validation_failed",
        reason: "companion_not_in_allow_list",
        companionName: name,
        actor: clerkUserId,
        policyVersion: POLICY_VERSION,
        outcome: "denied",
        timestamp: new Date().toISOString(),
      })
    );
    return new NextResponse(
      JSON.stringify({ Message: "Companion not permitted." }),
      {
        status: 403,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }

  // Validate and sanitize prompt
  if (!prompt || typeof prompt !== "string" || prompt.trim().length === 0) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid prompt." }),
      {
        status: 400,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }

  if (prompt.length > MAX_PROMPT_LENGTH) {
    return new NextResponse(
      JSON.stringify({ Message: "Prompt too long." }),
      {
        status: 400,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }

  const sanitizedPrompt = sanitizeInput(sanitizeForPromptInjection(prompt));

  if (containsMaliciousPatterns(sanitizedPrompt)) {
    console.error(
      JSON.stringify({
        event: "prompt_rejected",
        reason: "malicious_pattern_detected",
        actor: clerkUserId,
        policyVersion: POLICY_VERSION,
        outcome: "denied",
        timestamp: new Date().toISOString(),
      })
    );
    return new NextResponse(
      JSON.stringify({ Message: "Prompt contains disallowed content." }),
      {
        status: 400,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }

  const companion_file_name = name + ".txt";

  // Load character "PREAMBLE" from character file. These are the core personality
  // characteristics that are used in every prompt. Additional background is
  // only included if it matches a similarity comparioson with the current
  // discussion. The PREAMBLE should include a seed conversation whose format will
  // vary by the model using it.
  const fs = require("fs").promises;
  const data = await fs.readFile("companions/" + companion_file_name, "utf8");

  // Clunky way to break out PREAMBLE and SEEDCHAT from the character file
  const presplit = data.split("###ENDPREAMBLE###");
  const preamble = presplit[0];
  const seedsplit = presplit[1].split("###ENDSEEDCHAT###");
  const seedchat = seedsplit[0];

  const companionKey = {
    companionName: name!,
    userId: clerkUserId!,
    modelName: "llama2-13b",
  };
  const memoryManager = await MemoryManager.getInstance();

  const records = await memoryManager.readLatestHistory(companionKey);
  if (records.length === 0) {
    await memoryManager.seedChatHistory(seedchat, "\n\n", companionKey);
  }
  await memoryManager.writeToHistory("User: " + sanitizedPrompt + "\n", companionKey);

  // Query Pinecone

  let recentChatHistory = await memoryManager.readLatestHistory(companionKey);

  // Right now the preamble is included in the similarity search, but that
  // shouldn't be an issue

  const similarDocs = await memoryManager.vectorSearch(
    recentChatHistory,
    companion_file_name
  );

  let relevantHistory = "";
  if (!!similarDocs && similarDocs.length !== 0) {
    relevantHistory = similarDocs.map((doc) => doc.pageContent).join("\n");
  }

  // Sanitize preamble and relevantHistory before injecting into prompt
  const sanitizedPreamble = sanitizeInput(sanitizeForPromptInjection(preamble));
  const sanitizedRelevantHistory = sanitizeInput(sanitizeForPromptInjection(relevantHistory));
  const sanitizedName = sanitizeForPromptInjection(name);

  if (containsMaliciousPatterns(sanitizedPreamble) || containsMaliciousPatterns(sanitizedRelevantHistory)) {
    console.error(
      JSON.stringify({
        event: "context_rejected",
        reason: "malicious_pattern_in_context",
        actor: clerkUserId,
        policyVersion: POLICY_VERSION,
        outcome: "denied",
        timestamp: new Date().toISOString(),
      })
    );
    return new NextResponse(
      JSON.stringify({ Message: "Context contains disallowed content." }),
      {
        status: 400,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }

  const { stream, handlers } = LangChainStream();

  // Log invocation attempt
  console.error(
    JSON.stringify({
      event: "llm_invocation",
      actor: clerkUserId,
      modelId: "gpt-3.5-turbo",
      companionName: name,
      policyVersion: POLICY_VERSION,
      outcome: "allowed",
      timestamp: new Date().toISOString(),
    })
  );

  // Call OpenAI for inference using approved model
  const model = new ChatOpenAI({
    modelName: "gpt-3.5-turbo",
    openAIApiKey: process.env.OPENAI_API_KEY,
    streaming: true,
    callbackManager: CallbackManager.fromHandlers(handlers),
  });

  // Turn verbose on for debugging
  model.verbose = true;

  const llmPrompt = `ONLY generate NO more than three sentences as ${sanitizedName}. DO NOT generate more than three sentences. 
       Make sure the output you generate starts with '${sanitizedName}:' and ends with a period.

       ${sanitizedPreamble}

       Below are relevant details about ${sanitizedName}'s past and the conversation you are in.
       ${sanitizedRelevantHistory}


       ${recentChatHistory}\n${sanitizedName}:`;

  // Log the prompt being sent to the LLM
  console.log(
    JSON.stringify({
      event: "llm_prompt_sent",
      actor: clerkUserId,
      modelId: "gpt-3.5-turbo",
      companionName: name,
      prompt: llmPrompt,
      policyVersion: POLICY_VERSION,
      timestamp: new Date().toISOString(),
    })
  );

  let resp = String(
    await model
      .call([
        {
          role: "user",
          content: llmPrompt,
        },
      ] as any)
      .catch(console.error)
  );

  // Log the response received from the LLM
  console.log(
    JSON.stringify({
      event: "llm_response_received",
      actor: clerkUserId,
      modelId: "gpt-3.5-turbo",
      companionName: name,
      response: resp,
      policyVersion: POLICY_VERSION,
      timestamp: new Date().toISOString(),
    })
  );

  // Sanitize LLM output for dangerous patterns
  resp = sanitizeLLMOutput(resp);

  // Right now just using super shoddy string manip logic to get at
  // the dialog.

  const cleaned = resp.replaceAll(",", "");
  const chunks = cleaned.split("\n");
  const response = chunks[0];

  await memoryManager.writeToHistory("" + response.trim(), companionKey);
  var Readable = require("stream").Readable;

  let s = new Readable();
  s.push(response);
  s.push(null);
  if (response !== undefined && response.length > 1) {
    memoryManager.writeToHistory("" + response.trim(), companionKey);
  }

  return new StreamingTextResponse(s);
}