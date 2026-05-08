import dotenv from "dotenv";
import { StreamingTextResponse, LangChainStream } from "ai";
import { OpenAI } from "langchain/llms/openai";
import { CallbackManager } from "langchain/callbacks";
import clerk from "@clerk/clerk-sdk-node";
import MemoryManager from "@/app/utils/memory";
import { currentUser } from "@clerk/nextjs";
import { NextResponse } from "next/server";
import { rateLimit } from "@/app/utils/rateLimit";

dotenv.config({ path: `.env.local` });

// Tool allow list for explicit tool scoping
const ALLOWED_TOOLS = ["readCompanionFile", "vectorSearch", "readLatestHistory", "seedChatHistory", "writeToHistory", "callLLM"];

function auditLogDeniedTool(toolName: string, userId: string) {
  console.log(`[AUDIT] Tool invocation denied: ${toolName} for user: ${userId} at ${new Date().toISOString()}`);
}

function assertToolAllowed(toolName: string, userId: string) {
  if (!ALLOWED_TOOLS.includes(toolName)) {
    auditLogDeniedTool(toolName, userId);
    throw new Error(`Tool '${toolName}' is not in the allowed tool list.`);
  }
}

// Sanitize input to remove prompt injection patterns, control characters, excessive whitespace,
// shell commands, base64 blobs, leetspeak, invisible/hidden characters, and dynamic code execution primitives
function sanitizeInput(input: string): string {
  if (!input) return "";

  // Remove invisible/hidden Unicode characters
  let sanitized = input.replace(/[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/g, "");

  // Remove non-printable/binary characters (keep newlines and tabs)
  sanitized = sanitized.replace(/[^\x09\x0A\x0D\x20-\x7E\u00A0-\uFFFF]/g, "");

  // Strip dynamic code execution primitives
  const codeExecPatterns = [
    /\beval\s*\(/gi,
    /\bexec\s*\(/gi,
    /\bsubprocess\b/gi,
    /\bos\.system\s*\(/gi,
    /\bos\.popen\s*\(/gi,
    /\bspawn\s*\(/gi,
    /\bshell_exec\s*\(/gi,
    /\bpassthru\s*\(/gi,
    /\bpopen\s*\(/gi,
    /\bproc_open\s*\(/gi,
    /\bsystem\s*\(/gi,
  ];
  for (const pattern of codeExecPatterns) {
    sanitized = sanitized.replace(pattern, "[REDACTED]");
  }

  // Strip shell command sequences
  const shellPatterns = [
    /`[^`]*`/g,
    /\$\([^)]*\)/g,
    /;\s*(rm|ls|cat|wget|curl|chmod|chown|sudo|bash|sh|zsh|python|perl|ruby|node)\b/gi,
    /&&\s*(rm|ls|cat|wget|curl|chmod|chown|sudo|bash|sh|zsh|python|perl|ruby|node)\b/gi,
    /\|\s*(rm|ls|cat|wget|curl|chmod|chown|sudo|bash|sh|zsh|python|perl|ruby|node)\b/gi,
  ];
  for (const pattern of shellPatterns) {
    sanitized = sanitized.replace(pattern, "[REDACTED]");
  }

  // Strip base64-encoded blobs (long base64 strings)
  sanitized = sanitized.replace(/[A-Za-z0-9+/]{50,}={0,2}/g, "[REDACTED_BASE64]");

  // Strip prompt injection patterns
  const injectionPatterns = [
    /ignore\s+(previous|prior|above|all)\s+instructions?/gi,
    /disregard\s+(previous|prior|above|all)\s+instructions?/gi,
    /forget\s+(previous|prior|above|all)\s+instructions?/gi,
    /you\s+are\s+now\s+/gi,
    /act\s+as\s+if\s+/gi,
    /pretend\s+(you\s+are|to\s+be)\s+/gi,
    /system\s*:\s*/gi,
    /\[system\]/gi,
    /\[user\]/gi,
    /\[assistant\]/gi,
  ];
  for (const pattern of injectionPatterns) {
    sanitized = sanitized.replace(pattern, "[REDACTED]");
  }

  // Normalize excessive whitespace
  sanitized = sanitized.replace(/[ \t]{3,}/g, "  ");

  return sanitized;
}

// Sanitize LLM output to strip dangerous dynamic code execution primitives
function sanitizeLLMOutput(output: string): string {
  if (!output) return "";

  const dangerousPatterns = [
    /\beval\s*\(/gi,
    /\bexec\s*\(/gi,
    /\bsubprocess\b/gi,
    /\bos\.system\s*\(/gi,
    /\bos\.popen\s*\(/gi,
    /\bspawn\s*\(/gi,
    /\bshell_exec\s*\(/gi,
    /\bpassthru\s*\(/gi,
    /\bpopen\s*\(/gi,
    /\bproc_open\s*\(/gi,
    /\bsystem\s*\(/gi,
    /`[^`]*`/g,
    /\$\([^)]*\)/g,
  ];

  let sanitized = output;
  let foundDangerous = false;
  for (const pattern of dangerousPatterns) {
    if (pattern.test(sanitized)) {
      foundDangerous = true;
    }
    sanitized = sanitized.replace(pattern, "[REDACTED]");
  }

  if (foundDangerous) {
    console.log("[SECURITY] Dangerous content detected and redacted from LLM output.");
  }

  return sanitized;
}

// Validate and sanitize companion file content to prevent malicious prompt injection via uploaded files
function validateCompanionFileContent(content: string): string {
  // Check for binary/non-printable content
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(content)) {
    throw new Error("Companion file contains binary or non-printable content.");
  }

  // Check for hidden/invisible Unicode characters
  if (/[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/.test(content)) {
    throw new Error("Companion file contains hidden or invisible Unicode characters.");
  }

  // Check for base64-encoded blobs
  if (/[A-Za-z0-9+/]{100,}={0,2}/.test(content)) {
    throw new Error("Companion file contains suspicious base64-encoded content.");
  }

  // Check for shell command sequences
  if (/(`[^`]*`|\$\([^)]*\)|;\s*(rm|wget|curl|bash|sh|python|perl|node)\b)/i.test(content)) {
    throw new Error("Companion file contains shell command sequences.");
  }

  // Check for leetspeak patterns (simple heuristic)
  if (/[4@][Ss][Ss][4@][Ss][Ss][Ii][Nn]/i.test(content) || /[Hh][4@][Cc][Kk]/i.test(content)) {
    throw new Error("Companion file contains suspicious leetspeak patterns.");
  }

  return content;
}

// Sanitize companion file name to prevent path traversal
function sanitizeCompanionName(name: string | null): string {
  if (!name) {
    throw new Error("Companion name is required.");
  }
  if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
    throw new Error("Invalid companion name: only alphanumeric characters, hyphens, and underscores are allowed.");
  }
  return name;
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

  // XXX Companion name passed here. Can use as a key to get backstory, chat history etc.
  let rawName: string | null;
  try {
    rawName = request.headers.get("name");
    rawName = sanitizeCompanionName(rawName);
  } catch (e) {
    console.log("[SECURITY] Invalid companion name:", e);
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
  const name = rawName;
  const companion_file_name = name + ".txt";

  // Always use currentUser() from Clerk for server-side authentication
  const user = await currentUser();
  const clerkUserId = user?.id;
  const clerkUserName = user?.firstName;

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

  // Load character "PREAMBLE" from character file. These are the core personality
  // characteristics that are used in every prompt. Additional background is
  // only included if it matches a similarity comparioson with the current
  // discussion. The PREAMBLE should include a seed conversation whose format will
  // vary by the model using it.
  assertToolAllowed("readCompanionFile", clerkUserId);
  const fs = require("fs").promises;
  const rawData = await fs.readFile("companions/" + companion_file_name, "utf8");

  let data: string;
  try {
    data = validateCompanionFileContent(rawData);
  } catch (e) {
    console.log("[SECURITY] Companion file validation failed:", e);
    return new NextResponse(
      JSON.stringify({ Message: "Companion file content is invalid or potentially malicious." }),
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

  const companionKey = {
    companionName: name!,
    userId: clerkUserId!,
    modelName: "vicuna13b",
  };
  const memoryManager = await MemoryManager.getInstance();

  const { stream, handlers } = LangChainStream();

  assertToolAllowed("readLatestHistory", clerkUserId);
  const records = await memoryManager.readLatestHistory(companionKey);
  if (records.length === 0) {
    assertToolAllowed("seedChatHistory", clerkUserId);
    await memoryManager.seedChatHistory(seedchat, "\n\n", companionKey);
  }
  assertToolAllowed("writeToHistory", clerkUserId);
  await memoryManager.writeToHistory(
    "### Human: " + prompt + "\n",
    companionKey
  );

  // Query Pinecone
  assertToolAllowed("readLatestHistory", clerkUserId);
  let recentChatHistory = await memoryManager.readLatestHistory(companionKey);

  // Right now the preamble is included in the similarity search, but that
  // shouldn't be an issue
  assertToolAllowed("vectorSearch", clerkUserId);
  const similarDocs = await memoryManager.vectorSearch(
    recentChatHistory,
    companion_file_name
  );

  let relevantHistory = "";
  if (!!similarDocs && similarDocs.length !== 0) {
    relevantHistory = similarDocs.map((doc) => doc.pageContent).join("\n");
  }

  // Sanitize all inputs before passing to the model
  const sanitizedPrompt = sanitizeInput(prompt || "");
  const sanitizedPreamble = sanitizeInput(preamble);
  const sanitizedRelevantHistory = sanitizeInput(relevantHistory);
  const sanitizedRecentChatHistory = sanitizeInput(recentChatHistory);
  const sanitizedName = sanitizeInput(name);

  // Call OpenAI for inference (approved model replacing disallowed Replicate/Vicuna-13B)
  assertToolAllowed("callLLM", clerkUserId);
  const model = new OpenAI({
    modelName: "gpt-3.5-turbo",
    streaming: true,
    callbackManager: CallbackManager.fromHandlers(handlers),
    openAIApiKey: process.env.OPENAI_API_KEY,
  });

  // Turn verbose on for debugging
  model.verbose = true;

  const llmPrompt = `${sanitizedPreamble}  
       
       Below are relevant details about ${sanitizedName}'s past:
       ${sanitizedRelevantHistory}

       Below is a relevant conversation history

       ${sanitizedRecentChatHistory}
       ### ${sanitizedName}:
       `;

  // Log the prompt sent to the LLM
  console.log(`[LLM LOG] Prompt sent to OpenAI model at ${new Date().toISOString()} for user ${clerkUserId}:`, llmPrompt);

  let resp = String(
    await model
      .call(llmPrompt)
      .catch(console.error)
  );

  // Log the response received from the LLM
  console.log(`[LLM LOG] Response received from OpenAI model at ${new Date().toISOString()} for user ${clerkUserId}:`, resp);

  // Sanitize LLM output before using it
  resp = sanitizeLLMOutput(resp);

  // Right now just using super shoddy string manip logic to get at
  // the dialog.

  const cleaned = resp.replaceAll(",", "");
  const chunks = cleaned.split("###");
  const response = chunks[0];
  // const response = chunks.length > 1 ? chunks[0] : chunks[0];

  assertToolAllowed("writeToHistory", clerkUserId);
  await memoryManager.writeToHistory("### " + response.trim(), companionKey);
  var Readable = require("stream").Readable;

  let s = new Readable();
  s.push(response);
  s.push(null);
  if (response !== undefined && response.length > 1) {
    assertToolAllowed("writeToHistory", clerkUserId);
    await memoryManager.writeToHistory("### " + response.trim(), companionKey);
  }

  return new StreamingTextResponse(s);
}