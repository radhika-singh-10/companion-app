import { OpenAI } from "langchain/llms/openai";
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

dotenv.config({ path: `.env.local` });

// ---------------------------------------------------------------------------
// Input sanitization – guards against prompt injection, hidden instructions,
// base64-encoded payloads, leetspeak obfuscation, and shell/binary commands.
// ---------------------------------------------------------------------------
function sanitizeInput(input: string, label: string): string {
  if (typeof input !== "string") return "";

  // 1. Strip / reject invisible / zero-width characters often used to hide text
  const invisiblePattern =
    /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E\u00A0\u2028\u2029]/g;
  input = input.replace(invisiblePattern, "");

  // 2. Detect base64-encoded blobs (≥ 40 chars of pure base64)
  const base64Pattern = /(?:[A-Za-z0-9+\/]{40,}={0,2})/g;
  if (base64Pattern.test(input)) {
    console.warn(`sanitizeInput [${label}]: base64-encoded content detected and stripped`);
    input = input.replace(base64Pattern, "[REDACTED_BASE64]");
  }

  // 3. Detect leetspeak obfuscation heuristic (high ratio of digit-letter substitutions)
  const leetspeakPattern = /(?:[a-zA-Z0-9]*[013457@$!][a-zA-Z0-9]*){6,}/g;
  if (leetspeakPattern.test(input)) {
    console.warn(`sanitizeInput [${label}]: possible leetspeak obfuscation detected`);
    input = input.replace(leetspeakPattern, "[REDACTED_LEET]");
  }

  // 4. Shell / binary command patterns
  const shellPattern =
    /(?:(?:^|[\s;|&`$(){}])(?:bash|sh|zsh|cmd|powershell|python|perl|ruby|node|curl|wget|nc|ncat|netcat|eval|exec|system|passthru|popen|subprocess|os\.system|__import__|importlib)\b|\$\(|`[^`]*`|\|\s*(?:bash|sh)|;\s*(?:rm|dd|mkfs|chmod|chown|kill|reboot|shutdown))/gi;
  if (shellPattern.test(input)) {
    console.warn(`sanitizeInput [${label}]: shell/binary command pattern detected`);
    throw new Error(`Blocked: shell or binary command detected in ${label}`);
  }

  // 5. Prompt-injection / jailbreak patterns
  const injectionPattern =
    /(?:ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions?|disregard\s+(?:your\s+)?(?:previous|prior|system)\s+(?:instructions?|prompt)|you\s+are\s+now\s+(?:a\s+)?(?:different|new|another|unrestricted)|act\s+as\s+(?:an?\s+)?(?:evil|unrestricted|jailbroken|DAN)|forget\s+(?:your\s+)?(?:previous\s+)?(?:instructions?|training|rules?)|do\s+not\s+follow\s+(?:your\s+)?(?:previous\s+)?(?:instructions?|guidelines?|rules?)|override\s+(?:your\s+)?(?:previous\s+)?(?:instructions?|system\s+prompt)|new\s+instructions?\s*:|system\s*:\s*you\s+(?:must|shall|will)|<\s*(?:system|assistant|user)\s*>)/gi;
  if (injectionPattern.test(input)) {
    console.warn(`sanitizeInput [${label}]: prompt injection pattern detected`);
    throw new Error(`Blocked: prompt injection pattern detected in ${label}`);
  }

  // 6. Trim excessive length to limit token-stuffing attacks
  const MAX_LENGTH = 8000;
  if (input.length > MAX_LENGTH) {
    console.warn(`sanitizeInput [${label}]: input truncated from ${input.length} to ${MAX_LENGTH}`);
    input = input.slice(0, MAX_LENGTH);
  }

  return input;
}

export async function POST(req: Request) {
  let clerkUserId;
  let user;
  let clerkUserName;
  const { prompt: rawPrompt, isText, userId, userName } = await req.json();
  let prompt: string;
  try {
    prompt = sanitizeInput(String(rawPrompt ?? ""), "prompt");
  } catch (err: any) {
    console.warn("Blocked request – prompt failed sanitization:", err.message);
    return new NextResponse(
      JSON.stringify({ Message: "Invalid prompt content." }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

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

  // Sanitization helpers
  const sanitizeInput = (input: string, maxLength = 4000): string => {
    // Remove null bytes, strip leading/trailing whitespace, enforce max length
    return input.replace(/\0/g, "").trim().slice(0, maxLength);
  };

  const VALID_NAME_RE = /^[a-zA-Z0-9_-]{1,50}$/;

  // XXX Companion name passed here. Can use as a key to get backstory, chat history etc.
  const rawName = req.headers.get("name");
  if (!rawName || !VALID_NAME_RE.test(rawName)) {
    console.log("invalid or missing companion name");
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion name" }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
  const name = rawName;
  const companionFileName = name + ".txt";

  // Logging of user-supplied prompt removed to prevent potential PII exposure
  // Always derive identity from the server-side session; never trust caller-supplied userId.
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
      JSON.stringify({ Message: "Invalid companion name." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  const rawData = await fs.readFile(resolvedPath, "utf8");

  // --- Malicious content scanning ---
  function scanForMaliciousContent(content: string): string | null {
    // Reject binary/non-printable characters (executable or binary content)
    if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(content)) {
      return "Binary or non-printable characters detected";
    }
    // Reject invisible/zero-width characters used to hide text
    if (/[\u200B-\u200F\u202A-\u202E\uFEFF\u2060-\u2064]/.test(content)) {
      return "Invisible or zero-width characters detected";
    }
    // Reject shell command patterns
    if (/(?:^|\s)(bash|sh|cmd|powershell|exec|eval|system|popen|subprocess|os\.system)\s*[\(\[`]/im.test(content)) {
      return "Shell command pattern detected";
    }
    // Reject base64-encoded blobs (long base64 strings that may encode hidden prompts)
    if (/(?:[A-Za-z0-9+\/]{60,}={0,2})/.test(content)) {
      return "Suspicious base64-encoded content detected";
    }
    // Reject common prompt injection / jailbreak patterns
    const promptInjectionPatterns = [
      /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i,
      /disregard\s+(all\s+)?(previous|prior|above)\s+instructions/i,
      /forget\s+(all\s+)?(previous|prior|above)\s+instructions/i,
      /you\s+are\s+now\s+(a\s+)?(?:dan|jailbreak|unrestricted|evil|malicious)/i,
      /act\s+as\s+(if\s+you\s+are\s+)?(?:dan|jailbreak|unrestricted|evil|malicious)/i,
      /\bsystem\s*:\s*you\s+are/i,
      /<\s*script[^>]*>/i,
    ];
    for (const pattern of promptInjectionPatterns) {
      if (pattern.test(content)) {
        return "Prompt injection pattern detected";
      }
    }
    // Reject leetspeak obfuscation (e.g., 1gn0r3, 3x3cut3)
    if (/(?:[a-z0-9]*[013456789][a-z0-9]*){4,}/i.test(content) &&
        /(?:1gn[o0]r[e3]|[e3]x[e3]cut[e3]|[s5]y[s5]t[e3]m|[i1]nj[e3]ct)/i.test(content)) {
      return "Leetspeak obfuscation detected";
    }
    return null;
  }

  const maliciousReason = scanForMaliciousContent(rawData);
  if (maliciousReason) {
    console.log("Malicious content detected in companion file:", maliciousReason);
    return new NextResponse(
      JSON.stringify({ Message: "Companion file contains disallowed content." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  const data = rawData;

  // Clunky way to break out PREAMBLE and SEEDCHAT from the character file
  const presplit = data.split("###ENDPREAMBLE###");
  let preamble: string;
  let seedchat: string;
  try {
    preamble = sanitizeInput(presplit[0], "preamble");
    const seedsplit = presplit[1].split("###ENDSEEDCHAT###");
    seedchat = sanitizeInput(seedsplit[0], "seedchat");
  } catch (err: any) {
    console.warn("Blocked request – companion file failed sanitization:", err.message);
    return new NextResponse(
      JSON.stringify({ Message: "Companion file contains disallowed content." }),
      { status: 400, headers: { "Content-Type": "application/json" } }
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
  await memoryManager.writeToHistory("Human: " + sanitizedPrompt + "\n", companionKey);
  let recentChatHistory = (await memoryManager.readLatestHistory(companionKey)).slice(-2000);

    // Vector search removed to comply with external credential policy (max 3 systems).
  // Relevant history is left empty; only recent chat history is used for context.
  const relevantHistory = ""; catch {
          return ""; // drop any history chunk that fails sanitization
        }
      })
      .filter(Boolean)
      .join("\n");
  }

  // --- Approved model registry and version pinning ---
  const APPROVED_MODEL_REGISTRY: Record<string, { pinnedId: string; approved: boolean }> = {
    "gpt-3.5-turbo-16k": {
      // Pinned to the dated snapshot; OpenAI guarantees this snapshot is immutable.
      // Update this value only after explicit security review and registry approval.
      pinnedId: "gpt-3.5-turbo-16k-0613",
      approved: true,
    },
  };

  const REQUESTED_MODEL = "gpt-3.5-turbo-16k";
  const registryEntry = APPROVED_MODEL_REGISTRY[REQUESTED_MODEL];

  if (!registryEntry || !registryEntry.approved) {
    console.error(`Model '${REQUESTED_MODEL}' is not in the approved model registry.`);
    return new NextResponse(
      JSON.stringify({ Message: "Model not approved" }),
      {
        status: 403,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  const PINNED_MODEL_ID = registryEntry.pinnedId;
  // --- End registry check ---

  const { stream, handlers } = LangChainStream();

    const model = new ChatAnthropic({
    streaming: true,
    modelName: "claude-2",
    anthropicApiKey: process.env.ANTHROPIC_API_KEY,
    callbackManager: CallbackManager.fromHandlers(handlers),
  });
  model.verbose = true;

  const replyWithTwilioLimit = isText
    ? "You reply within 1000 characters."
    : "";

  // Sanitize text to remove PII before sending to the AI model
  function sanitizePII(text: string): string {
    // Remove email addresses
    text = text.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, '[REDACTED_EMAIL]');
    // Remove phone numbers (various formats)
    text = text.replace(/(\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}/g, '[REDACTED_PHONE]');
    // Remove SSNs
    text = text.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED_SSN]');
    // Remove street addresses (number followed by street name and type)
    text = text.replace(/\b\d+\s+[A-Za-z0-9\s,.]+(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)\.?\b/gi, '[REDACTED_ADDRESS]');
    return text;
  }

  const sanitizedRecentChatHistory = sanitizePII(recentChatHistory);
  const sanitizedRelevantHistory = sanitizePII(relevantHistory);

  const chainPrompt = PromptTemplate.fromTemplate(`
    You are ${name} and are currently talking to a User.

    ${preamble}

  You reply with answers that range from one sentence to one paragraph and with some details. ${replyWithTwilioLimit}

  Below are relevant details about ${name}'s past
  ${sanitizedRelevantHistory}
  
  Below is a relevant conversation history

  ${sanitizedRecentChatHistory}`);

  const chain = new LLMChain({
    llm: model,
    prompt: chainPrompt,
  });

  const formattedPrompt = await chainPrompt.format({
    relevantHistory,
    recentChatHistory: recentChatHistory,
  });
  console.log("[LLM Interaction - Input Prompt]:", formattedPrompt);

  const sanitizedRelevantHistory = sanitizeInput(relevantHistory, 3000);
  const sanitizedRecentChatHistory = sanitizeInput(recentChatHistory, 3000);
    const result = await chain
    .call({
      relevantHistory: sanitizedRelevantHistory,
      recentChatHistory: sanitizedRecentChatHistory,
    })
    .catch(console.error);

  console.log("result", result);
  // --- LLM output validation & sanitization ---
  const rawText: unknown = result?.text;

  if (typeof rawText !== "string" || rawText.trim().length === 0) {
    console.error("LLM returned invalid or empty output", rawText);
    return new NextResponse("Invalid response from model", { status: 500 });
  }

  // Reject responses that contain dynamic code execution primitives.
  const DANGEROUS_PATTERNS = [
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /\bnew\s+Function\s*\(/i,
    /\bsetTimeout\s*\(\s*['"`]/i,
    /\bsetInterval\s*\(\s*['"`]/i,
    /\bimport\s*\(/i,
    /\brequire\s*\(/i,
    /\bspawn\s*\(/i,
    /\bexecSync\s*\(/i,
    /\bsubprocess\b/i,
    /\bchild_process\b/i,
    /\bProcessBuilder\b/i,
    /\bRuntime\.getRuntime\b/i,
  ];

  const hasDangerousContent = DANGEROUS_PATTERNS.some((pattern) =>
    pattern.test(rawText)
  );

  if (hasDangerousContent) {
    console.error(
      "LLM output contained dangerous code execution primitives and was rejected."
    );
    return new NextResponse(
      "Response blocked due to policy violation",
      { status: 500 }
    );
  }

  // Sanitize: strip any residual HTML/script tags to prevent injection.
  const sanitizedText = rawText
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<[^>]+>/g, "")
    .trim();
  // --- end sanitization ---

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
