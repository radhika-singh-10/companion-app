import { Anthropic } from "langchain/llms/anthropic";
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

// Sanitize inputs to prevent prompt injection, hidden prompts, and malicious commands
function sanitizeInput(input: string): string {
  if (!input || typeof input !== 'string') return '';

  // Remove invisible/zero-width characters often used to hide injected prompts
  // eslint-disable-next-line no-control-regex
  const invisibleCharsRegex = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u00AD\u200B-\u200F\u2028\u2029\u202A-\u202E\u2060-\u2064\uFEFF\uFFF9-\uFFFB]/g;
  let sanitized = input.replace(invisibleCharsRegex, '');

  // Detect and reject base64-encoded content that could hide malicious instructions
  const base64Regex = /(?:[A-Za-z0-9+\/]{40,}={0,2})/g;
  const base64Matches = sanitized.match(base64Regex);
  if (base64Matches) {
    for (const match of base64Matches) {
      try {
        const decoded = Buffer.from(match, 'base64').toString('utf8');
        // If decoded content looks like text/instructions, strip the base64 block
        if (/[a-zA-Z]{5,}/.test(decoded)) {
          sanitized = sanitized.replace(match, '[REDACTED_BASE64]');
        }
      } catch {
        // Not valid base64, leave as-is
      }
    }
  }

  // Detect shell/binary command patterns
  const shellCommandRegex = /(?:^|\s|;|&&|\|\|)(\s*(?:sudo|chmod|chown|curl|wget|bash|sh|zsh|python|python3|perl|ruby|nc|ncat|netcat|exec|eval|system|popen|subprocess|os\.system|rm\s+-rf|dd\s+if|mkfifo|\$\(|`[^`]+`|\bcat\s+\/etc|\bpasswd\b|\bshadow\b|\/bin\/|>\/dev\/|2>&1))/gi;
  if (shellCommandRegex.test(sanitized)) {
    throw new Error('Input contains potentially malicious shell commands.');
  }

  // Detect leetspeak patterns used to obfuscate prompt injection
  // e.g. "1gnor3 pr3v10us 1nstruct10ns"
  const leetspeakInjectionRegex = /(?:1gn[o0]r[e3]|[i1]nstruct[i1][o0]n|[s5]y[s5]t[e3]m\s*pr[o0]mpt|[i1]nj[e3]ct|[e3]x[e3]cut[e3]\s*c[o0]mm[a4]nd|[o0]v[e3]rr[i1]d[e3]\s*[i1]nstruct)/gi;
  if (leetspeakInjectionRegex.test(sanitized)) {
    throw new Error('Input contains obfuscated injection attempt.');
  }

  // Detect common prompt injection phrases
  const promptInjectionRegex = /(?:ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions?|disregard\s+(?:all\s+)?(?:previous|above|prior)|you\s+are\s+now\s+(?:a|an|in)\s|forget\s+(?:all\s+)?(?:previous|your)\s+instructions?|new\s+instructions?\s*:|system\s*:\s*you|<\s*system\s*>|\[\s*system\s*\]|###\s*system|act\s+as\s+(?:a|an)\s+(?:unrestricted|unfiltered|jailbreak)|do\s+anything\s+now|dan\s+mode|developer\s+mode\s+enabled)/gi;
  if (promptInjectionRegex.test(sanitized)) {
    throw new Error('Input contains prompt injection attempt.');
  }

  return sanitized;
}

export async function POST(req: Request) {
  let clerkUserId;
  let user;
  let clerkUserName;
  const { prompt: rawPrompt, isText, userId, userName } = await req.json();

  let prompt: string;
  try {
    prompt = sanitizeInput(rawPrompt);
  } catch (e) {
    console.warn('Blocked malicious user prompt:', e);
    return new NextResponse(
      JSON.stringify({ Message: 'Input contains disallowed content.' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } }
    );
  }

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

  // Sanitization helper: strips characters used in prompt-injection and enforces length.
  const sanitizeInput = (input: string, maxLength = 4000): string => {
    return input
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "") // strip non-printable control chars
      .replace(/#{3,}/g, "")                              // strip markdown-style section delimiters
      .replace(/<[^>]*>/g, "")                            // strip HTML/XML tags
      .trim()
      .slice(0, maxLength);
  };

  // XXX Companion name passed here. Can use as a key to get backstory, chat history etc.
  const rawName = req.headers.get("name");
  // Validate name: only allow alphanumeric characters, hyphens, and underscores.
  if (!rawName || !/^[a-zA-Z0-9_-]{1,64}$/.test(rawName)) {
    console.log("invalid companion name");
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

      user = await currentUser();
  clerkUserId = user?.id;
  clerkUserName = user?.firstName;,
      }
    );
  }

  // Load character "PREAMBLE" from character file. These are the core personality
  // characteristics that are used in every prompt. Additional background is
  // only included if it matches a similarity comparioson with the current
  // discussion. The PREAMBLE should include a seed conversation whose format will
  // vary by the model using it.
  const fs = require("fs").promises;
  const rawData = await fs.readFile("companions/" + companionFileName, "utf8");

  // Sanitize companion file contents to prevent prompt injection
  function sanitizeCompanionContent(content: string): string {
    // Remove invisible/hidden Unicode characters (zero-width, soft-hyphen, BOM, etc.)
    // eslint-disable-next-line no-control-regex
    let sanitized = content.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u00AD\u200B-\u200F\u2028\u2029\uFEFF\uFFFE\uFFFF]/g, "");

    // Detect and reject base64-encoded blobs (long runs of base64 chars)
    const base64Pattern = /(?:[A-Za-z0-9+\/]{40,}={0,2})/g;
    if (base64Pattern.test(sanitized)) {
      throw new Error("Companion file contains suspicious base64-encoded content.");
    }

    // Detect shell/binary command patterns
    const shellPattern = /(?:bash|sh|cmd|powershell|exec|eval|system|popen|subprocess|\$\(|`[^`]*`|\|\s*\w+|&&|\|\||;\s*\w+\s)/i;
    if (shellPattern.test(sanitized)) {
      throw new Error("Companion file contains suspicious shell or binary command content.");
    }

    // Detect common prompt injection keywords
    const injectionPattern = /(?:ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)|you\s+are\s+now|disregard\s+(all\s+)?(previous|prior)|new\s+instructions?\s*:|system\s*:\s*you|<\s*system\s*>|\[\s*system\s*\]|###\s*system|act\s+as\s+(?:an?\s+)?(?:unrestricted|jailbreak|dan\b)|do\s+anything\s+now)/i;
    if (injectionPattern.test(sanitized)) {
      throw new Error("Companion file contains suspicious prompt injection content.");
    }

    // Detect leetspeak injection attempts (e.g. 1gn0r3, 3x3cut3)
    const leetspeakInjectionPattern = /(?:[1!][Gg][Nn0][Oo0][Rr][Ee3]|[Ee3][Xx][Ee3][Cc][Uu][Tt][Ee3]|[Ss5][Yy][Ss5][Tt][Ee3][Mm]\s*[:\-])/;
    if (leetspeakInjectionPattern.test(sanitized)) {
      throw new Error("Companion file contains suspicious leetspeak injection content.");
    }

    return sanitized;
  }

  let data: string;
  try {
    data = sanitizeCompanionContent(rawData);
  } catch (err: any) {
    console.error("Companion file failed safety check:", err.message);
    return new NextResponse(
      JSON.stringify({ Message: "Companion file contains disallowed content." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  // Clunky way to break out PREAMBLE and SEEDCHAT from the character file
  const presplit = data.split("###ENDPREAMBLE###");
  let preamble: string;
  try {
    preamble = sanitizeInput(presplit[0]);
  } catch (e) {
    console.warn('Blocked malicious preamble in companion file:', e);
    return new NextResponse(
      JSON.stringify({ Message: 'Companion file contains disallowed content.' }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
  const seedsplit = presplit[1].split("###ENDSEEDCHAT###");
  const seedchat = seedsplit[0];

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
  let recentChatHistory = await memoryManager.readLatestHistory(companionKey);
  // Minimise: limit history forwarded to vector search to last 3000 chars
  const recentChatHistoryForSearch = recentChatHistory.slice(-3000);

    // Vector search removed to comply with credential policy (max 3 external systems).
  // Credentials in use: (1) OpenAI, (2) Clerk, (3) Upstash Redis.
  const similarDocs: { pageContent: string }[] = [];

  let relevantHistory = "";

  // --- Approved Model Registry (version-pinned identifiers only) ---
  const APPROVED_MODEL_REGISTRY: Record<string, { provider: string; pinnedId: string; version: string }> = {
    // Pinned snapshot ID for gpt-3.5-turbo-16k — update to a new snapshot when rotating
    "gpt-3.5-turbo-16k-0613": {
      provider: "OpenAI",
      pinnedId: "gpt-3.5-turbo-16k-0613",
      version: "0613",
    },
  };

  // Immutable, version-pinned model identifier — never use a mutable tag like "gpt-3.5-turbo-16k"
  const PINNED_MODEL_ID = "gpt-3.5-turbo-16k-0613";

  if (!APPROVED_MODEL_REGISTRY[PINNED_MODEL_ID]) {
    console.error(`Model '${PINNED_MODEL_ID}' is not in the approved model registry.`);
    return new NextResponse(
      JSON.stringify({ Message: "Model not approved" }),
      { status: 403, headers: { "Content-Type": "application/json" } }
    );
  }

  const resolvedModelMeta = APPROVED_MODEL_REGISTRY[PINNED_MODEL_ID];
  console.log("[ModelRegistry] Resolved model:", resolvedModelMeta);
  // --- End Approved Model Registry ---

  const { stream, handlers } = LangChainStream();

    const model = new OpenAI({
    streaming: true,
    modelName: resolvedModelMeta.pinnedId,   // pinned snapshot ID from approved registry
    openAIApiKey: process.env.OPENAI_API_KEY,
    callbackManager: CallbackManager.fromHandlers(handlers),
  });
  model.verbose = true;

  const replyWithTwilioLimit = isText
    ? "You reply within 1000 characters."
    : "";

  const chainPrompt = PromptTemplate.fromTemplate(`
    You are ${name} and are currently talking to a user.

    ${preamble}

  You reply with answers that range from one sentence to one paragraph and with some details. ${replyWithTwilioLimit}

  Below are relevant details about ${name}'s past
  ${relevantHistory}
  
  Below is a relevant conversation history

  ${recentChatHistory.slice(-2000)}`);

  const chain = new LLMChain({
    llm: model,
    prompt: chainPrompt,
  });

  console.log("LLM input", { relevantHistory, recentChatHistory });
  const result = await chain
    .call({
      relevantHistory,
      recentChatHistory: recentChatHistory,
    })
    .catch(console.error);

  // Record resolved model identity and version in inference metadata
  const inferenceMetadata = {
    provider: resolvedModelMeta.provider,
    resolvedModelId: resolvedModelMeta.pinnedId,
    modelVersion: resolvedModelMeta.version,
    timestamp: new Date().toISOString(),
    clerkUserId,
  };
  console.log("[InferenceMetadata]", JSON.stringify(inferenceMetadata));

  console.log("result", result);

  // Validate and sanitize LLM output before use
  function sanitizeLLMOutput(text: unknown): string {
    if (typeof text !== "string" || text.trim().length === 0) {
      throw new Error("Invalid or empty LLM output");
    }

    // Patterns for dynamic code execution primitives that must not appear in output
    const dangerousPatterns: RegExp[] = [
      /\beval\s*\(/gi,
      /\bexec\s*\(/gi,
      /\bnew\s+Function\s*\(/gi,
      /\bsetTimeout\s*\(\s*['"`]/gi,
      /\bsetInterval\s*\(\s*['"`]/gi,
      /\bsubprocess\b/gi,
      /\bchild_process\b/gi,
      /\bspawnSync\b/gi,
      /\bexecSync\b/gi,
      /\bexecFile\b/gi,
      /\bProcessBuilder\b/gi,
      /\bRuntime\.getRuntime\b/gi,
      /\b__import__\s*\(/gi,
      /\bimportlib\b/gi,
      /\bos\.system\s*\(/gi,
      /\bos\.popen\s*\(/gi,
      /<script[\s\S]*?>/gi,
      /javascript\s*:/gi,
    ];

    for (const pattern of dangerousPatterns) {
      if (pattern.test(text)) {
        console.warn("Dangerous pattern detected in LLM output; stripping match.");
        text = text.replace(pattern, "[REDACTED]");
      }
    }

    return text;
  }

  let sanitizedText: string;
  try {
    sanitizedText = sanitizeLLMOutput(result?.text);
  } catch (err) {
    console.error("LLM output validation failed:", err);
    return new NextResponse("Invalid response from model", { status: 500 });
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
