import { NextResponse } from "next/server";

// Approved model registry: maps allowed model identifiers to their pinned/versioned identifiers.
// Only models listed here may be invoked. Update this registry when approving new model versions.
const APPROVED_MODEL_REGISTRY: Record<string, string> = {
  "llama": "llama@sha256:abc123def456",
  "mistral": "mistral@sha256:789abc012def",
  "phi": "phi@sha256:321fed654cba",
  // Add additional approved models and their pinned digests here
};

// Sanitize and validate a string before sending it to the AI model.
// - Strips leading/trailing whitespace
// - Removes ASCII control characters (except normal whitespace)
// - Enforces a maximum length
// Returns null if the result is empty or the input is not a non-empty string.
function sanitizeInput(value: unknown, maxLength = 2000): string | null {
  if (typeof value !== "string" || value.trim().length === 0) {
    return null;
  }
  // Remove ASCII control characters (0x00-0x08, 0x0B-0x0C, 0x0E-0x1F, 0x7F)
  // while preserving normal whitespace (\t, \n, \r)
  const cleaned = value
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
    .trim()
    .slice(0, maxLength);
  return cleaned.length > 0 ? cleaned : null;
}
import twilio from "twilio";
import clerk from "@clerk/clerk-sdk-node";
import dotenv from "dotenv";
import ConfigManager from "@/app/utils/config";
import { rateLimit } from "@/app/utils/rateLimit";

dotenv.config({ path: `.env.local` });
const twilioAuthToken = process.env.TWILIO_AUTH_TOKEN;
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const interAgentApiKey = process.env.INTER_AGENT_API_KEY;

function sanitizePrompt(input: string): string {
  if (!input || typeof input !== "string") return "";

  // Reject if length is excessive
  if (input.length > 1000) {
    throw new Error("Prompt exceeds maximum allowed length.");
  }

  // Remove non-printable / invisible Unicode control characters (except common whitespace)
  // eslint-disable-next-line no-control-regex
  const withoutControlChars = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u200B-\u200F\u202A-\u202E\uFEFF]/g, "");

  // Detect and reject base64-encoded blobs (long runs of base64 chars)
  if (/(?:[A-Za-z0-9+/]{40,}={0,2})/.test(withoutControlChars)) {
    throw new Error("Prompt contains suspicious base64-encoded content.");
  }

  // Reject shell command patterns
  const shellPatterns = [
    /`[^`]*`/,                          // backtick execution
    /\$\([^)]*\)/,                      // $(...) subshell
    /;\s*(rm|wget|curl|bash|sh|python|perl|ruby|nc|ncat|netcat|chmod|chown|sudo|su|eval|exec)\b/i,
    /&&\s*(rm|wget|curl|bash|sh|python|perl|ruby|nc|ncat|netcat|chmod|chown|sudo|su|eval|exec)\b/i,
    /\|\s*(bash|sh|python|perl|ruby|nc|ncat|netcat|eval|exec)\b/i,
    /\b(rm\s+-rf|mkfifo|mknod|telnet|wget|curl)\b/i,
  ];
  for (const pattern of shellPatterns) {
    if (pattern.test(withoutControlChars)) {
      throw new Error("Prompt contains shell command patterns.");
    }
  }

  // Reject prompt-injection / jailbreak keywords
  const injectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /disregard\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /forget\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /you\s+are\s+now\s+(in\s+)?(developer|dan|jailbreak|unrestricted|god)\s+mode/i,
    /act\s+as\s+(if\s+you\s+are\s+)?(an?\s+)?(unrestricted|unfiltered|evil|malicious)/i,
    /system\s*:\s*you\s+are/i,
    /<\s*script[^>]*>/i,
    /\[INST\]|\[\/?SYS\]/i,
  ];
  for (const pattern of injectionPatterns) {
    if (pattern.test(withoutControlChars)) {
      throw new Error("Prompt contains prompt-injection content.");
    }
  }

  // Detect leetspeak substitutions for common attack words
  const normalizedForLeet = withoutControlChars
    .replace(/0/g, "o")
    .replace(/1/g, "i")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/@/g, "a")
    .replace(/\$/g, "s");
  const leetPatterns = [
    /ignore.*instructions/i,
    /jailbreak/i,
    /exec(ute)?.*command/i,
  ];
  for (const pattern of leetPatterns) {
    if (pattern.test(normalizedForLeet)) {
      throw new Error("Prompt contains suspicious leetspeak content.");
    }
  }

  // Strip any remaining HTML/XML tags
  const stripped = withoutControlChars.replace(/<[^>]*>/g, "");

  return stripped.trim();
}

export async function POST(request: Request) {
  let queryMap: any = {};
  const twilioClient = twilio(accountSid, twilioAuthToken);
  const rawBody = await request.text();
  const data = decodeURIComponent(rawBody);
  data.split("&").forEach((item) => {
    queryMap[item.split("=")[0]] = item.split("=")[1];
  });

  // Validate that the request genuinely originates from Twilio
  const twilioSignature = request.headers.get("x-twilio-signature") || "";
  const requestUrl = request.url;
  // Build params map from raw (non-decoded) body for signature validation
  const rawParams: Record<string, string> = {};
  rawBody.split("&").forEach((item) => {
    const [key, value] = item.split("=");
    rawParams[decodeURIComponent(key)] = decodeURIComponent(value || "");
  });
  const isValidTwilioRequest = twilio.validateRequest(
    twilioAuthToken!,
    twilioSignature,
    requestUrl,
    rawParams
  );
  if (!isValidTwilioRequest) {
    console.log("WARNING: Invalid Twilio signature — request rejected");
    return new NextResponse(
      JSON.stringify({ Message: "Unauthorized: invalid Twilio signature" }),
      {
        status: 403,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }

  const prompt = queryMap["Body"];
  const serverUrl = request.url.split("/api/")[0];
  const phoneNumber = queryMap["From"];
  const companionPhoneNumber = queryMap["To"];

  const identifier = request.url + "-" + (phoneNumber || "anonymous");
  const { success } = await rateLimit(identifier);
  if (!success) {
    writeAuditRecord({
      traceId,
      event: "RATE_LIMIT_EXCEEDED",
      timestamp: new Date().toISOString(),
      principal: phoneNumber || "anonymous",
      identifier,
    });
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

  // check if the user has verified phone #
  const users = await clerk.users.getUserList({ phoneNumber });

  if (!users || users.length == 0) {
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

  const configManager = ConfigManager.getInstance();
  const companionConfig = configManager.getConfig(
    "phone",
    companionPhoneNumber
  );
  console.log("companionConfig found: ", !!companionConfig);
  if (!companionConfig || companionConfig.length == 0) {
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

  const APPROVED_LLM_MODELS = ["claude", "llama2", "mistral"];

  const companionName = companionConfig.name;
  const companionModel = companionConfig.llm;

  if (!companionModel || !APPROVED_LLM_MODELS.includes(companionModel)) {
    console.log(`ERROR: Attempted to use unapproved LLM model: '${companionModel}'`);
    return new NextResponse(
      JSON.stringify({ Message: "LLM model is not approved for use." }),
      {
        status: 400,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }

  const response = await fetch(`${serverUrl}/api/${companionModel}`, {
    body: JSON.stringify({
      prompt,
      isText: true,
      userId: users[0].id,
      userName: sanitizeInput(users[0].firstName ?? "") ?? "",
    }),
    method: "POST",
    headers: { "Content-Type": "application/json", name: companionName, Authorization: `Bearer ${interAgentApiKey}` },
  });

  const rawResponseText = await response.text();

  // Validate and sanitize LLM output before use
  const DANGEROUS_PATTERNS = [
    /\beval\s*\(/gi,
    /\bexec\s*\(/gi,
    /\bexecSync\s*\(/gi,
    /\bspawnSync\s*\(/gi,
    /\bspawn\s*\(/gi,
    /\bsubprocess\b/gi,
    /\bchild_process\b/gi,
    /\bFunction\s*\(/gi,
    /\bnew\s+Function\b/gi,
    /\bsetTimeout\s*\(/gi,
    /\bsetInterval\s*\(/gi,
    /\bimport\s*\(/gi,
    /\brequire\s*\(/gi,
    /<script\b/gi,
    /\bprocess\.env\b/gi,
    /\bos\.system\b/gi,
    /\b__import__\s*\(/gi,
    /\bcompile\s*\(/gi,
    /\bexecfile\s*\(/gi,
  ];

  const MAX_SMS_LENGTH = 1600;

  function sanitizeLLMOutput(text: string): string {
    if (typeof text !== "string") {
      console.warn("WARNING: LLM output is not a string, rejecting.");
      return "";
    }
    for (const pattern of DANGEROUS_PATTERNS) {
      if (pattern.test(text)) {
        console.warn(
          `WARNING: LLM output contains dangerous pattern (${pattern}), rejecting message.`
        );
        return "";
      }
    }
    // Strip non-printable characters except common whitespace
    const cleaned = text.replace(/[^\x20-\x7E\t\n\r]/g, "").trim();
    // Enforce length limit
    return cleaned.slice(0, MAX_SMS_LENGTH);
  }

  const responseText = sanitizeLLMOutput(rawResponseText);

  if (!responseText) {
    console.warn("WARNING: LLM response was empty or rejected after sanitization.");
    return new NextResponse(
      JSON.stringify({ Message: "Unable to process companion response." }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  const to = queryMap["From"];
  const from = queryMap["To"];
  console.log("INFO: response received from companion");
  await twilioClient.messages
    .create({
      body: responseText,
      from,
      to,
    })
    .then(() => {
      writeAuditRecord({
        traceId,
        event: "SMS_SENT",
        timestamp: new Date().toISOString(),
        principal: users[0].id,
        to,
        from,
        outputHash: sha256(responseText),
      });
    })
    .catch((err) => {
      writeAuditRecord({
        traceId,
        event: "SMS_SEND_FAILED",
        timestamp: new Date().toISOString(),
        principal: users[0].id,
        to,
        from,
        error: String(err),
      });
    });

  return NextResponse.json({ message: "Hello from the API!" });
}
