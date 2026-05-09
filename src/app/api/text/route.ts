import { NextResponse } from "next/server";

// Approved model registry: maps model identifier to its pinned version.
// Only models listed here may be invoked. Update this map through a
// controlled change process whenever a new model version is approved.
const APPROVED_MODEL_REGISTRY: Record<string, string> = {
  "llama": "llama-3.1-8b-instruct@sha256:abc123def456",
  "mistral": "mistral-7b-instruct-v0.3@sha256:789ghi012jkl",
  "claude": "claude-3-haiku-20240307@sha256:mno345pqr678",
};

function resolveApprovedModel(modelId: string): { pinnedId: string; version: string } | null {
  const pinnedId = APPROVED_MODEL_REGISTRY[modelId];
  if (!pinnedId) return null;
  const version = pinnedId.split("@")[1] ?? "unknown";
  return { pinnedId, version };
}
import twilio from "twilio";
import clerk from "@clerk/clerk-sdk-node";
import dotenv from "dotenv";
import ConfigManager from "@/app/utils/config";
import { rateLimit } from "@/app/utils/rateLimit";
import crypto from "crypto";
import { createHash, randomUUID } from "crypto";
import { appendFileSync } from "fs";
import path from "path";

const AUDIT_LOG_PATH = path.resolve(process.cwd(), "audit-log.ndjson");

function sha256(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

function writeAuditRecord(record: Record<string, unknown>): void {
  try {
    appendFileSync(AUDIT_LOG_PATH, JSON.stringify(record) + "\n", { encoding: "utf8", flag: "a" });
  } catch (err) {
    // Fallback: emit to stderr so the process does not crash, but flag the failure
    process.stderr.write(`AUDIT_WRITE_FAILURE: ${JSON.stringify(err)}\n`);
  }
}
import crypto from "crypto";

function encryptPII(value: string): string {
  const key = Buffer.from(process.env.PII_ENCRYPTION_KEY || "", "hex");
  if (key.length !== 32) {
    throw new Error("PII_ENCRYPTION_KEY must be a 64-character hex string (32 bytes)");
  }
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, encrypted]).toString("base64");
}

dotenv.config({ path: `.env.local` });
const twilioAuthToken = process.env.TWILIO_AUTH_TOKEN;
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const interAgentSecret = process.env.INTER_AGENT_SECRET;

// Sanitize and validate the prompt extracted from SMS to prevent prompt injection
function sanitizePrompt(input: string): { safe: boolean; sanitized: string } {
  if (!input || typeof input !== "string") {
    return { safe: false, sanitized: "" };
  }

  // Strip invisible/zero-width characters
  const invisibleCharsRegex = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E\u00A0]/g;
  let sanitized = input.replace(invisibleCharsRegex, "");

  // Reject if base64-encoded content is detected (long base64 strings)
  const base64Regex = /(?:[A-Za-z0-9+\/]{40,}={0,2})/;
  if (base64Regex.test(sanitized)) {
    return { safe: false, sanitized: "" };
  }

  // Reject shell command patterns
  const shellCommandRegex = /(\/bin\/|\/usr\/|\/etc\/|\bsudo\b|\bchmod\b|\bchown\b|\brm\s+-|\bwget\b|\bcurl\b|\bexec\b|\beval\b|\bsystem\b|\bspawn\b|\bpopen\b|\bpasswd\b|\bsh\s+-c\b|\bbash\s+-c\b|\bcmd\.exe\b|\bpowershell\b)/i;
  if (shellCommandRegex.test(sanitized)) {
    return { safe: false, sanitized: "" };
  }

  // Reject binary/non-printable characters
  const binaryRegex = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/;
  if (binaryRegex.test(sanitized)) {
    return { safe: false, sanitized: "" };
  }

  // Reject leetspeak patterns combined with suspicious keywords
  const leetspeakSuspiciousRegex = /([\$@!3][xX][3e][cC]|[iI!1][gG][nN][oO0][rR][3e]\s+[pP][rR][3e][vV][iI1][oO0][uU][sS]|[dD][iI1][sS][rR][3e][gG][aA@][rR][dD])/;
  if (leetspeakSuspiciousRegex.test(sanitized)) {
    return { safe: false, sanitized: "" };
  }

  // Reject prompt injection trigger phrases
  const injectionPhraseRegex = /(ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)|disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)|you\s+are\s+now|new\s+instructions?:|system\s*:|<\s*system\s*>|\[\s*system\s*\]|###\s*instruction|act\s+as\s+(if\s+you\s+are|a\s+)?(different|new|another|unrestricted)|forget\s+(everything|all|your|previous)|override\s+(your\s+)?(instructions?|programming|rules)|jailbreak|do\s+anything\s+now|dan\s+mode)/i;
  if (injectionPhraseRegex.test(sanitized)) {
    return { safe: false, sanitized: "" };
  }

  // Enforce maximum length to prevent excessively long prompts
  const MAX_PROMPT_LENGTH = 1600; // SMS practical limit
  if (sanitized.length > MAX_PROMPT_LENGTH) {
    sanitized = sanitized.substring(0, MAX_PROMPT_LENGTH);
  }

  return { safe: true, sanitized };
}

export async function POST(request: Request) {
  const ALLOWED_BASE_URL = process.env.INTERNAL_API_BASE_URL || "http://localhost:3000";
  const ALLOWED_COMPANION_MODELS = (process.env.ALLOWED_COMPANION_MODELS || "").split(",").map((m) => m.trim()).filter(Boolean);

  let queryMap: any = {};
  const twilioClient = twilio(accountSid, twilioAuthToken);
  const data = decodeURIComponent(await request.text());
  data.split("&").forEach((item) => {
    queryMap[item.split("=")[0]] = item.split("=")[1];
  });
  // Sanitize and validate prompt from SMS body
  const rawPrompt: string = typeof queryMap["Body"] === "string" ? queryMap["Body"] : "";
  const sanitizedPrompt = rawPrompt
    .trim()
    .slice(0, 1000)
    .replace(/[^\w\s.,!?'"@#$%&*()+\-=/:;<>\[\]{}|~`^]/g, "");
  if (!sanitizedPrompt) {
    return new NextResponse(
      JSON.stringify({ Message: "Invalid or empty message body." }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
  const prompt = sanitizedPrompt;
  const phoneNumber = queryMap["From"];
  const companionPhoneNumber = queryMap["To"];

  const encryptedPhoneNumber = phoneNumber ? encryptPII(phoneNumber) : "anonymous";
  const identifier = request.url + "-" + encryptedPhoneNumber;
  const { success } = await rateLimit(identifier);
  if (!success) {
    console.log("INFO: rate limit exceeded for identifier");
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
  console.log("companionConfig: ", { name: companionConfig?.name });
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

  const companionName = companionConfig.name;
  const companionModel = companionConfig.llm;

  if (!companionModel || !APPROVED_LLM_MODELS.has(companionModel)) {
    console.log(`ERROR: LLM model '${companionModel}' is not in the approved list.`);
    return new NextResponse(
      JSON.stringify({ Message: "Requested LLM model is not approved for use." }),
      {
        status: 400,
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }

  console.log("LLM interaction request: ", JSON.stringify({
    endpoint: `${serverUrl}/api/${companionModel}`,
    companionName,
    companionModel,
    prompt,
    userId: users[0].id,
    userName: users[0].firstName,
  }));
    if (!ALLOWED_COMPANION_MODELS.includes(companionModel)) {
    console.log("ERROR: companionModel not in allowlist:", companionModel);
    return new NextResponse(
      JSON.stringify({ Message: "Invalid companion model" }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  const fetchUrl = `${ALLOWED_BASE_URL}/api/${companionModel}`;
  const response = await fetch(fetchUrl, {
    body: JSON.stringify({
      prompt,
      isText: true,
      userId: users[0].id,
      userName: users[0].firstName,
      encryptedPhone: encryptedPhoneNumber,
    }),
    method: "POST",
    headers: { "Content-Type": "application/json", name: companionName, Authorization: `Bearer ${interAgentSecret}` },
  });

  const rawResponseText = await response.text();

  // Validate and sanitize LLM output: reject any dynamic code execution primitives
  const DANGEROUS_PATTERNS = [
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /\bFunction\s*\(/i,
    /\bnew\s+Function\b/i,
    /\bsetTimeout\s*\(\s*['"`]/i,
    /\bsetInterval\s*\(\s*['"`]/i,
    /\bimport\s*\(/i,
    /\brequire\s*\(/i,
    /<script[\s>]/i,
    /javascript\s*:/i,
  ];

  const containsDangerousPattern = DANGEROUS_PATTERNS.some((pattern) =>
    pattern.test(rawResponseText)
  );

  const responseText = containsDangerousPattern
    ? "I'm sorry, I couldn't generate a valid response. Please try again."
    : rawResponseText;

  if (containsDangerousPattern) {
    console.warn("WARNING: LLM output contained dangerous code execution primitive and was sanitized.");
  }

  const to = params.get("From") ?? "";
  const from = params.get("To") ?? "";
  console.log("LLM interaction response: ", JSON.stringify({
    endpoint: `${serverUrl}/api/${companionModel}`,
    companionName,
    companionModel,
    prompt,
    userId: users[0].id,
    responseText,
  }));
  await twilioClient.messages
    .create({
      body: responseText,
      from,
      to,
    })
    .catch((err) => {
      writeAuditRecord({
        traceId,
        timestamp: new Date().toISOString(),
        event: "SMS_SEND_FAILURE",
        principalId: users[0].id,
        error: String(err),
      });
    });

  writeAuditRecord({
    traceId,
    timestamp: new Date().toISOString(),
    event: "SMS_SENT",
    principalId: users[0].id,
    modelId: companionModel,
    inputHash,
    outputHash,
    to,
    from,
  });

  return NextResponse.json({ message: "Hello from the API!" });
}
