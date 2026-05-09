import dotenv from "dotenv";
import clerk from "@clerk/clerk-sdk-node";
import { NextResponse } from "next/server";
import { currentUser } from "@clerk/nextjs";
import { rateLimit } from "@/app/utils/rateLimit";
import {Md5} from 'ts-md5'
import ConfigManager from "@/app/utils/config";

// ── Tool Allow List Policy ────────────────────────────────────────────────────
const POLICY_VERSION = "tool-allowlist-v1";

/**
 * Explicit allow list of tool names the agent is permitted to invoke.
 * Any tool not present here is denied and the request is rejected.
 */
const ALLOWED_TOOLS: ReadonlySet<string> = new Set([
  "search",
  "calculator",
  "weather",
  // Add additional approved tool names here.
]);

/**
 * Patterns that indicate a prompt is attempting to invoke a tool.
 * Adjust these regexes to match your agent's tool-call syntax.
 */
const TOOL_INVOCATION_PATTERN = /\btool\s*[:=]\s*["']?([\w-]+)["']?/gi;

interface AuditEntry {
  timestamp: string;
  policyVersion: string;
  actorId: string;
  actorName: string | null | undefined;
  companionName: string;
  tool: string;
  allowed: boolean;
  reason: string;
}

function auditLog(entry: AuditEntry): void {
  // Write to stdout so the entry is captured by any log aggregation pipeline.
  console.log(JSON.stringify({ audit: true, ...entry }));
}

/**
 * Scans the prompt for tool invocation attempts and enforces the allow list.
 * Returns { allowed: true } when the prompt is clean, or
 * { allowed: false, tool, reason } for the first denied tool found.
 */
function enforceToolAllowList(
  prompt: string,
  actorId: string,
  actorName: string | null | undefined,
  companionName: string
): { allowed: true } | { allowed: false; tool: string; reason: string } {
  let match: RegExpExecArray | null;
  // Reset lastIndex before iterating
  TOOL_INVOCATION_PATTERN.lastIndex = 0;
  while ((match = TOOL_INVOCATION_PATTERN.exec(prompt)) !== null) {
    const toolName = match[1].toLowerCase();
    const isAllowed = ALLOWED_TOOLS.has(toolName);
    const reason = isAllowed
      ? "tool is on the allow list"
      : `tool '${toolName}' is not on the allow list`;
    auditLog({
      timestamp: new Date().toISOString(),
      policyVersion: POLICY_VERSION,
      actorId,
      actorName,
      companionName,
      tool: toolName,
      allowed: isAllowed,
      reason,
    });
    if (!isAllowed) {
      return { allowed: false, tool: toolName, reason };
    }
  }
  return { allowed: true };
}

// Simple in-memory rate limiter to avoid holding Upstash Redis credentials
const rateLimitMap = new Map<string, { count: number; ts: number }>();
function localRateLimit(identifier: string, limit = 10, windowMs = 60000): boolean {
  const now = Date.now();
  const entry = rateLimitMap.get(identifier);
  if (!entry || now - entry.ts > windowMs) {
    rateLimitMap.set(identifier, { count: 1, ts: now });
    return true;
  }
  if (entry.count >= limit) return false;
  entry.count++;
  return true;
}
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { createHmac } from "crypto";

dotenv.config({ path: `.env.local` });

// Approved model registry: only these base URLs are permitted as agent endpoints.
// Add or update entries here as new approved model versions are onboarded.
const APPROVED_AGENT_URLS: string[] = (
  process.env.APPROVED_AGENT_URLS ||
  "https://api.steamship.com/api/v1/package/instance/"
)
  .split(",")
  .map((u) => u.trim())
  .filter(Boolean);

// Required pinned model version identifier (e.g. a semver, commit hash, or digest).
// Set MODEL_VERSION in your environment (e.g. MODEL_VERSION=v1.2.3-abc1234).
const MODEL_VERSION = process.env.MODEL_VERSION;

// Allowlist of permitted hostnames for outbound agent fetches.
// Add or adjust entries to match your deployed Steamship agent endpoints.
const ALLOWED_AGENT_HOSTS: string[] = [
  "api.steamship.com",
];

function isAllowedAgentUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") {
      return false;
    }
    return ALLOWED_AGENT_HOSTS.some(
      (host) => parsed.hostname === host || parsed.hostname.endsWith("." + host)
    );
  } catch {
    return false;
  }
}

/**
 * Sanitizes and validates a prompt to prevent prompt injection attacks.
 * Throws an error if the prompt contains suspicious content.
 */
function sanitizePrompt(input: string): string {
  if (!input || typeof input !== 'string') {
    throw new Error('Invalid prompt: must be a non-empty string.');
  }

  // Reject prompts that are too long
  const MAX_PROMPT_LENGTH = 2000;
  if (input.length > MAX_PROMPT_LENGTH) {
    throw new Error(`Invalid prompt: exceeds maximum length of ${MAX_PROMPT_LENGTH} characters.`);
  }

  // Remove invisible/zero-width characters (hidden prompt injection)
  const invisibleCharsRegex = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E\u00A0]/g;
  const cleaned = input.replace(invisibleCharsRegex, '');

  // Detect base64-encoded content (long base64 strings are suspicious)
  const base64Regex = /(?:[A-Za-z0-9+\/]{40,}={0,2})/;
  if (base64Regex.test(cleaned)) {
    throw new Error('Invalid prompt: contains potentially encoded content.');
  }

  // Detect shell command patterns
  const shellCommandRegex = /(?:^|\s|;|&&|\|\|)(\s*)(rm\s+-|chmod\s+|chown\s+|wget\s+|curl\s+|bash\s+|sh\s+|exec\s+|eval\s+|system\s*\(|subprocess|os\.system|__import__|powershell|cmd\.exe|\/bin\/sh|\/bin\/bash)/i;
  if (shellCommandRegex.test(cleaned)) {
    throw new Error('Invalid prompt: contains shell command patterns.');
  }

  // Detect binary/executable content (non-printable ASCII bytes)
  const binaryRegex = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/;
  if (binaryRegex.test(cleaned)) {
    throw new Error('Invalid prompt: contains binary or non-printable characters.');
  }

  // Detect leetspeak combined with suspicious keywords (e.g., 1gn0r3, 3x3cut3)
  const leetspeakSuspiciousRegex = /(?:1gn[o0]r[e3]|[e3]x[e3]cut[e3]|[i1]nj[e3]ct|[s5]y[s5]t[e3]m|[e3]v[a4]l|[p9]r[o0]mpt)/i;
  if (leetspeakSuspiciousRegex.test(cleaned)) {
    throw new Error('Invalid prompt: contains suspicious leetspeak patterns.');
  }

  // Detect prompt injection instruction patterns
  const injectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i,
    /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i,
    /forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i,
    /you\s+are\s+now\s+(a\s+)?(?!assistant|helpful)/i,
    /act\s+as\s+(if\s+you\s+are\s+)?(?:an?\s+)?(?:evil|malicious|unrestricted|jailbroken|DAN)/i,
    /\bDAN\b/,
    /do\s+anything\s+now/i,
    /override\s+(your\s+)?(safety|guidelines|instructions|rules)/i,
    /bypass\s+(your\s+)?(safety|guidelines|instructions|rules|filters)/i,
    /<\s*script[^>]*>/i,
    /<!--[\s\S]*?-->/,
  ];

  for (const pattern of injectionPatterns) {
    if (pattern.test(cleaned)) {
      throw new Error('Invalid prompt: contains prompt injection patterns.');
    }
  }

  return cleaned.trim();
}

const DANGEROUS_PATTERNS = [
  /\beval\s*\(/i,
  /\bexec\s*\(/i,
  /\bsubprocess\b/i,
  /\bnew\s+Function\s*\(/i,
  /\bsetTimeout\s*\(\s*['"`]/i,
  /\bsetInterval\s*\(\s*['"`]/i,
  /\bexecSync\s*\(/i,
  /\bspawnSync\s*\(/i,
  /\bspawn\s*\(/i,
  /\bexecFile\s*\(/i,
  /\b__import__\s*\(/i,
  /\bimportlib\b/i,
  /\bos\.system\s*\(/i,
  /\bos\.popen\s*\(/i,
];

function containsDangerousContent(value: unknown): boolean {
  if (typeof value === "string") {
    return DANGEROUS_PATTERNS.some((pattern) => pattern.test(value));
  }
  if (Array.isArray(value)) {
    return value.some((item) => containsDangerousContent(item));
  }
  if (value !== null && typeof value === "object") {
    return Object.values(value as Record<string, unknown>).some((v) =>
      containsDangerousContent(v)
    );
  }
  return false;
}

function returnError(code: number, message: string) {
  return new NextResponse(
      JSON.stringify({ Message: message }),
      {
        status: code,
        headers: {
          "Content-Type": "application/json",
        },
      }
  );
}

export async function POST(req: Request) {
  let clerkUserId;
  let user;
  let clerkUserName;
  const { prompt: rawPrompt, isText, userId, userName } = await req.json();
  const rawCompanionName = req.headers.get("name");

  // Validate and sanitize companionName: must be a non-empty alphanumeric/dash/underscore/space string
  if (!rawCompanionName || typeof rawCompanionName !== "string") {
    return returnError(400, `Hi, please add a valid 'name' field in your headers specifying the Companion Name.`);
  }
  const companionNameSanitized = rawCompanionName.trim().replace(/[^a-zA-Z0-9\-_ ]/g, "");
  if (!companionNameSanitized || companionNameSanitized.length === 0 || companionNameSanitized.length > 100) {
    return returnError(400, `Hi, the companion name provided is invalid.`);
  }
  const companionName = companionNameSanitized;

  // Validate and sanitize prompt: must be a non-empty string within length limits
  if (!rawPrompt || typeof rawPrompt !== "string") {
    return returnError(400, `Hi, please provide a valid prompt.`);
  }
  const promptTrimmed = rawPrompt.trim();
  if (promptTrimmed.length === 0) {
    return returnError(400, `Hi, the prompt cannot be empty.`);
  }
  if (promptTrimmed.length > 4000) {
    return returnError(400, `Hi, the prompt is too long. Please keep it under 4000 characters.`);
  }
  // Remove null bytes and non-printable control characters (except common whitespace)
  const prompt = promptTrimmed.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

  // companionName has already been validated and sanitized above

  // Load the companion config
  const configManager = ConfigManager.getInstance();
  const companionConfig = configManager.getConfig("name", companionName);
  if (!companionConfig) {
    return returnError(404, `Hi, we were unable to find the configuration for a companion named ${companionName}.`)
  }

    user = await currentUser();
  clerkUserId = user?.id;
  clerkUserName = user?.firstName;

    // Make sure we're not rate limited
  const identifier = req.url + "-" + req.headers.get("x-forwarded-for") || "unknown";
  const { success } = await rateLimit(identifier);
  if (!success) {
    console.log("INFO: rate limit exceeded");
    return returnError(429, `Hi, the companions can't talk this fast.`)
  }

  if (!process.env.STEAMSHIP_API_KEY) {
    return returnError(500, `Please set the STEAMSHIP_API_KEY env variable and make sure ${companionName} is connected to an Agent instance that you own.`)
  }

  console.log(`Companion Name: ${companionName}`)
  console.log(`Prompt: ${prompt}`);

  if (!clerkUserId) {
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

  // Create a chat session id for the user
  const chatSessionId = Md5.hashStr(clerkUserId || "anonymous");

  // Make sure we have a generate endpoint.
  // TODO: Create a new instance of the agent per user if this proves advantageous.
  const agentUrl = companionConfig.generateEndpoint;
  if (!agentUrl) {
    return returnError(500, `Please add a Steamship 'generateEndpoint' to your ${companionName} configuration in companions.json.`)
  }
  // SSRF mitigation: validate agentUrl against an allowlist of trusted hostnames.
  const ALLOWED_AGENT_HOSTNAMES: string[] = (
    process.env.ALLOWED_AGENT_HOSTNAMES || 'api.steamship.com'
  ).split(',').map(h => h.trim().toLowerCase());
  let parsedAgentUrl: URL;
  try {
    parsedAgentUrl = new URL(agentUrl);
  } catch {
    return returnError(500, `The generateEndpoint for ${companionName} is not a valid URL.`);
  }
  if (
    !['https:', 'http:'].includes(parsedAgentUrl.protocol) ||
    !ALLOWED_AGENT_HOSTNAMES.includes(parsedAgentUrl.hostname.toLowerCase())
  ) {
    console.error(`SSRF guard: blocked request to disallowed host '${parsedAgentUrl.hostname}'`);
    return returnError(500, `The generateEndpoint for ${companionName} points to a disallowed host.`);
  }

  if (!isAllowedAgentUrl(agentUrl)) {
    console.error(`ERROR: agentUrl '${agentUrl}' is not on the permitted allowlist.`);
    return returnError(500, `The configured generateEndpoint for ${companionName} is not permitted. Only HTTPS requests to approved Steamship hosts are allowed.`);
  }

  // POLICY VIOLATION BLOCKED: The Steamship agent endpoint uses an unapproved LLM/agent
  // infrastructure (GPT via Steamship is NOT_IN_REGISTRY per the organization's approved LLM list).
  // This endpoint has been disabled until an approved LLM from the organization's registry is used.
  return returnError(403, `The LLM agent infrastructure configured for ${companionName} is not on the organization's approved list. Please update the companion configuration to use an approved LLM endpoint.`);
}
