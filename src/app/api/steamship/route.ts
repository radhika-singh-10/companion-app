import dotenv from "dotenv";
import clerk from "@clerk/clerk-sdk-node";
import { NextResponse } from "next/server";
import { currentUser } from "@clerk/nextjs";
import { rateLimit } from "@/app/utils/rateLimit";
import {Md5} from 'ts-md5'
import ConfigManager from "@/app/utils/config";

// ---------------------------------------------------------------------------
// Tool allow list policy
// ---------------------------------------------------------------------------
// STEAMSHIP_ALLOWED_TOOLS is a comma-separated list of tool identifiers that
// this agent is permitted to invoke, e.g.:
//   STEAMSHIP_ALLOWED_TOOLS=search,calculator,weather
// If the variable is absent or empty the request is denied (fail-closed).
function getAllowedTools(): Set<string> | null {
  const raw = process.env.STEAMSHIP_ALLOWED_TOOLS;
  if (!raw || raw.trim() === "") return null;
  const tools = raw
    .split(",")
    .map((t) => t.trim().toLowerCase())
    .filter(Boolean);
  return tools.length > 0 ? new Set(tools) : null;
}

function auditLog(entry: {
  event: string;
  actor: string;
  companionName: string;
  tool: string;
  allowed: boolean;
  reason: string;
  policyVersion: string;
  timestamp: string;
}) {
  // Write a structured audit record to stdout (captured by your log aggregator).
  console.log(JSON.stringify({ audit: true, ...entry }));
}
import { randomUUID } from "crypto";
import fs from "fs";
import path from "path";

// ---------------------------------------------------------------------------
// Audit logger — writes one JSON-lines record per AI decision to a persistent
// append-only file.  Replace the fs.appendFileSync call with your preferred
// persistent store (database, SIEM, cloud logging sink) as needed.
// ---------------------------------------------------------------------------
interface AuditRecord {
  traceId: string;
  timestamp: string;
  principal: { clerkUserId: string | undefined; clerkUserName: string | undefined | null };
  companionName: string | null;
  companionConfigId: string | undefined;
  agentUrl: string;
  chatSessionId: string;
  inputHash: string;
  prompt: string;
  httpStatus: number;
  responseOutput: unknown;
  error?: string;
}

function writeAuditRecord(record: AuditRecord): void {
  const auditDir = path.join(process.cwd(), "audit_logs");
  if (!fs.existsSync(auditDir)) {
    fs.mkdirSync(auditDir, { recursive: true });
  }
  const auditFile = path.join(auditDir, "ai_decisions.jsonl");
  fs.appendFileSync(auditFile, JSON.stringify(record) + "\n", "utf8");
}

dotenv.config({ path: `.env.local` });

// Approved model registry: maps companion name -> pinned versioned endpoint.
// All AI workloads MUST resolve to an entry in this registry.
// Update entries here when a new pinned version is approved.
const APPROVED_MODEL_REGISTRY: Record<string, string> = {
  // Example entries — replace with your actual approved, versioned endpoints:
  // "my-companion": "https://api.steamship.com/api/v1/package/instance/my-companion-v1-2-3/call/generate",
  ...(process.env.APPROVED_MODEL_REGISTRY
    ? JSON.parse(process.env.APPROVED_MODEL_REGISTRY)
    : {}),
};

/**
 * Sanitizes the prompt to detect and block malicious or suspicious content.
 * Returns an error string if suspicious content is found, or null if the prompt is safe.
 */
function sanitizePrompt(input: string): string | null {
  if (!input || typeof input !== "string") {
    return "Invalid prompt.";
  }

  // Reject excessively long prompts
  if (input.length > 4000) {
    return "Prompt exceeds maximum allowed length.";
  }

  // Detect base64-encoded content (long base64 strings are suspicious)
  const base64Pattern = /(?:[A-Za-z0-9+\/]{40,}={0,2})/;
  if (base64Pattern.test(input)) {
    return "Prompt contains potentially encoded content.";
  }

  // Detect shell command patterns
  const shellCommandPattern =
    /(\b(bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess|os\.system|child_process|spawn|execSync|execFile)\b|[`$]\(|&&|\|\||;\s*\w|\bsudo\b|\brm\s+-rf\b|\bchmod\b|\bchown\b|\bcurl\b.*\|.*sh|\bwget\b.*\|.*sh)/i;
  if (shellCommandPattern.test(input)) {
    return "Prompt contains shell command patterns.";
  }

  // Detect binary/executable references
  const binaryPattern =
    /(\/bin\/|\/usr\/bin\/|\/etc\/passwd|\/etc\/shadow|\.exe\b|\.sh\b|\.bat\b|\.cmd\b|\.ps1\b)/i;
  if (binaryPattern.test(input)) {
    return "Prompt contains references to binary or executable files.";
  }

  // Detect common prompt injection / jailbreak phrases
  const injectionPattern =
    /(ignore (previous|all|above|prior) instructions?|disregard (your|all|previous) (instructions?|rules?|guidelines?)|you are now|act as (an?|if)|pretend (you are|to be)|your new (role|persona|instructions?)|system prompt|\[INST\]|<\|im_start\||<\|system\||\bDAN\b|do anything now)/i;
  if (injectionPattern.test(input)) {
    return "Prompt contains potential prompt injection content.";
  }

  // Detect leetspeak obfuscation (e.g., 3x3cut3, 1nj3ct)
  const leetspeakPattern = /\b[a-z]*[013456789][a-z0-9]*[013456789][a-z0-9]*\b/i;
  const leetspeakWords = input.match(/\b\w+\b/g) || [];
  const suspiciousLeet = leetspeakWords.filter(
    (w) => leetspeakPattern.test(w) && w.length > 4
  );
  if (suspiciousLeet.length > 3) {
    return "Prompt contains potential leetspeak obfuscation.";
  }

  // Detect null bytes or non-printable control characters
  // eslint-disable-next-line no-control-regex
  const controlCharPattern = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/;
  if (controlCharPattern.test(input)) {
    return "Prompt contains non-printable or control characters.";
  }

  return null;
}

// Organization-approved LLM list. Only models in this list may be invoked.
const APPROVED_MODELS: ReadonlySet<string> = new Set([
  // Add approved model identifiers here, e.g.:
  // "gpt-4o",
  // "gpt-4-turbo",
]);

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
  // Validate and sanitize the prompt input
  if (!rawPrompt || typeof rawPrompt !== "string") {
    return returnError(400, "Invalid request: 'prompt' must be a non-empty string.");
  }
  const MAX_PROMPT_LENGTH = 2000;
  if (rawPrompt.length > MAX_PROMPT_LENGTH) {
    return returnError(400, `Invalid request: 'prompt' must not exceed ${MAX_PROMPT_LENGTH} characters.`);
  }
  // Strip null bytes and non-printable control characters (except common whitespace)
  const prompt = rawPrompt
    .replace(/\0/g, "")
    .replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
    .trim();
  if (prompt.length === 0) {
    return returnError(400, "Invalid request: 'prompt' must not be empty after sanitization.");
  }

  const companionName = req.headers.get("name");

  if (!companionName) {
    console.log("ERROR: no companion name");
    return returnError(429, `Hi, please add a 'name' field in your headers specifying the Companion Name.`)
  }

  // Load the companion config
  const configManager = ConfigManager.getInstance();
  const companionConfig = configManager.getConfig("name", companionName);
  if (!companionConfig) {
    return returnError(404, `Hi, we were unable to find the configuration for a companion named ${companionName}.`)
  }

  // Make sure we're not rate limited
  const identifier = req.url + "-" + (clerkUserId || "anonymous");
  const { success } = await rateLimit(identifier);
  if (!success) {
    console.log("INFO: rate limit exceeded");
    return returnError(429, `Hi, the companions can't talk this fast.`)
  }

  if (!process.env.STEAMSHIP_API_KEY) {
    return returnError(500, `Please set the STEAMSHIP_API_KEY env variable and make sure ${companionName} is connected to an Agent instance that you own.`)
  }

  console.log(`Companion Name: ${companionName}`)

  // Sanitize the prompt before any further processing
  const promptError = sanitizePrompt(prompt);
  if (promptError) {
    console.log(`INFO: Prompt rejected — ${promptError}`);
    return returnError(400, `Your message could not be processed: ${promptError}`);
  }

  console.log(`Prompt: ${prompt}`);

  user = await currentUser();
  clerkUserId = user?.id;
  clerkUserName = user?.firstName;

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

  // Create a signed, expiry-bound chat session id for the verified user
  const sessionSecret = process.env.SESSION_SECRET;
  if (!sessionSecret) {
    return returnError(500, 'Server misconfiguration: SESSION_SECRET is not set.');
  }
  const sessionExpiry = Math.floor(Date.now() / 1000) + 3600; // 1-hour expiry
  const sessionPayload = `${clerkUserId}:${sessionExpiry}`;
  const sessionHmac = crypto
    .createHmac('sha256', sessionSecret)
    .update(sessionPayload)
    .digest('hex');
  const chatSessionId = `${sessionPayload}:${sessionHmac}`;

  // Verify the session token integrity before use
  const [tokenUserId, tokenExpiry, tokenHmac] = chatSessionId.split(':');
  const expectedHmac = crypto
    .createHmac('sha256', sessionSecret)
    .update(`${tokenUserId}:${tokenExpiry}`)
    .digest('hex');
  const isValidSignature = crypto.timingSafeEqual(
    Buffer.from(tokenHmac, 'hex'),
    Buffer.from(expectedHmac, 'hex')
  );
  if (!isValidSignature || parseInt(tokenExpiry, 10) < Math.floor(Date.now() / 1000)) {
    return returnError(401, 'Invalid or expired session token.');
  }

  // Make sure we have a generate endpoint.
  // TODO: Create a new instance of the agent per user if this proves advantageous.
  const agentUrl = companionConfig.generateEndpoint
  if (!agentUrl) {
    return returnError(500, `Please add a Steamship 'generateEndpoint' to your ${companionName} configuration in companions.json.`)
  }

  // --- Model registry & version-pinning enforcement ---
  // Reject any endpoint that is not in the approved model registry.
  const approvedEndpoint = APPROVED_MODEL_REGISTRY[companionName];
  if (!approvedEndpoint) {
    console.error(`POLICY VIOLATION: companion '${companionName}' has no entry in the approved model registry.`);
    return returnError(403, `Companion '${companionName}' is not listed in the approved model registry. Register a pinned endpoint before use.`);
  }
  if (agentUrl !== approvedEndpoint) {
    console.error(`POLICY VIOLATION: resolved endpoint '${agentUrl}' does not match approved pinned endpoint '${approvedEndpoint}' for companion '${companionName}'.`);
    return returnError(403, `The endpoint configured for '${companionName}' does not match the approved pinned version. Update the registry or the configuration.`);
  }
  // Log model identity at inference time for auditability.
  console.log(`MODEL IDENTITY: companion='${companionName}' pinnedEndpoint='${approvedEndpoint}'`);

  // SSRF prevention: validate agentUrl against a strict allowlist of permitted URL prefixes.
  const ALLOWED_AGENT_URL_PREFIXES: string[] = (
    process.env.ALLOWED_AGENT_URL_PREFIXES || "https://api.steamship.com/"
  ).split(",").map((p) => p.trim()).filter(Boolean);
  const isAllowedUrl = ALLOWED_AGENT_URL_PREFIXES.some((prefix) =>
    agentUrl.startsWith(prefix)
  );
  if (!isAllowedUrl) {
    console.error(`Blocked SSRF attempt: agentUrl '${agentUrl}' is not in the allowlist.`);
    return returnError(500, `The configured agent endpoint is not permitted.`);
  }

  // Enforce the organization's approved LLM policy.
  // The companion config must specify a 'model' field that is on the approved list.
  const companionModel: string | undefined = companionConfig.model;
  if (!companionModel) {
    console.log(`ERROR: companion '${companionName}' has no 'model' field in its configuration.`);
    return returnError(403, `Companion '${companionName}' does not specify a model. Only organization-approved models may be used.`);
  }
  if (!APPROVED_MODELS.has(companionModel)) {
    console.log(`ERROR: model '${companionModel}' for companion '${companionName}' is not on the organization's approved LLM list.`);
    return returnError(403, `Model '${companionModel}' is not on the organization's approved LLM list. Please contact your administrator.`);
  }

    // Invoke the generation. Tool invocation, chat history management, backstory injection, etc is all done within this endpoint.
  // To build, deploy, and host your own multi-tenant agent see: https://www.steamship.com/learn/agent-guidebook

  // Termination criteria: enforce a hard timeout and a maximum number of attempts
  // so the agent cannot run indefinitely.
  const AGENT_TIMEOUT_MS = 30_000; // 30-second hard deadline
  const MAX_ATTEMPTS = 3;          // maximum fetch attempts before giving up

  let response: Response | null = null;
  let lastError: string = "Unknown error";

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), AGENT_TIMEOUT_MS);

    try {
      response = await fetch(agentUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${process.env.STEAMSHIP_API_KEY}`
        },
        body: JSON.stringify({
          question: prompt,
          chat_session_id: chatSessionId
        }),
        signal: controller.signal
      });
      // Successful fetch — exit the retry loop
      break;
    } catch (err: unknown) {
      if (err instanceof Error && err.name === "AbortError") {
        lastError = `Agent request timed out after ${AGENT_TIMEOUT_MS / 1000}s (attempt ${attempt}/${MAX_ATTEMPTS})`;
        console.error(lastError);
      } else {
        lastError = err instanceof Error ? err.message : String(err);
        console.error(`Agent fetch error on attempt ${attempt}/${MAX_ATTEMPTS}: ${lastError}`);
      }
      response = null;
    } finally {
      clearTimeout(timeoutId);
    }

    // If we have exhausted all attempts, return a termination error
    if (attempt === MAX_ATTEMPTS && response === null) {
      return returnError(504, `Agent did not complete within the allowed time or attempts. Last error: ${lastError}`);
    }
  }

  if (response === null) {
    return returnError(504, `Agent did not produce a response. Last error: ${lastError}`);
  }

  console.log(`MCP Interaction - Response: status=${response.status}, ok=${response.ok}`);
        if (response.ok) {
    const responseText = await response.text()
    const responseBlocks = JSON.parse(responseText)

    // Provenance, labeling, and watermarking must succeed — fail closed if they do not.
    try {
      const provenanceTimestamp = new Date().toISOString();
      const agentUrlHash = Md5.hashStr(agentUrl);

      // Watermark: a deterministic string derived from session, timestamp, and agent identity.
      const watermark = `[AI-GENERATED | session:${chatSessionId} | agent:${agentUrlHash} | ts:${provenanceTimestamp}]`;

      // Provenance metadata attached to the response envelope.
      const provenance = {
        synthetic: true,
        contentOrigin: "steamship-agent",
        agentEndpointHash: agentUrlHash,
        companionName: companionName,
        generatedAt: provenanceTimestamp,
        watermark: watermark,
      };

      // Label every block in the response as AI-generated and embed the watermark.
      const labeledBlocks = (Array.isArray(responseBlocks) ? responseBlocks : [responseBlocks]).map(
        (block: Record<string, unknown>) => ({
          ...block,
          _aiGenerated: true,
          _contentLabel: "SYNTHETIC_AI_OUTPUT",
          _watermark: watermark,
          _provenance: provenance,
        })
      );

      return NextResponse.json({
        blocks: labeledBlocks,
        _provenance: provenance,
      });
    } catch (labelingError) {
      // Fail closed: never serve unlabeled AI content.
      console.error("ERROR: provenance/labeling failed, refusing to serve unlabeled AI content", labelingError);
      return returnError(500, "Internal error: could not attach required AI content provenance labels.");
    }
  } else {
    console.error(`Upstream agent error for companion '${companionName}': ${await response.text()}`);
    return returnError(500, "An error occurred while contacting the agent. Please try again later.")
  } | User: ${clerkUserId} | Prompt: ${prompt} | Response: ${responseText}`)
    return NextResponse.json(responseBlocks)
  } else {
    const errorText = await response.text()
    console.log(`LLM Interaction - Companion: ${companionName} | User: ${clerkUserId} | Prompt: ${prompt} | Error Response: ${errorText}`)
    return returnError(500, errorText)
  } catch {
      return returnError(502, "Invalid JSON received from agent endpoint.");
    }

    // Validate top-level structure: must be an array of block objects
    if (!Array.isArray(parsedResponse)) {
      return returnError(502, "Unexpected response structure from agent endpoint.");
    }

    // Sanitize each block by allowlisting known safe fields only
    const ALLOWED_MIME_TYPES = new Set([
      "text/plain",
      "text/markdown",
      "image/png",
      "image/jpeg",
      "image/gif",
      "image/webp",
      "audio/mp3",
      "audio/mpeg",
      "audio/wav",
    ]);

    const sanitizedBlocks = parsedResponse.map((block: unknown) => {
      if (typeof block !== "object" || block === null || Array.isArray(block)) {
        return null; // drop invalid blocks
      }
      const b = block as Record<string, unknown>;

      // Allowlist and sanitize individual fields
      const sanitized: Record<string, unknown> = {};

      if (typeof b.text === "string") {
        // Strip any HTML/script tags from text content
        sanitized.text = b.text.replace(/<[^>]*>/g, "");
      }

      if (typeof b.mimeType === "string" && ALLOWED_MIME_TYPES.has(b.mimeType)) {
        sanitized.mimeType = b.mimeType;
      }

      if (typeof b.url === "string") {
        // Only allow http/https URLs
        try {
          const parsed = new URL(b.url);
          if (parsed.protocol === "http:" || parsed.protocol === "https:") {
            sanitized.url = b.url;
          }
        } catch {
          // drop invalid URLs
        }
      }

      return sanitized;
    }).filter((block) => block !== null && Object.keys(block as object).length > 0);

    return NextResponse.json(sanitizedBlocks);
  } else {
    const errorText = await response.text();
    console.log(`MCP Interaction - Error Response: status=${response.status}, body=${errorText}`);
    return returnError(500, errorText)
  }
}
