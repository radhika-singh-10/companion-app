"use client";
import { useEffect, useState } from "react";
import QAModal from "./QAModal";
import Image from "next/image";
import { Tooltip } from "react-tooltip";

import { getCompanions } from "./actions";

// ---------------------------------------------------------------------------
// Inline audit logger — writes a structured forensic record to the server.
// In production, replace the fetch target with your persistent audit endpoint
// (e.g. a SIEM ingest URL, append-only log service, or database API).
// ---------------------------------------------------------------------------
type AuditEvent = {
  traceId: string;
  timestamp: string;
  principal: string;
  action: string;
  modelId: string | null;
  inputHash: string | null;
  outputSummary: string | null;
  status: "success" | "error";
  errorMessage?: string;
};

async function sha256Hex(data: string): Promise<string> {
  if (typeof window === "undefined" || !window.crypto?.subtle) {
    // Fallback: return a placeholder when SubtleCrypto is unavailable
    return "hash-unavailable";
  }
  const encoded = new TextEncoder().encode(data);
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", encoded);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function generateTraceId(): string {
  if (typeof window !== "undefined" && window.crypto?.randomUUID) {
    return window.crypto.randomUUID();
  }
  // Fallback for environments without randomUUID
  return `trace-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

async function writeAuditLog(event: AuditEvent): Promise<void> {
  try {
    // Persist to server-side audit endpoint (append-only, tamper-evident store).
    // Replace "/api/audit" with your actual persistent audit log endpoint.
    await fetch("/api/audit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(event),
      keepalive: true, // ensures delivery even if page unloads
    });
  } catch (auditErr) {
    // Never suppress the original flow; only note the audit failure.
    console.error("[AUDIT] Failed to persist audit record:", auditErr);
  }
  // Always echo to console for local observability (not a substitute for persistence).
  console.info("[AUDIT]", JSON.stringify(event));
}

export default function Examples() {
  const [QAModalOpen, setQAModalOpen] = useState(false);
  const [CompParam, setCompParam] = useState({
    name: "",
    title: "",
    imageUrl: "",
  });
  const [examples, setExamples] = useState([
    {
      name: "",
      title: "",
      imageUrl: "",
      llm: "",
      telegramLink: null
    },
  ]);

  const APPROVED_LLMS: string[] = [
    "gpt-4",
    "gpt-4o",
    "gpt-3.5-turbo",
    "claude-3-opus",
    "claude-3-sonnet",
    "claude-3-haiku",
    "gemini-pro",
    "gemini-1.5-pro",
  ];

    // Approved model registry: only these exact identifiers are permitted.
  const APPROVED_MODEL_REGISTRY: ReadonlySet<string> = new Set([
    "gpt-4",
    "gpt-4-turbo",
    "gpt-3.5-turbo",
    "claude-3-opus",
    "claude-3-sonnet",
    "claude-3-haiku",
    "gemini-1.5-pro",
    "gemini-1.5-flash",
    "llama-3-70b",
    "mistral-large",
  ]);

  const validateModelIdentifier = (llm: string): string => {
    if (typeof llm === "string" && APPROVED_MODEL_REGISTRY.has(llm.trim())) {
      return llm.trim();
    }
    return "Unregistered Model";
  };

  useEffect(() => {
    const fetchData = async () => {
      try {
        const companions = await getCompanions();
        let entries = JSON.parse(companions);
        let setme = entries.map((entry: any) => ({
          name: entry.name,
          title: entry.title,
          imageUrl: entry.imageUrl,
          llm: validateModelIdentifier(entry.llm),
          phone: entry.phone,
          telegramLink: entry.telegramLink
        }));
        setExamples(setme);
      } catch (err) {
        console.log(err);
      }
    };

    fetchData();
  }, []);

  return (
    <div id="ExampleDiv">
      <QAModal
        open={QAModalOpen}
        setOpen={setQAModalOpen}
        example={CompParam}
      />
      <ul
        role="list"
        className="mt-14 m-auto max-w-3xl grid grid-cols-1 gap-6 lg:grid-cols-2"
      >
        {examples.map((example, i) => (
          <li
            key={example.name}
            onClick={async () => {
              setCompParam(example);
              setQAModalOpen(true);

              // Audit: record user-initiated QA interaction with companion
              const interactionTraceId = generateTraceId();
              const inputPayload = JSON.stringify({ companionName: example.name, llm: example.llm });
              const inputHash = await sha256Hex(inputPayload);
              await writeAuditLog({
                traceId: interactionTraceId,
                timestamp: new Date().toISOString(),
                principal: "anonymous-client", // replace with authenticated user ID when available
                action: "INITIATE_QA_INTERACTION",
                modelId: example.llm || null,
                inputHash,
                outputSummary: `QA modal opened for companion: ${example.name}`,
                status: "success",
              });
            }}
            className="col-span-2 flex flex-col rounded-lg bg-slate-800  text-center shadow relative ring-1 ring-white/10 cursor-pointer hover:ring-sky-300/70 transition"
            data-provenance={JSON.stringify((example as any)._provenance ?? { contentOrigin: "ai-generated", modelId: example.llm || "unknown" })}
            data-ai-generated="true"
          >
            <div className="absolute -bottom-px left-10 right-10 h-px bg-gradient-to-r from-sky-300/0 via-sky-300/70 to-sky-300/0"></div>
            <div className="flex flex-1 flex-col p-8">
              <Image
                width={0}
                height={0}
                sizes="100vw"
                className="mx-auto h-32 w-32 flex-shrink-0 rounded-full"
                src={sanitizeImageUrl(example.imageUrl)}
                alt=""
              />
              <h3 className="mt-6 text-sm font-medium text-white">
                {example.name}
              </h3>
              <dl className="mt-1 flex flex-grow flex-col justify-between">
                <dt className="sr-only"></dt>
                <dd className="text-sm text-slate-400">
                  <span
                    className="inline-block mb-1 px-2 py-0.5 rounded text-xs font-semibold bg-sky-900 text-sky-300 border border-sky-500"
                    aria-label="This content is AI-generated"
                    data-content-label="ai-generated"
                  >
                    🤖 AI-Generated Content
                  </span>
                  <br />
                  {example.title}.{" "}
                  <span
                    data-model-id={example.llm || "unknown"}
                    data-provenance-field="model"
                    aria-label={`AI model: ${example.llm}`}
                  >
                    Model: <b>{example.llm}</b>
                  </span>.
                  {example.telegramLink && isSafeTelegramUrl(example.telegramLink) && (
                    <span className="ml-1"><a onClick={(event) => {event?.stopPropagation(); event?.preventDefault()}} href={example.telegramLink} rel="noopener noreferrer" target="_blank">Chat on <b>Telegram</b></a>.</span>
                  )}
                </dd>
              </dl>
              <dl className="mt-1 flex flex-grow flex-col justify-between">
                <dt className="sr-only"></dt>
                {isPhoneNumber(example.phone) && (
                  <>
                    <dd
                      data-tip="Helpful tip goes here"
                      className="text-sm text-slate-400 inline-block"
                    >
                      📱Text me at: <b>{maskPhoneNumber(example.phone)}</b>
                      &nbsp;
                      <svg
                        data-tooltip-id="help-tooltip"
                        data-tooltip-content="Unlock this freature by clicking on 
                        your profile picture on the top right 
                        -> Manage Account -> Add a phone number."
                        data-tooltip-target="tooltip-default"
                        data-tip="Helpful tip goes here"
                        className="w-[15px] h-[15px] text-slate-400 inline-block cursor-pointer"
                        xmlns="http://www.w3.org/2000/svg"
                        fill="currentColor"
                        viewBox="0 0 20 20"
                      >
                        <path d="M10 .5a9.5 9.5 0 1 0 9.5 9.5A9.51 9.51 0 0 0 10 .5ZM9.5 4a1.5 1.5 0 1 1 0 3 1.5 1.5 0 0 1 0-3ZM12 15H8a1 1 0 0 1 0-2h1v-3H8a1 1 0 0 1 0-2h2a1 1 0 0 1 1 1v4h1a1 1 0 0 1 0 2Z" />
                      </svg>
                      <Tooltip id="help-tooltip" />
                    </dd>
                  </>
                )}
              </dl>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

function isPhoneNumber(input: string): boolean {
  const phoneNumberRegex = /^\+\d{1,11}$/;
  return phoneNumberRegex.test(input);
}

/**
 * Only allow Telegram links pointing to the official t.me domain over HTTPS.
 * Returns null if the URL is not a valid Telegram link.
 */
function sanitizeTelegramLink(url: string): string | null {
  try {
    const parsed = new URL(url);
    if (
      parsed.protocol === 'https:' &&
      (parsed.hostname === 't.me' || parsed.hostname.endsWith('.t.me'))
    ) {
      return parsed.toString();
    }
  } catch {
    // invalid URL
  }
  return null;
}

/**
 * Only allow image URLs that use HTTPS.
 * Returns a safe placeholder if the URL is not valid or not HTTPS.
 */
function sanitizeImageUrl(url: string): string {
  const FALLBACK = '/placeholder-avatar.png';
  try {
    const parsed = new URL(url);
    if (parsed.protocol === 'https:') {
      return parsed.toString();
    }
  } catch {
    // invalid URL
  }
  return FALLBACK;
}

const ALLOWED_TELEGRAM_SCHEMES = ['https:'];
const ALLOWED_TELEGRAM_HOSTNAMES = ['t.me'];

function isSafeTelegramUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return (
      ALLOWED_TELEGRAM_SCHEMES.includes(parsed.protocol) &&
      ALLOWED_TELEGRAM_HOSTNAMES.includes(parsed.hostname)
    );
  } catch {
    return false;
  }
}

function maskPhoneNumber(phone: string): string {
  if (phone.length <= 5) return '***';
  const visible_start = phone.slice(0, 3);
  const visible_end = phone.slice(-2);
  const masked_middle = '*'.repeat(phone.length - 5);
  return `${visible_start}${masked_middle}${visible_end}`;
}
