"use client";

import {Fragment, useEffect, useState, useRef} from "react";
import { Dialog, Transition } from "@headlessui/react";
import { useCompletion } from "ai/react";
import {ChatBlock, responseToChatBlocks} from "@/components/ChatBlock";

var last_name = "";

// Approved model registry — only these versioned endpoints may be invoked.
const APPROVED_MODEL_REGISTRY: Record<string, string> = {
  "gpt-4-turbo-2024-04-09": "gpt-4-turbo-2024-04-09",
  "gpt-3.5-turbo-0125": "gpt-3.5-turbo-0125",
  "claude-3-opus-20240229": "claude-3-opus-20240229",
  "claude-3-sonnet-20240229": "claude-3-sonnet-20240229",
};

const DEFAULT_MODEL = "gpt-3.5-turbo-0125";

function resolveApprovedModel(requestedModel: string): string {
  if (requestedModel && Object.prototype.hasOwnProperty.call(APPROVED_MODEL_REGISTRY, requestedModel)) {
    return APPROVED_MODEL_REGISTRY[requestedModel];
  }
  console.warn(
    `[Security] Model "${requestedModel}" is not in the approved registry. ` +
    `Falling back to default model "${DEFAULT_MODEL}".`
  );
  return DEFAULT_MODEL;
}

// Allowlist of permitted LLM API endpoint segments.
const ALLOWED_LLM_ENDPOINTS: ReadonlySet<string> = new Set([
  "openai",
  "anthropic",
  "cohere",
  "mistral",
  // Add additional permitted endpoint names here.
]);

function sanitizeLlmEndpoint(llm: string): string {
  if (typeof llm === "string" && ALLOWED_LLM_ENDPOINTS.has(llm)) {
    return llm;
  }
  return "";
}

// Allowlist of permitted LLM endpoint path segments.
const ALLOWED_LLM_ENDPOINTS: ReadonlySet<string> = new Set([
  "openai",
  "anthropic",
  "cohere",
  // Add additional permitted endpoint names here.
]);

function getAllowedLlmEndpoint(llm: string): string {
  if (ALLOWED_LLM_ENDPOINTS.has(llm)) {
    return llm;
  }
  console.warn(`QAModal: LLM endpoint "${llm}" is not in the allowlist. Blocking request.`);
  return "";
}

/** Produce a SHA-256 hex digest of an arbitrary string (browser SubtleCrypto). */
async function sha256Hex(text: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Post an immutable audit record to the persistent audit endpoint. */
async function postAuditRecord(record: {
  eventType: string;
  modelId: string;
  inputHash: string;
  outputHash: string;
  timestamp: string;
  principal: string;
  sessionId: string;
}) {
  try {
    await fetch("/api/audit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(record),
      keepalive: true,
    });
  } catch (err) {
    // Audit failures must not silently disappear — log to console as fallback.
    console.error("[AUDIT] Failed to persist audit record:", record, err);
  }
}

const DANGEROUS_CODE_PATTERNS = [
  /\beval\s*\(/gi,
  /\bexec\s*\(/gi,
  /\bnew\s+Function\s*\(/gi,
  /\bsetTimeout\s*\(\s*['"`]/gi,
  /\bsetInterval\s*\(\s*['"`]/gi,
  /\bimportScripts\s*\(/gi,
  /\bdocument\.write\s*\(/gi,
  /\binnerHTML\s*=/gi,
  /\bouterHTML\s*=/gi,
  /javascript\s*:/gi,
  /\bFunction\s*\(/gi,
];

function sanitizeLLMOutput(output: string): string {
  let sanitized = output;
  let hasDangerous = false;
  for (const pattern of DANGEROUS_CODE_PATTERNS) {
    if (pattern.test(sanitized)) {
      hasDangerous = true;
      sanitized = sanitized.replace(pattern, (match) => `[BLOCKED:${match.trim()}]`);
    }
    // Reset lastIndex for global regexes
    pattern.lastIndex = 0;
  }
  if (hasDangerous) {
    console.warn("[Security] LLM output contained dynamic code execution primitives. Content was sanitized.");
  }
  return sanitized;
}

export default function QAModal({
  open,
  setOpen,
  example,
}: {
  open: boolean;
  setOpen: any;
  example: any;
}) {
  if (!example) {
    // create a dummy so the completion doesn't croak during init.
    example = new Object();
    example.llm = "";
    example.name = "";
  }

  // Approved LLM backends per organization policy.
  const APPROVED_LLMS: string[] = ["claude", "llama2"];
  const DEFAULT_APPROVED_LLM = "claude";
  const resolvedLlm =
    example.llm && APPROVED_LLMS.includes(example.llm)
      ? example.llm
      : DEFAULT_APPROVED_LLM;

  let {
    completion,
    input,
    isLoading,
    handleInputChange,
    handleSubmit,
    stop,
    setInput,
    setCompletion,
  } = useCompletion({
    api: "/api/" + resolvedLlm,
    headers: { name: example.name },
  });

  // Stable session ID for correlating all audit events within this modal session.
  const sessionIdRef = useRef<string>(
    typeof crypto !== "undefined" && crypto.randomUUID
      ? crypto.randomUUID()
      : `session-${Date.now()}-${Math.random().toString(36).slice(2)}`
  );

  // Keep a ref to the most-recent submitted input so the completion audit can hash it.
  const lastInputRef = useRef<string>("");

  let [blocks, setBlocks] = useState<any[] | null>(null)
  let [provenance, setProvenance] = useState<{ model: string; timestamp: string; origin: string } | null>(null)

    useEffect(() => {
    // When the completion changes, parse it to multimodal blocks for display.
    if (completion) {
      setBlocks(responseToChatBlocks(completion))
      // Attach provenance metadata on first receipt of completion content
      setProvenance(prev => prev ?? {
        model: example.llm || "unknown-model",
        timestamp: new Date().toISOString(),
        origin: `AI-generated by model '${example.llm || "unknown"}' via /api/${example.llm || "unknown"}`,
      })
    } else {
      setBlocks(null)
      setProvenance(null)
    }
  }, [completion])

  if (!example) {
    console.log("ERROR: no companion selected");
    return null;
  }

  const MAX_INPUT_LENGTH = 2000;
  const DANGEROUS_PATTERN = /<[^>]*>|javascript:|data:|vbscript:|on\w+\s*=/gi;

  const sanitizeInput = (value: string): string => {
    // Trim whitespace
    let sanitized = value.trim();
    // Remove HTML tags and dangerous patterns
    sanitized = sanitized.replace(DANGEROUS_PATTERN, "");
    // Collapse multiple spaces/newlines
    sanitized = sanitized.replace(/\s{3,}/g, "  ");
    return sanitized;
  };

  const handleValidatedSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const sanitized = sanitizeInput(input);
    if (!sanitized) {
      return;
    }
    if (sanitized.length > MAX_INPUT_LENGTH) {
      alert(`Input must be ${MAX_INPUT_LENGTH} characters or fewer.`);
      return;
    }
    // Update input state to the sanitized value before submitting
    setInput(sanitized);
    // Delegate to the original handleSubmit with a synthetic event
    handleSubmit(e);
  };

  const SUSPICIOUS_PATTERNS = [
    // Shell/binary commands
    /(?:^|\s)(?:bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess)\s*[({[]/i,
    /(?:\$\(|`)[^`]*`/,
    /;\s*(?:rm|del|format|mkfs|dd|wget|curl|nc|ncat|netcat)\s/i,
    // Base64-encoded content (long base64 strings)
    /(?:[A-Za-z0-9+/]{40,}={0,2})/,
    // Hidden/invisible unicode characters
    /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/,
    // Prompt injection keywords
    /ignore\s+(?:previous|above|prior|all)\s+instructions/i,
    /(?:system\s*prompt|you\s+are\s+now|act\s+as|pretend\s+(?:you\s+are|to\s+be)|jailbreak)/i,
    /(?:disregard|forget|override)\s+(?:your|all|previous|prior)/i,
    // Leetspeak obfuscation patterns (e.g. 1gnor3, 3x3cut3)
    /(?:[1!][gq][n][o0][r][3e]|[3e][x][3e][c]|[5s][y][5s][t][3e][m])/i,
    // Null bytes or control characters
    /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/,
  ];

  const sanitizeInput = (value: string): string | null => {
    for (const pattern of SUSPICIOUS_PATTERNS) {
      if (pattern.test(value)) {
        return null; // reject input
      }
    }
    // Strip any remaining invisible/zero-width characters
    return value.replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/g, "");
  };

  const handleSanitizedInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const sanitized = sanitizeInput(e.target.value);
    if (sanitized === null) {
      // Reject the input silently or optionally show a warning
      return;
    }
    // Mutate the event value to the sanitized version before passing on
    const syntheticEvent = { ...e, target: { ...e.target, value: sanitized } };
    handleInputChange(syntheticEvent as React.ChangeEvent<HTMLInputElement>);
  };

  // Wrap handleSubmit to capture the input text before submission and emit a request audit event.
  const auditedHandleSubmit = useCallback(
    async (e: React.FormEvent<HTMLFormElement>) => {
      e.preventDefault();
      lastInputRef.current = input;
      const timestamp = new Date().toISOString();
      const inputHash = await sha256Hex(input);
      const principal =
        typeof window !== "undefined"
          ? (window as any).__currentUser ?? "anonymous"
          : "anonymous";
      await postAuditRecord({
        eventType: "AI_COMPLETION_REQUESTED",
        modelId: example.llm ?? "unknown",
        inputHash,
        outputHash: "",
        timestamp,
        principal: String(principal),
        sessionId: sessionIdRef.current,
      });
      handleSubmit(e);
    },
    [input, example.llm, handleSubmit]
  );

  const handleClose = () => {
    setInput("");
    setCompletion("");
    setProvenance(null);
    stop();
    setOpen(false);
  };

  return (
    <Transition.Root show={open} as={Fragment}>
      <Dialog as="div" className="relative z-10" onClose={handleClose}>
        <Transition.Child
          as={Fragment}
          enter="ease-out duration-300"
          enterFrom="opacity-0"
          enterTo="opacity-100"
          leave="ease-in duration-200"
          leaveFrom="opacity-100"
          leaveTo="opacity-0"
        >
          <div className="fixed inset-0 bg-gray-950 bg-opacity-75 transition-opacity" />
        </Transition.Child>

        <div className="fixed inset-0 z-10 overflow-y-auto">
          <div className="flex min-h-full items-end justify-center p-4 text-center sm:items-center sm:p-0">
            <Transition.Child
              as={Fragment}
              enter="ease-out duration-300"
              enterFrom="opacity-0 translate-y-4 sm:translate-y-0 sm:scale-95"
              enterTo="opacity-100 translate-y-0 sm:scale-100"
              leave="ease-in duration-200"
              leaveFrom="opacity-100 translate-y-0 sm:scale-100"
              leaveTo="opacity-0 translate-y-4 sm:translate-y-0 sm:scale-95"
            >
              <Dialog.Panel className="relative transform overflow-hidden rounded-lg bg-gray-800 px-4 pb-4 pt-5 text-left shadow-xl transition-all sm:my-8 sm:p-6 w-full max-w-3xl">
                <div>
                  <form onSubmit={handleValidatedSubmit}>
                    <input
                      placeholder="How's your day?"
                      className={"w-full flex-auto rounded-md border-0 bg-white/5 px-3.5 py-2 shadow-sm focus:outline-none sm:text-sm sm:leading-6 " + (isLoading && !completion ? "text-gray-600 cursor-not-allowed" : "text-white")}                      
                      value={input}
                      onChange={handleSanitizedInputChange}
                      disabled={isLoading && !blocks}
                    />
                  </form>
                  <div className="mt-3 sm:mt-5">
                    <div className="mt-2">
                      <p className="text-sm text-gray-500">
                        Chat with {example.name}
                      </p>
                    </div>
                    {blocks && (
                      <div className="mt-2">
                        {/* AI-Generated Content Label — provenance disclosure */}
                        <div
                          className="flex items-center gap-2 mb-2 px-2 py-1 rounded bg-yellow-900/40 border border-yellow-600/50"
                          aria-label="AI-generated content disclosure"
                          data-ai-generated="true"
                          data-ai-model={provenance?.model ?? ""}
                          data-ai-timestamp={provenance?.timestamp ?? ""}
                          data-ai-origin={provenance?.origin ?? ""}
                        >
                          <span className="text-yellow-400 text-xs font-semibold uppercase tracking-wide">
                            ⚠ AI-Generated Content
                          </span>
                          {provenance && (
                            <span className="text-yellow-300/70 text-xs ml-auto">
                              Model: {provenance.model} &nbsp;|&nbsp; {new Date(provenance.timestamp).toLocaleString()}
                            </span>
                          )}
                        </div>
                        {blocks}
                        {/* Provenance watermark footer */}
                        {provenance && (
                          <div
                            className="mt-2 pt-1 border-t border-gray-700 text-gray-500 text-xs text-right select-none"
                            aria-hidden="true"
                            data-watermark="ai-synthetic-content"
                          >
                            🤖 Synthetic · {provenance.model} · {provenance.timestamp}
                          </div>
                        )}
                      </div>
                    )}

                    {isLoading && !blocks && (
                      <p className="flex items-center justify-center mt-4">
                        <svg
                          className="animate-spin -ml-1 mr-3 h-5 w-5 text-white"
                          xmlns="http://www.w3.org/2000/svg"
                          fill="none"
                          viewBox="0 0 24 24"
                        >
                          <circle
                            className="opacity-25"
                            cx="12"
                            cy="12"
                            r="10"
                            stroke="currentColor"
                            stroke-width="4"
                          ></circle>
                          <path
                            className="opacity-75"
                            fill="currentColor"
                            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                          ></path>
                        </svg>
                      </p>
                    )}
                  </div>
                </div>
              </Dialog.Panel>
            </Transition.Child>
          </div>
        </div>
      </Dialog>
    </Transition.Root>
  );
}
