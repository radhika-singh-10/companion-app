"use client";

import {Fragment, useEffect, useState, useRef} from "react";
import { Dialog, Transition } from "@headlessui/react";
import { useCompletion } from "ai/react";
import {ChatBlock, responseToChatBlocks} from "@/components/ChatBlock";

var last_name = "";

// Allowlist of permitted LLM API route segments to prevent SSRF / path traversal
const ALLOWED_LLM_ROUTES: ReadonlySet<string> = new Set([
  "openai",
  "anthropic",
  "cohere",
  "mistral",
  // Add additional permitted route segments here as needed
]);

/**
 * Returns the API path only if the llm segment is in the allowlist.
 * Falls back to an empty string (no-op) for unknown/untrusted values.
 */
function sanitizeLlmRoute(llm: unknown): string {
  if (typeof llm !== "string") return "";
  const segment = llm.trim();
  if (!ALLOWED_LLM_ROUTES.has(segment)) return "";
  return segment;
}

/**
 * Strips characters that could enable HTTP header injection
 * (CR, LF, NUL, and other control characters).
 */
function sanitizeHeaderValue(value: unknown): string {
  if (typeof value !== "string") return "";
  // Remove carriage return, line feed, NUL, and all other ASCII control chars
  return value.replace(/[\r\n\x00-\x1F\x7F]/g, "");
}

// Patterns that indicate potentially malicious prompt injection attempts
const MALICIOUS_PATTERNS: RegExp[] = [
  // Hidden/system prompt injection
  /ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)/i,
  /system\s*prompt/i,
  /you\s+are\s+now/i,
  /act\s+as\s+(a\s+)?(different|new|another|evil|unrestricted)/i,
  /pretend\s+(you\s+are|to\s+be)/i,
  /forget\s+(everything|all|your|previous)/i,
  /disregard\s+(all|previous|prior|your)/i,
  /override\s+(your|all|previous)\s*(instructions?|rules?|constraints?)/i,
  /new\s+(instructions?|directives?|rules?|persona)/i,
  /\[INST\]|\[SYS\]|<\|system\|>|<\|user\|>|<\|assistant\|>/i,
  /###\s*(instruction|system|human|assistant)/i,
  // Base64-encoded content (long base64 strings)
  /(?:[A-Za-z0-9+\/]{40,}={0,2})/,
  // Shell commands
  /(?:^|\s|;|&&|\|\|)(rm\s+-rf|chmod\s+|chown\s+|sudo\s+|curl\s+|wget\s+|bash\s+|sh\s+|exec\s+|eval\s+|system\s*\()/i,
  /`[^`]+`/,
  /\$\([^)]+\)/,
  // Binary/executable indicators
  /\\x[0-9a-fA-F]{2}/,
  /\\u[0-9a-fA-F]{4}/g,
  // Leetspeak patterns for common injection phrases
  /1gn[o0]r[e3]\s+[a4]ll/i,
  /[s5]y[s5][t7][e3]m\s+[p9]r[o0]m[p9][t7]/i,
  // Prompt delimiter abuse
  /[-]{3,}|[=]{3,}|[*]{3,}/,
  // Jailbreak keywords
  /jailbreak|DAN\b|do\s+anything\s+now/i,
  /unrestricted\s+mode|developer\s+mode|god\s+mode/i,
  /bypass\s+(safety|filter|restriction|guideline)/i,
];

function containsMaliciousContent(text: string): boolean {
  if (!text || text.trim().length === 0) return false;
  return MALICIOUS_PATTERNS.some((pattern) => pattern.test(text));
}

const DANGEROUS_PATTERNS = [
  /\beval\s*\(/gi,
  /\bexec\s*\(/gi,
  /new\s+Function\s*\(/gi,
  /setTimeout\s*\(\s*['"`]/gi,
  /setInterval\s*\(\s*['"`]/gi,
  /\bimportScripts\s*\(/gi,
  /document\.write\s*\(/gi,
  /\.innerHTML\s*=/gi,
  /\.outerHTML\s*=/gi,
  /\bexecScript\s*\(/gi,
];

function sanitizeLLMOutput(output: string): string {
  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.test(output)) {
      console.warn("Potentially dangerous content detected in LLM output and blocked.");
      return "[Response blocked: potentially unsafe content detected.]";
    }
  }
  return output;
}

const APPROVED_LLMS: string[] = [
  "claude",
  "llama",
  "mistral",
];

function getApprovedLlmEndpoint(llm: string): string {
  if (!llm || llm === "") return "";
  if (!APPROVED_LLMS.includes(llm)) {
    throw new Error(`LLM '${llm}' is not on the organization's approved list.`);
  }
  return "/api/" + llm;
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
  const { data: session, status } = useSession();

  if (!example) {
    // create a dummy so the completion doesn't croak during init.
    example = new Object();
    example.llm = "";
    example.name = "";
  }

  // Allowlist of permitted LLM API endpoint path segments.
  const ALLOWED_LLM_ENDPOINTS: string[] = [
    "openai",
    "anthropic",
    "cohere",
    "mistral",
  ];

  const safeLlmEndpoint: string =
    typeof example.llm === "string" && ALLOWED_LLM_ENDPOINTS.includes(example.llm)
      ? example.llm
      : "";

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
    api: getApprovedLlmEndpoint(example.llm),
    headers: { name: example.name },
  });

  let [blocks, setBlocks] = useState<any[] | null>(null)
  let [provenance, setProvenance] = useState<{ model: string; timestamp: string; origin: string } | null>(null)

      useEffect(() => {
    // When the completion changes, parse it to multimodal blocks for display.
    if (completion) {
      setBlocks(responseToChatBlocks(completion));

      // --- Audit / forensic logging ---
      if (!isLoading && pendingAuditRef.current) {
        const pending = pendingAuditRef.current;
        const record: AuditRecord = {
          traceId: pending.traceId,
          timestamp: new Date().toISOString(),
          modelId: pending.modelId,
          principal: pending.principal,
          inputHash: pending.inputHash,
          input: pending.input,
          output: completion,
        };
        writeAuditRecord(record);
        pendingAuditRef.current = null;
      }
    } else {
      setBlocks(null);
    }
  }, [completion, isLoading])

  if (!example) {
    console.log("ERROR: no companion selected");
    return null;
  }

  const MAX_INPUT_LENGTH = 1000;

  const sanitizeInput = (value: string): string => {
    // Trim whitespace
    let sanitized = value.trim();
    // Remove null bytes and other control characters
    sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
    // Truncate to max length
    sanitized = sanitized.slice(0, MAX_INPUT_LENGTH);
    return sanitized;
  };

  const validateInput = (value: string): string | null => {
    if (!value || value.length === 0) {
      return "Input must not be empty.";
    }
    if (value.length > MAX_INPUT_LENGTH) {
      return `Input must not exceed ${MAX_INPUT_LENGTH} characters.`;
    }
    // Reject prompt injection patterns
    const injectionPatterns = [
      /ignore (all |previous |above )?instructions/i,
      /system\s*:/i,
      /\[INST\]/i,
      /<\|.*?\|>/i,
    ];
    for (const pattern of injectionPatterns) {
      if (pattern.test(value)) {
        return "Input contains disallowed content.";
      }
    }
    return null;
  };

  const handleValidatedSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const sanitized = sanitizeInput(input);
    const validationError = validateInput(sanitized);
    if (validationError) {
      // Silently reject invalid input without submitting
      return;
    }
    setInput(sanitized);
    handleSubmit(e);
  };

  const [inputError, setInputError] = useState<string | null>(null);

  const safeHandleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setInputError(null);
    handleInputChange(e);
  };

  const safeHandleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (containsMaliciousContent(input)) {
      setInputError("Your message contains content that cannot be processed. Please rephrase your question.");
      return;
    }
    handleSubmit(e);
  };

  const handleClose = () => {
    setInput("");
    setCompletion("");
    stop();
    setOpen(false);
  };

  const guardedHandleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!session || !session.user) {
      console.warn("Unauthenticated submit attempt blocked.");
      return;
    }
    handleSubmit(e);
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
                      onChange={safeHandleInputChange}
                      disabled={isLoading && !blocks}
                      aria-invalid={!!inputError}
                    />
                    {inputError && (
                      <p className="mt-1 text-sm text-red-400" role="alert">{inputError}</p>
                    )}
                  </form>
                  <div className="mt-3 sm:mt-5">
                    <div className="mt-2">
                      <p className="text-sm text-gray-500">
                        Chat with {example.name}
                      </p>
                    </div>
                    {blocks && provenance && (
                      <div className="mt-2">
                        {/* AI Content Provenance Watermark — do not remove */}
                        <div
                          className="flex items-center gap-2 rounded-md bg-yellow-900/60 border border-yellow-500 px-3 py-1.5 mb-2 text-xs text-yellow-300"
                          aria-label="AI-generated content label"
                          data-ai-origin={provenance.origin}
                          data-ai-model={provenance.model}
                          data-ai-timestamp={provenance.timestamp}
                        >
                          <span className="font-bold uppercase tracking-wide">⚠ AI-Generated Content</span>
                          <span className="mx-1">·</span>
                          <span>Model: <span className="font-mono">{provenance.model}</span></span>
                          <span className="mx-1">·</span>
                          <span>Generated: {provenance.timestamp}</span>
                        </div>
                        {blocks}
                        <div
                          className="mt-1 text-xs text-gray-500 select-none"
                          aria-hidden="true"
                          data-watermark="ai-synthetic-content"
                          data-watermark-model={provenance.model}
                          data-watermark-timestamp={provenance.timestamp}
                        >
                          {/* Watermark: synthetic content · {provenance.origin} · {provenance.timestamp} */}
                          This response was synthetically generated by an AI model ({provenance.model}) and may not reflect factual information.
                        </div>
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
