"use client";
import { useState } from "react";

function sanitizeAndValidateUrl(raw: string): { url: string; error: string | null } {
  // Trim whitespace
  const trimmed = raw.trim();

  // Strip null bytes and control characters
  const stripped = trimmed.replace(/[\x00-\x1F\x7F]/g, "");

  // Only allow http and https schemes (blocks javascript:, data:, vbscript:, etc.)
  let parsed: URL;
  try {
    parsed = new URL(stripped);
  } catch {
    return { url: "", error: "Please enter a valid URL." };
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { url: "", error: "Only http and https URLs are allowed." };
  }

  // Reject URLs with credentials embedded (e.g. http://user:pass@host)
  if (parsed.username || parsed.password) {
    return { url: "", error: "URLs with embedded credentials are not allowed." };
  }

  // Return the normalized, serialized URL (browser-normalized, no raw user string)
  return { url: parsed.toString(), error: null };
}

"use client";
import { useState, FormEvent } from "react";

// Patterns that indicate prompt injection or malicious content
const INVISIBLE_CHARS_RE = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/;
const SHELL_COMMAND_RE = /(?:^|[\s;&|`$])(?:bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess|wget|curl|nc|ncat|netcat|python|perl|ruby|php|node|rm\s+-rf|chmod|chown|sudo|su\s|passwd|dd\s|mkfs|format\s)/i;
const BINARY_MAGIC_RE = /^(?:[\x00-\x08\x0E-\x1F\x7F]|\x7fELF|MZ\x90)/;
const BASE64_INJECTION_RE = /(?:data:[^,]*;base64,|(?:[A-Za-z0-9+/]{40,}={0,2}))/;
const LEETSPEAK_INJECTION_RE = /(?:[i!1][g9][n][o0][r][e]|[i!1][g9][n][o0][r][e]\s+(?:previous|above|prior|all)|[f][o0][r][g9][e3][t]\s+(?:previous|above|prior|all)|[s5][y][s5][t][e3][m]\s+[p][r][o0][m][p][t])/i;
const PROMPT_INJECTION_RE = /(?:ignore\s+(?:previous|above|prior|all)|forget\s+(?:previous|above|prior|all)|disregard\s+(?:previous|above|prior|all)|you\s+are\s+now|new\s+instructions?:|system\s*:\s*|assistant\s*:\s*|\[INST\]|<\|(?:im_start|im_end|system|user|assistant)\|>|###\s*(?:instruction|system|human|assistant))/i;

function screenInput(value: string): { safe: boolean; reason: string } {
  if (INVISIBLE_CHARS_RE.test(value)) {
    return { safe: false, reason: "Input contains invisible or zero-width characters." };
  }
  if (BINARY_MAGIC_RE.test(value)) {
    return { safe: false, reason: "Input contains binary or executable content." };
  }
  if (BASE64_INJECTION_RE.test(value)) {
    return { safe: false, reason: "Input contains suspicious base64-encoded content." };
  }
  if (SHELL_COMMAND_RE.test(value)) {
    return { safe: false, reason: "Input contains shell command patterns." };
  }
  if (LEETSPEAK_INJECTION_RE.test(value)) {
    return { safe: false, reason: "Input contains obfuscated injection patterns." };
  }
  if (PROMPT_INJECTION_RE.test(value)) {
    return { safe: false, reason: "Input contains prompt injection patterns." };
  }
  // Enforce that the value is a plain HTTPS/HTTP URL with no extra query trickery
  try {
    const parsed = new URL(value);
    if (!['https:', 'http:'].includes(parsed.protocol)) {
      return { safe: false, reason: "Only http and https URLs are allowed." };
    }
    // Re-screen the decoded components individually
    const components = [parsed.hostname, parsed.pathname, parsed.search, parsed.hash];
    for (const part of components) {
      const decoded = decodeURIComponent(part);
      if (
        INVISIBLE_CHARS_RE.test(decoded) ||
        SHELL_COMMAND_RE.test(decoded) ||
        PROMPT_INJECTION_RE.test(decoded) ||
        LEETSPEAK_INJECTION_RE.test(decoded) ||
        BASE64_INJECTION_RE.test(decoded)
      ) {
        return { safe: false, reason: "URL components contain suspicious content." };
      }
    }
  } catch {
    return { safe: false, reason: "Invalid URL format." };
  }
  return { safe: true, reason: "" };
}

export default function InputCard() {
  const [inputValue, setInputValue] = useState("");
  const [error, setError] = useState("");

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError("");
    const result = screenInput(inputValue);
    if (!result.safe) {
      setError(`Submission blocked: ${result.reason}`);
      return;
    }
    // Safe to proceed — submit the form or call your handler here
    (e.currentTarget as HTMLFormElement).submit();
  }

  return (
    <>
      <form
        className="mx-auto mt-16 flex max-w-3xl gap-x-4"
        onSubmit={handleSubmit}
      >
        <label htmlFor="website-link" className="sr-only">
          Link
        </label>
        <input
          autoFocus={true}
          id="website-link"
          name="link"
          type="url"
          autoComplete="url"
          required
          value={inputValue}
          onChange={(e) => {
            setError("");
            setInputValue(e.target.value);
          }}
          className="min-w-0 flex-auto rounded-md border-0 bg-white/5 px-3.5 py-2 text-white shadow-sm ring-1 ring-inset ring-white/10 focus:ring-2 focus:ring-inset focus:ring-white sm:text-sm sm:leading-6"
          placeholder="Enter a link to a blog"
        />
        <button
          type="submit"
          className="flex-none rounded-md bg-white px-3.5 py-2.5 text-sm font-semibold text-gray-900 shadow-sm hover:bg-gray-100 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-white"
        >
          Chat
        </button>
      </form>
      {error && (
        <p role="alert" className="mx-auto mt-2 max-w-3xl text-sm text-red-400">
          {error}
        </p>
      )}
    </>
  );
}

  function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const { url, error } = sanitizeAndValidateUrl(inputValue);
    if (error) {
      setValidationError(error);
      return;
    }
    // Replace the raw input with the sanitized, validated URL before forwarding
    const form = e.currentTarget;
    const linkInput = form.elements.namedItem("link") as HTMLInputElement;
    linkInput.value = url;
    // TODO: pass `url` to the AI model invocation layer here
  }

  return (
    <form
      className="mx-auto mt-16 flex max-w-3xl gap-x-4"
      onSubmit={handleSubmit}
    >
      <label htmlFor="website-link" className="sr-only">
        Link
      </label>
      <div className="min-w-0 flex-auto">
        <input
          autoFocus={true}
          id="website-link"
          name="link"
          type="url"
          autoComplete="url"
          required
          value={inputValue}
          onChange={handleChange}
          aria-describedby={validationError ? "link-error" : undefined}
          aria-invalid={validationError ? true : undefined}
          className="w-full rounded-md border-0 bg-white/5 px-3.5 py-2 text-white shadow-sm ring-1 ring-inset ring-white/10 focus:ring-2 focus:ring-inset focus:ring-white sm:text-sm sm:leading-6"
          placeholder="Enter a link to a blog"
        />
        {validationError && (
          <p id="link-error" className="mt-1 text-sm text-red-400" role="alert">
            {validationError}
          </p>
        )}
      </div>
      <button
        type="submit"
        className="flex-none rounded-md bg-white px-3.5 py-2.5 text-sm font-semibold text-gray-900 shadow-sm hover:bg-gray-100 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-white"
      >
        Chat
      </button>
    </form>
  );
}
