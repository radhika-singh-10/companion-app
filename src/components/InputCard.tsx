"use client";
import { useState } from "react";

function sanitizeUrl(raw: string): string {
  // Trim whitespace
  let value = raw.trim();
  // Remove null bytes and control characters
  value = value.replace(/[\x00-\x1F\x7F]/g, "");
  return value;
}

function validateUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    // Only allow http and https protocols
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

"use client";
import { useState } from "react";

// Patterns indicative of prompt injection, shell commands, base64 payloads,
// leetspeak obfuscation, binary/executable content, or hidden instructions.
const INJECTION_PATTERNS: RegExp[] = [
  // Hidden / system prompt injection keywords
  /ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)/i,
  /system\s*prompt/i,
  /you\s+are\s+now/i,
  /act\s+as\s+(an?\s+)?/i,
  /disregard\s+(all|any|previous)/i,
  /forget\s+(everything|all|previous)/i,
  /new\s+instructions?/i,
  /override\s+(instructions?|prompt)/i,
  // Shell command indicators
  /[`$]\s*\(/,                        // backtick or $( subshell
  /;\s*(rm|ls|cat|wget|curl|bash|sh|python|perl|ruby|nc|ncat|chmod|chown|sudo|su|exec|eval)\b/i,
  /\|\s*(bash|sh|python|perl|ruby|nc|ncat|exec|eval)\b/i,
  /&&\s*(rm|ls|cat|wget|curl|bash|sh|python|perl|ruby|nc|ncat|chmod|chown|sudo|su|exec|eval)\b/i,
  // Binary / executable file extensions in the URL path
  /\.(exe|bat|cmd|sh|bin|elf|dll|so|dylib|ps1|vbs|jar|py|rb|pl)(\?|#|$)/i,
  // Base64-encoded blobs (long runs of base64 chars, possibly with padding)
  /[A-Za-z0-9+\/]{40,}={0,2}/,
  // Leetspeak obfuscation heuristic: mixed digit-letter substitutions in suspicious words
  /[i1][g9][n][o0][r3][e3]/i,
  /[s5][y][s5][t7][e3][m]/i,
  /[p][r][o0][m][p][t7]/i,
  // Null bytes or non-printable characters
  // eslint-disable-next-line no-control-regex
  /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/,
  // Data URIs
  /^data:/i,
  // JavaScript URIs
  /^javascript:/i,
];

function containsInjection(value: string): boolean {
  const decoded = (() => {
    try {
      return decodeURIComponent(value);
    } catch {
      return value;
    }
  })();
  return INJECTION_PATTERNS.some(
    (pattern) => pattern.test(value) || pattern.test(decoded)
  );
}

function isValidHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

export default function InputCard() {
  const [inputValue, setInputValue] = useState("");
  const [error, setError] = useState<string | null>(null);

  function handleChange(e: React.ChangeEvent<HTMLInputElement>) {
    setInputValue(e.target.value);
    setError(null);
  }

  function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    const trimmed = inputValue.trim();

    if (!isValidHttpUrl(trimmed)) {
      e.preventDefault();
      setError("Please enter a valid http:// or https:// URL.");
      return;
    }

    if (containsInjection(trimmed)) {
      e.preventDefault();
      setError(
        "The URL contains disallowed content. Please enter a plain blog URL."
      );
      return;
    }
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
          className="w-full rounded-md border-0 bg-white/5 px-3.5 py-2 text-white shadow-sm ring-1 ring-inset ring-white/10 focus:ring-2 focus:ring-inset focus:ring-white sm:text-sm sm:leading-6"
          placeholder="Enter a link to a blog"
        />
        {error && (
          <p className="mt-1 text-sm text-red-400" role="alert">
            {error}
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

  function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const sanitized = sanitizeUrl(link);
    if (!validateUrl(sanitized)) {
      setError("Please enter a valid http or https URL.");
      return;
    }
    setError("");
    // Submit sanitized value — replace this with your actual submission logic
    const form = e.currentTarget;
    const data = new FormData(form);
    data.set("link", sanitized);
    // TODO: pass `data` to your AI model submission handler here
  }

  return (
    <form
      className="mx-auto mt-16 flex max-w-3xl gap-x-4 flex-wrap"
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
          value={link}
          onChange={handleChange}
          className="w-full rounded-md border-0 bg-white/5 px-3.5 py-2 text-white shadow-sm ring-1 ring-inset ring-white/10 focus:ring-2 focus:ring-inset focus:ring-white sm:text-sm sm:leading-6"
          placeholder="Enter a link to a blog"
        />
        {error && (
          <p className="mt-1 text-sm text-red-400" role="alert">
            {error}
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
