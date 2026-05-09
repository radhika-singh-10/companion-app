import dotenv from "dotenv";

dotenv.config({ path: `.env.local` });

import { Fragment, useState } from "react";
import { Dialog, Transition } from "@headlessui/react";
import Image from "next/image";

export default function TextToImgModal({
  open,
  setOpen,
}: {
  open: boolean;
  setOpen: any;
}) {
    const [imgSrc, setImgSrc] = useState("");

  /**
   * Validates and sanitizes LLM image output.
   * Checks for dynamic code execution primitives and ensures the value
   * is a valid image URL (http/https) or base64 data URI.
   * Returns the sanitized string if safe, or null if invalid/unsafe.
   */
  function sanitizeLLMImageOutput(value: unknown): string | null {
    if (typeof value !== "string") return null;

    // Check for dynamic code execution primitives
    const dangerousPatterns = [
      /\beval\s*\(/i,
      /\bexec\s*\(/i,
      /\bFunction\s*\(/i,
      /\bnew\s+Function\b/i,
      /\bsetTimeout\s*\(\s*['"`]/i,
      /\bsetInterval\s*\(\s*['"`]/i,
      /\bimportScripts\s*\(/i,
      /javascript\s*:/i,
      /data\s*:\s*text\s*\/\s*(html|javascript)/i,
      /<\s*script/i,
    ];

    for (const pattern of dangerousPatterns) {
      if (pattern.test(value)) {
        console.error("LLM output contains dangerous pattern:", pattern);
        return null;
      }
    }

    // Allow only http/https URLs or base64 image data URIs
    const isHttpUrl = /^https?:\/\/.+/i.test(value);
    const isBase64Image = /^data:image\/(png|jpeg|jpg|gif|webp|svg\+xml);base64,[A-Za-z0-9+/=]+$/.test(value);

    if (!isHttpUrl && !isBase64Image) {
      console.error("LLM output is not a valid image URL or base64 data URI.");
      return null;
    }

    return value;
  }
  const [loading, setLoading] = useState(false);

  /**
   * Sanitize user-supplied prompt before sending to the MCP server.
   * Allows only printable ASCII characters (letters, digits, spaces,
   * and common punctuation). Strips everything else and trims whitespace.
   */
  const sanitizePrompt = (raw: string): string => {
    // Remove any character that is not a printable ASCII character
    return raw.replace(/[^\x20-\x7E]/g, "").trim();
  };

  /**
   * Validate the image URL returned by the MCP server.
   * Accepts only http/https URLs or base64 data URIs for common image types.
   */
  const validateImageSrc = (src: unknown): string => {
    if (typeof src !== "string" || src.trim() === "") {
      throw new Error("Invalid image source: expected a non-empty string.");
    }
    const trimmed = src.trim();
    const httpsPattern = /^https?:\/\/.+/i;
    const dataUriPattern = /^data:image\/(png|jpeg|jpg|gif|webp);base64,[A-Za-z0-9+/]+=*$/;
    if (!httpsPattern.test(trimmed) && !dataUriPattern.test(trimmed)) {
      throw new Error(
        "Invalid image source: URL must be http/https or a base64 image data URI."
      );
    }
    return trimmed;
  };

  const onSubmit = async (e: any) => {
    e.preventDefault();
    setLoading(true);
    try {
      const rawPrompt: string =
        typeof e.target.value === "string" ? e.target.value : "";
      const sanitizedPrompt = sanitizePrompt(rawPrompt);

          const rawPrompt: string = e.target.value ?? "";
    const safePrompt = sanitizePrompt(rawPrompt);
    if (!safePrompt) {
      setLoading(false);
      alert("Your prompt contains disallowed content. Please revise and try again.");
      return;
    }
        const apiSecret = process.env.NEXT_PUBLIC_API_SECRET;
    if (!apiSecret) {
      throw new Error("API secret is not configured. Set NEXT_PUBLIC_API_SECRET in your environment.");
    }
    const response = await fetch("/api/txt2img", {
      method: "POST",
      body: JSON.stringify({
        prompt: e.target.value,
      }),
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${apiSecret}`,
      },
    });

      if (!response.ok) {
        throw new Error(`Server responded with status ${response.status}`);
      }

      const data = await response.json();

      // Validate the MCP server output before using it as an image source
      const validatedSrc = validateImageSrc(Array.isArray(data) ? data[0] : data);
      setImgSrc(validatedSrc);
    } catch (err) {
      console.error("TextToImgModal error:", err);
      setImgSrc("");
    } finally {
      setLoading(false);
    }
  };
    console.log("[MCP Request] POST /api/txt2img", { payload: requestPayload, timestamp: new Date().toISOString() });
    const response = await fetch("/api/txt2img", {
      method: "POST",
      body: JSON.stringify(requestPayload),
      headers: {
        "Content-Type": "application/json",
      },
    });
    const data = await response.json();
    console.log("[MCP Response] POST /api/txt2img", { status: response.status, data, timestamp: new Date().toISOString() });
    setImgSrc(data[0]);
    setLoading(false);
  };
  return (
    <Transition.Root show={open} as={Fragment}>
      <Dialog as="div" className="relative z-10" onClose={setOpen}>
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
                  <input
                    className="w-full flex-auto rounded-md border-0 bg-white/5 px-3.5 py-2 text-white shadow-sm focus:outline-none  sm:text-sm sm:leading-6"
                    placeholder="Describe the image you want"
                    value={promptValue}
                    onChange={(e) => setPromptValue(e.target.value)}
                    // when user click enter key, submit the form
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        onSubmit(e);
                      }
                    }}
                  ></input>
                  <div className="mt-3">
                    <div className="my-2">
                      <p className="text-sm text-gray-500">
                        Powered by an approved image generation service
                        >
                          stability-ai/stable-diffusion
                        </a>
                      </p>
                    </div>
                  </div>
                </div>
                {imgSrc && !loading && (
                  <Image
                    width={0}
                    height={0}
                    sizes="100vw"
                    src={imgSrc}
                    alt="img"
                    className="w-full h-full object-contain"
                  />
                )}
                {loading && (
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
              </Dialog.Panel>
            </Transition.Child>
          </div>
        </div>
      </Dialog>
    </Transition.Root>
  );
}
