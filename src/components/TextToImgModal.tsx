import dotenv from "dotenv";

dotenv.config({ path: `.env.local` });

// Approved model registry entry — do NOT change without a registry approval ticket.
// Registry: internal-model-registry / stable-diffusion
// Approved version digest (immutable): ac732df83cea7fff18b8472768c88ad041fa750d
const APPROVED_MODEL_ID = "stability-ai/stable-diffusion";
const APPROVED_MODEL_VERSION = "ac732df83cea7fff18b8472768c88ad041fa750d";
const APPROVED_MODEL_REGISTRY_URL =
  "https://internal-model-registry.example.com/models/stability-ai/stable-diffusion/ac732df83cea7fff18b8472768c88ad041fa750d";

import { Fragment, useState } from "react";
import { useSession, signIn } from "next-auth/react";
import { Dialog, Transition } from "@headlessui/react";
import Image from "next/image";

const DYNAMIC_CODE_EXECUTION_PATTERNS = [
  /\beval\s*\(/i,
  /\bexec\s*\(/i,
  /\bFunction\s*\(/i,
  /\bsetTimeout\s*\(/i,
  /\bsetInterval\s*\(/i,
  /\bnew\s+Function\b/i,
  /javascript\s*:/i,
  /data\s*:\s*text\/html/i,
  /<script[\s>]/i,
];

function sanitizeLLMImageOutput(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }

  // Check for dynamic code execution primitives
  for (const pattern of DYNAMIC_CODE_EXECUTION_PATTERNS) {
    if (pattern.test(value)) {
      console.error("LLM output contains forbidden pattern:", pattern);
      return null;
    }
  }

  // Allow only valid http/https URLs or base64 image data URIs
  const isHttpUrl = /^https?:\/\/.+/i.test(value);
  const isBase64Image = /^data:image\/(png|jpeg|jpg|gif|webp);base64,[A-Za-z0-9+/=]+$/.test(value);

  if (!isHttpUrl && !isBase64Image) {
    console.error("LLM output is not a valid image URL or base64 data URI.");
    return null;
  }

  return value;
}

export default function TextToImgModal({
  open,
  setOpen,
}: {
  open: boolean;
  setOpen: any;
}) {
    const [imgSrc, setImgSrc] = useState("");
  const [imgError, setImgError] = useState("");

  // Allowlist of trusted image-source hostname suffixes
  const ALLOWED_IMG_HOSTS = [
    "cdn.openai.com",
    "oaidalleapiprodscus.blob.core.windows.net",
    "replicate.delivery",
    "pbxt.replicate.delivery",
  ];

  const isAllowedImgUrl = (url: string): boolean => {
    try {
      const parsed = new URL(url);
      if (parsed.protocol !== "https:") return false;
      return ALLOWED_IMG_HOSTS.some(
        (host) => parsed.hostname === host || parsed.hostname.endsWith("." + host)
      );
    } catch {
      return false;
    }
  };

  const MAX_PROMPT_LENGTH = 500;

  const sanitizePrompt = (raw: string): string => {
    // Remove ASCII control characters (except normal whitespace) and trim
    return raw
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
      .trim()
      .slice(0, MAX_PROMPT_LENGTH);
  };
  const [loading, setLoading] = useState(false);
  const [provenance, setProvenance] = useState<{
    model: string;
    timestamp: string;
    origin: string;
  } | null>(null);

  /**
   * Applies a visible steganographic-style text watermark to a base64 image
   * and returns a new base64 data-URL with the watermark burned in.
   */
  const applyWatermark = (
    base64Src: string,
    watermarkText: string
  ): Promise<string> => {
    return new Promise((resolve) => {
      const img = new window.Image();
      img.onload = () => {
        const canvas = document.createElement("canvas");
        canvas.width = img.naturalWidth || img.width;
        canvas.height = img.naturalHeight || img.height;
        const ctx = canvas.getContext("2d")!;
        ctx.drawImage(img, 0, 0);
        // Watermark styling
        const fontSize = Math.max(14, Math.floor(canvas.width / 40));
        ctx.font = `bold ${fontSize}px sans-serif`;
        ctx.fillStyle = "rgba(255, 255, 255, 0.55)";
        ctx.strokeStyle = "rgba(0, 0, 0, 0.45)";
        ctx.lineWidth = 2;
        ctx.textAlign = "right";
        ctx.textBaseline = "bottom";
        const padding = 10;
        ctx.strokeText(watermarkText, canvas.width - padding, canvas.height - padding);
        ctx.fillText(watermarkText, canvas.width - padding, canvas.height - padding);
        resolve(canvas.toDataURL("image/png"));
      };
      img.src = base64Src.startsWith("data:")
        ? base64Src
        : `data:image/png;base64,${base64Src}`;
    });
  };
  const [promptValue, setPromptValue] = useState("");
  const [inputError, setInputError] = useState("");

  const MAX_PROMPT_LENGTH = 500;

  const sanitizeAndValidatePrompt = (input: string): { valid: boolean; sanitized: string; error: string } => {
    // Trim whitespace
    let sanitized = input.trim();

    // Reject empty input
    if (!sanitized) {
      return { valid: false, sanitized: "", error: "Prompt cannot be empty." };
    }

    // Enforce maximum length
    if (sanitized.length > MAX_PROMPT_LENGTH) {
      return { valid: false, sanitized: "", error: `Prompt must be ${MAX_PROMPT_LENGTH} characters or fewer.` };
    }

    // Strip characters that are not alphanumeric, spaces, or common punctuation safe for prompts
    sanitized = sanitized.replace(/[^\w\s.,!?'"()\-]/g, "");

    // After stripping, ensure the result is still non-empty
    if (!sanitized.trim()) {
      return { valid: false, sanitized: "", error: "Prompt contains invalid characters only." };
    }

    return { valid: true, sanitized, error: "" };
  };

  const onSubmit = async (e: any) => {
    e.preventDefault();
    setInputError("");

    const { valid, sanitized, error } = sanitizeAndValidatePrompt(promptValue);
    if (!valid) {
      setInputError(error);
      return;
    }

    setLoading(true);
        const rawPrompt: string = (e.target as HTMLInputElement).value ?? "";
    const safePrompt = sanitizePrompt(rawPrompt);
    if (!safePrompt) {
      setLoading(false);
      return;
    }
        const response = await fetch("/api/txt2img", {
      method: "POST",
      body: JSON.stringify({
        prompt: e.target.value,
        // Model identity recorded at inference time per policy requirement.
        modelId: APPROVED_MODEL_ID,
        modelVersion: APPROVED_MODEL_VERSION,
      }),
      headers: {
        "Content-Type": "application/json",
      },
    });
    const data = await response.json();
    const generatedAt = new Date().toISOString();
    const modelId = "stable-diffusion-v1-5";
    const originTag = "AI-GENERATED";
    const watermarkText = `${originTag} | ${modelId} | ${generatedAt}`;
    const rawSrc: string = data[0];
    const watermarkedSrc = await applyWatermark(rawSrc, watermarkText);
    setProvenance({ model: modelId, timestamp: generatedAt, origin: originTag });
    setImgSrc(watermarkedSrc);
    setLoading(false);
  };
  const [loading, setLoading] = useState(false);
  const onSubmit = async (e: any) => {
    e.preventDefault();
    setLoading(true);
    const requestPayload = { prompt: e.target.value };
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
    const sanitized = sanitizeImageSrc(data[0]);
    setImgSrc(sanitized);
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
                  {promptError && (
                    <p className="text-red-400 text-sm mb-2" role="alert">
                      {promptError}
                    </p>
                  )}
                  <input
                    className="w-full flex-auto rounded-md border-0 bg-white/5 px-3.5 py-2 text-white shadow-sm focus:outline-none  sm:text-sm sm:leading-6"
                    placeholder="Describe the image you want"
                    value={promptValue}
                    maxLength={500}
                    onChange={(e) => {
                      setPromptValue(e.target.value);
                      setInputError("");
                    }}
                    // when user click enter key, submit the form
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        onSubmit(e);
                      }
                    }}
                  ></input>
                  {imgError && (
                    <p className="mt-2 text-sm text-red-400">{imgError}</p>
                  )}
                  <div className="mt-3">
                    <div className="my-2">
                      <p className="text-sm text-gray-500">
                        Powered by{" "}
                        an approved image generation model
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
