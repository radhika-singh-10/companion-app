/*
 * Represents a unit of multimodal chat: text, video, audio, or image.
 *
 * For streaming responses, just update the `text` argument.
 */
export interface Provenance {
    modelId?: string;
    timestamp?: string;
    contentOrigin?: string;
}

export function ChatBlock({text, mimeType, url, provenance} : {
    text?: string,
    mimeType?: string,
    url?: string,
    provenance?: Provenance
}) {
    // Build a stable provenance record so every AI-generated block carries origin metadata.
    const prov: Provenance = {
        modelId: provenance?.modelId ?? "unknown-model",
        timestamp: provenance?.timestamp ?? new Date().toISOString(),
        contentOrigin: provenance?.contentOrigin ?? "ai-generated",
    };

    // Watermark attribute string embedded in media elements.
    const watermarkAttr = `ai-generated|model:${prov.modelId}|ts:${prov.timestamp}`;

    let internalComponent = <></>
    if (text) {
        internalComponent = <span>{text}</span>
        } else if (mimeType && url) {
        const safeUrl = sanitizeUrl(url);
        if (safeUrl) {
            if (mimeType.startsWith("audio")) {
                internalComponent = <audio controls={true} src={safeUrl} />
            } else if (mimeType.startsWith("video")) {
                internalComponent = <video controls width="250">
                    <source src={safeUrl} type={mimeType} />
                    Download the <a href={safeUrl}>video</a>
                </video>
            } else if (mimeType.startsWith("image")) {
                internalComponent = <img src={safeUrl} />
            }
        } else {
            internalComponent = <span>[Blocked: unsafe URL]</span>
        }
    } else if (url) {
        const safeUrl = sanitizeUrl(url);
        if (safeUrl) {
            internalComponent = <a href={safeUrl}>Link</a>
        } else {
            internalComponent = <span>[Blocked: unsafe URL]</span>
        }
    } else if (mimeType && url) {
        if (mimeType.startsWith("audio")) {
            internalComponent = <audio
                controls={true}
                src={url}
                data-ai-watermark={watermarkAttr}
                aria-label="AI-generated audio"
            />
        } else if (mimeType.startsWith("video")) {
            internalComponent = <video
                controls
                width="250"
                data-ai-watermark={watermarkAttr}
                aria-label="AI-generated video"
            >
                <source src={url} type={mimeType} />
                Download the <a href={url}>video</a>
            </video>
        } else if (mimeType.startsWith("image")) {
            internalComponent = <img
                src={url}
                data-ai-watermark={watermarkAttr}
                alt="AI-generated image"
            />
        }
    } else if (url) {
        internalComponent = <a href={url}>Link</a>
    }

    return (
        <p
            className="text-sm text-gray-200 pb-2"
            data-ai-provenance={JSON.stringify(prov)}
        >
            {/* AI-generated content label */}
            <span
                className="inline-block text-xs font-semibold text-yellow-400 border border-yellow-400 rounded px-1 mr-2"
                title={`Model: ${prov.modelId} | Generated: ${prov.timestamp} | Origin: ${prov.contentOrigin}`}
                aria-label="AI-generated content"
            >
                ⚠ AI-generated
            </span>
            {internalComponent}
        </p>
    );
}

// Patterns that indicate dangerous dynamic code execution primitives in LLM output.
const DANGEROUS_PATTERNS: RegExp[] = [
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /\bnew\s+Function\s*\(/i,
    /\bsetTimeout\s*\(\s*['"`]/i,
    /\bsetInterval\s*\(\s*['"`]/i,
    /\bimportScripts\s*\(/i,
    /\bdocument\.write\s*\(/i,
    /\binnerHTML\s*=/i,
    /\bouterHTML\s*=/i,
    /\bjavascript\s*:/i,
    /<\s*script[\s>]/i,
];

/**
 * Checks a string for dangerous dynamic code execution primitives.
 * Throws an error if any are found.
 */
function assertNoDangerousContent(value: string, context: string = "LLM output"): void {
    for (const pattern of DANGEROUS_PATTERNS) {
        if (pattern.test(value)) {
            throw new Error(
                `Security violation: Dangerous pattern detected in ${context}: ${pattern.toString()}`
            );
        }
    }
}

/**
 * Sanitizes a string field from LLM output by stripping non-printable characters
 * and asserting no dangerous code execution primitives are present.
 */
function sanitizeString(value: unknown, fieldName: string = "field"): string {
    if (typeof value !== "string") {
        return "";
    }
    // Strip null bytes and other non-printable control characters (except common whitespace).
    const sanitized = value.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
    assertNoDangerousContent(sanitized, fieldName);
    return sanitized;
}

/**
 * Validates and sanitizes a ChatBlock-shaped object from LLM output.
 * Only allows known safe fields (text, mimeType, url) with string values.
 */
function sanitizeBlock(block: any): { text?: string; mimeType?: string; url?: string } {
    if (typeof block !== "object" || block === null || Array.isArray(block)) {
        throw new Error("Security violation: LLM block is not a plain object.");
    }
    // Only permit known safe fields.
    const allowedFields = new Set(["text", "mimeType", "url"]);
    for (const key of Object.keys(block)) {
        if (!allowedFields.has(key)) {
            throw new Error(
                `Security violation: Unexpected field "${key}" in LLM block output.`
            );
        }
    }
    return {
        text: block.text !== undefined ? sanitizeString(block.text, "block.text") : undefined,
        mimeType: block.mimeType !== undefined ? sanitizeString(block.mimeType, "block.mimeType") : undefined,
        url: block.url !== undefined ? sanitizeString(block.url, "block.url") : undefined,
    };
}

/*
 * Take a completion, which may be a string, JSON encoded as a string, or JSON object,
 * and produce a list of ChatBlock objects. This is intended to be a one-size-fits-all
 * method for funneling different LLM output into structure that supports different media
 * types and can easily grow to support more metadata (such as speaker).
 */
export function responseToChatBlocks(completion: any) {
    // First we try to parse completion as JSON in case we're dealing with an object.
    if (typeof completion == "string") {
        try {
            completion = JSON.parse(completion)
        } catch {
            // Do nothing; we'll just treat it as a string.
        }
    }
    let blocks = []
    if (typeof completion == "string") {
        console.log("still string")
        const safeText = sanitizeString(completion, "completion text");
        blocks.push(<ChatBlock text={safeText} />)
            } else if (Array.isArray(completion)) {
        console.log("Is array")
        for (let block of completion) {
            console.log(block)
            // Extract only known-safe props to prevent prototype pollution
            // and injection of arbitrary React props (e.g. onError, __proto__).
            const safeBlock = {
                text: typeof block.text === "string" ? block.text : undefined,
                mimeType: typeof block.mimeType === "string" ? block.mimeType : undefined,
                url: typeof block.url === "string" ? block.url : undefined,
            };
            blocks.push(<ChatBlock {...safeBlock} />)
        }
    } else {
        // Extract only known-safe props to prevent prototype pollution
        // and injection of arbitrary React props from untrusted LLM output.
        const safeCompletion = {
            text: typeof completion.text === "string" ? completion.text : undefined,
            mimeType: typeof completion.mimeType === "string" ? completion.mimeType : undefined,
            url: typeof completion.url === "string" ? completion.url : undefined,
        };
        blocks.push(<ChatBlock {...safeCompletion} />)
    } else if (Array.isArray(completion)) {
        for (const block of completion) {
            if (block && typeof block === "object") {
                const { text, mimeType, url } = block as { text?: string; mimeType?: string; url?: string };
                blocks.push(<ChatBlock text={text} mimeType={mimeType} url={url} />)
            }
        }
    } else if (completion && typeof completion === "object") {
        const { text, mimeType, url } = completion as { text?: string; mimeType?: string; url?: string };
        blocks.push(<ChatBlock text={text} mimeType={mimeType} url={url} />)
    }
    return blocks
}

