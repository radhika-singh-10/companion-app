/*
 * Represents a unit of multimodal chat: text, video, audio, or image.
 *
 * For streaming responses, just update the `text` argument.
 *
 * Provenance fields (modelId, generatedAt, contentOrigin) are required to
 * satisfy the synthetic-content provenance, labeling, and watermarking policy.
 */

const AI_LABEL_STYLE: React.CSSProperties = {
    display: "inline-block",
    fontSize: "0.65rem",
    fontWeight: 700,
    color: "#fff",
    background: "#7c3aed",
    borderRadius: "4px",
    padding: "1px 6px",
    marginBottom: "4px",
    letterSpacing: "0.05em",
    userSelect: "none" as const,
};

const WATERMARK_STYLE: React.CSSProperties = {
    position: "absolute",
    bottom: "6px",
    right: "8px",
    fontSize: "0.6rem",
    color: "rgba(255,255,255,0.75)",
    background: "rgba(0,0,0,0.45)",
    borderRadius: "3px",
    padding: "1px 5px",
    pointerEvents: "none",
    userSelect: "none" as const,
    zIndex: 10,
};

function ProvenanceBadge({
    modelId,
    generatedAt,
    contentOrigin,
}: {
    modelId: string;
    generatedAt: string;
    contentOrigin: string;
}) {
    return (
        <span
            title={`Model: ${modelId} | Generated: ${generatedAt} | Origin: ${contentOrigin}`}
            style={AI_LABEL_STYLE}
            aria-label="AI-Generated Content"
            data-provenance-model={modelId}
            data-provenance-timestamp={generatedAt}
            data-provenance-origin={contentOrigin}
        >
            ⚠ AI-Generated
        </span>
    );
}

export function ChatBlock({
    text,
    mimeType,
    url,
    modelId = "unknown-model",
    generatedAt = new Date().toISOString(),
    contentOrigin = "ai-generated",
}: {
    text?: string;
    mimeType?: string;
    url?: string;
    modelId?: string;
    generatedAt?: string;
    contentOrigin?: string;
}) {
    let internalComponent = <></>
    let isMedia = false;

    if (text) {
        internalComponent = <span>{text}</span>
    } else if (mimeType && url) {
        isMedia = true;
        if (mimeType.startsWith("audio")) {
            internalComponent = (
                <div
                    style={{ position: "relative", display: "inline-block" }}
                    data-content-origin={contentOrigin}
                    data-model-id={modelId}
                    data-generated-at={generatedAt}
                >
                    <audio controls={true} src={url} />
                    <span style={WATERMARK_STYLE}>AI-Generated Audio</span>
                </div>
            )
        } else if (mimeType.startsWith("video")) {
            internalComponent = (
                <div
                    style={{ position: "relative", display: "inline-block" }}
                    data-content-origin={contentOrigin}
                    data-model-id={modelId}
                    data-generated-at={generatedAt}
                >
                    <video controls width="250">
                        <source src={url} type={mimeType} />
                        Download the <a href={url}>video</a>
                    </video>
                    <span style={WATERMARK_STYLE}>AI-Generated Video</span>
                </div>
            )
        } else if (mimeType.startsWith("image")) {
            internalComponent = (
                <div
                    style={{ position: "relative", display: "inline-block" }}
                    data-content-origin={contentOrigin}
                    data-model-id={modelId}
                    data-generated-at={generatedAt}
                >
                    <img src={url} alt="AI-generated image" />
                    <span style={WATERMARK_STYLE}>AI-Generated Image</span>
                </div>
            )
        }
    } else if (url) {
        internalComponent = <a href={url}>Link</a>
    }

    return (
        <p
            className="text-sm text-gray-200 pb-2"
            data-content-origin={contentOrigin}
            data-model-id={modelId}
            data-generated-at={generatedAt}
        >
            <ProvenanceBadge
                modelId={modelId}
                generatedAt={generatedAt}
                contentOrigin={contentOrigin}
            />
            <br />
            {internalComponent}
        </p>
    );
}

// Allowlist of safe keys accepted from LLM output blocks.
const ALLOWED_BLOCK_KEYS: ReadonlySet<string> = new Set(["text", "mimeType", "url"]);

// Patterns that indicate dynamic code execution primitives.
const DANGEROUS_PATTERNS: ReadonlyArray<RegExp> = [
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /\bFunction\s*\(/i,
    /\bnew\s+Function\b/i,
    /\bsetTimeout\s*\(/i,
    /\bsetInterval\s*\(/i,
    /\bsetImmediate\s*\(/i,
    /\bimportScripts\s*\(/i,
    /javascript\s*:/i,
    /data\s*:\s*text\s*\/\s*(html|javascript)/i,
    /<\s*script\b/i,
];

function containsDangerousContent(value: string): boolean {
    return DANGEROUS_PATTERNS.some((pattern) => pattern.test(value));
}

/**
 * Sanitizes a raw block object from LLM output.
 * Only allows known safe keys with string values.
 * Returns null if the block contains dangerous content.
 */
function sanitizeBlock(raw: unknown): { text?: string; mimeType?: string; url?: string } | null {
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
        return null;
    }
    const sanitized: { text?: string; mimeType?: string; url?: string } = {};
    for (const key of ALLOWED_BLOCK_KEYS) {
        const value = (raw as Record<string, unknown>)[key];
        if (value === undefined) {
            continue;
        }
        if (typeof value !== "string") {
            // Reject blocks with non-string values for allowed keys.
            return null;
        }
        if (containsDangerousContent(value)) {
            console.warn(`[ChatBlock] Rejected LLM block: dangerous content detected in key "${key}".`);
            return null;
        }
        (sanitized as Record<string, string>)[key] = value;
    }
    return sanitized;
}

/*
 * Take a completion, which may be a string, JSON encoded as a string, or JSON object,
 * and produce a list of ChatBlock objects. This is intended to be a one-size-fits-all
 * method for funneling different LLM output into structure that supports different media
 * types and can easily grow to support more metadata (such as speaker).
 */
export function responseToChatBlocks(completion: any) {
    // First we try to parse completion as JSON in case we're dealing with an object.
    console.log("got completoin", completion, typeof completion)
    if (typeof completion == "string") {
        try {
            completion = JSON.parse(completion)
        } catch {
            // Do nothing; we'll just treat it as a string.
            console.log("Couldn't parse")
        }
    }
    let blocks = []
    if (typeof completion == "string") {
        console.log("still string")
        blocks.push(<ChatBlock text={completion} />)
    } else if (Array.isArray(completion)) {
        console.log("Is array")
                for (let block of completion) {
            console.log(block)
            if (block && typeof block === "object" && !Array.isArray(block)) {
                const safeText: string | undefined = typeof block.text === "string" ? block.text : undefined;
                const safeMimeType: string | undefined = typeof block.mimeType === "string" ? block.mimeType : undefined;
                const safeUrl: string | undefined = typeof block.url === "string" ? block.url : undefined;
                blocks.push(<ChatBlock text={safeText} mimeType={safeMimeType} url={safeUrl} />)
            }
        }
    } else if (completion && typeof completion === "object" && !Array.isArray(completion)) {
        const safeText: string | undefined = typeof completion.text === "string" ? completion.text : undefined;
        const safeMimeType: string | undefined = typeof completion.mimeType === "string" ? completion.mimeType : undefined;
        const safeUrl: string | undefined = typeof completion.url === "string" ? completion.url : undefined;
        blocks.push(<ChatBlock text={safeText} mimeType={safeMimeType} url={safeUrl} />)
    } />)
            } else {
                console.warn("[ChatBlock] Skipped unsafe or invalid block from LLM output.");
            }
        }
    } else {
        const safeCompletion = sanitizeBlock(completion);
        if (safeCompletion !== null) {
            blocks.push(<ChatBlock {...safeCompletion} />)
        } else {
            console.warn("[ChatBlock] Skipped unsafe or invalid completion object from LLM output.");
        }
    }
    console.log(blocks)
    return blocks
}

