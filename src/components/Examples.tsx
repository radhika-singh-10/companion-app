"use client";
import { useEffect, useState } from "react";
import QAModal from "./QAModal";
import Image from "next/image";
import { Tooltip } from "react-tooltip";

import { getCompanions } from "./actions";

// Approved model registry: only these pinned model identifiers are permitted.
const APPROVED_MODEL_REGISTRY: Record<string, string> = {
  "gpt-4-0613": "gpt-4-0613",
  "gpt-3.5-turbo-0125": "gpt-3.5-turbo-0125",
  "claude-3-opus-20240229": "claude-3-opus-20240229",
  "claude-3-sonnet-20240229": "claude-3-sonnet-20240229",
  "gemini-1.0-pro-001": "gemini-1.0-pro-001",
};

const FALLBACK_MODEL = "unverified-model";

function resolveApprovedModel(llm: string): string {
  const trimmed = (llm ?? "").trim();
  if (Object.prototype.hasOwnProperty.call(APPROVED_MODEL_REGISTRY, trimmed)) {
    return APPROVED_MODEL_REGISTRY[trimmed];
  }
  console.warn(`[Model Registry] Rejected unregistered model identifier: "${trimmed}"`);
  return FALLBACK_MODEL;
}

export default function Examples() {
  const [QAModalOpen, setQAModalOpen] = useState(false);
  const [CompParam, setCompParam] = useState({
    name: "",
    title: "",
    imageUrl: "",
  });
  const APPROVED_LLMS = ["Claude", "Gemini", "Llama", "Mistral"];

  const [examples, setExamples] = useState([
    {
      name: "",
      title: "",
      imageUrl: "",
      telegramLink: null
    },
  ]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const companions = await getCompanions();
        let entries = JSON.parse(companions);
                let setme = entries.map((entry: any) => ({
          name: entry.name,
          title: entry.title,
          imageUrl: entry.imageUrl,
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
            onClick={() => {
              setCompParam(example);
              setQAModalOpen(true);
            }}
            className="col-span-2 flex flex-col rounded-lg bg-slate-800  text-center shadow relative ring-1 ring-white/10 cursor-pointer hover:ring-sky-300/70 transition"
            data-ai-generated="true"
            data-content-origin="ai-companion"
            data-llm={example.llm}
            data-provenance-timestamp={new Date().toISOString()}
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
              <div className="mt-4 flex justify-center">
                <span
                  aria-label="AI-Generated Content"
                  title="This companion is AI-generated synthetic content"
                  className="inline-flex items-center rounded-full bg-sky-900/60 px-2 py-0.5 text-xs font-medium text-sky-300 ring-1 ring-sky-300/40"
                >
                  🤖 AI-Generated
                </span>
              </div>
              <h3 className="mt-2 text-sm font-medium text-white">
                {example.name}
              </h3>
              <dl className="mt-1 flex flex-grow flex-col justify-between">
                <dt className="sr-only"></dt>
                <dd className="text-sm text-slate-400" data-ai-generated="true" data-llm={example.llm} data-content-origin="ai-companion">
                  {example.title}.
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
 * Validates a Telegram link URL.
 * Only allows https: scheme URLs pointing to t.me to prevent
 * open redirect and javascript: URI injection attacks.
 */
function sanitizeTelegramLink(url: string | undefined | null): string | null {
  if (!url) return null;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:') return null;
    if (parsed.hostname !== 't.me' && !parsed.hostname.endsWith('.t.me')) return null;
    return parsed.toString();
  } catch {
    return null;
  }
}

/**
 * Validates an image source URL.
 * Only allows https: scheme URLs to prevent SSRF-adjacent risks
 * and information leakage via referrer headers.
 */
function sanitizeImageUrl(url: string | undefined | null): string {
  if (!url) return '';
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:') return '';
    return parsed.toString();
  } catch {
    return '';
  }
}

function isSafeTelegramUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' && parsed.hostname === 't.me';
  } catch {
    return false;
  }
}

function maskPhoneNumber(phone: string): string {
  if (!phone || phone.length < 4) return '***';
  // Keep the '+' and country code (up to 3 chars after '+'), mask the middle, show last 2 digits
  const visiblePrefix = phone.startsWith('+') ? phone.slice(0, Math.min(3, phone.length - 2)) : phone.slice(0, 1);
  const visibleSuffix = phone.slice(-2);
  const maskedLength = phone.length - visiblePrefix.length - visibleSuffix.length;
  const masked = '*'.repeat(Math.max(maskedLength, 3));
  return `${visiblePrefix}${masked}${visibleSuffix}`;
}
