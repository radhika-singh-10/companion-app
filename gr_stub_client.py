# lineaje-gr-stub-client version=2.0.0-alpha sha256=83ca1d7696c142e1ad49d2d88fcee00a6491bd838f7ec8a2c7c8dd775904120e
# Copyright (c) Lineaje, Inc. All rights reserved.
#
# This file is part of the Lineaje AI Policy Orchestration (AIPO) guardrail
# runtime. It is copied alongside instrumented source files so a generated
# guardrail stub can load it via ``_lineaje_load_gr_client()`` and call
# ``enforce()``/``check()`` without any change to the customer's own
# dependencies.
"""Stdlib HTTP client for GR /enforce. Copied into the scanned repo at runtime.

``check(site, payload)`` is the current stub API. ``call_gr_enforce`` remains
for older inserted sites. Both fail open unless the site fail_mode is BLOCK.
Unknown sites are registered. The stub applies no masking of its own: the GR is the enforcement point (an ALLOW
leaves the data unchanged, a mask changes only the text the GR changed; review r4 N1).

A genuine fail-closed policy block (blocked LLM, CBRN, …) latches for the
rest of this *request* context: later ``check()``/``enforce()`` calls for
*other* sites skip POST /enforce so a processing-note catch cannot keep
extracting files, calling MCP, or dumping document contents. The site that
blocked may still re-POST (model settings can change). The latch is not
process-wide — a blocked chat must not 500 a later GET /chat/jobs poll.
"""
from __future__ import annotations

__version__ = '2.0.0-alpha'
# What every stub of this application shares, stamped by the scan that wrote this file (stubs do not repeat it):
# app_name, app_version, app_branch, app_purl, project, organization, and workflow when the scan named one.
# Environment variables win (UNIFAI_APP_NAME / _VERSION / _BRANCH / _PURL; GR_PROJECT, GR_ORGANIZATION and
# GR_WORKFLOW override everything, then UNIFAI_PROJECT / UNIFAI_ORGANIZATION). The workflow run and step come from
# the application at runtime (workflow_context(), GR_SESSION_ID / GR_STEP; CON-3356), never from the scan.
SCAN_CONTEXT: dict = {'app_branch': 'main', 'app_name': 'companion-app', 'app_purl': 'pkg:github/radhika-singh-10/companion-app@main?commit-id=a50c9371816440196049cca0eba9b1373341600e&commit-time=2023-09-19%2003%3A57%3A56%20%2B0000&build_file=package.json&repo_strategy=single-repo', 'app_version': 'main', 'organization': 'Development Test SubOrg', 'organization_id': 'vdna_p4OfAQywlTKfbfgD', 'project': 'radhika-singh-10-companion-app', 'repository': 'radhika-singh-10/companion-app'}

import atexit
import base64
import collections
import contextvars
import http.client
import io
import json
import mimetypes
import logging
import os
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

_logger = logging.getLogger("aipo_mcp.gr_stub_client")


def _check_own_header() -> None:
    """Every copy the scan writes starts with ``# lineaje-gr-stub-client version=<v> sha256=<hex>`` (the sha256 of
    the rest of the file, LIN-36162). A copy edited by hand, or left from another version, logs one warning at
    import; it still loads. A file without the header (this repo's own copy) is not checked."""
    try:
        with open(__file__, "rb") as fh:
            first, _, body = fh.read().partition(b"\n")
        m = re.match(rb"# lineaje-gr-stub-client version=(\S*) sha256=([0-9a-f]{64})\r?$", first)
        # The sha256 covers the body with its SCAN_CONTEXT line as {}: the scan stamps that line per repository.
        body = re.sub(rb"(?m)^SCAN_CONTEXT: dict = [^\r\n]*", b"SCAN_CONTEXT: dict = {}", body.replace(b"\r\n", b"\n"),
                      count=1)
        if m and __import__("hashlib").sha256(body).hexdigest() != m.group(2).decode():
            _logger.warning("gr_stub_client: %s differs from the Lineaje client it was written as (version %s); "
                            "re-run the scan to restore it", __file__, m.group(1).decode())
    except Exception as exc:  # noqa: BLE001 — a check only, never stops the client loading
        _logger.debug("gr_stub_client: header check skipped (%s)", type(exc).__name__)


_check_own_header()

_DEFAULT_ENFORCE_TIMEOUT_SEC = 30.0


def _resolve_enforce_timeout_seconds() -> float:
    """How long a single /enforce POST waits before giving up.

    Default 30 s; GR_TIMEOUT_MS (milliseconds) overrides it. Real round trips (scanning a slow model's full
    response, a cold start) can run 20-30 s, and an earlier 5 s default caused spurious timeouts. A timeout fails
    open, as any GR outage does. A guardrail that keeps failing does not cost 30 s per call: after 5 consecutive
    infrastructure failures the circuit breaker opens and calls fail open for 30 s without waiting (_Breaker).
    """
    raw = (os.environ.get("GR_TIMEOUT_MS") or "").strip()
    if raw:
        try:
            return max(float(raw) / 1000.0, 0.1)
        except ValueError:
            _logger.warning("GR_TIMEOUT_MS=%r is not a number — using default %.1fs", raw, _DEFAULT_ENFORCE_TIMEOUT_SEC)
    return _DEFAULT_ENFORCE_TIMEOUT_SEC


_RUNTIME_ENV_LOADED = False
_CA_BUNDLE_TRUSTED = False
_MANIFEST_CACHE: dict[str, Any] | None = None
_ACCESS_TOKEN_CACHE: dict[str, tuple[str, float]] = {}
_TOKEN_LOCK = threading.Lock()
_TOKEN_SKEW_SEC = 120
# Customer stubs exchange guardrail.json ``refreshtoken`` (a SCIM refresh
# token) here. Identity-service renew cannot decrypt SCIM tokens (HTTP 500
# "trying to decrypt the string") — same rewrite as scripts/gha_repo_scan.py.
_SCIM_RENEW_ACCESS_TOKEN_PATH = "/scim/api/v1/auth/native/renew-access-token"
_IDENTITY_RENEW_ACCESS_TOKEN_PATH = "/lineajeidentity/api/v1/auth/native/renew-access-token"
_GR_URL_MISSING_WARNED = False
# No service URL is built in: GR_SERVICE_URL and LINEAJE_RENEW_ACCESS_TOKEN_URL come from
# .env / .env.example (written by the scan) or the process environment.


_SITE_REGISTER_ATTEMPTED: set[str] = set()
_SITE_REGISTERED: set[str] = set()
_SITE_POLICY_MAPPINGS: dict[str, list[Any]] = {}
# Request-context latch: a fail-closed policy block on one site must not
# fan out POST /enforce to the remaining insertion points (file_upload,
# mcp_call, tool_to_user, …). Stored as a *mutable object* in a ContextVar
# so ``asyncio.to_thread`` (which copies the context *into* the worker)
# still lets the worker write a block the parent task can see — without a
# process-wide singleton that poisons later HTTP requests (GET /chat/jobs
# after a blocked chat). The blocking site_id may still re-POST.
class _RequestBlockLatch:
    __slots__ = ("payload",)

    def __init__(self) -> None:
        self.payload: dict[str, Any] | None = None


_PROCESS_BLOCK_LATCH: contextvars.ContextVar[_RequestBlockLatch | None] = contextvars.ContextVar(
    "gr_process_block_latch", default=None,
)


def _ensure_request_latch() -> _RequestBlockLatch:
    """Create the per-request latch on the current context if missing.

    Inserted stubs construct ``SiteDescriptor`` on the event-loop thread
    *before* ``asyncio.to_thread(enforce)``, so the same latch object is
    what the worker inherits and mutates.
    """
    latch = _PROCESS_BLOCK_LATCH.get()
    if latch is None:
        latch = _RequestBlockLatch()
        _PROCESS_BLOCK_LATCH.set(latch)
    return latch


def _reset_runtime_caches() -> None:
    """Test helper — drop manifest / access-token / site-register caches."""
    global _RUNTIME_ENV_LOADED, _CA_BUNDLE_TRUSTED, _MANIFEST_CACHE
    _RUNTIME_ENV_LOADED = False
    _CA_BUNDLE_TRUSTED = False
    _MANIFEST_CACHE = None
    _ACCESS_TOKEN_CACHE.clear()
    _SITE_REGISTER_ATTEMPTED.clear()
    _SITE_REGISTERED.clear()
    _SITE_POLICY_MAPPINGS.clear()
    _SITE_POLICIES.clear()
    _PROCESS_BLOCK_LATCH.set(None)
    _reset_observability()


def _record_process_block(site_id: str, warning: str, policy_id: str = "") -> None:
    """Latch a genuine fail-closed block so later sites skip POST /enforce."""
    latch = _ensure_request_latch()
    if latch.payload is None:
        latch.payload = {
            "site_id": site_id or "",
            "warning": warning or "Request denied by policy enforcement.",
            "policy_id": policy_id or "",
        }


def _current_process_block() -> dict[str, Any] | None:
    latch = _PROCESS_BLOCK_LATCH.get()
    if latch is None:
        return None
    return latch.payload


def _process_block_for_other_site(site_id: str) -> dict[str, Any] | None:
    """Prior block, unless this is the same site_id re-checking."""
    prior = _current_process_block()
    if not prior:
        return None
    blocked_site = str(prior.get("site_id") or "")
    this_site = site_id or ""
    if this_site and blocked_site and this_site == blocked_site:
        return None
    return prior


def _policy_id_from_decision(decision: "Decision") -> str:
    actions = decision.actions_applied or []
    if actions and isinstance(actions[0], dict):
        return str(actions[0].get("policy_id") or "")
    return ""


def _maybe_record_process_block(decision: "Decision", site: "SiteDescriptor") -> None:
    """Record only a live policy block — not an infra/outage fail-closed."""
    if not decision.blocked or getattr(decision, "infra_failure", False):
        return
    _record_process_block(
        getattr(site, "site_id", "") or "",
        decision.warning or "",
        _policy_id_from_decision(decision),
    )


def _skipped_other_site_decision(
    site: "SiteDescriptor", payload: Any, prior: dict[str, Any],
) -> "Decision":
    """Fail-closed locally without POSTing — prior site already blocked."""
    hop = f"site_id={site.site_id}" if getattr(site, "site_id", "") else "site_id=<unknown>"
    reason = prior.get("warning") or "Request denied by policy enforcement."
    policy_id = prior.get("policy_id") or "prior_block"
    _logger.warning(
        "gr_stub_client.check[%s]: skipping POST /enforce — request already "
        "blocked at site_id=%s (%s)",
        hop, prior.get("site_id") or "<unknown>", reason,
    )
    _announce_enforce(
        "-", hop, "block",
        extra=f"skipped — prior policy block at site_id={prior.get('site_id') or '<unknown>'}",
    )
    return Decision({
        "status": "block",
        "result": {"data": payload},
        "actions_applied": [{"policy_id": policy_id, "action": "block"}],
        "recommendations": [],
        "warning": reason,
    }, site_id=getattr(site, "site_id", "") or "")


def _guardrail_manifest_candidates() -> list[str]:
    here = os.path.dirname(os.path.abspath(__file__))
    cwd = os.getcwd()
    candidates = [
        os.path.join(here, ".lineaje", "guardrail.json"),
        os.path.join(cwd, ".lineaje", "guardrail.json"),
    ]
    # Walk parents so a nested source file can still find repo-root manifest.
    cur = here
    for _ in range(6):
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        candidates.append(os.path.join(parent, ".lineaje", "guardrail.json"))
        cur = parent
    return candidates


def _load_guardrail_manifest() -> dict[str, Any]:
    """Load ``.lineaje/guardrail.json`` (written by GHA PRs / MCP workflow)."""
    global _MANIFEST_CACHE
    if _MANIFEST_CACHE is not None:
        return _MANIFEST_CACHE
    for path in _guardrail_manifest_candidates():
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                _MANIFEST_CACHE = data
                return data
        except (OSError, ValueError, TypeError):
            continue
    _MANIFEST_CACHE = {}
    return _MANIFEST_CACHE


def _origin_for_enforce_api(url: str) -> str:
    """Strip a trailing ``/mcp`` or ``/enforce`` path so callers can POST
    ``/enforce`` without doubling it up.

    Combined MCP+GR serves the guardrail at the server root. A scan that
    recorded the MCP endpoint (``http://host:8000/mcp``) as GR_SERVICE_URL
    would otherwise miss the handler entirely. GR_SERVICE_URL is also written
    with the ``/enforce`` path already spelled out (customer-facing
    ``.env.example`` files show the actual endpoint) — stripping it here
    keeps both forms equivalent.
    """
    s = (url or "").strip()
    if " #" in s:
        s = s.split(" #", 1)[0].strip()
    s = s.rstrip("/")
    if s.lower().endswith("/mcp"):
        s = s[: -len("/mcp")].rstrip("/")
    elif s.lower().endswith("/enforce"):
        s = s[: -len("/enforce")].rstrip("/")
    return s


def _is_loopback_origin(origin: str) -> bool:
    u = (origin or "").lower()
    return any(marker in u for marker in ("127.0.0.1", "localhost", "::1"))


def _load_guardrail_manifest_url() -> str:
    """Enforce origin from ``.lineaje/guardrail.json`` (no ``/mcp`` suffix)."""
    return _origin_for_enforce_api(_load_guardrail_manifest().get("gr_service_url") or "")


def _agentic_platform() -> str:
    """The AI platform this application runs on, for the Run view (``Run -> <platform> -> <platform>-<cloud>-<region>``):
    ``GR_AGENTIC_PLATFORM`` (environment, ``.env``, ``.env.example``), else ``.lineaje/guardrail.json``'s
    ``gr_agentic_platform``, the same sources as ``GR_SERVICE_URL``. ``""`` when neither names one (nothing is sent)."""
    _ensure_runtime_env_loaded()
    value = (os.environ.get("GR_AGENTIC_PLATFORM") or "").strip()
    if not value:
        value = str(_load_guardrail_manifest().get("gr_agentic_platform") or "").strip()
    return value if value.isprintable() else ""


def _resolve_gr_origin(explicit: str | None = None) -> str:
    """Resolve the GR origin, preserving configured local loopback servers.

    Prefers an explicit origin, then ``GR_SERVICE_URL`` (including local),
    then the legacy ``.lineaje/guardrail.json`` URL. ``""`` when none is set:
    the caller then skips the guardrail (fail-open) instead of guessing a host.
    """
    try:
        _ensure_runtime_env_loaded()
        for candidate in (
            _origin_for_enforce_api(explicit or ""),
            _origin_for_enforce_api(os.environ.get("GR_SERVICE_URL", "")),
            _load_guardrail_manifest_url(),
        ):
            if candidate:
                return candidate
        global _GR_URL_MISSING_WARNED
        if not _GR_URL_MISSING_WARNED:
            _GR_URL_MISSING_WARNED = True
            _logger.warning("gr_stub_client: GR_SERVICE_URL is not set (.env / .env.example) — guardrail skipped")
        return ""
    except Exception:
        return ""


def _looks_like_jwt(value: str) -> bool:
    s = (value or "").strip()
    return s.count(".") == 2 and s.startswith("eyJ")


def _scim_renew_url(url: str) -> str:
    """Map identity-service renew URLs onto SCIM. SCIM-issued refresh tokens
    fail at identity with HTTP 500 ``trying to decrypt the string``."""
    u = (url or "").strip().rstrip("/")
    if not u or _IDENTITY_RENEW_ACCESS_TOKEN_PATH not in u:
        return u
    parsed = urllib.parse.urlparse(u)
    host = (parsed.netloc or "").replace("lineaje-identity-service", "scim-service")
    scheme = parsed.scheme or "https"
    return f"{scheme}://{host}{_SCIM_RENEW_ACCESS_TOKEN_PATH}"


def _parse_access_token(raw_text: str) -> str:
    text = (raw_text or "").strip()
    if not text:
        return ""
    try:
        parsed: Any = json.loads(text)
    except json.JSONDecodeError:
        return text if _looks_like_jwt(text) else ""
    if isinstance(parsed, str):
        return parsed.strip()
    if isinstance(parsed, dict):
        return (parsed.get("access_token") or "").strip()
    return ""


def _jwt_payload(token: str) -> dict[str, Any]:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        import base64
        data = json.loads(base64.urlsafe_b64decode(payload))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _jwt_exp_epoch(token: str) -> float:
    exp = _jwt_payload(token).get("exp")
    if isinstance(exp, (int, float)):
        return float(exp)
    return time.time() + 3600.0


def _tenant_id_from_bearer(pat: str, fallback: str = "") -> str:
    """Tenant for site-manifest register — same identity /enforce binds to."""
    explicit = (fallback or "").strip()
    if explicit:
        return explicit
    claims = _jwt_payload(pat)
    meta = claims.get("user_metadata") if isinstance(claims.get("user_metadata"), dict) else {}
    for key in ("tenant_id",):
        for src in (claims, meta):
            val = src.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
    return (os.environ.get("GR_TENANT_ID") or "").strip()


def _identity_from_bearer(pat: str) -> "dict[str, str]":
    """tenant_id, company_id and org_name for the runtime JSONs: from the token's claims
    (and its user_metadata), else the environment. Never baked into the stubs."""
    claims = _jwt_payload(pat) if (pat or "").count(".") == 2 else {}
    meta = claims.get("user_metadata") if isinstance(claims.get("user_metadata"), dict) else {}

    def pick(keys: "tuple[str, ...]", envs: "tuple[str, ...]") -> str:
        for key in keys:
            for src in (claims, meta):
                val = src.get(key)
                if isinstance(val, str) and val.strip():
                    return val.strip()
        return _first_env(*envs)

    return {
        "tenant_id": pick(("tenant_id", "tenantId"), ("GR_TENANT_ID", "LINEAJE_TENANT_ID")),
        "company_id": pick(("company_id", "companyId"), ("GR_COMPANY_ID", "LINEAJE_COMPANY_ID")),
        "org_name": pick(("active_org_name", "org_name", "org"), ("LINEAJE_ORG_NAME", "GR_ORG_NAME")),
    }


def _exchange_refresh_for_access(refresh_token: str, renew_url: str) -> str:
    """POST renew-access-token?refreshToken=… → short-lived access JWT. Empty on failure."""
    if not refresh_token or not renew_url:
        return ""
    key = refresh_token
    now = time.time()
    cached = _ACCESS_TOKEN_CACHE.get(key)
    if cached is not None:
        access, deadline = cached
        if access and now < deadline - _TOKEN_SKEW_SEC:
            return access
    q = urllib.parse.urlencode({"refreshToken": refresh_token})
    req = urllib.request.Request(
        f"{renew_url.rstrip('/')}?{q}",
        data=b"null",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            access = _parse_access_token(resp.read().decode())
    except Exception as exc:
        _logger.warning("refresh-token exchange failed (%s) — using refresh token as Bearer", exc)
        return ""
    if not access:
        return ""
    _ACCESS_TOKEN_CACHE[key] = (access, _jwt_exp_epoch(access))
    return access


def _looks_like_lineaje_pat(value: str) -> bool:
    return (value or "").strip().startswith("lineaje_pat")


def _usable_scim_refresh_token(raw: str) -> str:
    """Opaque SCIM refresh token only — never a JWT, URL, or identity PAT."""
    s = (raw or "").strip()
    if not s or s.startswith("http"):
        return ""
    if _looks_like_jwt(s) or _looks_like_lineaje_pat(s):
        return ""
    return s


def _strip_bearer_prefix(value: str) -> str:
    raw = (value or "").strip()
    if raw.lower().startswith("bearer "):
        return raw[7:].strip()
    return raw


def _mcp_access_jwt_from_env() -> str:
    """Access JWT the MCP server already has (session / local-dev env)."""
    for key in (
        "MCP_BEARER_TOKEN",
        "LINEAJE_BEARER_TOKEN",
        "GR_BEARER_TOKEN",
        "BEARER_TOKEN",
    ):
        token = _strip_bearer_prefix(os.environ.get(key, ""))
        # An expired JWT is skipped: /enforce rejects it, and it would shadow the caller's own credential.
        if token and _looks_like_jwt(token) and _jwt_exp_epoch(token) > time.time():
            return token
    return ""


def _pat_candidate(raw: str) -> str:
    """A ``lineaje_pat_…`` credential, verbatim — never a JWT or refresh blob.

    Used as a last-resort Bearer: POST /enforce exchanges a Lineaje PAT
    server-side (see mcp_server.py's ``_admin_http_bearer`` comment — only
    /admin/site-manifest/register requires a real access JWT up front).
    """
    s = (raw or "").strip()
    return s if _looks_like_lineaje_pat(s) else ""


def _resolve_enforce_bearer(lineaje_pat: str = "") -> str:
    """Return the Authorization Bearer for POST /enforce.

    Prefer an access JWT the MCP server already has. Otherwise take a SCIM
    refresh token (``LINEAJE_REFRESH_TOKEN`` / ``.lineaje/guardrail.json``
    ``refreshtoken``) and exchange it at SCIM renew-access-token. Identity-service
    renew URLs are rewritten to SCIM (identity cannot decrypt SCIM refresh
    tokens). If the exchange cannot run, the refresh token itself is sent so
    ``POST /enforce`` can exchange it server-side.

    A scan-operator ``LINEAJE_PAT_TOKEN=lineaje_pat_…`` in a local ``.env``
    must not win over the customer refresh token — that PAT is a different
    identity and skips the renew path on /enforce.

    When no genuine SCIM refresh token is available anywhere (the common MCP/
    IDE-scan case: ``.lineaje/guardrail.json``'s ``refreshtoken`` holds the
    ``unifai-runtime`` PAT minted by ``inject_runtime_pat_into_manifest_json``
    instead), fall back to that ``lineaje_pat_…`` value directly as the
    Bearer — /enforce exchanges it server-side. Without this fallback,
    ``_usable_scim_refresh_token`` discards every PAT-shaped candidate and
    this function returns "", so /enforce is called unauthenticated and
    fails open silently.
    """
    explicit = _strip_bearer_prefix(lineaje_pat)
    if explicit and _looks_like_jwt(explicit):
        return explicit

    mcp_jwt = _mcp_access_jwt_from_env()
    if mcp_jwt:
        return mcp_jwt

    manifest = _load_guardrail_manifest()
    refresh = (
        _usable_scim_refresh_token(os.environ.get("LINEAJE_REFRESH_TOKEN") or "")
        or _usable_scim_refresh_token(os.environ.get("MCP_REFRESH_TOKEN") or "")
        or _usable_scim_refresh_token(str(manifest.get("refreshtoken") or ""))
        or _usable_scim_refresh_token(str(manifest.get("refresh_token") or ""))
        or _usable_scim_refresh_token(explicit)
        or _usable_scim_refresh_token(os.environ.get("LINEAJE_PAT_TOKEN") or "")
        or _usable_scim_refresh_token(os.environ.get("LINEAJE_PAT") or "")
    )

    if not refresh:
        env_pat = (
            os.environ.get("LINEAJE_PAT_TOKEN")
            or os.environ.get("LINEAJE_PAT")
            or ""
        ).strip()
        if env_pat and _looks_like_jwt(env_pat):
            return env_pat
        if explicit and _looks_like_jwt(explicit):
            return explicit
        # Same priority order as the genuine-refresh-token search above: the
        # customer's own manifest-embedded PAT wins over a scan-operator's
        # local-env PAT.
        return (
            _pat_candidate(str(manifest.get("refreshtoken") or ""))
            or _pat_candidate(str(manifest.get("refresh_token") or ""))
            or _pat_candidate(explicit)
            or _pat_candidate(os.environ.get("LINEAJE_PAT_TOKEN") or "")
            or _pat_candidate(os.environ.get("LINEAJE_PAT") or "")
        )

    raw_renew = (
        (os.environ.get("LINEAJE_RENEW_ACCESS_TOKEN_URL") or "").strip()
        or (manifest.get("renew_access_token_url") or "").strip()
    )
    renew_url = _scim_renew_url(raw_renew) or raw_renew
    with _TOKEN_LOCK:
        access = _exchange_refresh_for_access(refresh, renew_url)
    return access or refresh


def _ca_bundle_candidates(name: str = "ca-bundle.pem") -> list[str]:
    """Same walk-parents search as _guardrail_manifest_candidates(), for a
    customer-provided ``.lineaje/ca-bundle.pem`` (or ``name``) instead of guardrail.json."""
    here = os.path.dirname(os.path.abspath(__file__))
    cwd = os.getcwd()
    candidates = [
        os.path.join(here, ".lineaje", name),
        os.path.join(cwd, ".lineaje", name),
    ]
    cur = here
    for _ in range(6):
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        candidates.append(os.path.join(parent, ".lineaje", name))
        cur = parent
    return candidates


# The scan ships the self-hosted GR VM's TLS root CA (public certificate) as .lineaje/gr-ca.crt.
_GR_CA_FILENAME = "gr-ca.crt"


def _public_ca_file() -> str:
    """A public CA bundle to combine the GR CA with (certifi when installed, else the platform default)."""
    try:
        # Optional dependency, looked up at runtime (no import statement: the customer repo may not have it).
        import importlib as _importlib
        path = _importlib.import_module("certifi").where()
        if path and os.path.isfile(path):
            return path
    except Exception:
        pass
    import ssl as _ssl
    path = _ssl.get_default_verify_paths().cafile or ""
    return path if path and os.path.isfile(path) else ""


def _bundle_with_gr_ca(gr_ca: str) -> str:
    """Path of a CA bundle = public CAs + ``gr_ca``, written once per process under the temp dir; ``""``
    when no public bundle is found (trusting the GR CA alone would break the app's other HTTPS)."""
    public = _public_ca_file()
    if not public:
        _logger.warning("gr_stub_client: %s found but no public CA bundle to combine it with — not trusted "
                        "(create .lineaje/ca-bundle.pem as in .env.example)", gr_ca)
        return ""
    import hashlib as _hashlib
    import tempfile as _tempfile
    with open(public, "rb") as fh:
        pub = fh.read()
    with open(gr_ca, "rb") as fh:
        extra = fh.read()
    data = pub.rstrip(b"\n") + b"\n" + extra
    out = os.path.join(_tempfile.gettempdir(), "lineaje-gr-ca-bundle-%s.pem" % _hashlib.sha256(data).hexdigest()[:16])
    if not os.path.isfile(out):
        tmp = out + ".%d.tmp" % os.getpid()
        with open(tmp, "wb") as fh:
            fh.write(data)
        os.replace(tmp, out)
    return out


def _ensure_ca_bundle_trusted() -> None:
    """Trust a self-hosted GR/MCP server's TLS cert without any change to
    the customer's own app entrypoint.

    A GR/MCP server fronted by Caddy (the common self-hosted-VM deployment)
    serves TLS off a self-signed local CA, not a public one — every request
    fails ``CERTIFICATE_VERIFY_FAILED: unable to get local issuer
    certificate`` until that CA is trusted. Python's urllib re-reads
    SSL_CERT_FILE/SSL_CERT_DIR (via ssl.get_default_verify_paths()) each
    time it builds a default SSLContext, so setting it here — right before
    this module's first request, not at interpreter startup — is enough;
    the customer's app never needs its own CA-bundle-loading code. See
    ``.env.example`` for the one-time steps to produce this file.
    Never overrides an SSL_CERT_FILE/REQUESTS_CA_BUNDLE the customer already
    set themselves. Cached — cheap to call from every function that issues
    a request, so each of them gets this without depending on call order.
    """
    global _CA_BUNDLE_TRUSTED
    if _CA_BUNDLE_TRUSTED:
        return
    _CA_BUNDLE_TRUSTED = True
    # Hybrid deployments only (GR on the customer's own VM behind a
    # self-signed CA). SaaS / unset: the GR endpoint has a publicly trusted
    # certificate, so never swap in a local CA bundle.
    if (os.environ.get("UNIFAI_MODE") or "").strip().lower() not in ("hybrid", "onprem"):
        return
    for path in _ca_bundle_candidates():
        if not os.path.isfile(path):
            continue
        os.environ.setdefault("SSL_CERT_FILE", path)
        os.environ.setdefault("REQUESTS_CA_BUNDLE", path)
        return
    # No customer bundle: use the GR VM's root CA the scan shipped (.lineaje/gr-ca.crt) with the public CAs.
    for path in _ca_bundle_candidates(_GR_CA_FILENAME):
        if not os.path.isfile(path):
            continue
        try:
            bundle = _bundle_with_gr_ca(path)
        except Exception as exc:  # never break the app over TLS setup
            _logger.warning("gr_stub_client: could not build a CA bundle with %s (%s)", path, exc)
            return
        if bundle:
            os.environ.setdefault("SSL_CERT_FILE", bundle)
            os.environ.setdefault("REQUESTS_CA_BUNDLE", bundle)
        return


def _ensure_runtime_env_loaded() -> None:
    """Load GR_SERVICE_URL / PAT from a nearby .env, then .env.example (the scan writes the service
    URLs there; a key already set by the environment or .env wins)."""
    global _RUNTIME_ENV_LOADED
    if _RUNTIME_ENV_LOADED:
        return
    _RUNTIME_ENV_LOADED = True
    _keys = frozenset({
        "GR_SERVICE_URL", "LINEAJE_PAT_TOKEN", "LINEAJE_PAT", "GR_BEARER_TOKEN",
        "LINEAJE_REFRESH_TOKEN", "MCP_REFRESH_TOKEN", "LINEAJE_RENEW_ACCESS_TOKEN_URL",
        "MCP_BEARER_TOKEN", "LINEAJE_BEARER_TOKEN", "BEARER_TOKEN", "UNIFAI_MODE", "GR_AGENTIC_PLATFORM",
    })
    _dirs = (os.path.dirname(os.path.abspath(__file__)), os.getcwd())
    for name in (".env", ".env.example"):
        path = next((p for p in (os.path.join(d, name) for d in _dirs) if os.path.isfile(p)), "")
        if not path:
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#") or "=" not in stripped:
                        continue
                    key, _, val = stripped.partition("=")
                    key, val = key.strip(), val.strip().strip('"').strip("'")
                    if key in _keys and val and not os.environ.get(key):
                        os.environ[key] = val
        except OSError:
            pass
    # After .env is read, so a UNIFAI_MODE=hybrid set there is honoured.
    _ensure_ca_bundle_trusted()


def call_gr_enforce(
    data: Any,
    source_type: str,
    destination_type: str,
    lineaje_pat: str = "",
    gr_service_url: str | None = None,
    violations: list[dict] | None = None,
    enabled_policies: list[str] | None = None,
    candidate_policies: list[str] | None = None,
    site_id: str | None = None,
    tenant_id: str = "",
    timeout: "float | None" = None,
) -> dict[str, Any]:
    """POST /enforce. Fail-open on errors; 403 is a real block. Queues one observability event per call."""
    obs: "dict[str, Any]" = {}
    result = _call_gr_enforce(data, source_type, destination_type, lineaje_pat, gr_service_url, violations,
                              enabled_policies, candidate_policies, site_id, tenant_id, timeout, _obs=obs)
    if "body" in obs:
        try:
            outcome = _outcome_of(result, obs.get("gr"))
        except Exception:  # noqa: BLE001
            outcome = {"status": "allow"}
        _enqueue_observability(obs["url"], obs["pat"], obs["body"], outcome)
    return result


def _call_gr_enforce(
    data: Any,
    source_type: str,
    destination_type: str,
    lineaje_pat: str = "",
    gr_service_url: str | None = None,
    violations: list[dict] | None = None,
    enabled_policies: list[str] | None = None,
    candidate_policies: list[str] | None = None,
    site_id: str | None = None,
    tenant_id: str = "",
    timeout: "float | None" = None,
    *,
    _obs: "dict[str, Any]",
) -> dict[str, Any]:
    """POST /enforce. Fail-open on errors; 403 is a real block."""
    if destination_type == "skill_check" and _looks_like_quarantined_skill_path(data):
        _logger.warning(
            "gr_stub_client[%s]: quarantined skill (*.blocked) — not loaded, GR not called",
            f"{source_type}->{destination_type}",
        )
        refused = {
            "status": "block",
            "result": {"data": data},
            "actions_applied": [{
                "policy_id": "AI_SKILL_SEC_001",
                "action": "deny_execute",
                "deny_execute": True,
            }],
            "recommendations": [],
            "warning": _DANGEROUS_SKILL_LOAD_NOTE,
        }
        _enqueue_local_block(_outcome_of(refused), gr_service_url=gr_service_url, lineaje_pat=lineaje_pat,
                             site_id=site_id or "", source_type=source_type, destination_type=destination_type,
                             candidate_policies=candidate_policies, tenant_id=tenant_id, quarantined=True)
        return refused
    if timeout is None:
        timeout = _resolve_enforce_timeout_seconds()
    url = _resolve_gr_origin(gr_service_url)
    if not url:
        return {
            "status": "allow",
            "result": {"data": data},
            "actions_applied": [],
            "recommendations": [],
            "warning": "GR_SERVICE_URL not configured — guardrail skipped (fail-open)",
        }
    if not _BREAKER.allow(url):
        return {
            "status": "allow",
            "result": {"data": data},
            "actions_applied": [],
            "recommendations": [],
            "warning": "guardrail circuit open — call skipped (fail-open)",
            "infra_failure": True,
        }

    hop = f"{source_type}->{destination_type}"
    if site_id:
        hop = f"{hop} site_id={site_id}"
    prior = _process_block_for_other_site(site_id or "")
    if prior is not None:
        reason = prior.get("warning") or "Request denied by policy enforcement."
        policy_id = prior.get("policy_id") or "prior_block"
        _logger.warning(
            "gr_stub_client[%s]: skipping POST /enforce — request already "
            "blocked at site_id=%s (%s)",
            hop, prior.get("site_id") or "<unknown>", reason,
        )
        skipped = {
            "status": "block",
            "result": {"data": data},
            "actions_applied": [{"policy_id": policy_id, "action": "block"}],
            "recommendations": [],
            "warning": reason,
        }
        _enqueue_local_block(_outcome_of(skipped), gr_service_url=gr_service_url, lineaje_pat=lineaje_pat,
                             site_id=site_id or "", source_type=source_type, destination_type=destination_type,
                             candidate_policies=candidate_policies, tenant_id=tenant_id, skipped_after_block=True)
        return skipped

    pat = _resolve_enforce_bearer(lineaje_pat)
    params_key = "out_params" if destination_type == "agent" else "in_params"
    plain = _jsonable_payload(data)
    sent, redacted = _redact_wire(plain)      # G8: never a credential to the GR

    body: dict[str, Any] = {
        "source_type": source_type,
        "destination_type": destination_type,
        params_key: {"data": sent},
    }
    if violations:
        body["violations"] = violations
    if enabled_policies:
        body["enabled_policies"] = enabled_policies
    if candidate_policies:
        body["candidate_policies"] = candidate_policies
    if site_id:
        body["site_id"] = site_id
    if tenant_id:
        body["tenant_id"] = tenant_id
    _obs.update(body=body, url=url, pat=pat)

    try:
        result = _post_enforce(url, body, pat, timeout)
        _obs["gr"] = _gr_verdict(result.get("status", "allow"), result.get("actions_applied"))
        if redacted and isinstance(result, dict) and "result" in result:
            try:     # the GR's ``result`` is its answer for the data: the caller's value back at every redacted path
                answer = result["result"]
                result["result"] = plain if _same_wire(answer, sent) else _unredact_answer(answer, sent, plain)
            except Exception:  # noqa: BLE001
                result["result"] = plain
        if result.get("status") == "escalate":
            _logger.warning("gr_stub_client[%s]: escalation flagged — passing through for human review", hop)
        _announce_enforce(url, hop, result.get("status", "allow"), extra=f"actions={_actions_brief(result.get('actions_applied') or [])}")
        if result.get("status") == "block":
            actions = result.get("actions_applied") or []
            pid = ""
            if actions and isinstance(actions[0], dict):
                pid = str(actions[0].get("policy_id") or "")
            _record_process_block(site_id or "", result.get("warning") or "", pid)
        return result
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            try:
                detail = json.loads(_http_error_body(exc)).get("detail", {})
            except Exception:
                detail = {}
            blocked_by = detail.get("blocked_by") or []
            policy_id = blocked_by[0].get("policy_id", "unknown") if blocked_by else "unknown"
            reason = detail.get("message", "Request denied by policy enforcement.")
            _obs["gr"] = _gr_verdict("block", blocked_by or [policy_id])
            _logger.warning("gr_stub_client[%s]: BLOCKED by policy=%s — %s", hop, policy_id, reason)
            _record_process_block(site_id or "", reason, policy_id)
            return {
                "status": "block",
                "result": {"data": data},
                "actions_applied": [{"policy_id": policy_id, "action": "block"}],
                "recommendations": [],
                "warning": reason,
            }
        _logger.warning(
            "gr_stub_client[%s]: GR service call failed (%s) POST %s/enforce — failing open",
            hop, exc, url,
        )
        return {
            "status": "allow",
            "result": {"data": data},
            "actions_applied": [],
            "recommendations": [],
            "warning": f"GR service error: {exc}",
        }
    except Exception as exc:
        _logger.warning(
            "gr_stub_client[%s]: GR service call failed (%s) POST %s/enforce — failing open",
            hop, exc, url,
        )
        return {
            "status": "allow",
            "result": {"data": data},
            "actions_applied": [],
            "recommendations": [],
            "warning": f"GR service unreachable: {exc}",
        }



_CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _new_ulid() -> str:
    """26-char Crockford ULID (48-bit timestamp + 80-bit randomness)."""
    import os as _os
    import time as _time

    ts_ms = int(_time.time() * 1000) & 0xFFFFFFFFFFFF  # 48 bits
    rand = int.from_bytes(_os.urandom(10), "big")  # 80 bits
    value = (ts_ms << 80) | rand
    chars = []
    for _ in range(26):
        chars.append(_CROCKFORD_ALPHABET[value & 0x1F])
        value >>= 5
    return "".join(reversed(chars))


def _current_trace_id() -> str:
    """Trace id of the caller's own active OpenTelemetry span, if the app uses
    OpenTelemetry. Never imports it (an app that doesn't use it pays nothing)."""
    mod = sys.modules.get("opentelemetry.trace")
    if mod is None:
        return ""
    try:
        ctx = mod.get_current_span().get_span_context()
        return format(ctx.trace_id, "032x") if ctx.is_valid else ""
    except Exception:
        return ""


# ── Runtime discovery ────────────────────────────────────────────────────────
# Where this application instance runs, worked out once per process and cached:
# every /enforce sends it as the call's source context (AIBOM relation mapping).
# Environment first; then the cloud metadata services (AWS / Azure / GCP, 200 ms
# timeouts, on by default, off with UNIFAI_RUNTIME_DISCOVERY_IMDS=0), still only once.

_RUNTIME_DISCOVERY: "dict[str, str] | None" = None
_RUNTIME_DISCOVERY_LOCK = threading.Lock()


def _first_env(*names: str) -> str:
    for name in names:
        value = (os.environ.get(name) or "").strip()
        if value:
            return value
    return ""


def _local_ip(probe_host: str = "") -> str:
    """The address this host uses for outbound traffic (no packet is sent)."""
    import socket

    for host in (probe_host, "10.255.255.255", "8.8.8.8"):
        if not host:
            continue
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect((host, 80))
            ip = sock.getsockname()[0]
            if ip and not ip.startswith("0."):
                return ip
        except OSError:
            continue
        finally:
            sock.close()
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return ""


# ── Cloud location (same logic as GR's gr_service/reporting/cloud_metadata.py) ──
# Platform env (Lambda, App Service, Cloud Run, Vercel, Fly, Railway, Render, Heroku),
# ECS / Fargate task metadata, the link-local metadata service (AWS, Azure, GCP, OCI,
# DigitalOcean, Hetzner, Linode, Vultr, OpenStack) and Alibaba / Tencent. Fills
# cloud_provider / region / az / instance_id / instance_name.

_CM_TIMEOUT = 0.2

_CMFIELDS = ("cloud_provider", "cloud_region", "cloud_az", "cloud_instance_id", "cloud_instance_name")


def _cm_get(url: str, headers: dict[str, str] | None = None, method: str = "GET") -> str:
    try:
        req = urllib.request.Request(url, headers=headers or {}, method=method)
        with urllib.request.urlopen(req, timeout=_CM_TIMEOUT) as resp:  # noqa: S310 (link-local)
            if resp.status >= 300:
                return ""
            return resp.read().decode("utf-8", "replace").strip()
    except Exception:
        return ""


def _current_span_id() -> str:
    """Span id of the caller's own active OpenTelemetry span (same rules as _current_trace_id)."""
    mod = sys.modules.get("opentelemetry.trace")
    if mod is None:
        return ""
    try:
        ctx = mod.get_current_span().get_span_context()
        return format(ctx.span_id, "016x") if ctx.is_valid else ""
    except Exception:
        return ""


_STUB_PLUMBING = frozenset({"gr_check", "_block", "_stub_client", "check", "enforce", "_gr_asyncio"})


def _caller_frames(limit: int = 12) -> "list[str]":
    """The app's own call path at the moment a stub fires: innermost-first
    "file:line function" for frames in the customer's code. Skips this client,
    the stub helper, the standard library and installed packages. Paths are
    made relative to the working directory when possible. A stub that runs in
    a worker thread (asyncio.to_thread / executors) only sees that thread's
    frames, so the chain can start part-way up — it is never reconstructed."""
    out: "list[str]" = []
    try:
        import sysconfig

        # realpath on both sides: a venv / Homebrew stdlib path is often a symlink
        skip_roots = tuple(os.path.realpath(p) for p in (sysconfig.get_paths().get("stdlib"), sysconfig.get_paths().get("platstdlib")) if p)
        here = os.path.realpath(__file__)
        cwd = os.getcwd()
        frame = sys._getframe(1)
        while frame is not None and len(out) < limit:
            code = frame.f_code
            fn = os.path.realpath(code.co_filename)
            if (fn != here and code.co_name not in _STUB_PLUMBING and not fn.startswith(skip_roots)
                    and "site-packages" not in fn and "dist-packages" not in fn and not code.co_filename.startswith("<")):
                rel = os.path.relpath(fn, cwd) if fn.startswith(cwd + os.sep) else fn
                out.append(f"{rel}:{frame.f_lineno} {code.co_name}")
            frame = frame.f_back
    except Exception:
        return out
    return out


def new_interaction_id() -> str:
    """One id per model call; the generated agent->llm stub stores it in a
    local so the llm->agent stub after the same call reuses it."""
    return _new_ulid()


def _process_facts() -> "dict[str, Any]":
    """pid and language of this process (AI_AGENT_ACTIVITY_LOG groups a request by host+pid).
    Where it runs (cloud, region, host, pod) comes from runtime_discovery, sent as runtime_context."""
    import platform as _platform
    return {"pid": os.getpid(), "language": "python", "language_version": _platform.python_version()}


def _cm_json(url: str, headers: dict[str, str] | None = None) -> dict:
    raw = _cm_get(url, headers)
    if not raw.startswith("{"):
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _cm_reachable(host: str, port: int = 80) -> bool:
    try:
        with socket.create_connection((host, port), timeout=_CM_TIMEOUT):
            return True
    except OSError:
        return False


def _cm_env(*names: str) -> str:
    for name in names:
        value = (os.environ.get(name) or "").strip()
        if value:
            return value
    return ""


# What the metadata probes already fetched, for the platform label (``_platform_from_labels``): the AWS IMDSv2
# token, Azure's compute tags, that GCP's metadata server answered, ECS task docker labels. Filled once, in discovery.
_CM_STASH: "dict[str, Any]" = {}


def _cm_set(found: dict[str, str], provider: str, region: str = "", az: str = "",
         instance_id: str = "", instance_name: str = "") -> bool:
    """Fill only what is still missing. ``True`` (the provider answered)."""
    for key, value in (("cloud_provider", provider), ("cloud_region", region), ("cloud_az", az),
                       ("cloud_instance_id", instance_id), ("cloud_instance_name", instance_name)):
        if value and not found.get(key):
            found[key] = str(value)
    return True


def _cm_complete(found: dict[str, str]) -> bool:
    return all(found.get(k) for k in _CMFIELDS)


# ── 1. platform environment ──────────────────────────────────────────────────

def _cm_discover_from_platform_env(found: dict[str, str]) -> None:
    if _cm_env("AWS_LAMBDA_FUNCTION_NAME"):
        _cm_set(found, "aws", _cm_env("AWS_REGION", "AWS_DEFAULT_REGION"), "",
             _cm_env("AWS_LAMBDA_LOG_STREAM_NAME"), _cm_env("AWS_LAMBDA_FUNCTION_NAME"))
    elif _cm_env("WEBSITE_SITE_NAME"):  # Azure App Service / Functions
        _cm_set(found, "azure", _cm_env("REGION_NAME"), "", _cm_env("WEBSITE_INSTANCE_ID"), _cm_env("WEBSITE_SITE_NAME"))
    elif _cm_env("K_SERVICE"):  # Cloud Run / Cloud Functions (region also from the metadata server)
        _cm_set(found, "gcp", _cm_env("GOOGLE_CLOUD_REGION", "FUNCTION_REGION"), "", "", _cm_env("K_REVISION", "K_SERVICE"))
    elif _cm_env("VERCEL_REGION"):
        _cm_set(found, "vercel", _cm_env("VERCEL_REGION"), "", _cm_env("VERCEL_DEPLOYMENT_ID"), _cm_env("VERCEL_URL"))
    elif _cm_env("FLY_REGION"):
        _cm_set(found, "fly", _cm_env("FLY_REGION"), "", _cm_env("FLY_MACHINE_ID", "FLY_ALLOC_ID"), _cm_env("FLY_APP_NAME"))
    elif _cm_env("RAILWAY_REPLICA_ID"):
        _cm_set(found, "railway", _cm_env("RAILWAY_REPLICA_REGION"), "", _cm_env("RAILWAY_REPLICA_ID"),
             _cm_env("RAILWAY_SERVICE_NAME"))
    elif _cm_env("RENDER_INSTANCE_ID"):
        _cm_set(found, "render", "", "", _cm_env("RENDER_INSTANCE_ID"), _cm_env("RENDER_SERVICE_NAME"))
    elif _cm_env("DYNO"):
        _cm_set(found, "heroku", "", "", _cm_env("DYNO"), _cm_env("HEROKU_APP_NAME") or _cm_env("DYNO"))


# ── 2. ECS / Fargate ─────────────────────────────────────────────────────────

def _cm_ecs(found: dict[str, str]) -> bool:
    base = _cm_env("ECS_CONTAINER_METADATA_URI_V4")
    if not base:
        return False
    task = _cm_json(base.rstrip("/") + "/task")
    if not task:
        return False
    _CM_STASH["ecs_labels"] = {k: v for c in (task.get("Containers") or []) if isinstance(c, dict)
                               for k, v in (c.get("Labels") or {}).items()}
    arn = str(task.get("TaskARN") or "")
    parts = arn.split(":")
    family = f"{task.get('Family') or ''}:{task.get('Revision') or ''}".strip(":")
    _cm_set(found, "aws", parts[3] if len(parts) > 3 else "", str(task.get("AvailabilityZone") or ""),
         arn.rsplit("/", 1)[-1], family)
    cluster = str(task.get("Cluster") or "")
    if cluster and not found.get("cluster"):
        found["cluster"] = cluster.rsplit("/", 1)[-1]
    return True


# ── 3. link-local metadata services ──────────────────────────────────────────

_CM_LL = "http://169.254.169.254"


def _cm_aws(found: dict[str, str]) -> bool:
    token = _cm_get(f"{_CM_LL}/latest/api/token", {"X-aws-ec2-metadata-token-ttl-seconds": "60"}, "PUT")
    if not token:
        return False
    h = {"X-aws-ec2-metadata-token": token}
    _CM_STASH["aws_token"] = token
    base = f"{_CM_LL}/latest/meta-data/"
    name = _cm_get(base + "tags/instance/Name", h) or _cm_get(base + "local-hostname", h)
    return _cm_set(found, "aws", _cm_get(base + "placement/region", h), _cm_get(base + "placement/availability-zone", h),
                _cm_get(base + "instance-id", h), name)


def _cm_azure(found: dict[str, str]) -> bool:
    compute = _cm_json(f"{_CM_LL}/metadata/instance/compute?api-version=2021-02-01", {"Metadata": "true"})
    if not compute:
        return False
    tags = {str(t.get("name")): str(t.get("value") or "") for t in (compute.get("tagsList") or [])
            if isinstance(t, dict) and t.get("name")}
    for pair in str(compute.get("tags") or "").split(";"):          # older form: "k1:v1;k2:v2"
        k, _, v = pair.partition(":")
        if k.strip():
            tags.setdefault(k.strip(), v.strip())
    _CM_STASH["azure_tags"] = tags
    return _cm_set(found, "azure", str(compute.get("location") or ""), str(compute.get("zone") or ""),
                str(compute.get("vmId") or ""), str(compute.get("name") or ""))


def _cm_gcp(found: dict[str, str]) -> bool:
    h = {"Metadata-Flavor": "Google"}
    base = "http://metadata.google.internal/computeMetadata/v1/instance/"
    instance_id = _cm_get(base + "id", h)
    if not instance_id:
        return False
    _CM_STASH["gcp"] = True
    zone = _cm_get(base + "zone", h).rsplit("/", 1)[-1]
    region = _cm_get(base + "region", h).rsplit("/", 1)[-1] or zone.rsplit("-", 1)[0]
    return _cm_set(found, "gcp", region, zone, instance_id, _cm_get(base + "name", h))


def _cm_oci(found: dict[str, str]) -> bool:
    inst = _cm_json(f"{_CM_LL}/opc/v2/instance/", {"Authorization": "Bearer Oracle"})
    if not inst:
        return False
    return _cm_set(found, "oci", str(inst.get("canonicalRegionName") or inst.get("region") or ""),
                str(inst.get("availabilityDomain") or ""), str(inst.get("id") or ""),
                str(inst.get("displayName") or ""))


def _cm_digitalocean(found: dict[str, str]) -> bool:
    meta = _cm_json(f"{_CM_LL}/metadata/v1.json")
    if not meta or "droplet_id" not in meta:
        return False
    return _cm_set(found, "digitalocean", str(meta.get("region") or ""), "", str(meta.get("droplet_id") or ""),
                str(meta.get("hostname") or ""))


def _cm_hetzner(found: dict[str, str]) -> bool:
    base = f"{_CM_LL}/hetzner/v1/metadata/"
    instance_id = _cm_get(base + "instance-id")
    if not instance_id.isdigit():
        return False
    return _cm_set(found, "hetzner", _cm_get(base + "region"), _cm_get(base + "availability-zone"), instance_id,
                _cm_get(base + "hostname"))


def _cm_linode(found: dict[str, str]) -> bool:
    token = _cm_get(f"{_CM_LL}/v1/token", {"Metadata-Token-Expiry-Seconds": "60"}, "PUT")
    if not token:
        return False
    inst = _cm_json(f"{_CM_LL}/v1/instance", {"Metadata-Token": token, "Accept": "application/json"})
    if not inst:
        return False
    return _cm_set(found, "linode", str(inst.get("region") or ""), "", str(inst.get("id") or ""),
                str(inst.get("label") or ""))


def _cm_vultr(found: dict[str, str]) -> bool:
    meta = _cm_json(f"{_CM_LL}/v1.json")
    if not meta or "instanceid" not in meta:
        return False
    region = meta.get("region")
    region = (region.get("regioncode") if isinstance(region, dict) else region) or ""
    return _cm_set(found, "vultr", str(region), "", str(meta.get("instanceid") or ""),
                str(meta.get("hostname") or ""))


def _cm_openstack(found: dict[str, str]) -> bool:
    meta = _cm_json(f"{_CM_LL}/openstack/latest/meta_data.json")
    if not meta or "uuid" not in meta:
        return False
    return _cm_set(found, "openstack", "", str(meta.get("availability_zone") or ""), str(meta.get("uuid") or ""),
                str(meta.get("name") or meta.get("hostname") or ""))


# ── 4. providers with their own address ──────────────────────────────────────

def _cm_alibaba(found: dict[str, str]) -> bool:
    if not _cm_reachable("100.100.100.200"):
        return False
    base = "http://100.100.100.200/latest/meta-data/"
    instance_id = _cm_get(base + "instance-id")
    if not instance_id:
        return False
    return _cm_set(found, "alibaba", _cm_get(base + "region-id"), _cm_get(base + "zone-id"), instance_id,
                _cm_get(base + "instance/instance-name") or _cm_get(base + "hostname"))


def _cm_tencent(found: dict[str, str]) -> bool:
    try:
        socket.getaddrinfo("metadata.tencentyun.com", 80)
    except OSError:
        return False
    base = "http://metadata.tencentyun.com/latest/meta-data/"
    instance_id = _cm_get(base + "instance-id")
    if not instance_id:
        return False
    return _cm_set(found, "tencent", _cm_get(base + "placement/region"), _cm_get(base + "placement/zone"), instance_id,
                _cm_get(base + "instance-name"))


_CM_LINK_LOCAL = (_cm_aws, _cm_azure, _cm_gcp, _cm_oci, _cm_digitalocean, _cm_hetzner, _cm_linode, _cm_vultr, _cm_openstack)


def _cm_discover_from_imds(found: dict[str, str]) -> None:
    """Fill missing cloud fields (provider, region, AZ, instance id, instance name)."""
    _cm_discover_from_platform_env(found)
    if _cm_complete(found):
        return
    if _cm_ecs(found):
        return
    if _cm_reachable("169.254.169.254"):
        for probe in _CM_LINK_LOCAL:
            if probe(found):
                return
    if not found.get("cloud_provider"):
        for probe in (_cm_alibaba, _cm_tencent):
            if probe(found):
                return


_discover_from_imds = _cm_discover_from_imds  # name kept for callers/tests


# ── The agentic platform (S&G Run view: Run -> <platform> -> <platform>-<CLOUD>-<region>) ──────────────────────────
# 1. GR_AGENTIC_PLATFORM (env / .env / .lineaje/guardrail.json gr_agentic_platform): the deployer's override.
# 2. A deployment label / tag named PLATFORM_LABEL_KEY: Kubernetes pod label (downward API labels file), ECS docker
#    label, EC2 instance tag (IMDS, only when instance tags in metadata are on), Azure compute tag, GCP instance
#    attribute. Metadata is only read from a service discovery already reached (no extra wait), and not at all with
#    UNIFAI_RUNTIME_DISCOVERY_IMDS=0; the labels file is a local read.
# 3. The runtime itself, from documented signals; Agent Engine wins over Cloud Run / Kubernetes (it runs on them).
# Nothing found: no platform (as before). Names are single CamelCase tokens: valid org names, and unambiguous in the
# region org's name <platform>-<CLOUD>-<region>.
PLATFORM_LABEL_KEY = "lineaje-agentic-platform"
_POD_LABELS_FILE = "/etc/podinfo/labels"
PLATFORM_NAMES = {"agent_engine": "VertexAIAgentEngine", "cloud_run": "CloudRun", "container_apps": "ContainerApps",
                  "lambda": "Lambda", "ecs": "ECS", "kubernetes": "Kubernetes"}


def _platform_name_ok(value: str) -> str:
    value = (value or "").strip().strip('"')
    return value if value and value.isprintable() and len(value) <= 64 else ""


def _pod_label(path: str) -> str:
    """``PLATFORM_LABEL_KEY`` from a downward-API labels file (``key="value"`` lines), "" when absent."""
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                key, _, value = line.strip().partition("=")
                if key.strip() == PLATFORM_LABEL_KEY:
                    return _platform_name_ok(value)
    except OSError:
        pass
    return ""


def _platform_from_labels(imds: bool) -> "tuple[str, str]":
    """``(name, where)`` from a deployment label / tag, ``("", "")`` when none names the platform."""
    name = _pod_label(_first_env("GR_POD_LABELS_FILE") or _POD_LABELS_FILE)
    if name:
        return name, "kubernetes_pod_label"
    if not imds:
        return "", ""
    name = _platform_name_ok(str((_CM_STASH.get("ecs_labels") or {}).get(PLATFORM_LABEL_KEY) or ""))
    if name:
        return name, "ecs_docker_label"
    name = _platform_name_ok(str((_CM_STASH.get("azure_tags") or {}).get(PLATFORM_LABEL_KEY) or ""))
    if name:
        return name, "azure_vm_tag"
    if _CM_STASH.get("aws_token"):        # 404 unless "instance tags in metadata" is on for the instance
        name = _platform_name_ok(_cm_get(f"{_CM_LL}/latest/meta-data/tags/instance/{PLATFORM_LABEL_KEY}",
                                         {"X-aws-ec2-metadata-token": _CM_STASH["aws_token"]}))
        if name:
            return name, "ec2_instance_tag"
    if _CM_STASH.get("gcp"):
        name = _platform_name_ok(_cm_get("http://metadata.google.internal/computeMetadata/v1/instance/attributes/"
                                         + PLATFORM_LABEL_KEY, {"Metadata-Flavor": "Google"}))
        if name:
            return name, "gcp_instance_attribute"
    return "", ""


def _platform_from_runtime() -> "tuple[str, str]":
    """``(name, signal)`` from the runtime's own environment, ``("", "")`` when none matches."""
    if _first_env("GOOGLE_CLOUD_AGENT_ENGINE_ID"):          # set by Agent Engine; it also sets K_SERVICE
        return PLATFORM_NAMES["agent_engine"], "GOOGLE_CLOUD_AGENT_ENGINE_ID"
    if _first_env("K_SERVICE") and not _first_env("KUBERNETES_SERVICE_HOST"):   # Knative on Kubernetes sets both
        return PLATFORM_NAMES["cloud_run"], "K_SERVICE"
    if _first_env("CONTAINER_APP_NAME"):
        return PLATFORM_NAMES["container_apps"], "CONTAINER_APP_NAME"
    if _first_env("AWS_LAMBDA_FUNCTION_NAME"):
        return PLATFORM_NAMES["lambda"], "AWS_LAMBDA_FUNCTION_NAME"
    if _first_env("ECS_CONTAINER_METADATA_URI_V4"):
        return PLATFORM_NAMES["ecs"], "ECS_CONTAINER_METADATA_URI_V4"
    if _first_env("KUBERNETES_SERVICE_HOST"):
        return PLATFORM_NAMES["kubernetes"], "KUBERNETES_SERVICE_HOST"
    return "", ""


def _detect_agentic_platform(imds: bool) -> "tuple[str, str]":
    """``(platform, source)``: the override, else a deployment label, else the runtime; ``("", "")`` when none."""
    override = _agentic_platform()
    if override:
        return override, "override"
    name, where = _platform_from_labels(imds)
    if name:
        return name, f"label:{where}"
    name, signal = _platform_from_runtime()
    if name:
        return name, f"runtime:{signal}"
    return "", ""


def runtime_discovery(gr_url: str = "") -> "dict[str, str]":
    """This application instance's runtime context, computed once and cached."""
    global _RUNTIME_DISCOVERY
    if _RUNTIME_DISCOVERY is not None:
        return _RUNTIME_DISCOVERY
    with _RUNTIME_DISCOVERY_LOCK:
        if _RUNTIME_DISCOVERY is not None:
            return _RUNTIME_DISCOVERY
        import socket

        found: "dict[str, str]" = {}
        try:
            provider = _first_env("UNIFAI_CLOUD_PROVIDER", "GR_CLOUD_PROVIDER")
            if not provider:
                if _first_env("AWS_REGION", "AWS_DEFAULT_REGION", "AWS_EXECUTION_ENV",
                              "ECS_CONTAINER_METADATA_URI_V4", "ECS_CONTAINER_METADATA_URI"):
                    provider = "aws"
                elif _first_env("WEBSITE_SITE_NAME", "AZURE_REGION", "REGION_NAME", "IDENTITY_ENDPOINT"):
                    provider = "azure"
                elif _first_env("GOOGLE_CLOUD_PROJECT", "GCP_PROJECT", "K_SERVICE", "FUNCTION_REGION"):
                    provider = "gcp"
            if provider:
                found["cloud_provider"] = provider.lower()
            region = _first_env("UNIFAI_CLOUD_REGION", "GR_REGION", "AWS_REGION", "AWS_DEFAULT_REGION",
                                "AZURE_REGION", "REGION_NAME", "GOOGLE_CLOUD_REGION", "GCP_REGION",
                                "FUNCTION_REGION")
            if region:
                found["cloud_region"] = region
            az = _first_env("UNIFAI_CLOUD_AZ", "GR_AZ", "AWS_AVAILABILITY_ZONE", "AZURE_ZONE", "GCP_ZONE")
            if az:
                found["cloud_az"] = az
            instance = _first_env("UNIFAI_CLOUD_INSTANCE_ID", "GR_INSTANCE_ID", "EC2_INSTANCE_ID",
                                  "WEBSITE_INSTANCE_ID")
            if instance:
                found["cloud_instance_id"] = instance
            # Cloud metadata (AWS / Azure / GCP): on by default, off with
            # UNIFAI_RUNTIME_DISCOVERY_IMDS=0; skipped when the env already names it all.
            imds = _first_env("UNIFAI_RUNTIME_DISCOVERY_IMDS").lower() not in ("0", "false", "no", "off")
            if imds:
                _discover_from_imds(found)
            # The AI platform: with cloud_provider / cloud_region, where GR files this app in the Run view.
            # GR_AGENTIC_PLATFORM overrides; else a deployment label; else the runtime (_detect_agentic_platform).
            # Left out when nothing names one, as before; the source says which decided (for debugging).
            platform, platform_source = _detect_agentic_platform(imds)
            if platform:
                found["agentic_platform"] = platform
                found["agentic_platform_source"] = platform_source
            found["hostname"] = socket.gethostname()
            # Instance name: the provider's own name for the machine, else the host name.
            found["cloud_instance_name"] = (_first_env("UNIFAI_CLOUD_INSTANCE_NAME")
                                            or found.get("cloud_instance_name") or found["hostname"])
            probe = urllib.parse.urlparse(gr_url).hostname if gr_url else ""
            found["ip"] = _first_env("UNIFAI_APP_IP", "POD_IP") or _local_ip(probe or "")
            for key, names in (
                ("source_code_name", ("UNIFAI_APP_NAME", "GR_APP_NAME")),
                ("source_code_version", ("UNIFAI_APP_VERSION", "GR_APP_VERSION")),
                ("source_code_branch", ("UNIFAI_APP_BRANCH", "GR_APP_BRANCH")),
                ("cluster", ("UNIFAI_CLUSTER", "GR_CLUSTER")),
                ("pod_name", ("POD_NAME",)),
                ("namespace", ("POD_NAMESPACE",)),
                ("node_name", ("NODE_NAME",)),
            ):
                value = _first_env(*names) or _scan_context(_SCAN_CONTEXT_KEYS.get(key, ""))
                if value:
                    found[key] = value
        except Exception as exc:  # never break the call path over discovery
            _logger.debug("gr_stub_client: runtime discovery incomplete: %s", exc)
        _RUNTIME_DISCOVERY = {k: v for k, v in found.items() if v}
        return _RUNTIME_DISCOVERY


# ── Heartbeat ────────────────────────────────────────────────────────────────
# One heartbeat per application process (not per stub), on its own daemon thread, to
# GR's POST /heartbeat: project identity, the instance's IP and runtime discovery.
# No refresh token is needed: without one the tenant / company / org come from
# GR_TENANT_ID / GR_COMPANY_ID / LINEAJE_ORG_NAME (or LINEAJE_* twins) in the body.
# GR marks an instance stale after several missed heartbeats. GR_HEARTBEAT_URL is the
# endpoint (default: GR_SERVICE_URL's host + /heartbeat); UNIFAI_HEARTBEAT_SECS sets the
# interval (default 1800, every 30 minutes); UNIFAI_HEARTBEAT=0 turns it off.

_DEFAULT_HEARTBEAT_SECS = 1800

_HEARTBEAT_STARTED = False
_HEARTBEAT_LOCK = threading.Lock()


def _heartbeat_interval() -> int:
    try:
        return max(30, int(_first_env("UNIFAI_HEARTBEAT_SECS") or _DEFAULT_HEARTBEAT_SECS))
    except ValueError:
        return _DEFAULT_HEARTBEAT_SECS


# Observability events (one per executed stub, log-only or enforcing) go to GR's POST /observability/batch (per
# event to /observability on a Guardrail without the batch route), never on the app's thread: see
# "Observability events" below. GR_OBSERVABILITY_URL is the full /observability endpoint (default:
# GR_SERVICE_URL's host + /observability; the batch route is that + /batch). A Guardrail without /observability
# answers 404; log-only events then go to /enforce, which also handles observe_only, and the client stops
# telling /enforce it reports calls itself (``reports_activity``).
_OBSERVABILITY_UNSUPPORTED = False


def _observability_endpoint(gr_url: str) -> "tuple[str, str]":
    explicit = _first_env("GR_OBSERVABILITY_URL").rstrip("/")
    return (explicit, "") if explicit else (gr_url, "/observability")


def _heartbeat_endpoint(gr_url: str) -> "tuple[str, str]":
    """``(url, path)`` for ``_post_json``: GR_HEARTBEAT_URL when set, else GR + /heartbeat."""
    explicit = _first_env("GR_HEARTBEAT_URL").rstrip("/")
    return (explicit, "") if explicit else (gr_url, "/heartbeat")


def _heartbeat_bearer(fallback: str) -> str:
    """Bearer for one heartbeat: the /enforce bearer, from the refresh token. Never raises."""
    try:
        return _resolve_enforce_bearer() or fallback
    except Exception:
        return fallback


def _ensure_heartbeat(gr_url: str, tenant_id: str, pat: str, site: Any) -> None:
    """Start the process's heartbeat thread once. ``site`` is a SiteDescriptor or the
    /enforce body (both carry the project fields). Never raises."""
    try:
        _start_heartbeat(gr_url, tenant_id, pat, site)
    except Exception as exc:  # never break enforcement over the heartbeat
        _logger.debug("gr_stub_client: heartbeat not started: %s", exc)


def _site_field(site: Any, name: str) -> Any:
    return site.get(name) if isinstance(site, dict) else getattr(site, name, None)


# runtime_discovery key -> SCAN_CONTEXT key (the application the scan saw, when no env var names it).
_SCAN_CONTEXT_KEYS = {"source_code_name": "app_name", "source_code_version": "app_version",
                      "source_code_branch": "app_branch"}


def _scan_context(key: str) -> str:
    """``SCAN_CONTEXT[key]`` (stamped by the scan), "" when absent."""
    value = SCAN_CONTEXT.get(key) if isinstance(SCAN_CONTEXT, dict) else ""
    return str(value or "")


_ORG_UNKNOWN_LOGGED = False


def _request_project(site: Any) -> str:
    """The project this call belongs to (LIN-36164): GR_PROJECT (runtime override), else the descriptor's project
    (older stubs), else UNIFAI_PROJECT, else the scan's SCAN_CONTEXT project (the repository name)."""
    return (_first_env("GR_PROJECT") or _site_field(site, "project") or _first_env("UNIFAI_PROJECT")
            or _scan_context("project") or "")


def _request_organization(site: Any) -> str:
    """The Lineaje organization (LIN-36163): GR_ORGANIZATION (runtime override), else the descriptor's (older
    stubs), else UNIFAI_ORGANIZATION, else the scan's SCAN_CONTEXT organization. "" when none: the request then
    carries no organization, and that is logged once per process."""
    global _ORG_UNKNOWN_LOGGED
    org = (_first_env("GR_ORGANIZATION") or _site_field(site, "organization") or _first_env("UNIFAI_ORGANIZATION")
           or _scan_context("organization") or "")
    if not org and not _ORG_UNKNOWN_LOGGED:
        _ORG_UNKNOWN_LOGGED = True
        _logger.info("gr_stub_client: no organization known (the scan stamped none); requests carry no organization "
                     "— set GR_ORGANIZATION to name it")
    return org


def _request_workflow() -> str:
    """The workflow this call belongs to (LIN-36165): GR_WORKFLOW, else the one the scan named; "" when neither
    names one. Never derived from the app or project name (LIN-36221: the Run view hides Workflow when none)."""
    return _first_env("GR_WORKFLOW") or _scan_context("workflow") or ""


# ── Workflow run and step (CON-3356) ─────────────────────────────────────────
# Which run of the workflow (session_id: one per run) and which node of it (step: "2/5", a node name) a call
# belongs to, so a violation traces to one workflow, one session, one step. Set by the application around the
# work: per run / per step with workflow_context() (a contextvar, so concurrent runs in threads or tasks stay
# apart and asyncio.to_thread carries it), or process-wide with GR_SESSION_ID / GR_STEP (a process that is one
# run, e.g. a batch job). The contextvar wins over the env. Never generated: nothing set -> nothing sent.
_WORKFLOW_CONTEXT: "contextvars.ContextVar[dict | None]" = contextvars.ContextVar(
    "gr_workflow_context", default=None)


class workflow_context:
    """Name the session (workflow run) and / or step of the calls made inside it.

        with gr_stub_client.workflow_context(session_id=run_id):
            for i, node in enumerate(nodes, 1):
                with gr_stub_client.workflow_context(step=f"{i}/{len(nodes)}"):
                    node.run()

    A value left as None is inherited from the enclosing context (or GR_SESSION_ID / GR_STEP); "" clears it.
    Also usable without ``with``: ``ctx = workflow_context(step="3/5").set()`` ... ``ctx.reset()``."""

    def __init__(self, *, session_id: "str | None" = None, step: "str | None" = None) -> None:
        self._values = {k: v for k, v in (("session_id", session_id), ("step", step)) if v is not None}
        self._token: "contextvars.Token | None" = None

    def set(self) -> "workflow_context":
        merged = dict(_WORKFLOW_CONTEXT.get() or {})
        merged.update({k: str(v).strip() for k, v in self._values.items()})
        self._token = _WORKFLOW_CONTEXT.set(merged)
        return self

    def reset(self) -> None:
        if self._token is not None:
            _WORKFLOW_CONTEXT.reset(self._token)
            self._token = None

    def __enter__(self) -> "workflow_context":
        return self.set()

    def __exit__(self, *exc: Any) -> None:
        self.reset()


def _workflow_value(key: str, env: str) -> str:
    ctx = _WORKFLOW_CONTEXT.get() or {}
    return ctx[key] if key in ctx else _first_env(env)


def _request_session_id() -> str:
    """This call's workflow run (CON-3356): workflow_context(session_id=...), else GR_SESSION_ID; "" when unset."""
    return _workflow_value("session_id", "GR_SESSION_ID")


def _request_step() -> str:
    """This call's step in the workflow (CON-3356): workflow_context(step=...), else GR_STEP; "" when unset."""
    return _workflow_value("step", "GR_STEP")


def _site_components(site: Any) -> dict:
    """The site's ``components`` with the application's identity (``identity.app``) added: stubs do not repeat
    it, it is the same for the whole application. From ``UNIFAI_APP_NAME`` / ``UNIFAI_APP_VERSION`` /
    ``UNIFAI_APP_PURL``, else the descriptor's project fields (older stubs), else ``SCAN_CONTEXT``.
    An ``identity.app`` the stub still carries (older stubs) is kept."""
    comps = _site_field(site, "components")
    comps = dict(comps) if isinstance(comps, dict) else {}
    identity = dict(comps.get("identity")) if isinstance(comps.get("identity"), dict) else {}
    if isinstance(identity.get("app"), dict):
        return comps
    app = {
        "name": _first_env("UNIFAI_APP_NAME", "GR_APP_NAME") or _site_field(site, "project_name")
        or _scan_context("app_name"),
        "version": _first_env("UNIFAI_APP_VERSION", "GR_APP_VERSION") or _site_field(site, "project_version")
        or _scan_context("app_version"),
        "purl": _first_env("UNIFAI_APP_PURL") or _scan_context("app_purl"),
    }
    if app["name"] or app["purl"]:
        comps["identity"] = {**identity, "app": app}
    return comps


def _start_heartbeat(gr_url: str, tenant_id: str, pat: str, site: Any) -> None:
    global _HEARTBEAT_STARTED
    if _HEARTBEAT_STARTED or not gr_url:
        return
    if _first_env("UNIFAI_HEARTBEAT").lower() in ("0", "false", "no", "off"):
        return
    with _HEARTBEAT_LOCK:
        if _HEARTBEAT_STARTED:
            return
        _HEARTBEAT_STARTED = True
    interval = _heartbeat_interval()
    ctx = _runtime_context_for(gr_url)
    app_identity = (_site_components(site).get("identity") or {}).get("app")
    ident = _identity_from_bearer(pat)
    body = {
        "tenant_id": tenant_id or ident["tenant_id"],
        "company_id": _site_field(site, "company_id") or ident["company_id"],
        "org_name": _site_field(site, "org_name") or ident["org_name"],
        "project_name": ctx.get("source_code_name") or _site_field(site, "project_name") or "",
        "project_version": ctx.get("source_code_version") or _site_field(site, "project_version") or "",
        "project_branch": ctx.get("source_code_branch") or _site_field(site, "project_branch") or "",
        "app_ip": _site_field(site, "app_ip") or ctx.get("ip", ""),
        "runtime_context": ctx,
        "components": {"identity": {"app": app_identity}} if app_identity else {},
        "interval_secs": interval,
    }

    def _beat() -> None:
        while True:
            try:
                # Same bearer as /enforce, resolved per beat: LINEAJE_REFRESH_TOKEN exchanged
                # for a short-lived access token (cached until it nears expiry). The token
                # captured at start would expire long before a 30-minute heartbeat stops.
                bearer = _heartbeat_bearer(pat)
                _post_json(*_heartbeat_endpoint(gr_url), body, bearer, 5.0)
            except Exception as exc:  # a missed beat is what marks an instance stale
                _logger.debug("gr_stub_client: heartbeat failed: %s", exc)
            time.sleep(interval)

    threading.Thread(target=_beat, daemon=True, name="unifai-heartbeat").start()


def _runtime_context_for(gr_url: str) -> "dict[str, str]":
    """``runtime_discovery`` for the /enforce body; ``{}`` if it cannot run."""
    try:
        return dict(runtime_discovery(gr_url))
    except Exception:
        return {}


@dataclass
class SiteDescriptor:
    """Scan-time facts for one call site. ``fail_mode`` is ALLOW_WITH_AUDIT or BLOCK."""
    site_id: str
    phase: str = ""
    boundary: dict = field(default_factory=dict)
    components: dict = field(default_factory=dict)
    candidate_policies: "list[dict]" = field(default_factory=list)
    site_manifest_version: "str | None" = None
    fail_mode: str = "ALLOW_WITH_AUDIT"
    source_type: str = ""
    destination_type: str = ""
    # Scan-time project (the SBOM document_name the scan uploaded under) and
    # organization — sent on every /enforce so project/org-scoped policy
    # lookups (e.g. the approved-LLM list) filter on them.
    project: str = ""
    organization: str = ""
    # Shared by an agent->llm stub and the llm->agent stub after the same call
    # (a local in the customer's function — see new_interaction_id) so the
    # prompt and its reply can be joined into one activity trace.
    interaction_id: "str | None" = None
    # Log-only call: the Guardrail records that this activity happened and runs no policy.
    # skipped_after_block: the call a stub makes instead of staying silent after an earlier block.
    observe_only: bool = False
    skipped_after_block: bool = False
    # Tenant, company and organization name for the runtime JSONs. Not written into
    # the inserted stubs: the stub client fills them at runtime from the token's claims
    # or the environment (GR_TENANT_ID / GR_COMPANY_ID / LINEAJE_ORG_NAME).
    tenant_id: str = ""
    company_id: str = ""
    org_name: str = ""
    # The application this site belongs to, baked in by the scan: project name,
    # version (from its manifest, else the branch) and branch.
    project_name: str = ""
    project_version: str = ""
    project_branch: str = ""
    # The running application's IP address. The scan cannot know it, so the stub
    # fills it from runtime discovery when it is empty; it tells GR (and SBOM 360)
    # which application instance made the call.
    app_ip: str = ""

    def __post_init__(self) -> None:
        # Bind the per-request latch on the constructing thread (the FastAPI
        # handler) before asyncio.to_thread copies the context into a worker.
        _ensure_request_latch()
        # The stub names only its site_id: its candidate_policies come from the
        # site's companion file (a log-only site's is the activity log).
        if not self.candidate_policies:
            self.candidate_policies = (["AI_AGENT_ACTIVITY_LOG"] if self.observe_only
                                       else _site_candidate_policies(self.site_id))


# The scan writes each site's candidate_policies to <this file's dir>/.lineaje/sites/<site key>.json
# (pipeline/stub/guardrail_stub_insertion.py site_policies_file); LINEAJE_SITES_DIR overrides the directory.
_SITE_POLICIES: "dict[str, list]" = {}
_SITE_POLICIES_LOCK = threading.Lock()


def _site_policies_key(site_id: str) -> str:
    m = re.fullmatch(r"site:sha256:([0-9a-f]{16,128})", (site_id or "").strip())
    if m:
        return m.group(1)
    import hashlib as _hashlib
    return _hashlib.sha256((site_id or "").encode("utf-8")).hexdigest()


def _site_candidate_policies(site_id: str) -> list:
    """``site_id``'s candidate_policies from its companion file, read once per process; ``[]``
    when there is no file (the Guardrail then registers the site from its own catalog)."""
    if not site_id:
        return []
    with _SITE_POLICIES_LOCK:
        if site_id in _SITE_POLICIES:
            return list(_SITE_POLICIES[site_id])
    base = (os.environ.get("LINEAJE_SITES_DIR") or "").strip() \
        or os.path.join(os.path.dirname(os.path.abspath(__file__)), ".lineaje", "sites")
    path = os.path.join(base, _site_policies_key(site_id) + ".json")
    policies: list = []
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        found = doc.get("candidate_policies") if isinstance(doc, dict) else None
        if isinstance(found, list) and (not doc.get("site_id") or doc.get("site_id") == site_id):
            policies = found
    except FileNotFoundError:
        _logger.warning("gr_stub_client: no candidate_policies file for site_id=%s (%s)", site_id, path)
    except Exception as exc:
        _logger.warning("gr_stub_client: unreadable candidate_policies file %s (%s)", path, exc)
    with _SITE_POLICIES_LOCK:
        _SITE_POLICIES[site_id] = policies
    return list(policies)


_PHASE_BOUNDARY_TO_SOURCE_DEST: dict[tuple[str, str, str], tuple[str, str]] = {
    ("pre_model", "agent_message", "model"): ("agent", "llm"),
    ("pre_model", "user_interface", "model"): ("user_interface", "llm"),
    ("post_model", "model", "agent_message"): ("llm", "agent"),
    ("pre_agent_send", "agent_message", "agent_message"): ("agent", "agent"),
    ("post_agent_receive", "user_interface", "agent_message"): ("user_interface", "agent"),
    ("post_tool", "database", "agent_message"): ("database", "agent"),
    ("post_tool", "external_endpoint", "agent_message"): ("api", "agent"),
    ("post_tool", "tool_result", "agent_message"): ("agent", "tool"),
    ("pre_tool", "agent_message", "tool_result"): ("agent", "tool"),
    ("pre_tool", "user_interface", "tool_result"): ("user_interface", "tool"),
    ("data_egress", "model", "user_interface"): ("llm", "user_interface"),
    ("data_egress", "agent_message", "user_interface"): ("agent", "user_interface"),
    ("data_egress", "agent_message", "external_endpoint"): ("agent", "external"),
    ("data_egress", "tool_result", "user_interface"): ("tool", "user_interface"),
    ("data_egress", "html", "user_interface"): ("html", "user_interface"),
    ("security_decision", "agent_message", "agent_message"): ("agent", "policy_engine"),
    ("log_emit", "log", "log"): ("agent", "log"),
    ("file_write", "agent_message", "file_content"): ("agent", "file"),
}


def _source_dest_from_site(site: "SiteDescriptor") -> tuple[str, str]:
    src = getattr(site, "source_type", "") or ""
    dst = getattr(site, "destination_type", "") or ""
    if src and dst:
        return src, dst
    boundary = getattr(site, "boundary", None) or {}
    phase = getattr(site, "phase", "") or ""
    sink = boundary.get("sink") or ""
    # ``source`` is a sorted list of source classes on log-evidence sites (IX.3), a string elsewhere.
    sources = boundary.get("source") or ""
    for source in (sources if isinstance(sources, (list, tuple)) else [sources]):
        hit = _PHASE_BOUNDARY_TO_SOURCE_DEST.get((phase, source or "", sink if isinstance(sink, str) else ""))
        if hit:
            return hit
    return "", ""


_DANGEROUS_SKILL_LOAD_NOTE = "This skill is dangerous to be loaded."
_QUARANTINED_SKILL_PATH_KEYS = (
    "skill_path", "skill_file", "path", "file_path", "data",
    "skill_manifest_path", "manifest_path",
)
_LIVE_SKILL_BASENAMES = frozenset({"skill.md", "skills.md"})
_BLOCKED_SKILL_BASENAMES = frozenset({
    "skill.md.blocked", "skills.md.blocked",
})


def _looks_like_quarantined_skill_path(value: Any) -> bool:
    """True when *value* names a ``SKILL.md.blocked`` file (or live sibling)."""
    if isinstance(value, dict):
        return any(
            _looks_like_quarantined_skill_path(value.get(k))
            for k in _QUARANTINED_SKILL_PATH_KEYS
        )
    if isinstance(value, (list, tuple)):
        return any(_looks_like_quarantined_skill_path(item) for item in value)
    raw = str(value or "").strip()
    if not raw:
        return False
    base = raw.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if base.endswith(".md.blocked") or base in _BLOCKED_SKILL_BASENAMES:
        return True
    try:
        if base in _LIVE_SKILL_BASENAMES and os.path.isfile(raw + ".blocked"):
            return True
        if os.path.isdir(raw):
            for name in ("SKILL.md.blocked", "skills.md.blocked", "skill.md.blocked"):
                if os.path.isfile(os.path.join(raw, name)):
                    return True
    except OSError:
        return False
    return False


def _site_is_skill_check(site: "SiteDescriptor") -> bool:
    phase = (getattr(site, "phase", "") or "").strip()
    _src, dst = _source_dest_from_site(site)
    return phase == "skill_check" or dst == "skill_check"


def _local_quarantined_skill_decision(site: "SiteDescriptor", payload: Any) -> "Decision | None":
    """Refuse a scan-quarantined skill on customer disk without POSTing /enforce.

    ``block_malicious_skills`` already renamed SKILL.md → SKILL.md.blocked.
    Hosted GR cannot see that file; this is the same local refuse the inline
    ``gr_check`` helper uses so the agent cannot keep invoking the skill.
    Site-local — does not latch the request-wide process block (job poll).
    """
    if not _site_is_skill_check(site):
        return None
    if not _looks_like_quarantined_skill_path(payload):
        return None
    hop = f"site_id={site.site_id}" if getattr(site, "site_id", "") else "site_id=<unknown>"
    _logger.warning(
        "gr_stub_client.check[%s]: quarantined skill (*.blocked) — not loaded, GR not called",
        hop,
    )
    return Decision({
        "status": "block",
        "result": {"data": payload},
        "actions_applied": [{
            "policy_id": "AI_SKILL_SEC_001",
            "action": "deny_execute",
            "deny_execute": True,
        }],
        "recommendations": [],
        "warning": _DANGEROUS_SKILL_LOAD_NOTE,
    }, site_id=getattr(site, "site_id", "") or "")


def _stub_must_not_crash_host(site: "SiteDescriptor") -> bool:
    """Leftover log/UI stubs sit on FastAPI handlers; raising is a 500.

    Only explicit log/user_interface destinations qualify. Do not infer from
    a leftover ``phase=data_egress`` default — LLM sites in tests (and any
    mis-tagged pre_model hop) must still raise.
    """
    src, dst = _source_dest_from_site(site)
    if dst == "llm" or src == "llm":
        return False
    explicit = (getattr(site, "destination_type", None) or "").strip()
    if explicit in ("log", "user_interface"):
        return True
    phase = (getattr(site, "phase", None) or "").strip()
    return phase == "log_emit"


def _payload_after_host_safe_block(
    site: "SiteDescriptor", decision: "Decision", original: Any,
) -> Any:
    """Keep HTTP/log handlers alive after a policy block.

    Log lines stay as-is (the logger still runs). JSON job/error dicts gain
    ``policy_error`` so a UI poll can render the block instead of 500.
    """
    _src, dst = _source_dest_from_site(site)
    phase = (getattr(site, "phase", None) or "").strip()
    if dst == "log" or phase == "log_emit":
        return original
    warning = (decision.warning or "Request blocked by guardrail policy").strip()
    if isinstance(original, dict):
        out = dict(original)
        out.setdefault("status", "error")
        out.setdefault("detail", warning)
        out["policy_error"] = {"type": "guardrail", "message": warning}
        return out
    return original


class GuardrailUnavailableError(PermissionError):
    """The GR service itself couldn't be reached/consulted (unreachable, misconfigured, errored) — never a live
    verdict. Since 2026-10-14 every outage FAILS OPEN inside the companion (``enforce`` / ``enforce_reply`` /
    ``enforce_request`` return the data unchanged), so the companion no longer raises it; generated stubs still
    catch it (``except _gr_client.GuardrailUnavailableError: pass``) for older companions. A ``PermissionError``
    that is NOT this subclass always means a real policy verdict.

    Callers (including generated stub call sites — see
    guardrail_stub_insertion.py's ``_make_check_stub_line``) can catch this
    specifically to fail OPEN (pass the original value through) on a GR
    outage, without weakening the fail-closed guarantee for genuine blocks.
    """


class Decision:
    """Result of ``check()``. Use ``blocked`` / ``payload`` / ``as_error()``."""

    def __init__(self, raw: dict, *, site_id: str = ""):
        self.raw = raw
        self.site_id = site_id
        self.status = raw.get("status", "allow")
        self.verdict = raw.get("verdict") or self.status.upper()
        self.result = raw.get("result") or {}
        self.payload = self.result.get("data")
        self.actions_applied = raw.get("actions_applied", [])
        self.recommendations = raw.get("recommendations", [])
        self.warning = raw.get("warning")
        self.infra_failure = bool(raw.get("infra_failure"))

    @property
    def blocked(self) -> bool:
        return self.status == "block"

    def as_error(self) -> PermissionError:
        """PermissionError (or GuardrailUnavailableError — see its docstring)
        for a policy block. ``check()`` never raises this itself.

        The message is always prefixed with ``Request blocked by guardrail
        policy:`` so customer agent code can fail closed (stop file
        extraction, MCP/tool calls, and document dumps) instead of treating
        the block as a normal model reply / processing note.
        """
        site_note = f" at site {self.site_id}" if self.site_id else ""
        message = (self.warning or f"blocked by guardrail policy{site_note}").strip()
        if not message.lower().startswith("request blocked by guardrail"):
            message = f"Request blocked by guardrail policy: {message}"
        if self.infra_failure:
            return GuardrailUnavailableError(message)
        return PermissionError(message)


_PII_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b", re.I), "[REDACTED_EMAIL]"),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
    ("cc", re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "[REDACTED_CC]"),
    (
        "phone",
        re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b"),
        "[REDACTED_PHONE]",
    ),
)


def _mask_pii_text(text: str) -> tuple[str, int]:
    hits = 0
    out = text
    for _kind, pat, repl in _PII_PATTERNS:
        out, n = pat.subn(repl, out)
        hits += n
    return out, hits


def _mask_pii_tree(value: Any) -> tuple[Any, int]:
    """Stdlib PII mask (kept for callers that ask for it explicitly; never applied to a GR verdict, review r4 N1)."""
    if isinstance(value, str):
        return _mask_pii_text(value)
    if isinstance(value, dict):
        total = 0
        rebuilt: dict[str, Any] = {}
        for k, v in value.items():
            nv, n = _mask_pii_tree(v)
            rebuilt[k] = nv
            total += n
        return rebuilt, total
    if isinstance(value, list):
        total = 0
        rebuilt_l: list[Any] = []
        for v in value:
            nv, n = _mask_pii_tree(v)
            rebuilt_l.append(nv)
            total += n
        return rebuilt_l, total
    if isinstance(value, tuple):
        items = []
        total = 0
        for v in value:
            nv, n = _mask_pii_tree(v)
            items.append(nv)
            total += n
        return tuple(items), total
    data = getattr(value, "data", None)
    if isinstance(value, urllib.request.Request) or (
        type(value).__name__ == "Request" and data is not None
    ):
        text = data.decode("utf-8", errors="replace") if isinstance(data, (bytes, bytearray)) else str(data or "")
        masked, n = _mask_pii_text(text)
        if n:
            try:
                value.data = masked.encode("utf-8")
            except Exception:
                pass
        return value, n
    page = getattr(value, "page_content", None)
    if isinstance(page, str):
        masked, n = _mask_pii_text(page)
        if n:
            try:
                value.page_content = masked
            except Exception:
                pass
        return value, n
    return value, 0


def _fail_response(site: "SiteDescriptor", warning: str, payload: Any) -> dict:
    """GR unreachable / erroring / unresolved unknown_site: FAIL OPEN in every mode (user decision 2026-10-14).

    The payload passes through unchanged — no local mask, no added fields, no reshaped value, no raise — whatever
    the site's policy fail mode (BLOCK included); the outage is logged and counted (``gr_outages()``). Verdicts
    from a reachable GR (block / mask) still apply as designed.
    """
    _note_outage(site, warning)
    return {
        "status": "allow",
        "result": {"data": payload},
        "actions_applied": [],
        "recommendations": [],
        "warning": f"{warning} — failing OPEN (guardrail unavailable: data passed through unchanged)",
        "infra_failure": True,
    }


_outages = {"count": 0}


def gr_outages() -> int:
    """How many enforce calls passed data through unchanged because the GR was unreachable or errored."""
    return _outages["count"]


def _note_outage(site: Any, why: Any) -> None:
    _outages["count"] += 1
    _logger.warning("gr_stub_client[site_id=%s]: guardrail unavailable (%s) — failing open, data unchanged",
                    getattr(site, "site_id", ""), why)


def _find_assignment_line(lines: list[str], var_name: str, before_line: int) -> int | None:
    """1-based line of ``var_name = ...`` assignment strictly before ``before_line``."""
    pat = re.compile(
        rf"^\s*(?:[A-Za-z_][\w.<>\[\],\s]*\s+)?{re.escape(var_name)}\s*(?::=|=)(?!=)\s*(?:f|[(\"']|\"\"\"|''')"
    )
    upper = min(max(before_line - 1, 0), len(lines))
    for i in range(upper - 1, -1, -1):
        if pat.match(lines[i]):
            return i + 1
    return None


def _assignment_stmt_span(lines: list[str], assign_line: int) -> tuple[int, int] | None:
    """0-based inclusive (start, end) line indices for a multi-line assignment."""
    import ast as _ast

    start = assign_line - 1
    if start < 0 or start >= len(lines):
        return None
    for end in range(start, min(start + 60, len(lines))):
        block = "".join(lines[start : end + 1])
        try:
            mod = _ast.parse(f"def __lineaje_fn():\n{block}\n")
        except SyntaxError:
            continue
        body = mod.body[0].body  # type: ignore[attr-defined]
        if not body or not isinstance(body[0], _ast.Assign):
            continue
        stmt = body[0]
        stmt_end = getattr(stmt, "end_lineno", None)
        if stmt_end is None:
            return start, end
        end_idx = start + max(0, stmt_end - 2)
        return start, min(end_idx, len(lines) - 1)
    return None


def _decode_body(raw: Any) -> Any:
    """Bytes/str body → parsed JSON if possible, else unicode text."""
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        text = bytes(raw).decode("utf-8", errors="replace")
        try:
            return json.loads(text)
        except ValueError:
            return text
    return raw


_MAX_INLINE_FILE_BYTES = 512 * 1024
_MAX_INLINE_FILES = 8
_MISSING_SENT = object()      # "the wire form was not given": compute it
# Binary documents (PDF, DOCX, DOC, …) are sent whole so the GR service can
# extract their text — a truncated PDF/DOCX cannot be parsed at all, so the
# 512 KB text cap above does not apply. Override with
# LINEAJE_MAX_UPLOAD_SCAN_BYTES; larger files are sent without content and a
# warning is logged (their contents are not scanned).
_DEFAULT_MAX_BINARY_UPLOAD_BYTES = 10 * 1024 * 1024
_MAX_JSONABLE_DEPTH = 8
_PATH_TYPE_NAMES = frozenset({"Path", "PosixPath", "WindowsPath", "PurePath", "PurePosixPath", "PureWindowsPath"})


def _document_like(obj: Any) -> bool:
    """LangChain Document (and lookalikes) carry text on ``page_content``."""
    return isinstance(getattr(obj, "page_content", None), str)


def _fspath_str(raw: Any) -> str:
    if hasattr(raw, "__fspath__"):
        try:
            raw = os.fspath(raw)
        except Exception:
            return ""
    return raw if isinstance(raw, str) else ""


def _looks_like_upload(obj: Any) -> bool:
    """True for Chainlit AskFileResponse-style handles: on-disk ``path`` + filename ``name``.

    Must not treat pathlib.Path, open files, or a dict that merely has a ``path``
    key (config, kwargs) as an upload — that would read arbitrary files and
    rewrite customer objects.
    """
    if obj is None or isinstance(obj, (str, bytes, bytearray, list, tuple, int, float, bool)):
        return False
    if type(obj).__name__ in _PATH_TYPE_NAMES:
        return False
    if isinstance(obj, dict):
        path, name = obj.get("path"), obj.get("name")
        extra = "size" in obj or "type" in obj or isinstance(obj.get("text"), str)
    else:
        path, name = getattr(obj, "path", None), getattr(obj, "name", None)
        extra = getattr(obj, "size", None) is not None or bool(getattr(obj, "type", None))
    path = _fspath_str(path)
    if path and os.path.isfile(path):
        return extra or (isinstance(name, str) and bool(name))
    # Fall through to the in-memory/stream shape (Werkzeug FileStorage and
    # similar): these frameworks never write the upload to disk unless the
    # app explicitly calls .save(), so an on-disk path never exists here —
    # not a case this function's disk-path branch above can ever cover.
    return _looks_like_stream_upload(obj)


def _looks_like_stream_upload(obj: Any) -> bool:
    """True for stream-based upload handles (Werkzeug ``FileStorage`` and
    similar): a readable/seekable stream plus a filename, but — unlike the
    Chainlit-style handles above — content lives in memory or a spooled temp
    file, never an on-disk path, until the framework explicitly saves it."""
    if obj is None or isinstance(obj, (str, bytes, bytearray, list, tuple, int, float, bool, dict)):
        return False
    if type(obj).__name__ in _PATH_TYPE_NAMES:
        return False
    target = _stream_upload_target(obj)
    filename = getattr(obj, "filename", None) or getattr(obj, "name", None)
    return (
        callable(getattr(target, "read", None))
        and callable(getattr(target, "seek", None))
        and isinstance(filename, str)
        and bool(filename)
    )


def _stream_upload_target(obj: Any) -> Any:
    """The actual readable/seekable stream for a stream-upload handle —
    ``obj.stream`` for Werkzeug's FileStorage, else ``obj`` itself for a bare
    file-like object."""
    stream = getattr(obj, "stream", None)
    return stream if stream is not None else obj


def _read_stream_upload_text(obj: Any, limit: int = _MAX_INLINE_FILE_BYTES) -> "str | None":
    """UTF-8 text from a stream-upload handle, restoring the stream's read
    position afterward. This same object is normally used for the real
    upload call immediately after the guardrail check — leaving it consumed
    or mispositioned would silently empty out that upload."""
    target = _stream_upload_target(obj)
    try:
        pos = target.tell()
    except Exception:
        pos = 0
    try:
        target.seek(0)
        raw = target.read(limit)
    except Exception:
        return None
    finally:
        try:
            target.seek(pos)
        except Exception:
            pass
    if raw is None:
        return None
    if isinstance(raw, str):
        return raw
    if b"\x00" in raw[:2048]:
        return None
    return raw.decode("utf-8", errors="replace")


def _write_stream_upload_text(obj: Any, text: str) -> bool:
    """Overwrite a stream-upload handle's content with masked text, leaving
    the stream positioned at 0 so the real upload call right after reads the
    redacted version instead of the original."""
    target = _stream_upload_target(obj)
    try:
        target.seek(0)
        if hasattr(target, "truncate"):
            target.truncate()
        target.write(text.encode("utf-8"))
        target.seek(0)
        return True
    except Exception as exc:
        _logger.warning("gr_stub_client: could not write masked content back to upload stream (%s)", exc)
        return False


def _file_like_path(obj: Any) -> str:
    """On-disk path for an upload handle, else ``\"\"`` (including for a
    stream-based upload handle, which has no on-disk path by definition —
    see ``_looks_like_stream_upload``)."""
    if not _looks_like_upload(obj):
        return ""
    if isinstance(obj, dict):
        return _fspath_str(obj.get("path"))
    path = _fspath_str(getattr(obj, "path", None))
    return path if path and os.path.isfile(path) else ""


def _read_text_file(path: str, limit: int = _MAX_INLINE_FILE_BYTES) -> "str | None":
    """UTF-8 text, or None when the file is binary / unreadable (do not rewrite it)."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(limit)
    except OSError:
        return None
    if b"\x00" in raw[:2048]:
        return None
    return raw.decode("utf-8", errors="replace")


def _write_text_file(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _max_binary_upload_bytes() -> int:
    raw = (os.environ.get("LINEAJE_MAX_UPLOAD_SCAN_BYTES") or "").strip()
    try:
        return max(int(raw), 0) if raw else _DEFAULT_MAX_BINARY_UPLOAD_BYTES
    except ValueError:
        return _DEFAULT_MAX_BINARY_UPLOAD_BYTES


_OOXML_MEDIA_TYPES = {
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}


def _upload_media_type(name: str, head: bytes) -> str:
    """Content type from the file's leading bytes, then its extension."""
    ext = os.path.splitext(name or "")[1].lower()
    if head.startswith(b"%PDF"):
        return "application/pdf"
    if head.startswith(b"PK\x03\x04") and ext in _OOXML_MEDIA_TYPES:
        return _OOXML_MEDIA_TYPES[ext]
    if head.startswith(b"PK\x03\x04"):
        return _OOXML_MEDIA_TYPES[".docx"] if ext in ("", ".doc") else (
            mimetypes.guess_type(name)[0] or "application/zip"
        )
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):   # OLE2 — legacy .doc / .xls / .ppt
        return mimetypes.guess_type(name)[0] or "application/msword"
    if head.startswith(b"{\\rtf"):
        return "application/rtf"
    return (ext in _OOXML_MEDIA_TYPES and _OOXML_MEDIA_TYPES[ext]) or \
        mimetypes.guess_type(name or "")[0] or "application/octet-stream"


# Always sent as bytes for server-side extraction, even when they happen to
# contain no NUL bytes (an uncompressed PDF, a tiny DOCX): their raw bytes are
# markup/containers, not the document's readable text.
_BINARY_DOCUMENT_TYPES = frozenset({
    "application/pdf", "application/msword", "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint", "application/zip", *_OOXML_MEDIA_TYPES.values(),
})


def _is_binary_document_result(masked: Any) -> bool:
    """True when GR's returned entry is text *extracted* from a binary
    document — that text can't be written back into the PDF/DOCX/DOC."""
    return isinstance(masked, dict) and bool(
        masked.get("extracted_from")
        or masked.get("content_type") in _BINARY_DOCUMENT_TYPES
        or masked.get("content_omitted")
    )


def _warn_binary_mask_not_applied(name: str, masked: Any) -> None:
    _emit_enforce_log(logging.WARNING, (
        f"[lineaje.enforce] upload {name!r} ({masked.get('content_type') or masked.get('extracted_from')}): "
        "GR masked its extracted text, but a binary document can't be rewritten — the "
        "original file is unchanged; PII is masked again at the next guarded hop (e.g. agent→llm)"
    ))


def _is_text_bytes(raw: bytes) -> bool:
    return b"\x00" not in raw[:2048]


def _read_upload_bytes(obj: Any, path: str, limit: int) -> "bytes | None":
    """Up to ``limit`` + 1 bytes of an upload (disk path or in-memory stream),
    restoring a stream's position so the app's real upload still reads it."""
    if path:
        try:
            with open(path, "rb") as fh:
                return fh.read(limit + 1)
        except OSError:
            return None
    target = _stream_upload_target(obj)
    try:
        pos = target.tell()
    except Exception:
        pos = 0
    try:
        target.seek(0)
        raw = target.read(limit + 1)
    except Exception:
        return None
    finally:
        try:
            target.seek(pos)
        except Exception:
            pass
    if isinstance(raw, str):
        return raw.encode("utf-8")
    return bytes(raw) if raw is not None else None


def _upload_entry(obj: Any, *, name: str, path: str) -> dict[str, Any]:
    """Wire form of one uploaded file: ``name``, ``path``, ``content_type``,
    ``size_bytes`` and its content —

      text files   → ``text`` (UTF-8), as before
      binary docs  → ``content_base64`` (whole file); the GR service extracts
                     the text (PDF / DOCX / DOC / …) into ``text`` before any
                     policy routine runs, so PII / injection checks see the
                     document's contents.
    """
    binary_limit = _max_binary_upload_bytes()
    raw = _read_upload_bytes(obj, path, max(binary_limit, _MAX_INLINE_FILE_BYTES))
    entry: dict[str, Any] = {"name": name, "path": path, "text": ""}
    if raw is None:
        entry["content_omitted"] = "unreadable"
        return entry
    size = os.path.getsize(path) if path and os.path.isfile(path) else len(raw)
    entry["size_bytes"] = size
    entry["content_type"] = _upload_media_type(name or path, raw[:16])
    if _is_text_bytes(raw) and entry["content_type"] not in _BINARY_DOCUMENT_TYPES:
        entry["text"] = raw[:_MAX_INLINE_FILE_BYTES].decode("utf-8", errors="replace")
        if entry["content_type"] == "application/octet-stream":
            entry["content_type"] = "text/plain"
        return entry
    if size > binary_limit:
        entry["content_omitted"] = f"file larger than LINEAJE_MAX_UPLOAD_SCAN_BYTES={binary_limit}"
        _emit_enforce_log(logging.WARNING, (
            f"[lineaje.enforce] upload {name!r} ({size} bytes, {entry['content_type']}) exceeds "
            f"LINEAJE_MAX_UPLOAD_SCAN_BYTES={binary_limit} — sent without content; NOT scanned"
        ))
        return entry
    entry["content_base64"] = base64.b64encode(raw).decode("ascii")
    return entry


def _payload_is_uploaded_files(payload: Any) -> bool:
    items = payload if isinstance(payload, (list, tuple)) else [payload]
    return any(_looks_like_upload(item) for item in items[:_MAX_INLINE_FILES])


def _is_pydantic_model(obj: Any) -> bool:
    return bool(
        getattr(obj, "model_fields", None)
        or getattr(obj, "__fields__", None)
        or getattr(obj, "__pydantic_fields__", None)
    )


def _pydantic_dump(obj: Any) -> "dict | None":
    """Dump only real Pydantic models — never a random ``.dict()`` method."""
    if not _is_pydantic_model(obj):
        return None
    dump = getattr(obj, "model_dump", None) or getattr(obj, "dict", None)
    if not callable(dump):
        return None
    try:
        data = dump()
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _same_wire(answer: Any, sent: Any, _depth: int = 0) -> bool:
    """``answer`` (parsed JSON from the GR) equals ``sent`` (what was serialized): exact JSON types only, never a
    user ``__eq__``; anything else in ``sent`` (an object serialized by its repr) counts as different."""
    if _depth > 64 or type(answer) is not type(sent):
        return False
    if sent is None or type(sent) in (str, int, bool):
        return answer == sent
    if type(sent) is float:
        return answer == sent or (answer != answer and sent != sent)
    if type(sent) is list:
        return len(answer) == len(sent) and all(_same_wire(a, b, _depth + 1) for a, b in zip(answer, sent))
    if type(sent) is dict:
        return (len(answer) == len(sent) and all(type(k) is str and k in answer for k in sent)
                and all(_same_wire(answer[k], sent[k], _depth + 1) for k in sent))
    return False


def _jsonable_payload(payload: Any, _depth: int = 0, _seen: "set[int] | None" = None) -> Any:
    """JSON-serializable form of payload (unwrap Request / Document / upload handles). A container that is its own
    ancestor (a cycle) becomes None; a sub-object repeated elsewhere is sent again (``_seen`` holds only the current
    ancestor path, review r4 N2 — ids of freed ``model_dump`` temporaries are reused and must not hide content)."""
    if payload is None or isinstance(payload, (str, int, float, bool)):
        return payload
    if _depth > _MAX_JSONABLE_DEPTH:
        return None
    if _seen is None:
        _seen = set()
    oid = id(payload)
    if oid in _seen:
        return None
    _seen.add(oid)
    try:
        return _jsonable_node(payload, _depth, _seen)
    finally:
        _seen.discard(oid)


def _jsonable_node(payload: Any, _depth: int, _seen: "set[int]") -> Any:
    if isinstance(payload, dict):
        path = _file_like_path(payload)
        if path and not isinstance(payload.get("text"), str):
            entry = _upload_entry(payload, name=str(payload.get("name") or os.path.basename(path)), path=path)
            payload = {**payload, **{k: v for k, v in entry.items() if k not in ("name", "path")}}
        return {str(k): _jsonable_payload(v, _depth + 1, _seen) for k, v in payload.items()}
    if isinstance(payload, (list, tuple)):
        items = payload[:_MAX_INLINE_FILES] if _payload_is_uploaded_files(payload) else payload
        return [_jsonable_payload(item, _depth + 1, _seen) for item in items]
    if isinstance(payload, (bytes, bytearray)):
        return _decode_body(payload)
    data = getattr(payload, "data", None)
    if isinstance(payload, urllib.request.Request) or (
        type(payload).__name__ == "Request" and data is not None
    ):
        return _decode_body(data)
    if _document_like(payload):
        meta = getattr(payload, "metadata", None)
        out: dict[str, Any] = {"page_content": payload.page_content}
        if isinstance(meta, dict):
            out["metadata"] = _jsonable_payload(meta, _depth + 1, _seen)
        return out
    path = _file_like_path(payload)
    if path:
        return _upload_entry(
            payload, name=str(getattr(payload, "name", "") or os.path.basename(path)), path=path,
        )
    if _looks_like_stream_upload(payload):
        return _upload_entry(
            payload,
            name=str(getattr(payload, "filename", "") or getattr(payload, "name", "") or ""),
            path="",
        )
    dumped = _pydantic_dump(payload)
    if dumped is not None:
        return _jsonable_payload(dumped, _depth + 1, _seen)
    return payload


def _json_default(obj: Any) -> Any:
    """json.dumps default: coerce leftover objects instead of failing open."""
    try:
        coerced = _jsonable_payload(obj)
    except Exception:
        return str(obj)
    if coerced is not obj:
        return coerced
    return str(obj)


def _wire_payload(payload: Any) -> Any:
    """JSON body for /enforce. File handles become ``{text, files}`` so PII routines see contents."""
    data = _jsonable_payload(payload)
    if not _payload_is_uploaded_files(payload):
        return data
    if isinstance(data, list):
        texts = [item.get("text") or "" for item in data if isinstance(item, dict)]
        return {"text": "\n".join(texts), "files": data}
    if isinstance(data, dict) and "text" in data:
        return data
    return {"text": data}


# ── Credentials never reach the GR (G8, 2026-10-14) ─────────────────────────────────────────────────────────────────
# The runtime GR is the enforcement point, but it must never receive a credential. Every /enforce body is built from
# ``_redact_wire(_wire_payload(payload))``: a COPY in which credential-bearing values are replaced by ``REDACTED`` —
# the caller's objects are never touched. Deterministic detector:
#   * a value under a credential-named key (``_credential_key``: api_key / apikey / Authorization / password / token /
#     client_secret / aws_secret_access_key / credentials / connection_string …; every str leaf below it), also a
#     ``[name, value]`` header pair;
#   * inside any text: ``key=value`` / ``"key": "value"`` / ``key: value`` with a credential key, URL query
#     parameters with one, ``Bearer`` / ``Basic`` auth values, known token shapes (OpenAI / Anthropic / GitHub /
#     GitLab / Slack / AWS / Google / Hugging Face / Stripe / Lineaje PAT keys, JWTs), private-key blocks and URL
#     passwords (``scheme://user:PASSWORD@host``).
# Model id, prompts and replies are still sent (masking PII in them is the GR's job). What the stub hands back never
# carries a marker: ``_unredact_answer`` puts the caller's value back at every leaf that was redacted (whatever the
# GR answered there — unchanged, masked or reshaped), so a leaf is substituted only when the GR changed it AND it was
# sent un-redacted. The insertion side (pipeline/stub/credential_payload.py) does not place stubs whose whole
# payload is a credential at all; this is the companion's half for mixed payloads (kwargs, headers, log lines).

REDACTED = "[REDACTED]"
# Text redactions (a credential inside a longer text) use per-call LABELLED placeholders, never ``REDACTED``: the
# production GR masks phone / financial / fallback values with the literal ``[REDACTED]`` itself, so a shared marker
# could not be told apart from the GR's own mask (review 2, A). ``[LINEAJE-CREDENTIAL-<8 random letters>-<n>]``: the
# letters are drawn per ``_redact_wire`` call, ``n`` counts the placeholders of that call. The GR's answer is mapped
# back BY LABEL (``_splice_answer``), never by position; whole-value redactions keep ``REDACTED`` (never spliced).
_LABEL_PREFIX = "[LINEAJE-CREDENTIAL-"
_LABEL_RE = re.compile(r"\[LINEAJE-CREDENTIAL-([a-z]{8})-([0-9]{1,9})\]")
_REDACT_MAX_DEPTH = 64


def _new_nonce() -> str:
    import secrets
    import string
    return "".join(secrets.choice(string.ascii_lowercase) for _ in range(8))


class _LabelCtx:
    """One redaction pass (one ``_redact_wire`` / ``_redact_text`` call): the nonce and the running label number."""

    __slots__ = ("nonce", "n")

    def __init__(self) -> None:
        self.nonce = _new_nonce()
        self.n = 0

    def leaf_nonce(self, text: str) -> str:
        """The nonce for ``text``: this call's, unless the caller's own text already contains a label shape with it
        (then a fresh one, so a label found in the GR's answer can only be ours)."""
        nonce = self.nonce
        for _ in range(16):
            if f"{_LABEL_PREFIX}{nonce}-" not in text:
                break
            nonce = _new_nonce()
        else:                                                   # 16 collisions: not random text; never reached
            nonce = "zzzzzzzz" if f"{_LABEL_PREFIX}zzzzzzzz-" not in text else "yyyyyyyy"
        return nonce
_CRED_KEY_RE = re.compile(
    r"^(?:[a-z0-9]+_)*(?:"
    r"api_?key|api_?secret|api_?token|access_?token|refresh_?token|id_?token|session_?token|auth_?token"
    r"|bearer(?:_?token)?|token|secret|client_?secret|secret_?key|secret_?access_?key|access_?key(?:_?id)?"
    r"|private_?key|account_?key|subscription_?key|signing_?key|encryption_?key|master_?key|shared_?access_?key"
    r"|shared_?access_?signature|sas_?token|password|passwd|passphrase|credentials?|creds|authorization|auth"
    r"|cookie|set_?cookie|connection_?string|conn_?str"
    r")$"
)
_QUERY_CRED_KEYS = frozenset({"sig", "signature"})
# a key starts at a word boundary; the value runs to whitespace / a quote / a separator (an auth scheme kept with it)
_KV_RE = re.compile(
    r"""(?<![A-Za-z0-9_.-])(?P<kq>["']?)(?P<key>[A-Za-z][A-Za-z0-9_.-]{0,60})(?P=kq)[ \t]*[:=][ \t]*(?P<vq>["']?)"""
    r"""(?P<val>(?:(?:[Bb]earer|[Bb]asic|[Tt]oken)[ \t]+)?[^\s"',;&}{)\](\[]{6,})"""
)
_QUERY_RE = re.compile(r"(?<=[?&;])(?P<key>[A-Za-z0-9_.-]{1,60})=(?P<val>[^&\s\"'#;]{4,})")
_AUTH_SCHEME_RE = re.compile(r"\b(?P<scheme>[Bb]earer|[Bb]asic)[ \t]+(?P<val>[A-Za-z0-9._~+/=-]{16,})")
_TOKEN_SHAPES_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:"
    r"sk-(?:proj-|or-v1-|ant-[a-z0-9]+-)?[A-Za-z0-9_-]{20,}"
    r"|(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}"
    r"|github_pat_[A-Za-z0-9_]{30,}"
    r"|glpat-[A-Za-z0-9_-]{20,}"
    r"|xox[abposr]-[A-Za-z0-9-]{10,}"
    r"|(?:AKIA|ASIA)[0-9A-Z]{16}"
    r"|AIza[0-9A-Za-z_-]{35}"
    r"|hf_[A-Za-z0-9]{30,}"
    r"|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}"
    r"|lineaje_pat_[A-Za-z0-9_-]{8,}"
    r"|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    r")"
)
_TOKEN_PREFIXES = ("sk-", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-", "xox", "AKIA", "ASIA",
                   "AIza", "hf_", "_live_", "_test_", "lineaje_pat_", "eyJ")
# The PEM armour is assembled from parts so no line of this file spells out a private-key marker: the code_fix secret
# check (pipeline.contract.redact.has_secret_line) would otherwise take this regex for a key and withhold the file.
# The assembled pattern is the plain five-dash BEGIN ... PRIVATE KEY ... END armour match; test_pem_regex_parts pins it.
_PEM_DASHES = "-" * 5
_PEM_RE = re.compile(
    _PEM_DASHES + r"BEGIN [A-Z0-9 ]*PRIVATE KEY" + _PEM_DASHES
    + r".*?(?:" + _PEM_DASHES + r"END [A-Z0-9 ]*PRIVATE KEY" + _PEM_DASHES + r"|\Z)",
    re.S)
# every quantifier bounded (review finding 1: an unbounded scheme run backtracked quadratically on kebab / dotted ids)
_URL_PASSWORD_RE = re.compile(
    r"(?P<pre>\b[a-zA-Z][a-zA-Z0-9+.-]{0,31}://[^:/\s@\"']{1,256}:)(?P<pw>[^@\s/\"']{1,256})(?=@)")


def _credential_key(key: Any) -> bool:
    """``key`` names a credential (``api_key``, ``X-Api-Key``, ``Authorization``, ``client_secret`` …): camelCase /
    dashes / dots / spaces normalized to snake_case. Counters and names are not (``max_tokens``, ``secret_name``)."""
    if not isinstance(key, str) or not key or len(key) > 120:
        return False
    norm = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).lower()
    norm = re.sub(r"[^a-z0-9]+", "_", norm).strip("_")
    return bool(norm) and bool(_CRED_KEY_RE.match(norm))


# Text keys that are ordinary identifiers in code (``token = tokenizer.encode(x)``, ``secret = os.environ[...]``):
# a credential only in a quoted key / quoted value pair (a dict repr, JSON).
_TEXT_AMBIGUOUS_KEYS = frozenset({"token", "secret", "auth", "cookie", "key"})
_SHAPED_SPECIALS = frozenset("-+/=~")


def _shaped_value(val: str) -> bool:
    """An unquoted free-text value that looks like a credential, not a code expression or a word: 8+ chars with a
    digit or one of ``- + / = ~`` (``TTSECRET-…``, ``hunter2secret``, base64), never ``tokenizer.encode``."""
    return len(val) >= 8 and any(c.isdigit() or c in _SHAPED_SPECIALS for c in val)


def _letters_sentence_end(secret: str, text: str, end: int) -> bool:
    """``_letters_secret`` for the value ``secret`` ending at ``end`` of ``text``; a sentence-final ``. ! ?`` after the
    letters is not part of the value."""
    core = secret.rstrip(".!?")
    if core != secret:
        return _letters_secret(core)
    return _letters_secret(secret) and not _code_follows(text, end)


def _code_follows(text: str, end: int) -> bool:
    """The value ends where a call / subscript / attribute / longer identifier continues (``f(``, ``a.b``, ``a_b``);
    a sentence-final ``.`` or a spaced ``-`` is not code."""
    ch = text[end:end + 1]
    if ch in ("(", "[", "_"):
        return True
    if ch in (".", "-"):
        nxt = text[end + 1:end + 2]
        return nxt.isalnum() or nxt == "_"
    return False


def _letters_secret(val: str) -> bool:
    """A letters-only unquoted value of 12+ chars after an unambiguous credential key (``api_key: abcdefghijklmnop``,
    ``export OPENAI_API_KEY=…``): a long word is no code expression (those have ``.`` / ``(`` / ``_`` …). The
    ambiguous keys (``token``, ``secret``, ``auth`` …) never reach here unquoted."""
    return len(val) >= 12 and val.isascii() and val.isalpha()


def _text_spans(text: str) -> "list[tuple[int, int]]":
    """The ``(start, end)`` spans of ``text`` to redact, merged and sorted. Every pattern runs on the ORIGINAL text
    (so the originals of a redacted text can be recovered: ``_splice_answer``) and only when a substring scan says it
    can match (review finding 1)."""
    spans: "list[tuple[int, int]]" = []
    if "PRIVATE KEY" in text:
        spans += [m.span() for m in _PEM_RE.finditer(text)]
    if any(p in text for p in _TOKEN_PREFIXES):
        spans += [m.span() for m in _TOKEN_SHAPES_RE.finditer(text)]
    if "://" in text:
        spans += [m.span("pw") for m in _URL_PASSWORD_RE.finditer(text)]
    if "=" in text and ("?" in text or "&" in text or ";" in text):
        for m in _QUERY_RE.finditer(text):
            key = m.group("key")
            if _credential_key(key) and _norm_key(key) not in _TEXT_AMBIGUOUS_KEYS or key.lower() in _QUERY_CRED_KEYS:
                spans.append(m.span("val"))
    if ":" in text or "=" in text:
        for m in _KV_RE.finditer(text):
            key, val, vq = m.group("key"), m.group("val"), m.group("vq")
            if not _credential_key(key):
                continue
            end = m.end("val")
            quoted = bool(vq) and text[end:end + 1] == vq
            if _norm_key(key) in _TEXT_AMBIGUOUS_KEYS and not (quoted and m.group("kq")):
                continue
            secret = val.split(None, 1)[-1] if val[:1] in "BbTt" and " " in val or "\t" in val else val
            if quoted or _shaped_value(secret) or _letters_sentence_end(secret, text, end):
                spans.append(m.span("val"))
    if "earer" in text or "asic" in text:
        spans += [m.span("val") for m in _AUTH_SCHEME_RE.finditer(text)]
    if not spans:
        return []
    spans.sort()
    merged = [spans[0]]
    for s0, e0 in spans[1:]:
        if s0 < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e0))
        else:
            merged.append((s0, e0))
    return merged


def _norm_key(key: str) -> str:
    norm = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).lower()
    return re.sub(r"[^a-z0-9]+", "_", norm).strip("_")


def _build_redacted(text: str, spans: "list[tuple[int, int]]", ctx: "_LabelCtx | None" = None) -> str:
    ctx = ctx or _LabelCtx()
    nonce = ctx.leaf_nonce(text)
    out, at = [], 0
    for s0, e0 in spans:
        out.append(text[at:s0])
        ctx.n += 1
        out.append(f"{_LABEL_PREFIX}{nonce}-{ctx.n}]")
        at = e0
    out.append(text[at:])
    return "".join(out)


def _redact_text(text: str, ctx: "_LabelCtx | None" = None) -> str:
    """``text`` with every credential-shaped value replaced by a labelled placeholder (the module notes above)."""
    if not isinstance(text, str) or not text:
        return text
    spans = _text_spans(text)
    return _build_redacted(text, spans, ctx) if spans else text


def _leaf_labels(sent: str, plain: str, spans: "list[tuple[int, int]]") -> "list[re.Match] | None":
    """The placeholders of ``sent`` (``plain`` redacted at ``spans``), in order, when ``sent`` really is that
    redaction (every other piece identical, one nonce); else ``None``. Linear, no search."""
    pos = at = 0
    found = []
    for s0, e0 in spans:
        seg = plain[at:s0]
        if not sent.startswith(seg, pos):
            return None
        pos += len(seg)
        m = _LABEL_RE.match(sent, pos)
        if m is None:
            return None
        found.append(m)
        pos, at = m.end(), e0
    if sent[pos:] != plain[at:]:
        return None
    if found and any(m.group(1) != found[0].group(1) for m in found):
        return None
    return found


def _splice_answer(answer: Any, sent: str, plain: str, misses: "list | None") -> Any:
    """The GR's answer for a text leaf ``sent`` (``plain`` with credentials replaced by labelled placeholders): each
    placeholder the answer still carries is replaced by the caller's original BY LABEL, the GR's other edits kept
    (review finding 3; review 2 A). A placeholder the GR removed or rewrote stays removed (the GR changed that text:
    nothing is reinserted); reordered ones follow their labels. A duplicated or unknown label of this pass, a
    non-text answer, or a ``sent`` that is not the redaction of ``plain`` -> the caller's ``plain`` + a counted miss.
    Whole-leaf redactions (a value under a credential key) always come back as ``plain``."""
    if sent == REDACTED:
        return plain
    if answer == sent:
        return plain
    spans = _text_spans(plain)
    labs = _leaf_labels(sent, plain, spans) if spans else None
    if labs and type(answer) is str:
        nonce = labs[0].group(1)
        originals = {m.group(2): plain[s0:e0] for m, (s0, e0) in zip(labs, spans)}
        mine = [m for m in _LABEL_RE.finditer(answer) if m.group(1) == nonce]
        ids = [m.group(2) for m in mine]
        if len(set(ids)) == len(ids) and all(i in originals for i in ids):
            if not mine:
                return answer
            out, at = [], 0
            for m in mine:
                out.append(answer[at:m.start()])
                out.append(originals[m.group(2)])
                at = m.end()
            out.append(answer[at:])
            return "".join(out)
    if misses is not None:
        misses.append("a partly redacted text the GR changed could not be mapped back")
    return plain


def _redact_all(value: Any, depth: int) -> "tuple[Any, bool]":
    """Every str (or non-JSON) leaf of ``value`` -> ``REDACTED`` (the value sits under a credential key)."""
    if value is None or type(value) is bool or (type(value) is str and not value):
        return value, False
    if type(value) in (int, float):
        return REDACTED, True                         # a numeric PIN / key: sent redacted (never written back)
    if depth > _REDACT_MAX_DEPTH:
        return REDACTED, True
    if type(value) is dict:
        out, changed = {}, False
        for k, v in value.items():
            out[k], ch = _redact_all(v, depth + 1)
            changed = changed or ch
        return (out, True) if changed else (value, False)
    if type(value) is list:
        items = [_redact_all(v, depth + 1) for v in value]
        if any(ch for _v, ch in items):
            return [v for v, _ch in items], True
        return value, False
    return REDACTED, True


def _redact_node(value: Any, depth: int, ctx: "_LabelCtx") -> "tuple[Any, bool]":
    if value is None or type(value) in (bool, int, float):
        return value, False
    if depth > _REDACT_MAX_DEPTH:
        return REDACTED, True
    if type(value) is str:
        red = _redact_text(value, ctx)
        return (red, True) if red != value else (value, False)
    if type(value) is dict:
        out, changed = {}, False
        for k, v in value.items():
            if _credential_key(k):
                out[k], ch = _redact_all(v, depth + 1)
            else:
                out[k], ch = _redact_node(v, depth + 1, ctx)
            changed = changed or ch
        return (out, True) if changed else (value, False)
    if type(value) is list:
        if len(value) == 2 and _credential_key(value[0]) and type(value[1]) is str and value[1]:
            return [value[0], REDACTED], True                 # a (name, value) header pair
        items = [_redact_node(v, depth + 1, ctx) for v in value]
        if any(ch for _v, ch in items):
            return [v for v, _ch in items], True
        return value, False
    # an object the wire would serialize through ``_json_default`` (its JSON form, else its repr): sent as that
    # form, redacted (the object itself is never sent nor changed; the write-back never replaces a non-str leaf)
    try:
        text = _json_default(value)
    except Exception:  # noqa: BLE001
        return REDACTED, True
    if type(text) is not str:
        return _redact_node(text, depth + 1, ctx)
    red = _redact_text(text, ctx)
    return (red, True) if red != text else (text, False)


def _redact_wire(data: Any) -> "tuple[Any, bool]":
    """``(copy of data with credentials redacted, whether anything was)``. Unchanged subtrees are the same objects;
    ``data`` itself is never modified. Never raises: a value it cannot inspect is sent as ``REDACTED``."""
    try:
        return _redact_node(data, 0, _LabelCtx())
    except Exception:  # noqa: BLE001
        return REDACTED, True


def _unredact_answer(answer: Any, sent: Any, plain: Any, depth: int = 0, misses: "list | None" = None) -> Any:
    """The GR's ``answer`` for ``sent`` (the redacted copy of ``plain``) mapped back onto ``plain``: at a redacted text
    leaf the caller's credentials are put back into the answer's markers and the GR's other edits kept
    (``_splice_answer``); a whole redacted value, or a redacted subtree the GR reshaped, comes back as ``plain``
    (nothing of it substituted). Paths that were sent as they are keep the GR's answer."""
    if sent is plain or depth > _REDACT_MAX_DEPTH + 2:
        return answer if sent is plain else plain
    if type(sent) is str and type(plain) is str:
        return _splice_answer(answer, sent, plain, misses)
    if type(sent) is dict and type(plain) is dict and type(answer) is dict:
        out = dict(answer)
        for k, v in sent.items():
            if k in out and k in plain:
                out[k] = _unredact_answer(answer[k], v, plain[k], depth + 1, misses)
        return out
    if type(sent) is list and type(plain) is list and type(answer) is list \
            and len(answer) == len(sent) == len(plain):
        return [_unredact_answer(a, s, p, depth + 1, misses) for a, s, p in zip(answer, sent, plain)]
    return plain


def _only_redacted_changed(answer: Any, sent: Any, plain: Any, depth: int = 0) -> bool:
    """The GR's ``answer`` differs from ``sent`` only at whole-value redactions (review finding 4): nothing to apply."""
    if depth > _REDACT_MAX_DEPTH + 2:
        return False
    if sent is plain:
        return _same_wire(answer, sent)
    if type(sent) is str:
        return sent == REDACTED or answer == sent
    if type(sent) is dict and type(answer) is dict and type(plain) is dict:
        return set(answer) == set(sent) and all(
            k in plain and _only_redacted_changed(answer[k], v, plain[k], depth + 1) for k, v in sent.items())
    if type(sent) is list and type(answer) is list and type(plain) is list and len(answer) == len(sent) == len(plain):
        return all(_only_redacted_changed(a, s, p, depth + 1) for a, s, p in zip(answer, sent, plain))
    return _same_wire(answer, sent)


def _looks_like_object_repr(text: str) -> bool:
    """True for ``str(Document)`` / ``str(obj)`` dumps, not real masked text."""
    if text.startswith("page_content=") or "page_content=" in text[:80]:
        return True
    if text.startswith("<") and "object at 0x" in text:
        return True
    return False


def _masked_text_from(masked: Any) -> "str | None":
    """Extract the masked text a routine returned, from either shape a
    decision's payload can take: the ``{"text": ..., "path": ...}``/
    ``{"page_content": ...}`` dict this SDK builds for file-like uploads, or
    a bare masked string."""
    if isinstance(masked, dict):
        raw = masked.get("text")
        if raw is None:
            raw = masked.get("page_content")
        return raw if isinstance(raw, str) else None
    if isinstance(masked, str) and not _looks_like_object_repr(masked):
        return masked
    return None


def _rehydrate_item(original: Any, masked: Any, sent: Any = _MISSING_SENT) -> Any:
    """Put the GR's answer for ``original`` back on it — only what the answer changed versus what was sent
    (``sent``, default: the wire form ``_jsonable_payload(original)``). See ``_apply_answer``."""
    if sent is _MISSING_SENT:
        sent = _jsonable_payload(original)
    misses: list = []
    return _apply_answer(original, sent, masked, misses)


def _reapply_payload(original: Any, masked: Any, sent: Any = _MISSING_SENT) -> Any:
    """Put the GR's answer back on the live payload (``_apply_answer``; ``sent`` defaults to the wire form)."""
    if sent is _MISSING_SENT:
        sent = _wire_payload(original)
    misses: list = []
    return _apply_answer(original, sent, masked, misses)


def persist_runtime_mask_to_source(
    masked_payload: Any,
    *,
    source_file: str,
    variable_name: str,
    before_line: int | None = None,
) -> bool:
    """Replace a source literal assignment with the masked value. Scalars only."""
    if not isinstance(masked_payload, (str, int, float, bool)):
        return False
    masked_text = str(masked_payload)
    path = os.path.abspath(source_file)
    if not os.path.isfile(path):
        _logger.warning("persist_runtime_mask_to_source: missing file %s", path)
        return False
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError as exc:
        _logger.warning("persist_runtime_mask_to_source: read failed %s (%s)", path, exc)
        return False

    assign_line = _find_assignment_line(lines, variable_name, before_line or len(lines))
    if assign_line is None:
        _logger.debug(
            "persist_runtime_mask_to_source: no assignment for %r before line %s in %s",
            variable_name, before_line, path,
        )
        return False
    span = _assignment_stmt_span(lines, assign_line)
    if span is None:
        _logger.warning(
            "persist_runtime_mask_to_source: could not span assignment for %r at line %d in %s",
            variable_name, assign_line, path,
        )
        return False
    start, end = span
    original = "".join(lines[start : end + 1])
    if "_gr_client" in original or "SiteDescriptor" in original:
        _logger.debug(
            "persist_runtime_mask_to_source: skip guardrail stub assignment %r in %s",
            variable_name, path,
        )
        return False
    if re.search(r"""=\s*(?:\()?\s*f(?:'''|\"\"\"|'|\")""", original) or re.search(
        r"\bf(?:'''|\"\"\"|'|\")", original
    ):
        _logger.info(
            "persist_runtime_mask_to_source: skip f-string assignment %r in %s",
            variable_name, path,
        )
        return False
    indent_match = re.match(r"^(\s*)", lines[start])
    base_indent = indent_match.group(1) if indent_match else ""
    quote = "'''" if '"""' in masked_text else '"""'
    new_lines = [f"{base_indent}{variable_name} = {quote}{masked_text}{quote}\n"]
    rewritten = lines[:]
    rewritten[start : end + 1] = new_lines
    try:
        compile("".join(rewritten), path, "exec")
    except SyntaxError as exc:
        _logger.warning(
            "persist_runtime_mask_to_source: rewrite would be invalid Python (%s) — left %s unchanged",
            exc, path,
        )
        return False
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.writelines(rewritten)
    except OSError as exc:
        _logger.warning("persist_runtime_mask_to_source: write failed %s (%s)", path, exc)
        return False
    _logger.info(
        "persist_runtime_mask_to_source: updated %s lines %d-%d (%r)",
        path, start + 1, end + 1, variable_name,
    )
    return True


def _normalize_http_error_detail(raw: Any) -> dict[str, Any]:
    """FastAPI wraps as ``{detail: {...}}``; some gateways send the dict unwrapped."""
    if not isinstance(raw, dict):
        return {}
    detail = raw.get("detail", raw)
    if isinstance(detail, dict):
        return detail
    if isinstance(detail, list) and detail and isinstance(detail[0], dict):
        return detail[0]
    return {}


def _http_error_body(exc: urllib.error.HTTPError) -> bytes:
    """Raw HTTPError body, read once and cached on the exception — the
    /enforce response log and the block handling both need it, and the
    underlying stream can only be read once."""
    raw = getattr(exc, "_lineaje_body", None)
    if raw is None:
        try:
            raw = exc.read() or b""
        except Exception:
            raw = b""
        try:
            exc._lineaje_body = raw
        except Exception:
            pass
    return raw


def _read_http_error_detail(exc: urllib.error.HTTPError) -> dict[str, Any]:
    body = _http_error_body(exc)
    if not body:
        return {}
    try:
        parsed = json.loads(body)
    except Exception:
        return {}
    return _normalize_http_error_detail(parsed)


def _is_unknown_site_error(detail: dict[str, Any]) -> bool:
    err = str(detail.get("error") or "").strip()
    return err in ("unknown_site", "unknown_site_id", "candidate_policies_mismatch")


def _should_register_unknown_site(detail: dict[str, Any], site_id: str) -> bool:
    """Register leftover / unregistered sites. Never treat a policy block as unknown."""
    if not (site_id or "").strip():
        return False
    if _is_unknown_site_error(detail):
        return True
    if detail.get("blocked_by") or str(detail.get("error") or "") == "request_blocked":
        return False
    return not detail


def _candidate_policies_from_mappings(mappings: list[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for mapping in mappings:
        if not isinstance(mapping, dict) or not mapping.get("policy_id"):
            continue
        out.append({
            "policy_id": mapping["policy_id"],
            "guardrail_id": mapping.get("guardrail_id"),
            "policy_version": mapping.get("policy_version"),
        })
    return out


def _apply_registered_mappings(
    body: dict[str, Any], site: "SiteDescriptor", mappings: list[Any],
) -> None:
    if not mappings:
        return
    candidates = _candidate_policies_from_mappings(mappings)
    body["candidate_policies"] = candidates
    try:
        site.candidate_policies = candidates
    except Exception:
        pass


def _finalize_decision(decision: Decision, original: Any) -> Decision:
    """A GR outage fails open untouched. A reachable GR's verdict is final (review r4 N1, user design 2026-10-14:
    the GR is the enforcement point): the stub applies no masking of its own, so an ALLOW leaves the data
    byte-identical and a mask changes only what the GR changed."""
    if decision.infra_failure:
        decision.payload = original
    return decision


def _actions_brief(actions: Any) -> str:
    """``[AI_APP_SEC_006:allow, AI_DAT_SEC_012:mask]`` — policy/decision only.
    The full actions carry original_snippet (raw PII) and must never be
    printed in the customer's process."""
    parts = []
    for a in actions or []:
        if isinstance(a, dict):
            if not a.get("policy_id") and a.get("type") in ("uploaded_file", "document_block"):
                parts.append(f"decode:{a.get('name') or a.get('media_type') or '?'}:{a.get('action')}")
                continue
            parts.append(f"{a.get('policy_id') or '?'}:{a.get('decision') or a.get('action') or '?'}")
    return "[" + ", ".join(parts) + "]"


_LAST_POST = threading.local()      # the path the last POST in this thread used, for the console line


def _announce_enforce(url: str, hop: str, status: str, extra: str = "") -> None:
    """Always visible on stderr so a local customer run shows /enforce (or /observability) actually fired."""
    suffix = f" {extra}" if extra else ""
    path = getattr(_LAST_POST, "path", "/enforce")
    _LAST_POST.path = "/enforce"
    msg = f"[lineaje.enforce] POST {url}{path} {hop} → {status}{suffix}"
    _logger.info("%s", msg)
    try:
        print(msg, file=sys.stderr, flush=True)
    except Exception:
        pass


# ── Transport (LIN-36167) ─────────────────────────────────────────────────────
# ONE shared, thread-safe pool of keep-alive connections per GR origin (http.client), instead of a new TCP + TLS
# connection for every call. A call checks out an idle connection (the most recently used one) or opens a new one,
# and returns it afterwards; a connection that errored, or that the server said it will close, is discarded. At most
# GR_POOL_SIZE (default 8) idle connections are kept per origin — extras are closed on return — and a call never
# waits for a connection, so a burst of concurrent calls is never queued behind the pool.
# Trust is unchanged: the TLS context is the default one, built after _ensure_ca_bundle's SSL_CERT_FILE /
# REQUESTS_CA_BUNDLE setup. A pooled connection the server already closed while idle (RemoteDisconnected / reset /
# broken pipe) is resent ONCE on a fresh connection — the ordinary keep-alive race, not a retry: timeouts and other
# errors are never resent. When an HTTP(S) proxy applies to the GR URL, urllib's urlopen is used as before
# (http.client ignores proxies). GR_KEEPALIVE=0 turns pooling off. A forked child never reuses its parent's sockets.
_STALE_SOCKET_ERRORS = (http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError,
                        ConnectionAbortedError, http.client.CannotSendRequest)


def _keepalive_enabled() -> bool:
    return (os.environ.get("GR_KEEPALIVE") or "1").strip().lower() not in ("0", "false", "no", "off")


def _pool_size() -> int:
    return int(_env_number("GR_POOL_SIZE", 8, 1))


def _uses_proxy(parsed: urllib.parse.ParseResult) -> bool:
    try:
        proxies = urllib.request.getproxies()
        return bool(proxies.get(parsed.scheme)) and not urllib.request.proxy_bypass(parsed.hostname or "")
    except Exception:
        return True          # unsure: keep the old, proxy-aware path


class _ConnPool:
    """Idle keep-alive connections to one GR origin, shared by every thread of the process."""

    def __init__(self, scheme: str, host: str, port: int) -> None:
        self.scheme, self.host, self.port = scheme, host, port
        self.lock = threading.Lock()
        self.idle: "collections.deque[http.client.HTTPConnection]" = collections.deque()
        self.stats = {"opened": 0, "reused": 0, "discarded": 0}

    def new(self, timeout: float) -> "http.client.HTTPConnection":
        if self.scheme == "https":
            import ssl as _ssl
            conn = http.client.HTTPSConnection(self.host, self.port, timeout=timeout,
                                               context=_ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(self.host, self.port, timeout=timeout)
        with self.lock:
            self.stats["opened"] += 1
        return conn

    def get(self, timeout: float) -> "tuple[http.client.HTTPConnection, bool]":
        """An idle connection (reused=True) or a new one; with this call's timeout."""
        with self.lock:
            conn = self.idle.pop() if self.idle else None
            if conn is not None:
                self.stats["reused"] += 1
        if conn is None:
            return self.new(timeout), False
        conn.timeout = timeout
        if conn.sock is not None:
            conn.sock.settimeout(timeout)
        return conn, True

    def put(self, conn: "http.client.HTTPConnection") -> None:
        with self.lock:
            if len(self.idle) < _pool_size():
                self.idle.append(conn)
                return
        conn.close()                                   # the pool is full: do not keep more idle connections

    def discard(self, conn: "http.client.HTTPConnection") -> None:
        with self.lock:
            self.stats["discarded"] += 1
        try:
            conn.close()
        except Exception:
            pass


_POOLS: "dict[tuple, _ConnPool]" = {}
_POOLS_LOCK = threading.Lock()
_POOLS_PID = [os.getpid()]


def _pool_for(parsed: urllib.parse.ParseResult) -> _ConnPool:
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    key = (parsed.scheme, parsed.hostname or "", port)
    with _POOLS_LOCK:
        if _POOLS_PID[0] != os.getpid():                # a forked child drops (never closes) the parent's sockets
            _POOLS.clear()
            _POOLS_PID[0] = os.getpid()
        pool = _POOLS.get(key)
        if pool is None:
            pool = _POOLS[key] = _ConnPool(*key)
        return pool


def _reset_pools() -> None:
    """Close every idle connection and forget the pools (tests, or after a configuration change)."""
    with _POOLS_LOCK:
        pools = list(_POOLS.values())
        _POOLS.clear()
    for pool in pools:
        with pool.lock:
            idle, pool.idle = list(pool.idle), collections.deque()
        for conn in idle:
            pool.discard(conn)


def _post_keepalive(url: str, path: str, data: bytes, headers: "dict[str, str]", timeout: float) -> bytes:
    parsed = urllib.parse.urlparse(url)
    target = (parsed.path.rstrip("/") + path) or "/"
    pool = _pool_for(parsed)
    for attempt in (1, 2):
        conn, reused = pool.get(timeout) if attempt == 1 else (pool.new(timeout), False)
        try:
            conn.request("POST", target, body=data, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
        except _STALE_SOCKET_ERRORS as exc:
            pool.discard(conn)
            if reused and attempt == 1:
                continue                          # idle connection closed by the server: resend once, on a fresh one
            raise urllib.error.URLError(exc) from exc
        except BaseException:
            pool.discard(conn)
            raise
        if resp.will_close:
            pool.discard(conn)
        else:
            pool.put(conn)
        if resp.status >= 300:                    # 4xx/5xx; urlopen never followed a redirect of a POST either
            raise urllib.error.HTTPError(f"{url}{path}", resp.status, resp.reason, resp.headers, io.BytesIO(raw))
        return raw
    raise urllib.error.URLError("unreachable")    # pragma: no cover


# ── Circuit breaker (LIN-36167) ───────────────────────────────────────────────
# The breaker opens after GR_BREAKER_FAILURES (default 5) consecutive infrastructure failures on /enforce — a
# timeout (default 30 s each), a connection error, an HTTP 5xx — and then calls fail open for GR_BREAKER_OPEN_SEC
# (default 30 s) without touching the network: the outage fallback
# (fail open, as any GR outage: _fail_response). Then ONE trial call goes out: success closes the breaker, failure
# re-opens it. A verdict (403, any 4xx) is not a failure. Opening and closing are each logged once. Per process
# and GR origin; GR_BREAKER_FAILURES=0 turns it off.
class _Breaker:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.state: "dict[str, dict[str, Any]]" = {}

    @staticmethod
    def _limits() -> "tuple[int, float]":
        return int(_env_number("GR_BREAKER_FAILURES", 5, 0)), _env_number("GR_BREAKER_OPEN_SEC", 30.0, 0.0)

    def allow(self, origin: str) -> bool:
        failures, open_sec = self._limits()
        if failures <= 0:
            return True
        with self.lock:
            st = self.state.get(origin)
            if not st or not st.get("open_until"):
                return True
            now = time.monotonic()
            # a trial that never reached the network (an early return) expires, so the breaker cannot stick open
            trial_live = st.get("trial") and now - st.get("trial_at", 0.0) < max(open_sec, 10.0)
            if now < st["open_until"] or trial_live:
                st["skipped"] = st.get("skipped", 0) + 1
                return False
            st.update(trial=True, trial_at=now)   # half-open: this call is the one trial
            return True

    def record(self, origin: str, ok: bool) -> None:
        failures, open_sec = self._limits()
        if failures <= 0:
            return
        with self.lock:
            st = self.state.setdefault(origin, {"failures": 0, "open_until": 0.0, "trial": False, "skipped": 0})
            if ok:
                if st["open_until"]:
                    _logger.warning("gr_stub_client: guardrail reachable again — circuit closed for %s "
                                    "(%d call(s) skipped while open)", origin, st.get("skipped", 0))
                st.update(failures=0, open_until=0.0, trial=False, skipped=0)
                return
            st["failures"] += 1
            if st["trial"] or (not st["open_until"] and st["failures"] >= failures):
                if not st["open_until"]:
                    _logger.warning("gr_stub_client: %d consecutive guardrail failures — circuit OPEN for %s: calls "
                                    "skip the guardrail for %.0fs and fail open", st["failures"], origin, open_sec)
                st.update(open_until=time.monotonic() + open_sec, trial=False)


_BREAKER = _Breaker()


def _infra_failure(exc: BaseException) -> bool:
    """A failure of the guardrail itself (counts for the breaker), not a verdict."""
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code >= 500
    return isinstance(exc, (urllib.error.URLError, OSError, http.client.HTTPException, TimeoutError))


def _post_json(
    url: str, path: str, body: dict[str, Any], pat: str, timeout: float,
) -> dict[str, Any]:
    data = json.dumps(body, default=_json_default).encode()
    # No token, no Authorization header: /heartbeat takes the tenant from the body.
    headers = {"Content-Type": "application/json", **({"Authorization": f"Bearer {pat}"} if pat else {})}
    try:
        if _keepalive_enabled() and not _uses_proxy(urllib.parse.urlparse(url)):
            raw = _post_keepalive(url, path, data, headers, timeout)
        else:
            req = urllib.request.Request(f"{url}{path}", data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
    except BaseException as exc:
        if path == "/enforce" and isinstance(exc, Exception):
            _BREAKER.record(url, not _infra_failure(exc))
        raise
    if path == "/enforce":
        _BREAKER.record(url, True)
    return json.loads(raw)


# ── /enforce request / response logs in the customer app ─────────────────────
#
# LINEAJE_ENFORCE_LOG controls what the customer's own process logs for every
# POST /enforce:
#   summary (default) — one request line, one response line, one line per
#                       policy action (policy, decision, type, model,
#                       list_status, entity types). Never payload contents.
#   full              — summary + the complete request and response JSON.
#                       The request carries the raw, unmasked payload (PII,
#                       prompts, file text) — for local debugging only.
#   off               — no request/response logs.
# The bearer token is never logged.
#
# Logged on the "lineaje.enforce" logger. When the customer app has not
# configured logging for that level (no handlers, or level above INFO — the
# Python default), the same line also goes to stderr, so the logs are always
# visible in a local run / container stdout.

_enforce_logger = logging.getLogger("lineaje.enforce")
_ENFORCE_LOG_MAX_CHARS = 20000


def _enforce_log_mode() -> str:
    raw = (os.environ.get("LINEAJE_ENFORCE_LOG") or "summary").strip().lower()
    return raw if raw in ("off", "summary", "full") else "summary"


def _emit_enforce_log(level: int, msg: str) -> None:
    # Exactly one of the two: the customer's logging when it will actually
    # emit this line, else stderr. (Logging with no handlers configured would
    # also hit Python's last-resort handler for WARNING — a duplicate line.)
    try:
        if _enforce_logger.hasHandlers() and _enforce_logger.isEnabledFor(level):
            _enforce_logger.log(level, "%s", msg)
        else:
            print(msg, file=sys.stderr, flush=True)
    except Exception:
        pass


_ENFORCE_MODEL_KEYS = ("model", "model_id", "model_name", "engine", "deployment_id", "deployment_name")


def _model_in_payload(data: Any) -> str:
    """Model id the GR service will check for AI_APP_SEC_006/028 (same keys it reads)."""
    if not isinstance(data, dict):
        return ""
    for candidate in (data, data.get("json"), data.get("data")):
        if isinstance(candidate, dict):
            for key in _ENFORCE_MODEL_KEYS:
                val = candidate.get(key)
                if isinstance(val, str) and val.strip():
                    return val.strip()
    return ""


def _policy_ids(policies: Any) -> list[str]:
    ids: list[str] = []
    for p in policies or []:
        pid = p.get("policy_id") if isinstance(p, dict) else p
        if pid:
            ids.append(str(pid))
    return ids


def _enforce_request_payload(body: dict[str, Any]) -> Any:
    if isinstance(body.get("payload"), dict):
        return body["payload"].get("data")
    for key in ("in_params", "out_params"):
        if isinstance(body.get(key), dict):
            params = body[key]
            return params.get("data", params)
    return None


def _log_enforce_request(url: str, body: dict[str, Any], mode: str) -> None:
    try:
        data = _enforce_request_payload(body)
        payload_bytes = len(json.dumps(data, default=_json_default)) if data is not None else 0
        files = []
        for f in (data.get("files") if isinstance(data, dict) and isinstance(data.get("files"), list)
                  else [data] if isinstance(data, dict) and "content_type" in data else []):
            if isinstance(f, dict):
                how = ("base64" if f.get("content_base64") else "text" if f.get("text")
                       else f.get("content_omitted") or "empty")
                files.append(f"{f.get('name') or '?'}({f.get('content_type') or '?'}, "
                             f"{f.get('size_bytes', '?')}B, {how})")
        _emit_enforce_log(logging.INFO, (
            f"[lineaje.enforce] → POST {url}/enforce site_id={body.get('site_id') or '-'} "
            f"{body.get('source_type') or '-'}→{body.get('destination_type') or '-'} "
            f"project={body.get('project') or '-'} organization={body.get('organization') or '-'} "
            f"workflow={body.get('workflow') or '-'} "
            f"session={body.get('session_id') or '-'} step={body.get('step') or '-'} "
            f"model={_model_in_payload(data) or '-'} "
            f"candidate_policies={_policy_ids(body.get('candidate_policies') or body.get('enabled_policies'))} "
            f"event_id={body.get('event_id') or '-'} payload_bytes={payload_bytes}"
            + (f" files={files}" if files else "")
        ))
        if mode == "full":
            _emit_enforce_log(logging.INFO, (
                "[lineaje.enforce] → request body: "
                + json.dumps(body, default=_json_default)[:_ENFORCE_LOG_MAX_CHARS]
            ))
    except Exception:
        pass


def _action_summary(entry: dict[str, Any]) -> str:
    """One policy's outcome: approved-LLM list verdict, PII entity types, etc.
    Snippets (original_snippet / masked_snippet) are never included."""
    if entry.get("type") in ("uploaded_file", "document_block") and not entry.get("policy_id"):
        return (f"document_decode {entry.get('action')} name={entry.get('name') or '-'} "
                f"media_type={entry.get('media_type') or '-'} "
                f"extracted_chars={entry.get('extracted_chars', '-')}"
                + (f" note={entry.get('note')!r}" if entry.get("action") != "decoded" else ""))
    inner = [a for a in (entry.get("actions") or []) if isinstance(a, dict)]
    parts = [f"policy={entry.get('policy_id') or '-'}",
             f"decision={entry.get('decision') or entry.get('action') or '-'}"]
    types = sorted({str(a["type"]) for a in inner if a.get("type")})
    if types:
        parts.append(f"type={','.join(types)}")
    for key in ("model", "list_status", "source"):
        vals = sorted({str(a[key]) for a in inner if a.get(key)})
        if vals:
            parts.append(f"{key}={','.join(vals)}")
    matched = sorted({
        f"{m.get('name')}:{m.get('status')}"
        for a in inner for m in (a.get("matched") or []) if isinstance(m, dict)
    })
    if matched:
        parts.append(f"matched=[{', '.join(matched)}]")
    entities = sorted({str(a.get("entity_type")) for a in inner if a.get("entity_type")})
    if entities:
        parts.append(f"entity_types={entities}")
        fields = sorted({str(a.get("field")) for a in inner if a.get("field")})
        parts.append(f"fields={fields}")
    return " ".join(parts)


def _log_enforce_response(
    url: str, body: dict[str, Any], http_status: int, result: Any, elapsed_ms: int, mode: str,
) -> None:
    try:
        site = body.get("site_id") or "-"
        res = result if isinstance(result, dict) else {}
        warning = res.get("warning")
        _emit_enforce_log(logging.INFO, (
            f"[lineaje.enforce] ← HTTP {http_status} site_id={site} status={res.get('status') or '-'} "
            f"elapsed_ms={elapsed_ms} actions={len(res.get('actions_applied') or [])} "
            f"recommendations={len(res.get('recommendations') or [])}"
            + (f" warning={warning!r}" if warning else "")
        ))
        for entry in res.get("actions_applied") or []:
            if isinstance(entry, dict):
                _emit_enforce_log(logging.INFO, f"[lineaje.enforce]     {_action_summary(entry)}")
        if mode == "full":
            _emit_enforce_log(logging.INFO, (
                "[lineaje.enforce] ← response body: "
                + json.dumps(result, default=_json_default)[:_ENFORCE_LOG_MAX_CHARS]
            ))
    except Exception:
        pass


def _log_enforce_http_error(
    url: str, body: dict[str, Any], exc: urllib.error.HTTPError, elapsed_ms: int, mode: str,
) -> None:
    try:
        raw = _http_error_body(exc)
        try:
            parsed = json.loads(raw) if raw else {}
        except Exception:
            parsed = {}
        detail = _normalize_http_error_detail(parsed)
        site = body.get("site_id") or "-"
        level = logging.WARNING
        if exc.code == 403 and detail.get("error") == "request_blocked":
            blocked_by = _policy_ids(detail.get("blocked_by"))
            msg = (f"[lineaje.enforce] ← HTTP 403 site_id={site} BLOCKED by {blocked_by} "
                   f"elapsed_ms={elapsed_ms} — {detail.get('message') or ''}")
        else:
            msg = (f"[lineaje.enforce] ← HTTP {exc.code} site_id={site} "
                   f"error={detail.get('error') or exc.reason!r} elapsed_ms={elapsed_ms}"
                   + (f" — {detail.get('message')}" if detail.get("message") else ""))
        _emit_enforce_log(level, msg)
        if mode == "full":
            _emit_enforce_log(level, (
                "[lineaje.enforce] ← response body: "
                + raw.decode("utf-8", "replace")[:_ENFORCE_LOG_MAX_CHARS]
            ))
    except Exception:
        pass


# ── Observability events: one bounded queue, one background flusher ───────────────────────────────────────
# Every executed stub produces exactly one observability event (a log-only stub: that the activity happened;
# an enforcing stub: the outcome of its /enforce call). The app thread only appends the event to an in-process
# queue; a daemon thread sends the queue to the Guardrail's observability endpoint, separate from /enforce, so
# observability never adds latency to the app and never raises into it.
#
# * Event = the /enforce body minus the data (payload / in_params / out_params / violations / tokens), plus the
#   payload's non-text facts (scalar model / tool / name facts, token counts; a log-only stub's ``activity``
#   name) and, for an enforcing stub, ``outcome`` (``status`` = what the app did, ``gr_status`` +
#   ``gr_policy_ids`` = what the Guardrail answered, warning, policy results) and ``logged_by_enforce`` (True when
#   /enforce already logged the call itself, i.e. the client did not send ``reports_activity``). Never the text.
#   A stub that never reached the Guardrail (a quarantined skill refused locally, a call skipped after an
#   earlier block) still queues one event (``quarantined`` / ``skipped_after_block``, ``gr_status: null``).
# * Queue: UNIFAI_OBS_QUEUE_MAX events (default 10 000); when full the oldest is dropped and counted.
# * Flusher: every UNIFAI_OBS_FLUSH_SEC (default 1 s) or as soon as UNIFAI_OBS_BATCH_MAX (default 100) events
#   wait, POST {events, dropped} to /observability/batch with UNIFAI_OBS_TIMEOUT_SEC (default 2 s); no retries.
#   A Guardrail that answers 404/405 there gets one POST /observability per event from then on (this process);
#   events /enforce already logged are not re-sent that way. One that also lacks /observability gets log-only
#   events on /enforce (``observe_only``), as before.
# * Exit: an atexit hook sends what is still queued, for at most UNIFAI_OBS_EXIT_DEADLINE_SEC (default 2 s).
_ACTIVITY_POLICY = "AI_AGENT_ACTIVITY_LOG"
_FACT_KEYS = ("model", "usage_metadata", "name", "tool_id", "tool_name", "tool", "connector_id")
_FACT_STR_MAX = 200
# Known sub-keys of the two nested facts; anything else (and any dict / list value) is dropped.
_USAGE_KEYS = ("input_tokens", "output_tokens", "total_tokens", "prompt_tokens", "completion_tokens",
               "cache_read_input_tokens", "cache_creation_input_tokens", "reasoning_tokens")
_META_KEYS = ("model_name", "model", "finish_reason", "stop_reason", "system_fingerprint")
_META_USAGE_KEYS = ("token_usage", "usage")
_EVENT_DROP_KEYS = ("payload", "in_params", "out_params", "violations", "enabled_policies",
                    "resume_token", "redecision_token")


def _lists_activity_policy(body: "dict[str, Any]") -> bool:
    for c in body.get("candidate_policies") or []:
        if (c.get("policy_id") if isinstance(c, dict) else c) == _ACTIVITY_POLICY:
            return True
    return False


def _payload_data(body: "dict[str, Any]") -> Any:
    data = (body.get("payload") or {}).get("data") if isinstance(body.get("payload"), dict) else None
    if data is None:
        for key in ("in_params", "out_params"):
            if isinstance(body.get(key), dict):
                return body[key].get("data", body[key])
    return data


def _fact_scalar(value: Any) -> bool:
    """A fact value that can carry no text: bool / int / float, or a short string."""
    if isinstance(value, bool) or isinstance(value, (int, float)):
        return True
    return isinstance(value, str) and len(value) <= _FACT_STR_MAX


def _usage_facts(value: Any) -> "dict[str, Any]":
    if not isinstance(value, dict):
        return {}
    return {k: value[k] for k in _USAGE_KEYS
            if k in value and isinstance(value[k], (int, float)) and not isinstance(value[k], bool)}


def _activity_facts(body: "dict[str, Any]") -> "dict[str, Any]":
    """The payload's non-text facts the span reads: scalar top-level facts, token counts, and a few known
    response-metadata scalars. Never the text, never an arbitrary dict or list."""
    data = _payload_data(body)
    if not isinstance(data, dict):
        return {}
    facts: "dict[str, Any]" = {}
    for k in _FACT_KEYS:
        if k not in data:
            continue
        if k == "usage_metadata":
            usage = _usage_facts(data[k])
            if usage:
                facts[k] = usage
        elif _fact_scalar(data[k]):
            facts[k] = data[k]
    meta = data.get("response_metadata")
    if isinstance(meta, dict):
        kept = {k: meta[k] for k in _META_KEYS if k in meta and _fact_scalar(meta[k])}
        for k in _META_USAGE_KEYS:
            usage = _usage_facts(meta.get(k))
            if usage:
                kept[k] = usage
        if kept:
            facts["response_metadata"] = kept
    return facts


def _log_only_facts(payload: Any) -> Any:
    """What a log-only call keeps of its payload: the fact keys only (read, never serialized)."""
    if not isinstance(payload, dict):
        return None
    keys = _FACT_KEYS + ("activity", "response_metadata")
    return {k: payload[k] for k in keys if k in payload}


# The site this event is about, named from the scan facts the stub's descriptor carries (``components``, written at
# insertion time) — never from scan-time site registration, which harness mode does not do (M1). Identifiers only:
# each value a short string or an int, anything else dropped; ``on_graph`` (a bool) is the one exception.
_SITE_FACT_KEYS = ("site_id", "boundary_id", "insertion_point", "agent_name", "agent_name_source",
                   "source_type", "destination_type", "source_entity_type", "source_name",
                   "destination_entity_type", "destination_name", "function", "file", "line", "call_target",
                   "model", "phase")
_SITE_STR_MAX = 256


def _site_ident(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, str) and 0 < len(value) <= _SITE_STR_MAX


def _site_facts(body: "dict[str, Any]") -> "dict[str, Any]":
    comps = body.get("components") if isinstance(body.get("components"), dict) else {}
    identity = comps.get("identity") if isinstance(comps.get("identity"), dict) else {}
    invocation = comps.get("invocation") if isinstance(comps.get("invocation"), dict) else {}
    ends = {side: (identity.get(side) if isinstance(identity.get(side), dict) else {})
            for side in ("source", "destination")}
    facts: "dict[str, Any]" = {
        "site_id": body.get("site_id"), "boundary_id": comps.get("boundary_id"),
        "source_type": body.get("source_type"), "destination_type": body.get("destination_type"),
        "phase": body.get("phase"), "call_target": comps.get("call_target"), "model": comps.get("model"),
    }
    for side, end in ends.items():
        facts[f"{side}_entity_type"] = end.get("entity_type")
        facts[f"{side}_name"] = end.get("name")
    for key in ("function", "file", "line"):
        facts[key] = comps.get(key) if comps.get(key) not in (None, "") else invocation.get(key)
    data = _payload_data(body)
    if body.get("observe_only") and isinstance(data, dict):
        facts["insertion_point"] = data.get("activity")
    # The agent: the runtime override, else the graph's agent end of the boundary, else the scan's inference.
    # A stub's descriptor carries no ``identity`` (``site_components.stub_components``): its endpoints name the agent.
    graph_agent = next((end.get("name") for end in (ends["source"], ends["destination"],
                                                    comps.get("source"), comps.get("destination"))
                        if isinstance(end, dict) and end.get("entity_type") in ("aiagent", "agent")
                        and _site_ident(end.get("name"))), None)
    if _site_ident(body.get("agent_name")):
        facts["agent_name"], facts["agent_name_source"] = body["agent_name"], "runtime_env"
    elif graph_agent:
        facts["agent_name"], facts["agent_name_source"] = graph_agent, "graph"
    else:
        facts["agent_name"], facts["agent_name_source"] = comps.get("agent_name"), comps.get("agent_name_source")
        if not _site_ident(facts["agent_name"]):
            facts["agent_name_source"] = None
    out = {k: facts[k] for k in _SITE_FACT_KEYS if _site_ident(facts.get(k))}
    # Harness-mode descriptors say which: a graph boundary_id, or not_on_graph (P4-1). Pipeline mode says neither.
    if out.get("boundary_id"):
        out["on_graph"] = True
    elif comps.get("not_on_graph") is True:
        out["on_graph"] = False
    return out


def _observability_event(body: "dict[str, Any]", outcome: "dict[str, Any] | None",
                         logged_by_enforce: "bool | None" = None) -> "dict[str, Any]":
    """The text-free event for one executed stub (see the block comment above)."""
    event = {k: v for k, v in body.items() if k not in _EVENT_DROP_KEYS}
    event["site"] = _site_facts(body)
    facts = _activity_facts(body)
    data = _payload_data(body)
    if body.get("observe_only") and isinstance(data, dict) and isinstance(data.get("activity"), str) \
            and len(data["activity"]) <= 64:
        facts["activity"] = data["activity"]          # a log-only stub's constant name, e.g. "agent_to_llm"
    event["out_params" if body.get("destination_type") == "agent" else "in_params"] = facts
    if outcome is not None:
        event["outcome"] = outcome
        event["logged_by_enforce"] = (not body.get("reports_activity")) if logged_by_enforce is None \
            else bool(logged_by_enforce)
    return event


def _gr_verdict(status: "str | None", actions: Any = None) -> "dict[str, Any]":
    """What the Guardrail itself answered (``gr_status`` + the policy ids it applied), kept apart from what the
    app finally did (``status``): a GR block passed through under ALLOW_WITH_AUDIT is ``gr_status: block``,
    ``status: allow``. Ids only."""
    return {"gr_status": status, "gr_policy_ids": _policy_ids(actions)}


def _outcome_of(result: "dict[str, Any]", gr: "dict[str, Any] | None" = None) -> "dict[str, Any]":
    out = {"status": result.get("status", "allow"), "warning": result.get("warning"),
           "actions_applied": result.get("actions_applied") or []}
    if result.get("infra_failure"):
        out["infra_failure"] = True
    out.update(gr or {"gr_status": None, "gr_policy_ids": []})       # None: the Guardrail gave no verdict
    return out


def _local_block_body(*, site_id: str, source_type: str, destination_type: str, phase: str = "",
                      candidate_policies: Any = None, components: Any = None, tenant_id: str = "",
                      **flags: Any) -> "dict[str, Any]":
    """The request-shaped, data-free body of a stub execution that never reached the Guardrail (a quarantined
    skill refused locally, a call skipped after an earlier block)."""
    body: "dict[str, Any]" = {
        "contract_version": "2.0", "event_id": _new_ulid(), "site_id": site_id or "", "phase": phase or "",
        "source_type": source_type or "", "destination_type": destination_type or "",
        "candidate_policies": candidate_policies or [], "components": components or {}, "tenant_id": tenant_id or "",
        "process": _process_facts(), "thread_name": threading.current_thread().name,
    }
    agent_name = os.environ.get("LINEAJE_AGENT_NAME", "").strip()
    if agent_name:
        body["agent_name"] = agent_name
    body.update({k: v for k, v in flags.items() if v})
    return body


def _env_number(name: str, default: float, minimum: float) -> float:
    raw = (os.environ.get(name) or "").strip()
    try:
        value = float(raw) if raw else default
    except ValueError:
        value = default
    return max(value, minimum)


def _obs_batch_endpoint(gr_url: str) -> "tuple[str, str]":
    base, path = _observability_endpoint(gr_url)
    return (base, f"{path}/batch") if path else (f"{base}/batch", "")


class _ObsTarget:
    """Where an event goes. ``url`` / ``bearer`` are None until resolved — on the flusher thread, so the app
    thread never resolves an origin or exchanges a token for observability."""

    __slots__ = ("url", "bearer", "url_hint", "bearer_hint")

    def __init__(self, url: "str | None" = None, bearer: "str | None" = None, *, url_hint: "str | None" = None,
                 bearer_hint: str = "") -> None:
        self.url, self.bearer, self.url_hint, self.bearer_hint = url, bearer, url_hint, bearer_hint

    def resolve(self) -> "tuple[str, str]":
        if self.url is None:
            self.url = _resolve_gr_origin(self.url_hint) or ""
        if self.bearer is None:
            try:
                self.bearer = _resolve_enforce_bearer(self.bearer_hint) or self.bearer_hint
            except Exception:  # noqa: BLE001
                self.bearer = self.bearer_hint
        return self.url, self.bearer


class _ObservabilityQueue:
    """Bounded, drop-oldest queue of ``(target, event)`` with one daemon flusher. Never raises.

    ``mode`` is written without the lock by whichever thread (flusher or exit drain) sees the 404 first. That is
    benign: it only ever moves forward (batch → single → enforce) and both writers write the same value; the worst
    case is one extra probe of the route that just answered 404."""

    def __init__(self) -> None:
        self.max_items = int(_env_number("UNIFAI_OBS_QUEUE_MAX", 10000, 1))
        self.batch_max = int(_env_number("UNIFAI_OBS_BATCH_MAX", 100, 1))
        self.flush_sec = _env_number("UNIFAI_OBS_FLUSH_SEC", 1.0, 0.01)
        self.timeout = _env_number("UNIFAI_OBS_TIMEOUT_SEC", 2.0, 0.05)
        self.exit_deadline = _env_number("UNIFAI_OBS_EXIT_DEADLINE_SEC", 2.0, 0.0)
        self.items: "collections.deque[tuple[_ObsTarget, dict]]" = collections.deque()
        self.cond = threading.Condition(threading.Lock())
        self.inflight = 0
        self.draining = False
        self.stopped = False
        self.thread: "threading.Thread | None" = None
        self.mode = "batch"            # batch → single (POST /observability per event) → enforce (older Guardrail)
        self.unreported_drops = 0
        self.stats = {"enqueued": 0, "sent": 0, "dropped": 0, "failed": 0, "skipped": 0, "batches": 0, "expired": 0}

    # app thread
    def put(self, target: _ObsTarget, event: "dict[str, Any]") -> None:
        with self.cond:
            if len(self.items) >= self.max_items:
                self.items.popleft()
                self.stats["dropped"] += 1
                self.unreported_drops += 1
                now = time.monotonic()
                if now - getattr(self, "_drop_logged_at", -1e9) >= 60.0:     # LIN-36167: at most once a minute
                    self._drop_logged_at = now
                    _logger.warning("gr_stub_client: observability queue full (%d) — oldest events dropped "
                                    "(%d so far); raise UNIFAI_OBS_QUEUE_MAX or check the guardrail",
                                    self.max_items, self.stats["dropped"])
            self.items.append((target, event))
            self.stats["enqueued"] += 1
            if self.thread is None:
                self.thread = threading.Thread(target=self._run, name="lineaje-observability", daemon=True)
                self.thread.start()
            if len(self.items) >= self.batch_max:
                self.cond.notify_all()

    # flusher
    def _take(self) -> "tuple[list, int]":
        """Caller holds the lock."""
        batch = [self.items.popleft() for _ in range(min(self.batch_max, len(self.items)))]
        drops, self.unreported_drops = self.unreported_drops, 0
        self.inflight += 1
        return batch, drops

    def _done(self) -> None:
        with self.cond:
            self.inflight -= 1
            self.cond.notify_all()

    def _run(self) -> None:
        while not self.stopped:
            try:
                with self.cond:
                    self.cond.wait_for(lambda: self.stopped or len(self.items) >= self.batch_max
                                       or (self.draining and self.items), timeout=self.flush_sec)
                    if self.stopped or not self.items:
                        continue
                    batch, drops = self._take()
                try:
                    self._send(batch, drops, self.timeout)
                finally:
                    self._done()
            except Exception:  # noqa: BLE001 - the flusher never dies and never reaches the app
                time.sleep(self.flush_sec)

    def drain(self, deadline_sec: float) -> bool:
        """Send everything queued (helping the flusher), for at most ``deadline_sec``. True when all was handed
        to the Guardrail (or given up on after an error), False when the deadline cut it short."""
        end = time.monotonic() + max(deadline_sec, 0.0)
        with self.cond:
            self.draining = True
            expired_before = self.stats["expired"]
            self.cond.notify_all()
        try:
            while True:
                remaining = end - time.monotonic()
                with self.cond:
                    if not self.items and self.inflight == 0:
                        return self.stats["expired"] == expired_before     # False: some ran out of time
                    if remaining <= 0:
                        return False
                    if not self.items:
                        self.cond.wait(remaining)
                        continue
                    batch, drops = self._take()
                try:
                    self._send(batch, drops, self.timeout, deadline=end)
                finally:
                    self._done()
        finally:
            with self.cond:
                self.draining = False

    def _send(self, batch: list, drops: int, timeout: float, deadline: "float | None" = None) -> None:
        groups: "dict[tuple[str, str], list[dict]]" = {}
        for target, event in batch:
            try:
                url, bearer = target.resolve()
            except Exception:  # noqa: BLE001
                url, bearer = "", ""
            if not url:
                self._count("skipped")        # no Guardrail configured: nowhere to send it
                continue
            groups.setdefault((url, bearer), []).append(event)
        for (url, pat), events in groups.items():
            try:
                self._send_group(url, pat, events, drops, timeout, deadline)
            except Exception as exc:  # noqa: BLE001
                self._count("failed", len(events))
                _logger.debug("gr_stub_client: observability send failed (%s)", exc)
            drops = 0

    def _count(self, key: str, n: int = 1) -> None:
        with self.cond:
            self.stats[key] += n

    @staticmethod
    def _budget(timeout: float, deadline: "float | None") -> "float | None":
        """The timeout for one POST, or None when the deadline has passed."""
        if deadline is None:
            return timeout
        remaining = deadline - time.monotonic()
        return None if remaining <= 0 else max(min(timeout, remaining), 0.05)

    def _send_group(self, url: str, pat: str, events: "list[dict]", drops: int, timeout: float,
                    deadline: "float | None" = None) -> None:
        if self.mode == "batch":
            budget = self._budget(timeout, deadline)
            if budget is None:
                self._count("expired", len(events))
                return
            try:
                _post_json(*_obs_batch_endpoint(url),
                           {"contract_version": "2.0", "events": events, "dropped": drops}, pat, budget)
                self._count("sent", len(events))
                self._count("batches")
                return
            except urllib.error.HTTPError as exc:
                if exc.code not in (404, 405):
                    raise
                self.mode = "single"      # no batch route on this Guardrail: per event from now on
        for i, event in enumerate(events):
            budget = self._budget(timeout, deadline)
            if budget is None:                                   # exit / flush deadline reached: stop here
                self._count("expired", len(events) - i)
                return
            try:
                self._send_one(url, pat, event, budget)
            except Exception as exc:  # noqa: BLE001
                self._count("failed")
                _logger.debug("gr_stub_client: observability event not sent (%s)", exc)

    def _send_one(self, url: str, pat: str, event: "dict[str, Any]", timeout: float) -> None:
        global _OBSERVABILITY_UNSUPPORTED
        if event.get("logged_by_enforce"):
            self._count("skipped")        # an older Guardrail logged this call on /enforce already
            return
        if self.mode == "single":
            try:
                _post_json(*_observability_endpoint(url), event, pat, timeout)
                self._count("sent")
                return
            except urllib.error.HTTPError as exc:
                if exc.code not in (404, 405):
                    raise
                self.mode = "enforce"
                _OBSERVABILITY_UNSUPPORTED = True     # /enforce keeps logging normal calls (no reports_activity)
        # An older Guardrail without /observability: /enforce logs an ``observe_only`` request without running
        # policies. A call whose /enforce request said ``reports_activity`` (so /enforce did not log it) goes
        # there too — as a log-only record — rather than being lost.
        _post_json(url, "/enforce", event if event.get("observe_only") else {**event, "observe_only": True},
                   pat, timeout)
        self._count("sent")


_OBS_QUEUE: "_ObservabilityQueue | None" = None
_OBS_LOCK = threading.Lock()


def _obs_queue() -> _ObservabilityQueue:
    global _OBS_QUEUE
    q = _OBS_QUEUE
    if q is None:
        with _OBS_LOCK:
            if _OBS_QUEUE is None:
                _OBS_QUEUE = _ObservabilityQueue()
            q = _OBS_QUEUE
    return q


def _enqueue_observability(url: "str | None", pat: "str | None", body: "dict[str, Any]",
                           outcome: "dict[str, Any] | None", *, logged_by_enforce: "bool | None" = None,
                           gr_service_url: "str | None" = None, lineaje_pat: str = "") -> None:
    """Queue the event for one executed stub. O(1) on the app thread; never raises. ``url`` / ``pat`` None:
    resolved on the flusher thread (from ``gr_service_url`` / ``lineaje_pat``)."""
    try:
        target = _ObsTarget(url, pat, url_hint=gr_service_url, bearer_hint=lineaje_pat or "")
        _obs_queue().put(target, _observability_event(body, outcome, logged_by_enforce))
    except Exception as exc:  # noqa: BLE001 - observability never affects the app
        _logger.debug("gr_stub_client: observability event not queued (%s)", exc)


def _enqueue_local_block(outcome: "dict[str, Any]", *, gr_service_url: "str | None" = None, lineaje_pat: str = "",
                         **body_fields: Any) -> None:
    """One event for a stub execution that never reached the Guardrail. Never raises."""
    try:
        _enqueue_observability(None, None, _local_block_body(**body_fields), outcome, logged_by_enforce=False,
                               gr_service_url=gr_service_url, lineaje_pat=lineaje_pat)
    except Exception as exc:  # noqa: BLE001
        _logger.debug("gr_stub_client: observability event not queued (%s)", exc)


def flush_observability(timeout: float = 5.0) -> bool:
    """Send the queued observability events now, waiting at most ``timeout`` seconds. Never raises."""
    try:
        q = _OBS_QUEUE
        return True if q is None else q.drain(timeout)
    except Exception:  # noqa: BLE001
        return False


def observability_stats() -> "dict[str, int]":
    """Counters of this process's observability queue (enqueued, sent, dropped, failed, skipped, expired, batches,
    queued)."""
    q = _OBS_QUEUE
    if q is None:
        return {"enqueued": 0, "sent": 0, "dropped": 0, "failed": 0, "skipped": 0, "batches": 0, "expired": 0,
                "queued": 0}
    with q.cond:
        return {**q.stats, "queued": len(q.items)}


def _reset_observability() -> None:
    """Drop the queue: pending events are discarded and its flusher ends. Test helper."""
    global _OBS_QUEUE
    old, _OBS_QUEUE = _OBS_QUEUE, None
    if old is not None:
        try:
            with old.cond:
                old.items.clear()
                old.stopped = True
                old.cond.notify_all()
        except Exception:  # noqa: BLE001
            pass


def _flush_observability_at_exit() -> None:
    try:
        q = _OBS_QUEUE
        if q is not None:
            q.drain(q.exit_deadline)
    except Exception:  # noqa: BLE001
        pass


def _observability_after_fork() -> None:
    """A forked worker starts with its own empty queue, flusher and lock (the parent's thread does not exist there,
    and its lock may have been held at fork time)."""
    global _OBS_QUEUE, _OBS_LOCK
    _OBS_QUEUE = None
    _OBS_LOCK = threading.Lock()


atexit.register(_flush_observability_at_exit)
if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_observability_after_fork)


def _post_enforce(url: str, body: dict[str, Any], pat: str, timeout: float) -> dict[str, Any]:
    """POST /enforce, logging the request and the response in the customer app
    (see LINEAJE_ENFORCE_LOG above). Errors are re-raised unchanged for the
    caller's block / fail-open handling. The call's observability event is queued
    by the caller (``check`` / ``call_gr_enforce``), once per executed stub."""
    mode = _enforce_log_mode()
    started = time.monotonic()
    if not _OBSERVABILITY_UNSUPPORTED and not body.get("observe_only") and _lists_activity_policy(body):
        body["reports_activity"] = True      # this client reports the call to /observability, so /enforce leaves it
    if mode != "off":
        _log_enforce_request(url, body, mode)
    try:
        _ensure_heartbeat(url, body.get("tenant_id") or "", pat, body)
        _LAST_POST.path = "/enforce"
        result = _post_json(url, "/enforce", body, pat, timeout)
    except urllib.error.HTTPError as exc:
        if mode != "off":
            _log_enforce_http_error(url, body, exc, int((time.monotonic() - started) * 1000), mode)
        raise
    except Exception as exc:
        if mode != "off":
            _emit_enforce_log(logging.WARNING, (
                f"[lineaje.enforce] ✗ POST {url}/enforce site_id={body.get('site_id') or '-'} "
                f"failed after {int((time.monotonic() - started) * 1000)}ms — {type(exc).__name__}: {exc}"
            ))
        raise
    if mode != "off":
        _log_enforce_response(url, body, 200, result, int((time.monotonic() - started) * 1000), mode)
    return result


def _ensure_site_registered(
    url: str,
    site: "SiteDescriptor",
    tenant_id: str,
    pat: str,
    timeout: float,
) -> "list[Any] | None":
    """POST /admin/site-manifest/register once per site_id, then /enforce can resolve it.

    Returns compiled ``policy_mappings`` (possibly empty) on success, or
    ``None`` if registration failed. Scan-time registration often lands in a
    different SQLite than commercialdev; runtime check() self-registers on
    unknown_site so leftover stubs still enforce with site_id.
    """
    site_id = (getattr(site, "site_id", "") or "").strip()
    if not site_id:
        return None
    if site_id in _SITE_REGISTERED:
        return _SITE_POLICY_MAPPINGS.get(site_id, [])
    if site_id in _SITE_REGISTER_ATTEMPTED:
        return None
    _SITE_REGISTER_ATTEMPTED.add(site_id)
    if not tenant_id:
        _logger.warning(
            "gr_stub_client: cannot register site_id=%s — no tenant_id in token/body",
            site_id,
        )
        return None
    try:
        result = _post_json(
            url,
            "/admin/site-manifest/register",
            {
                "tenant_id": tenant_id,
                "site_id": site_id,
                "phase": getattr(site, "phase", "") or "",
                "boundary": getattr(site, "boundary", None) or {},
                "components": _site_components(site),
                # Record the stub's own list as the site's mapping so the
                # /enforce exact-match holds. No list (its site file is
                # missing): left out, so the Guardrail compiles the site from
                # its catalog instead of recording an empty mapping.
                **({"candidate_policies": [
                    (c.get("policy_id") if isinstance(c, dict) else getattr(c, "policy_id", c))
                    for c in site.candidate_policies
                ]} if getattr(site, "candidate_policies", None) else {}),
            },
            pat,
            timeout,
        )
    except Exception as exc:
        _logger.warning(
            "gr_stub_client: site-manifest register failed for %s (%s) — "
            "will retry /enforce without site_id",
            site_id, exc,
        )
        return None
    if not result.get("ok"):
        _logger.warning(
            "gr_stub_client: site-manifest register rejected for %s (%s) — "
            "will retry /enforce without site_id",
            site_id, result.get("error"),
        )
        return None
    mappings = result.get("policy_mappings") or []
    _SITE_REGISTERED.add(site_id)
    _SITE_POLICY_MAPPINGS[site_id] = mappings
    _logger.info(
        "gr_stub_client: registered site_id=%s tenant=%s mappings=%d on %s",
        site_id, tenant_id, len(mappings), url,
    )
    return mappings


def _decision_for_genuine_block(
    site: "SiteDescriptor", url: str, hop: str, detail: dict, payload: Any, obs: "dict | None" = None,
) -> "Decision":
    """A confirmed policy block (``detail["blocked_by"]`` populated, not an
    unknown_site resolution issue) — respects ``site.fail_mode`` exactly like
    the first-attempt 403 handler in ``check()`` does. Factored out so the
    unknown_site retry paths below can reach the SAME real-block handling
    when a retry's own 403 turns out to be a genuine block rather than
    another unknown_site cycle — see those callers' comments for the bug
    this fixes (a real block during a retry used to fall through to
    ``_fail_response``'s generic "unresolved unknown_site" path, which
    fails OPEN even when fail_mode=BLOCK, since that path's own safety
    check explicitly excludes anything with "unknown_site" in its warning
    text — exactly the string used to describe that fallback).
    """
    blocked_by = detail.get("blocked_by") or []
    policy_id = blocked_by[0].get("policy_id", "unknown") if blocked_by else "unknown"
    reason = detail.get("message", "Request denied by policy enforcement.")
    if obs is not None:
        obs["gr"] = _gr_verdict("block", blocked_by or [policy_id])     # the GR's verdict, whatever fail_mode does
    if getattr(site, "fail_mode", None) != "BLOCK":
        _announce_enforce(
            url, hop, "allow",
            extra=f"HTTP 403 {policy_id} passed through (fail_mode={getattr(site, 'fail_mode', '') or 'ALLOW_WITH_AUDIT'})",
        )
        allowed = Decision({
            "status": "allow",
            "result": {"data": payload},
            "actions_applied": [{"policy_id": policy_id, "action": "block"}],
            "recommendations": [],
            "warning": reason,
        }, site_id=site.site_id)
        return _finalize_decision(allowed, payload)
    _announce_enforce(url, hop, "block", extra=f"policy={policy_id} {reason}")
    blocked = Decision({
        "status": "block",
        "result": {"data": payload},
        "actions_applied": [{"policy_id": policy_id, "action": "block"}],
        "recommendations": [],
        "warning": reason,
    }, site_id=site.site_id)
    _maybe_record_process_block(blocked, site)
    return _finalize_decision(blocked, payload)


def _genuine_block_detail_from_retry_exc(retry_exc: Exception, site_id: str) -> "dict | None":
    """None unless ``retry_exc`` is an HTTPError(403) carrying a real policy
    block — i.e. NOT another unknown_site cycle (that gets a fresh register/
    retry of its own upstream, not folded into this check). Callers use
    this to route a retry's own confirmed block through
    ``_decision_for_genuine_block`` instead of the generic
    "unresolved unknown_site" fail-open/closed fallback.
    """
    if not isinstance(retry_exc, urllib.error.HTTPError) or retry_exc.code != 403:
        return None
    detail = _read_http_error_detail(retry_exc)
    if _should_register_unknown_site(detail, site_id):
        return None
    if not detail.get("blocked_by"):
        return None
    return detail


def _report_skipped_after_block(site: "SiteDescriptor", tenant_id: str = "") -> None:
    """Tell the Guardrail this call was skipped because the request was already blocked, with no
    payload and no policy run. Best effort and short: it must never slow or break the app."""
    try:
        import dataclasses as _dc
        check(_dc.replace(site, observe_only=True, skipped_after_block=True), None,
              tenant_id=tenant_id, timeout=1.5)
    except Exception:
        pass


def check(
    site: SiteDescriptor,
    payload: Any,
    content_type: str = "application/json",
    *,
    tenant_id: str = "",
    correlation_id: "str | None" = None,
    event_id: "str | None" = None,
    operation_identity: "dict | None" = None,
    gr_service_url: "str | None" = None,
    lineaje_pat: str = "",
    timeout: "float | None" = None,
) -> Decision:
    """POST /enforce for this site. Never raises; 403 → ``decision.blocked``.

    After a fail-closed policy block, later calls for *other* site_ids skip
    the POST entirely (do not extract/upload file contents for PII/MCP
    sites). The blocking site may still re-POST.

    A log-only site (``observe_only``) makes no call on the app's thread: its
    event is queued for the observability flusher and the call is allowed.
    Every call that builds a request queues exactly one observability event
    (text-free; see ``_observability_event``) — log-only or enforcing, whatever
    the candidate policies.
    """
    obs: "dict[str, Any]" = {}
    decision = _check(site, payload, content_type, tenant_id=tenant_id, correlation_id=correlation_id,
                      event_id=event_id, operation_identity=operation_identity, gr_service_url=gr_service_url,
                      lineaje_pat=lineaje_pat, timeout=timeout, _obs=obs)
    if "body" in obs:
        try:
            outcome = None if obs["body"].get("observe_only") else _outcome_of({
                "status": decision.status, "warning": decision.warning,
                "actions_applied": decision.actions_applied, "infra_failure": decision.infra_failure}, obs.get("gr"))
        except Exception:  # noqa: BLE001
            outcome = {"status": "allow"}
        _enqueue_observability(obs["url"], obs["pat"], obs["body"], outcome,
                               gr_service_url=gr_service_url, lineaje_pat=lineaje_pat)
    return decision


def _check(
    site: SiteDescriptor,
    payload: Any,
    content_type: str = "application/json",
    *,
    tenant_id: str = "",
    correlation_id: "str | None" = None,
    event_id: "str | None" = None,
    operation_identity: "dict | None" = None,
    gr_service_url: "str | None" = None,
    lineaje_pat: str = "",
    timeout: "float | None" = None,
    _obs: "dict[str, Any]",
) -> Decision:
    """``check`` without the observability event; fills ``_obs`` (body, url, bearer) once a request is built."""
    observe = bool(getattr(site, "observe_only", False))
    # A log-only call never enforces, so an earlier block neither skips it nor does it set one.
    prior = None if observe else _process_block_for_other_site(getattr(site, "site_id", "") or "")
    if prior is not None:
        _report_skipped_after_block(site, tenant_id)    # the activity is still logged, without its data
        return _skipped_other_site_decision(site, payload, prior)
    local_block = None if observe else _local_quarantined_skill_decision(site, payload)
    if local_block is not None:
        src, dst = _source_dest_from_site(site)
        _enqueue_local_block(
            _outcome_of({"status": local_block.status, "warning": local_block.warning,
                         "actions_applied": local_block.actions_applied}),
            gr_service_url=gr_service_url, lineaje_pat=lineaje_pat, site_id=getattr(site, "site_id", "") or "",
            source_type=src, destination_type=dst, phase=getattr(site, "phase", "") or "",
            candidate_policies=getattr(site, "candidate_policies", None), components=_site_components(site),
            tenant_id=tenant_id or getattr(site, "tenant_id", "") or "", quarantined=True)
        return local_block
    if timeout is None:
        timeout = _resolve_enforce_timeout_seconds()
    url = _resolve_gr_origin(gr_service_url)
    if not url:
        return Decision(
            _fail_response(site, "GR_SERVICE_URL not configured — guardrail skipped", payload),
            site_id=site.site_id,
        )

    if not observe and not _BREAKER.allow(url):
        return Decision(_fail_response(site, "guardrail circuit open — call skipped", payload), site_id=site.site_id)

    # A log-only call sends nothing on this thread: its bearer is resolved by the observability flusher and its
    # payload is never serialized (only its fact keys are read).
    pat = None if observe else _resolve_enforce_bearer(lineaje_pat)
    ident_pat = pat or ""

    wire_plain: Any = None
    redacted = False
    if observe:
        wire_data = _redact_wire(_log_only_facts(payload))[0]     # G8: fact values never carry a credential
    else:
        try:
            wire_plain = _wire_payload(payload)
        except Exception as exc:
            _logger.warning("gr_stub_client.check: payload serialize failed (%s) — original object unchanged", exc)
            wire_plain = {"text": None}
        # G8: the GR never receives a credential — a redacted copy is sent (the caller's objects are untouched)
        wire_data, redacted = _redact_wire(wire_plain)

    wire_src, wire_dst = _source_dest_from_site(site)
    if _payload_is_uploaded_files(payload):
        # AskFileMessage / upload handles were classified as api→agent
        # (post_tool + external_endpoint). The file body lives on disk; PII
        # upload policies are bound to file_upload (file_storage→agent).
        wire_src, wire_dst = "file_storage", "agent"
    body: dict[str, Any] = {
        "contract_version": "2.0",
        "event_id": event_id or _new_ulid(),
        "correlation_id": correlation_id or _new_ulid(),
        "tenant_id": tenant_id or getattr(site, "tenant_id", "") or _identity_from_bearer(ident_pat)["tenant_id"]
        or os.environ.get("GR_TENANT_ID", ""),
        "company_id": getattr(site, "company_id", "") or _identity_from_bearer(ident_pat)["company_id"],
        "org_name": getattr(site, "org_name", "") or _identity_from_bearer(ident_pat)["org_name"]
        or getattr(site, "organization", "") or "",
        "site_id": site.site_id,
        "site_manifest_version": site.site_manifest_version,
        "phase": site.phase,
        "candidate_policies": site.candidate_policies,
        "boundary": site.boundary,
        "components": _site_components(site),
        # Newer stubs leave project / organization out: the scan stamps them once in SCAN_CONTEXT
        # (GR_PROJECT / GR_ORGANIZATION override; no organization known: none is sent, see below).
        "project": _request_project(site),
        "organization": _request_organization(site),
        # The application (scan-time values; the running instance's
        # UNIFAI_APP_NAME / UNIFAI_APP_VERSION / UNIFAI_APP_BRANCH win when set).
        "project_name": _runtime_context_for(url).get("source_code_name")
        or getattr(site, "project_name", "") or "",
        "project_version": _runtime_context_for(url).get("source_code_version")
        or getattr(site, "project_version", "") or "",
        "project_branch": _runtime_context_for(url).get("source_code_branch")
        or getattr(site, "project_branch", "") or "",
        # Cached once per process: where this application instance runs.
        "runtime_context": _runtime_context_for(url),
        "app_ip": getattr(site, "app_ip", "") or _runtime_context_for(url).get("ip", ""),
        "source_type": wire_src,
        "destination_type": wire_dst,
        "payload": {"mode": "inline", "content_type": content_type, "data": wire_data},
        "client_deadline_hint_ms": int(timeout * 1000),
        "resume_token": None,
        "redecision_token": None,
        "operation_identity": operation_identity,
        "process": _process_facts(),
        "interaction_id": getattr(site, "interaction_id", None),
    }
    if not body["organization"]:
        del body["organization"]            # LIN-36163: nothing known — send nothing rather than ""
    elif not _first_env("GR_ORGANIZATION") and _scan_context("organization_id"):
        body["organization_id"] = _scan_context("organization_id")   # the scanned org's id (not with an override)
    workflow = _request_workflow()
    if workflow:
        body["workflow"] = workflow         # LIN-36165: the Run view's workflow (older Guardrails ignore it)
    session_id = _request_session_id()
    if session_id:
        body["session_id"] = session_id     # CON-3356: the workflow run (never generated)
    step = _request_step()
    if step:
        body["step"] = step                 # CON-3356: the node within the workflow (older Guardrails ignore it)
    if observe:
        body["observe_only"] = True
    if getattr(site, "skipped_after_block", False):
        body["skipped_after_block"] = True
    agent_name = os.environ.get("LINEAJE_AGENT_NAME", "").strip()
    if agent_name:
        body["agent_name"] = agent_name
    trace_id = _current_trace_id()
    if trace_id:
        body["trace_id"] = trace_id
        span_id = _current_span_id()
        if span_id:
            body["span_id"] = span_id
    stack = _caller_frames()
    if stack:
        body["call_stack"] = stack
    body["thread_name"] = threading.current_thread().name

    hop = f"site_id={site.site_id}" if site.site_id else "site_id=<unknown>"
    _obs.update(body=body, url=url, pat=pat)
    if observe:
        # Log-only: nothing to enforce, so nothing on the app's thread but queueing the event (by ``check``).
        _ensure_heartbeat(url, body.get("tenant_id") or "", lineaje_pat or "", body)
        _LAST_POST.path = "/observability"
        _announce_enforce(url, hop, "allow", extra="(queued)")
        return Decision({"status": "allow", "result": {"data": payload}, "actions_applied": [],
                         "recommendations": []}, site_id=site.site_id)

    def _decision_from(result: dict[str, Any]) -> Decision:
        _obs["gr"] = _gr_verdict(result.get("status", "allow"), result.get("actions_applied"))
        server_result = result.get("result")
        wrapped = dict(result)
        if not isinstance(wire_data, dict) and isinstance(server_result, dict) and "text" in server_result:
            wrapped["result"] = {"data": server_result["text"]}
        else:
            wrapped["result"] = {"data": server_result}
        decision = Decision(wrapped, site_id=site.site_id)
        unchanged = False
        try:
            unchanged = _same_wire(decision.payload, wire_data)
            if redacted and not unchanged:
                unchanged = _only_redacted_changed(decision.payload, wire_data, wire_plain)
            if redacted and not unchanged:
                # G8: the caller's value back at every redacted path — a marker is never substituted into the call
                unredact_misses: list = []
                decision.payload = _unredact_answer(decision.payload, wire_data, wire_plain, misses=unredact_misses)
                if unredact_misses:
                    _reply_failed(site, f"{len(unredact_misses)} masked field(s) not applied "
                                        f"({'; '.join(unredact_misses[:3])})")
        except Exception as exc:  # noqa: BLE001
            _logger.warning("gr_stub_client.check[%s]: unredact failed (%s) — original payload kept", hop, exc)
            unchanged = True
        decision.server_data = wire_plain if (unchanged and redacted) else decision.payload
        try:
            if unchanged:
                decision.payload = payload       # F1: the GR changed nothing -> the caller's object, untouched
            elif decision.status != "block":
                # r4 N3/N4: only what the GR changed versus what was sent is written back
                misses: list = []
                # G8: a redacted answer was mapped back to the un-redacted wire form (``_unredact_answer``): it is
                # compared with that, so a redacted leaf is never "changed" and never substituted
                decision.payload = _apply_answer(payload, wire_plain if redacted else wire_data, decision.payload,
                                                 misses)
                if misses:
                    _reply_failed(site, f"{len(misses)} masked field(s) not applied ({'; '.join(misses[:3])})")
            else:
                decision.payload = payload
        except Exception as exc:
            _logger.warning("gr_stub_client.check[%s]: reapply failed (%s) — original payload kept", hop, exc)
            decision.payload = payload
        finished = _finalize_decision(decision, payload)
        _maybe_record_process_block(finished, site)
        return finished

    try:
        result = _post_enforce(url, body, pat, timeout)
        if result.get("status") == "escalate":
            _logger.warning("gr_stub_client.check[%s]: escalation flagged — passing through for human review", hop)
        decision = _decision_from(result)
        _announce_enforce(
            url, hop, decision.status,
            extra=f"actions={_actions_brief(decision.actions_applied or [])}",
        )
        return decision
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            detail = _read_http_error_detail(exc)
            if _should_register_unknown_site(detail, str(body.get("site_id") or "")):
                register_tenant = _tenant_id_from_bearer(pat, str(body.get("tenant_id") or ""))
                mappings = _ensure_site_registered(url, site, register_tenant, pat, timeout)
                if mappings is not None:
                    _apply_registered_mappings(body, site, mappings)
                    _announce_enforce(
                        url, hop, "unknown_site",
                        extra="registered site manifest — retrying with site_id",
                    )
                    try:
                        result = _post_enforce(url, body, pat, timeout)
                        decision = _decision_from(result)
                        _announce_enforce(
                            url, hop, decision.status,
                            extra=f"actions={_actions_brief(decision.actions_applied or [])}",
                        )
                        return decision
                    except Exception as retry_exc:
                        # A CONFIRMED block on this retry (not another unknown_site
                        # cycle) must go through the same fail_mode-respecting path
                        # as the very first attempt — see
                        # _genuine_block_detail_from_retry_exc's docstring for the
                        # bug this closes: falling through to the generic
                        # "unresolved unknown_site" _fail_response below silently
                        # turned a real block into an allow whenever site
                        # registration was flaky, regardless of fail_mode=BLOCK.
                        retry_detail = _genuine_block_detail_from_retry_exc(
                            retry_exc, str(body.get("site_id") or ""),
                        )
                        if retry_detail is not None:
                            return _decision_for_genuine_block(site, url, hop, retry_detail, payload, _obs)
                        _logger.warning(
                            "gr_stub_client.check[%s]: retry after register failed (%s)",
                            hop, retry_exc,
                        )
                _announce_enforce(
                    url, hop, "unknown_site",
                    extra="retrying without site_id so policies still evaluate",
                )
                retry_body = dict(body)
                retry_body["site_id"] = ""
                try:
                    result = _post_enforce(url, retry_body, pat, timeout)
                    decision = _decision_from(result)
                    _announce_enforce(
                        url, hop, decision.status,
                        extra=f"(no site_id) actions={_actions_brief(decision.actions_applied or [])}",
                    )
                    return decision
                except Exception as retry_exc:
                    # Same reasoning as the "retry after register" branch above —
                    # a genuine block on the no-site_id retry (the common case,
                    # since evaluating the full tenant policy set with no site
                    # scoping is exactly what turns up a real AI_APP_SEC_006/028
                    # etc. match) must not be folded into the generic
                    # unknown_site-unresolved fallback below.
                    retry_detail = _genuine_block_detail_from_retry_exc(retry_exc, "")
                    if retry_detail is not None:
                        return _decision_for_genuine_block(site, url, hop, retry_detail, payload, _obs)
                    _logger.warning("gr_stub_client.check[%s]: retry without site_id failed (%s)", hop, retry_exc)
                masked_unknown = _fail_response(
                    site, "unknown_site unresolved after register/retry", payload,
                )
                _announce_enforce(url, hop, masked_unknown["status"], extra=masked_unknown.get("warning") or "")
                return Decision(masked_unknown, site_id=site.site_id)
            return _decision_for_genuine_block(site, url, hop, detail, payload, _obs)
        _logger.warning(
            "gr_stub_client.check[%s]: GR service call failed (%s) POST %s/enforce — %s",
            hop, exc, url,
            "failing open (data unchanged; any fail_mode)",
        )
        return Decision(_fail_response(site, f"GR service error: {exc}", payload), site_id=site.site_id)
    except Exception as exc:
        _logger.warning(
            "gr_stub_client.check[%s]: GR service call failed (%s) POST %s/enforce — %s",
            hop, exc, url,
            "failing open (data unchanged; any fail_mode)",
        )
        return Decision(_fail_response(site, f"GR service unreachable: {exc}", payload), site_id=site.site_id)


def enforce(
    site: SiteDescriptor,
    payload: Any,
    content_type: str = "application/json",
    *,
    variable_name: str = "",
    source_file: str = "",
    before_line: "int | None" = None,
) -> Any:
    """Single call-site entry point for an inserted stub — call this, get the value back.

    ``check()`` never raises (infra failures fail open/closed internally via
    ``_fail_response``), so the only exception surface here is truly
    unexpected breakage in the call itself (e.g. a bad companion version).
    This wraps that surface, the blocked -> ``PermissionError`` raise, and
    the optional persist-to-source rewrite, so an inserted stub only needs a
    single call plus a narrow ``except GuardrailUnavailableError`` around it,
    instead of inlining its own try/except/logging block.

    GR outage (unreachable / misconfigured / erroring, any site fail mode,
    BLOCK included): FAIL OPEN — the payload is returned unchanged (the
    same object), nothing is raised, no field is added; the outage is
    logged and counted (``gr_outages()``). User decision 2026-10-14. A
    genuine policy block from a reachable GR still raises ``PermissionError``.
    A masked container comes back as the caller's own object, updated in
    place (``keep_identity``), so aliases of it stay aliases.

    Leftover log_emit / user_interface stubs sit on FastAPI handlers (error
    log lines, GET /chat/jobs polls). Raising there 500s the customer app
    even after the LLM hop already blocked. Those sites return a safe
    payload instead of raising; LLM / tool / MCP / file hops still raise.
    """
    _LAST_ENFORCE.decision = None
    try:
        decision = check(site, payload, content_type=content_type)
    except GuardrailUnavailableError as exc:
        _note_outage(site, exc)
        return payload
    except PermissionError:
        raise
    except Exception as exc:
        # an outage / unexpected failure fails OPEN in every mode, whatever the site's fail mode (2026-10-14)
        _note_outage(site, exc)
        return payload
    if decision.infra_failure:
        return payload
    _LAST_ENFORCE.decision = decision
    if decision.blocked:
        if _stub_must_not_crash_host(site):
            _logger.warning(
                "gr_stub_client.enforce[site_id=%s]: policy block — not raising "
                "(leftover log/UI stub must not crash the host): %s",
                site.site_id, decision.warning,
            )
            return _payload_after_host_safe_block(site, decision, payload)
        raise decision.as_error()
    if variable_name and source_file:
        persist_runtime_mask_to_source(
            decision.payload, source_file=source_file, variable_name=variable_name, before_line=before_line,
        )
    return _enforced_value(site, payload, decision)


_LAST_ENFORCE = threading.local()    # the last verdict enforce() acted on in this thread (None: an outage)


def _answer_shape(decision: "Decision | None") -> Any:
    """The GR's answer as it came back (before any write-back); ``_MISSING`` when there was none (an outage)."""
    if decision is None:
        return _MISSING
    return decision.__dict__.get("server_data", decision.payload)


def _enforced_value(site: "SiteDescriptor", payload: Any, decision: "Decision") -> Any:
    """What ``enforce`` hands back for an allow / mask verdict: the caller's own object (``check`` already wrote the
    GR's changed ``str`` leaves into it, ``_apply_answer``), or for a ``str`` payload the GR's changed text."""
    got = decision.payload
    if got is payload:
        return payload
    if "server_data" not in decision.__dict__:
        # a Decision not built by check()'s answer handling (a replaced check / older path): apply it here, against
        # the wire form the payload has
        misses: list = []
        got = _apply_answer(payload, _wire_payload(payload), got, misses)
        if misses:
            _reply_failed(site, f"{len(misses)} masked field(s) not applied ({'; '.join(misses[:3])})")
        if got is payload:
            return payload
    if type(payload) is str and type(got) is str:
        return got
    return payload


def _static_pydantic(obj: Any) -> bool:
    """A pydantic model instance, decided from its class dicts only (no attribute access on the object)."""
    try:
        return any("__pydantic_fields__" in vars(c) or "__fields__" in vars(c) for c in type(obj).__mro__
                   if c is not object)
    except Exception:  # noqa: BLE001
        return False


def _static_instance_dict(obj: Any) -> "dict | None":
    """``obj``'s own instance ``__dict__`` read without running user code: only when the first ``__dict__`` its class
    defines is the interpreter's slot (not a property / custom descriptor) and the dict is a plain ``dict``."""
    import types as _types

    try:
        for c in type(obj).__mro__:
            entry = vars(c).get("__dict__", _MISSING)
            if entry is _MISSING:
                continue
            if type(entry) is not _types.GetSetDescriptorType:
                return None
            d = object.__getattribute__(obj, "__dict__")
            return d if type(d) is dict else None
    except Exception:  # noqa: BLE001
        return None
    return None


_JSON_KEY_TYPES = (str, int, float, bool, type(None))


def _answer_changed(got: Any, sent: Any) -> bool:
    return not _same_wire(got, sent)


def _is_type(obj: Any, cls: type) -> bool:
    """``isinstance`` without a user ``__class__`` / ``__instancecheck__`` (review r4 N6)."""
    return issubclass(type(obj), cls)


def _write_back_file(original: Any, sent: dict, got: Any, misses: list) -> None:
    """An uploaded file (on disk, or a stream handle) the GR answered for: rewritten only when the GR changed its
    text, the whole file was sent (not truncated at ``_MAX_INLINE_FILE_BYTES``) and it is valid UTF-8 exactly as
    sent — never a partial or re-encoded file (review r4 N4). Anything else is counted as not masked."""
    sent_text = sent.get("text")
    new = got.get("text") if type(got) is dict else got if type(got) is str else None
    binary = ("content_base64" in sent or "content_omitted" in sent
              or sent.get("content_type") in _BINARY_DOCUMENT_TYPES
              or (type(got) is dict and _is_binary_document_result(got)))
    if type(sent_text) is not str or type(new) is not str or new == sent_text:
        return
    if binary:
        # never overwrite a PDF / DOCX (or an unread file) with extracted plain text
        _warn_binary_mask_not_applied(str(sent.get("name") or ""), got)
        misses.append(f"binary document {sent.get('name')!r}")
        return
    size = sent.get("size_bytes")
    name = str(sent.get("name") or sent.get("path") or "")
    if type(size) is not int or size >= _MAX_INLINE_FILE_BYTES or "\ufffd" in sent_text:
        misses.append(f"file {name!r} not rewritten (truncated or not UTF-8 when sent)")
        return
    path = sent.get("path")
    if type(path) is str and path:
        try:
            with open(path, "rb") as fh:
                raw = fh.read(_MAX_INLINE_FILE_BYTES + 1)
            if raw.decode("utf-8") != sent_text:
                misses.append(f"file {name!r} not rewritten (changed since it was sent)")
                return
            _write_text_file(path, new)
        except (OSError, UnicodeDecodeError) as exc:
            misses.append(f"file {name!r} not rewritten ({type(exc).__name__})")
        return
    if not _write_stream_upload_text(original, new):
        misses.append(f"upload stream {name!r} not rewritten")


def _apply_answer(original: Any, sent: Any, got: Any, misses: list, depth: int = 0) -> Any:
    """The GR's answer ``got`` for the wire form ``sent`` of ``original``, applied to ``original`` IN PLACE (review
    round 3 F1, round 4 N2–N5): a ``str`` leaf is substituted only where the answer differs from what was SENT at
    the same path; non-``str`` values are never replaced, containers never cleared or reshaped, no user ``__eq__`` /
    ``__setitem__`` runs; keys map back from their JSON (``str()``) form; paths the GR invented are ignored. Returns
    the value to hold at this path (a changed ``str``, else ``original`` itself).

    Known limit (counted and logged via ``reply_mask_failures``, never raised): a changed leaf that cannot be put
    back without rebinding the caller's value — inside a tuple / frozenset / mapping proxy, a ``str`` subclass,
    ``bytes``, an object sent as its repr, a frozen model, a colliding key set (``{1: .., "1": ..}``), a truncated
    or non-UTF-8 file — stays unmasked."""
    if not _answer_changed(got, sent):
        return original
    if depth > 64:
        misses.append("nesting too deep")
        return original
    if _is_type(original, urllib.request.Request) or (type(original).__name__ == "Request"
                                                      and not _is_type(original, (dict, list, tuple, str))):
        return _apply_request(original, sent, got, misses)
    if type(sent) is dict and "files" in sent and type(sent["files"]) is list and _is_type(original, (list, tuple)):
        # uploaded files (``_wire_payload``): each item against its own wire entry; the joined text is not mapped
        files = got.get("files") if type(got) is dict else None
        if type(files) is list:
            _apply_answer(original, sent["files"], files, misses, depth + 1)
        if type(got) is not dict or _answer_changed(got.get("text"), sent.get("text")) and not (
                type(files) is list and _answer_changed(files, sent["files"])):
            misses.append("uploaded files' joined text")
        return original
    if type(sent) is str:
        if type(got) is not str:
            misses.append("text answered as non-text")
            return original
        if type(original) is str:
            return got
        if _document_like(original):
            if type(getattr(original, "page_content", None)) is str and not _looks_like_object_repr(got):
                try:
                    original.page_content = got
                except Exception:  # noqa: BLE001
                    misses.append(f"read-only {type(original).__name__}.page_content")
            return original
        misses.append(f"text of a {type(original).__name__}")
        return original
    if type(sent) is dict and type(got) is dict:
        if "page_content" in sent and not _is_type(original, dict) and _document_like(original):
            _apply_answer_fields(original, {k: sent[k] for k in ("page_content",) if k in sent},
                                 {k: got[k] for k in ("page_content",) if k in got}, misses, depth)
            meta = getattr(original, "metadata", None)
            if _is_type(meta, dict) and "metadata" in sent and "metadata" in got:
                _apply_answer(meta, sent["metadata"], got["metadata"], misses, depth + 1)
            return original
        if "path" in sent and "name" in sent and ("text" in sent or "content_base64" in sent
                                                  or "content_omitted" in sent) \
                and (_file_like_path(original) or _looks_like_stream_upload(original)):
            _write_back_file(original, sent, got, misses)
            if not _is_type(original, dict):
                return original
            sent = {k: v for k, v in sent.items() if k in original}
        if _is_type(original, dict):
            items = list(dict.items(original))
            if any(type(k) not in _JSON_KEY_TYPES for k, _v in items):
                misses.append("a mapping with non-JSON keys")
                return original
            names = [k if type(k) is str else str(k) for k, _v in items]
            dup = {n for n in names if names.count(n) > 1}
            for (k, v), name in zip(items, names):
                if name not in sent or name not in got:
                    continue
                if name in dup:
                    if _answer_changed(got[name], sent[name]):
                        misses.append(f"colliding key {name!r}")
                    continue
                new = _apply_answer(v, sent[name], got[name], misses, depth + 1)
                if new is not v:
                    dict.__setitem__(original, k, new)
            return original
        if _static_pydantic(original):
            _apply_answer_fields(original, sent, got, misses, depth)
            return original
        misses.append(f"fields of a {type(original).__name__}")
        return original
    if type(sent) is list and type(got) is list:
        if len(got) != len(sent):
            misses.append("a list answered with another length")
            return original
        if _is_type(original, list):
            values = list(list.__iter__(original))
        elif _is_type(original, tuple):
            values = list(tuple.__iter__(original))
        else:
            misses.append(f"items of a {type(original).__name__}")
            return original
        if len(values) < len(sent):
            misses.append("a list that changed length")
            return original
        for i, v in enumerate(values[:len(sent)]):
            new = _apply_answer(v, sent[i], got[i], misses, depth + 1)
            if new is v:
                continue
            if _is_type(original, list):
                list.__setitem__(original, i, new)
            else:
                misses.append(f"text inside a {type(original).__name__}")
        return original
    misses.append(f"a {type(sent).__name__} answered as {type(got).__name__}")
    return original


def _apply_answer_fields(original: Any, sent: dict, got: dict, misses: list, depth: int) -> None:
    """A pydantic model's (or a Document's) fields: each sent field the answer changed, through its instance value."""
    fields = _static_instance_dict(original)
    for name in sent:
        if type(name) is not str or name not in got or not _answer_changed(got[name], sent[name]):
            continue
        if fields is None or name not in fields:
            misses.append(f"{type(original).__name__}.{name} (not an instance field)")
            continue
        v = dict.get(fields, name)
        new = _apply_answer(v, sent[name], got[name], misses, depth + 1)
        if new is not v:
            try:
                setattr(original, name, new)
            except Exception:  # noqa: BLE001 — a frozen model
                misses.append(f"read-only {type(original).__name__}.{name}")


def _apply_request(original: Any, sent: Any, got: Any, misses: list) -> Any:
    """A ``urllib`` Request body the GR changed: re-encoded only when the body was valid UTF-8 as sent."""
    data = getattr(original, "data", None)
    try:
        if _is_type(data, (bytes, bytearray)):
            bytes(data).decode("utf-8")
        new = got if type(got) is str else json.dumps(got)
        original.data = new.encode("utf-8")
    except UnicodeDecodeError:
        misses.append("request body not UTF-8 when sent")
    except Exception as exc:  # noqa: BLE001
        misses.append(f"request body not rewritten ({type(exc).__name__})")
    return original


# ── Model replies (harness direct model calls) ─────────────────────────────────────────────────────────────────────
# A stub after a direct SDK call (``response = client.chat.completions.create(...)``) reassigns
# ``response = enforce_reply(site, response)``. enforce() alone cannot sanitize an SDK reply object: the masked JSON
# that comes back is only re-applied to str / dict / list payloads, so an OpenAI ``ChatCompletion`` would stay
# unmasked and a Bedrock ``invoke_model`` dict would lose its ``StreamingBody``. enforce_reply() finds the reply's
# text fields (OpenAI / litellm choices + tool-call arguments, Anthropic content blocks + tool_use input, LangChain
# messages, Bedrock converse / invoke_model bodies of every vendor — Anthropic, Titan, Llama, Mistral, Cohere
# ``generations``, AI21 ``completions`` —, Gemini parts, OpenAI-compatible / Ollama JSON over requests / httpx),
# enforces them as one list and writes the masked strings back in place; when the list comes back in another shape
# the joined text is enforced instead, and a reply that still cannot be masked is logged and counted
# (``reply_mask_failures``). A policy block raises like enforce().
#
# Streams are BUFFERED (product decision, 2026-10-13): the whole stream is collected, enforced as one text and then
# replayed (masked text in the first text chunk). Full enforcement has a latency cost: the caller's first chunk
# arrives only after the model finished generating (time-to-first-token = full generation time). An async stream is
# enforced in a worker thread (``asyncio.to_thread``) so the event loop is not blocked. A GR outage
# (GuardrailUnavailableError) at replay time fails open exactly like a non-stream stub: the chunks are replayed
# unchanged and a warning is logged. SDK helpers that would read the raw events (``text_stream``,
# ``get_final_text``, ``get_final_message`` …) are served from the masked buffer or enforced again; private
# attributes of the wrapped stream are not exposed.
#
# A direct request whose payload is a ``**kwargs`` mapping (``litellm.acompletion(**completion_kwargs)``) goes
# through enforce_request(): only the message fields are sent (never ``api_key`` / ``aws_*`` credentials) and only
# those fields are written back.

STUB_API = 6      # 2: enforce_reply + enforce_request; 3: enforce_request(evidence=...); 4: receiver_model /
#                   header_model, GR outages fail open everywhere; the stub applies no mask of its own (r4 N1);
#                   5: aenforce / aenforce_request / aenforce_reply for stubs inside async def (LIN-36167);
#                   6: workflow_context(session_id=, step=) for the application (CON-3356)

_REPLY_TEXT_KEYS = ("content", "text", "outputText", "completion", "generation", "response", "arguments")
_REPLY_CONTAINER_KEYS = ("choices", "message", "delta", "content", "output", "outputs", "results", "candidates",
                         "parts", "contentBlockDelta", "content_block", "data", "generations", "completions",
                         "tool_calls", "function")
_REPLY_ANY_KEYS = ("input", "args")         # tool_use input / LangChain tool_call args: every string leaf
_REPLY_MAX_DEPTH = 10
_REPLY_SEP = "\n␞\n"
_reply_failures = {"count": 0}


def reply_mask_failures() -> int:
    """How many model replies (or request payloads) could not be masked (shape mismatch, frozen object)."""
    return _reply_failures["count"]


def _reply_failed(site: "SiteDescriptor", why: str) -> None:
    _reply_failures["count"] += 1
    _logger.warning("gr_stub_client.enforce_reply[site_id=%s]: reply not masked — %s", site.site_id, why)


class _ReplySlot:
    """One text field of a reply: ``obj[key]`` (``item``) or ``obj.key``. ``group`` names the text it belongs to: the
    message content of a choice, or one tool call's arguments (``("choice", 0, "tool", 1)``) — a stream's chunks are
    joined, enforced and written back per group, never across groups."""

    __slots__ = ("obj", "key", "item", "group")

    def __init__(self, obj: Any, key: Any, item: bool, group: tuple = ()):
        self.obj, self.key, self.item, self.group = obj, key, item, group

    def get(self) -> Any:
        return self.obj[self.key] if self.item else getattr(self.obj, self.key, None)

    def set(self, value: str) -> bool:
        try:
            if self.item:
                self.obj[self.key] = value
            else:
                setattr(self.obj, self.key, value)
            return True
        except Exception:  # noqa: BLE001 — a frozen SDK object: reported by the caller
            return False


def _reply_plain(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, float, bool, bytes, bytearray))


def _leaf_slots(node: Any, out: "list[_ReplySlot]", depth: int = 0, group: tuple = ()) -> None:
    """Every string leaf of a dict / list (tool-call input), each its own group."""
    if depth > _REPLY_MAX_DEPTH:
        return
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, str):
                out.append(_ReplySlot(node, k, True, (*group, k)))
            else:
                _leaf_slots(v, out, depth + 1, (*group, k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            if isinstance(v, str):
                out.append(_ReplySlot(node, i, True, (*group, i)))
            else:
                _leaf_slots(v, out, depth + 1, (*group, i))


def _item_index(item: Any, default: int) -> Any:
    value = item.get("index") if isinstance(item, dict) else getattr(item, "index", None)
    return value if isinstance(value, (int, str)) else default


def _reply_slots(node: Any, out: "list[_ReplySlot]", depth: int = 0, seen: "set[int] | None" = None,
                 group: tuple = (), container: str = "") -> None:
    """Collect the text fields of ``node`` (dicts, lists and SDK objects) into ``out``; a choice and a tool call open
    their own group (by their ``index``, else their position)."""
    if depth > _REPLY_MAX_DEPTH or _reply_plain(node):
        return
    seen = set() if seen is None else seen
    if id(node) in seen:
        return
    seen.add(id(node))
    if isinstance(node, (list, tuple)):
        for i, item in enumerate(node):
            sub = group
            if container == "choices":
                sub = (*group, "choice", _item_index(item, i))
            elif container == "tool_calls":
                sub = (*group, "tool", _item_index(item, i))
            if isinstance(item, str) and isinstance(node, list):
                out.append(_ReplySlot(node, i, True, sub))
            else:
                _reply_slots(item, out, depth + 1, seen, sub)
        return
    is_dict = isinstance(node, dict)
    has_text = False
    for key in dict.fromkeys(_REPLY_TEXT_KEYS + _REPLY_CONTAINER_KEYS + _REPLY_ANY_KEYS):
        if not is_dict:
            declared = getattr(type(node), key, None)
            if callable(declared) or (isinstance(declared, property) and declared.fset is None):
                continue       # a method, or a derived read-only property (Gemini ``.text``)
        try:
            value = node.get(key) if is_dict else getattr(node, key, None)
        except Exception:  # noqa: BLE001 — a property that raises is not a text field
            continue
        if isinstance(value, str):
            if key in _REPLY_TEXT_KEYS and not has_text:
                out.append(_ReplySlot(node, key, is_dict, (*group, key) if key == "arguments" else group))
                has_text = True
        elif value is not None and key in _REPLY_ANY_KEYS and isinstance(value, (dict, list)):
            _leaf_slots(value, out, depth + 1, (*group, key))
        elif value is not None and key in _REPLY_CONTAINER_KEYS:
            _reply_slots(value, out, depth + 1, seen, group, key)


def _json_bytes_body(body: Any) -> "tuple[Any, bytes] | None":
    """``(parsed, raw)`` of a readable JSON body (Bedrock ``StreamingBody``), else ``(None, raw)``. The body is
    consumed."""
    read = getattr(body, "read", None)
    if not callable(read):
        return None
    raw = read()
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    try:
        return json.loads(raw.decode("utf-8")), raw
    except Exception:  # noqa: BLE001 — not JSON: enforced as text
        return None, raw


class _ReplayBody:
    """A consumed ``StreamingBody`` replayed from bytes: ``read()``, iteration (1 KiB chunks), ``iter_lines()``,
    ``iter_chunks()``, ``close()`` and ``with``."""

    def __init__(self, data: bytes):
        import io as _io
        self._data = data
        self._buf = _io.BytesIO(data)

    def read(self, amt: "int | None" = None) -> bytes:
        return self._buf.read() if amt is None else self._buf.read(amt)

    def readable(self) -> bool:
        return True

    def iter_lines(self, chunk_size: int = 1024, keepends: bool = False) -> Any:
        return iter(self._data.splitlines(keepends))

    def iter_chunks(self, chunk_size: int = 1024) -> Any:
        data = self._data
        return iter(data[i:i + chunk_size] for i in range(0, len(data), chunk_size))

    def __iter__(self) -> Any:
        return self.iter_chunks()

    def __enter__(self) -> "_ReplayBody":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        pass


def _write_back(site: "SiteDescriptor", slots: "list[_ReplySlot]", texts: list, masked: list) -> int:
    changed = 0
    for slot, before, after in zip(slots, texts, masked):
        if isinstance(after, str) and after != before:
            if slot.set(after):
                changed += 1
            else:
                _reply_failed(site, f"a masked field could not be written back (read-only {type(slot.obj).__name__})")
    return changed


def _enforce_slots(site: "SiteDescriptor", slots: "list[_ReplySlot]", content_type: str) -> int:
    """Enforce the slots' texts as one list; write the masked ones back. Returns how many changed. A list that comes
    back in another shape: the joined text is enforced and split back (all of it into the first slot when the
    separators did not survive); anything else is logged and counted."""
    texts = [s.get() for s in slots]
    masked = enforce(site, list(texts), content_type=content_type)
    answer = _answer_shape(getattr(_LAST_ENFORCE, "decision", None))
    if answer is _MISSING or (type(answer) is list and len(answer) == len(texts)):
        return _write_back(site, slots, texts, masked)
    # another shape came back: each field on its own (never joined: a tool call's JSON arguments and the message
    # text must not be merged); a field that still does not come back as text is counted
    parts: list = []
    for text in texts:
        one = enforce(site, text, content_type=content_type) if isinstance(text, str) else text
        if isinstance(text, str) and not isinstance(one, str):
            _reply_failed(site, f"masked field came back as {type(one).__name__}")
            one = text
        parts.append(one)
    return _write_back(site, slots, texts, parts)


def _enforce_groups(site: "SiteDescriptor", slots: "list[_ReplySlot]", content_type: str) -> int:
    """A stream's (or SSE body's) slots: the chunks of each group joined, all groups enforced as one list, each
    group's masked text written into its first slot and its other slots emptied (only when it changed). A list back
    in another shape: each group on its own; a group that still does not come back as text is counted and left
    unchanged. Groups are never merged. Returns how many groups changed."""
    order: list = []
    members: dict = {}
    for s in slots:
        if s.group not in members:
            order.append(s.group)
            members[s.group] = []
        members[s.group].append(s)
    joined = ["".join(t for t in (m.get() for m in members[g]) if isinstance(t, str)) for g in order]
    if not order:
        return 0
    masked = enforce(site, list(joined), content_type=content_type)
    answer = _answer_shape(getattr(_LAST_ENFORCE, "decision", None))
    if not (answer is _MISSING or (type(answer) is list and len(answer) == len(joined))):
        masked = []
        for text in joined:
            one = enforce(site, text, content_type=content_type)
            if not isinstance(one, str):
                _reply_failed(site, f"masked stream text came back as {type(one).__name__}")
                one = text
            masked.append(one)
    changed = 0
    for g, before, after in zip(order, joined, masked):
        if not isinstance(after, str) or after == before:
            continue
        changed += 1
        for i, slot in enumerate(members[g]):
            if not slot.set(after if i == 0 else ""):
                _reply_failed(site, "a masked stream chunk could not be written back")
    return changed


def _is_reply_stream(reply: Any) -> bool:
    if _reply_plain(reply) or isinstance(reply, (dict, list, tuple)):
        return False
    if hasattr(reply, "__aiter__"):
        return True
    if not hasattr(reply, "__iter__"):
        return False
    probe: "list[_ReplySlot]" = []
    _reply_slots(reply, probe)
    return not probe and (hasattr(reply, "__next__") or "stream" in type(reply).__name__.lower()
                          or type(reply).__name__ == "generator")


class _MaskedText:
    """``stream.text_stream`` over the masked buffer (sync and async iteration)."""

    def __init__(self, stream: "_ReplyStream"):
        self._stream = stream

    def __iter__(self) -> Any:
        return iter(self._stream._texts(self._stream._buffer()))

    def __aiter__(self) -> Any:
        async def _gen() -> Any:
            for t in self._stream._texts(await self._stream._abuffer()):
                yield t
        return _gen()


class _ReplyStream:
    """Collects a streamed reply, enforces it once, then replays the chunks: each group (a choice's content, each
    tool call's arguments) joined and masked on its own, the masked text in the group's first chunk and its other
    chunks emptied, when the text changed. Buffering: the first chunk is returned only after the whole generation
    (time-to-first-token = full generation time). ``__iter__`` returns the stream itself (one iterator shared with
    ``__next__``). Attribute access: ``text_stream`` / ``get_final_text()`` come from the masked buffer,
    ``get_final_*()`` results are enforced, a few non-data attributes (``close``, ``response`` …) pass through,
    and private attributes and any ``*_stream`` / ``*snapshot*`` attribute of the wrapped SDK stream are REFUSED
    (``AttributeError``): they would expose the unmasked events. Everything else is delegated.

    Enforcement happens at replay, so a policy BLOCK on a streamed reply surfaces LAZILY — as a ``PermissionError``
    raised by the caller's first iteration (``for chunk in stream`` / ``next(stream)`` / ``async for``), not by the
    stub after the call. A GR outage (or any other failure) at replay replays the stream unchanged (fail open)."""

    _PASS = frozenset({"close", "aclose", "response", "headers", "status_code", "http_response", "request_id",
                       "model", "id"})

    def __init__(self, source: Any, site: "SiteDescriptor", content_type: str):
        self._source, self._site, self._content_type = source, site, content_type
        self._chunks: "list | None" = None
        self._it: Any = None

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)            # private state of the raw stream is never exposed
        if name.startswith("get_final_"):
            fn = getattr(self._source, name)
            site, ct = self._site, self._content_type

            def _final(*a: Any, **kw: Any) -> Any:
                import inspect as _inspect
                res = fn(*a, **kw)
                if _inspect.isawaitable(res):
                    async def _await() -> Any:
                        import asyncio as _asyncio
                        value = await res
                        if isinstance(value, str):
                            return await _asyncio.to_thread(self._safe_text, value)
                        return await _asyncio.to_thread(enforce_reply, site, value, ct)
                    return _await()
                return self._safe_text(res) if isinstance(res, str) else enforce_reply(site, res, ct)
            return _final
        if name in self._PASS:
            return getattr(self._source, name)
        if name.endswith("_stream") or "snapshot" in name:
            raise AttributeError(f"{name} is not available on a guardrail-enforced stream (it would expose the "
                                 f"unmasked events): iterate the stream instead")
        return getattr(self._source, name)

    def _safe_text(self, text: str) -> str:
        try:
            out = enforce(self._site, text, content_type=self._content_type)
        except GuardrailUnavailableError as exc:
            _logger.warning("gr_stub_client.enforce_reply[site_id=%s]: guardrail unavailable (%s) — passing the "
                            "final text through", self._site.site_id, exc)
            return text
        return out if isinstance(out, str) else text

    @property
    def text_stream(self) -> _MaskedText:
        return _MaskedText(self)

    def get_final_text(self) -> Any:
        if hasattr(self._source, "__aiter__") and not hasattr(self._source, "__iter__"):
            async def _text() -> str:
                return "".join(self._texts(await self._abuffer()))
            return _text()
        return "".join(self._texts(self._buffer()))

    def __enter__(self) -> "_ReplyStream":
        enter = getattr(self._source, "__enter__", None)
        if callable(enter):
            inner = enter()
            if inner is not None and inner is not self._source:
                self._source = inner          # a stream manager: wrap the stream it opens
        return self

    def __exit__(self, *exc: Any) -> Any:
        leave = getattr(self._source, "__exit__", None)
        return leave(*exc) if callable(leave) else None

    async def __aenter__(self) -> "_ReplyStream":
        enter = getattr(self._source, "__aenter__", None)
        if callable(enter):
            inner = await enter()
            if inner is not None and inner is not self._source:
                self._source = inner
        return self

    async def __aexit__(self, *exc: Any) -> Any:
        leave = getattr(self._source, "__aexit__", None)
        return (await leave(*exc)) if callable(leave) else None

    @staticmethod
    def _slots(chunks: list) -> "list[_ReplySlot]":
        slots: "list[_ReplySlot]" = []
        for chunk in chunks:
            if isinstance(chunk, dict) and isinstance(chunk.get("chunk"), dict) and "bytes" in chunk["chunk"]:
                _bytes_event_slots(chunk["chunk"], slots)
            else:
                _reply_slots(chunk, slots)
        return slots

    def _texts(self, chunks: list) -> "list[str]":
        return [t for t in (s.get() for s in self._slots(chunks)) if isinstance(t, str) and t]

    def _replay(self, chunks: list) -> list:
        slots = self._slots(chunks)
        if not slots:
            return chunks
        try:
            _enforce_groups(self._site, slots, self._content_type)
        except GuardrailUnavailableError as exc:
            _note_outage(self._site, exc)            # fail open: the stream is replayed unchanged
        except PermissionError:
            raise                                    # a genuine policy block surfaces here, at iteration time
        except Exception as exc:  # noqa: BLE001 — never crash the host: replay unchanged, counted
            _note_outage(self._site, exc)
        return chunks

    def _buffer(self) -> list:
        if self._chunks is None:
            self._chunks = self._replay(list(self._source))
        return self._chunks

    async def _abuffer(self) -> list:
        if self._chunks is None:
            import asyncio as _asyncio
            if hasattr(self._source, "__aiter__"):
                chunks = [c async for c in self._source]
            else:
                chunks = list(self._source)
            self._chunks = await _asyncio.to_thread(self._replay, chunks)
        return self._chunks

    def __iter__(self) -> "_ReplyStream":
        # one iterator shared with __next__ (``first = next(s); rest = list(s)``), like the SDK streams
        if self._it is None:
            self._it = iter(self._buffer())
        return self

    def __next__(self) -> Any:
        if self._it is None:
            self._it = iter(self._buffer())
        return next(self._it)

    def __aiter__(self) -> Any:
        async def _gen() -> Any:
            for c in await self._abuffer():
                yield c
        return _gen()


class _EncodedSlot(_ReplySlot):
    """A text field inside a JSON-encoded bytes event (Bedrock ``invoke_model_with_response_stream``): setting it
    re-encodes the event's ``bytes``."""

    __slots__ = ("inner", "event", "parsed")

    def __init__(self, inner: _ReplySlot, event: dict, parsed: Any):
        super().__init__(inner.obj, inner.key, inner.item, inner.group)
        self.inner, self.event, self.parsed = inner, event, parsed

    def set(self, value: str) -> bool:
        if not self.inner.set(value):
            return False
        self.event["bytes"] = json.dumps(self.parsed).encode("utf-8")
        return True


def _bytes_event_slots(event: dict, out: "list[_ReplySlot]") -> None:
    try:
        parsed = json.loads(bytes(event["bytes"]).decode("utf-8"))
    except Exception:  # noqa: BLE001 — not JSON: no text to enforce
        return
    inner: "list[_ReplySlot]" = []
    _reply_slots(parsed, inner)
    out.extend(_EncodedSlot(slot, event, parsed) for slot in inner)


def _enforce_body(site: "SiteDescriptor", body: Any, content_type: str) -> _ReplayBody:
    parsed, raw = _json_bytes_body(body) or (None, b"")
    slots: "list[_ReplySlot]" = []
    if parsed is not None:
        _reply_slots(parsed, slots)
    if slots:
        if _enforce_slots(site, slots, content_type):
            raw = json.dumps(parsed).encode("utf-8")
        return _ReplayBody(raw)
    if parsed is None:
        text = raw.decode("utf-8", errors="replace")
        masked = enforce(site, text, content_type=content_type)
        if isinstance(masked, str):
            if masked != text:
                raw = masked.encode("utf-8")
        else:
            _reply_failed(site, f"masked body text came back as {type(masked).__name__}")
        return _ReplayBody(raw)
    before = json.dumps(parsed)
    masked = enforce(site, parsed, content_type=content_type)       # masked text is written into ``parsed``
    if isinstance(masked, (dict, list)) and json.dumps(masked) != before:
        raw = json.dumps(masked).encode("utf-8")
    return _ReplayBody(raw)


_SSE_START = (b"data:", b"event:", b":", b"id:")


def _enforce_sse(site: "SiteDescriptor", reply: Any, content_type: str) -> bool:
    """A requests / httpx response whose body is a server-sent-event stream (``stream=True`` + ``iter_lines()``):
    the whole body is read (buffered, like ``_ReplyStream``: time-to-first-token = full generation), each
    ``data: {json}`` event's text fields enforced per group, the events rewritten and the body replaced, so
    ``iter_lines()`` / ``iter_content()`` / ``.text`` / ``.content`` replay the masked events. False when the body
    is not SSE. An event that is not JSON leaves the body unchanged and is counted."""
    raw = getattr(reply, "_content", None)
    if raw is False or raw is None:
        try:
            raw = reply.content            # requests stream=True: not read yet — read (and cache) it all
        except Exception:  # noqa: BLE001
            return False
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if not isinstance(raw, (bytes, bytearray)) or not bytes(raw).lstrip().startswith(_SSE_START):
        return False
    lines = bytes(raw).decode("utf-8", errors="replace").split("\n")
    events: list = []
    bad = 0
    for i, line in enumerate(lines):
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if not data or data == "[DONE]":
            continue
        try:
            events.append((i, json.loads(data)))
        except Exception:  # noqa: BLE001
            bad += 1
    if bad:
        _reply_failed(site, f"{bad} server-sent event(s) are not JSON: the streamed reply is not masked")
        enforce(site, bytes(raw).decode("utf-8", errors="replace"), content_type=content_type)   # audited
        return True
    slots: "list[_ReplySlot]" = []
    for _i, parsed in events:
        _reply_slots(parsed, slots)
    if slots and _enforce_groups(site, slots, content_type):
        for i, parsed in events:
            lines[i] = "data: " + json.dumps(parsed)
        try:
            reply._content = "\n".join(lines).encode("utf-8")
        except Exception:  # noqa: BLE001
            _reply_failed(site, "masked server-sent events could not be written back")
    return True


def enforce_reply(site: "SiteDescriptor", reply: Any, content_type: str = "application/json") -> Any:
    """``enforce()`` for a model's reply: mask its text fields in place and return it (same object, same type; a
    stream comes back wrapped by ``_ReplyStream``). A reply with no recognisable text field goes through
    ``enforce()`` unchanged (str / dict / list payloads are masked there; anything else is audited only). A policy
    block raises (for a stream: lazily, when the caller first iterates it); any other failure returns the reply
    unchanged (fail open, counted)."""
    try:
        return _enforce_reply(site, reply, content_type)
    except GuardrailUnavailableError as exc:
        _note_outage(site, exc)
        return reply
    except PermissionError:
        raise
    except Exception as exc:  # noqa: BLE001 — never crash the host
        _note_outage(site, exc)
        return reply


def _enforce_reply(site: "SiteDescriptor", reply: Any, content_type: str) -> Any:
    if isinstance(reply, str):
        return enforce(site, reply, content_type=content_type)
    if isinstance(reply, dict):
        for key in ("stream", "body"):
            inner = reply.get(key)
            if inner is not None and not _reply_plain(inner) and not callable(getattr(inner, "read", None)) \
                    and hasattr(inner, "__iter__") and not isinstance(inner, (dict, list, tuple)):
                reply[key] = _ReplyStream(inner, site, content_type)
                return reply
        body = reply.get("body")
        if body is not None and callable(getattr(body, "read", None)):
            reply["body"] = _enforce_body(site, body, content_type)
            return reply
    if _is_reply_stream(reply):
        return _ReplyStream(reply, site, content_type)
    if hasattr(reply, "_content") and hasattr(reply, "status_code") and _enforce_sse(site, reply, content_type):
        return reply
    json_method = getattr(reply, "json", None)
    if callable(json_method) and hasattr(reply, "_content") and hasattr(reply, "status_code"):
        # requests / httpx Response: the parsed JSON's text fields, written back into the cached body
        try:
            data = json_method()
        except Exception:  # noqa: BLE001 — not JSON
            data = None
        slots: "list[_ReplySlot]" = []
        if data is not None:
            _reply_slots(data, slots)
        if slots:
            if _enforce_slots(site, slots, content_type):
                try:
                    reply._content = json.dumps(data).encode("utf-8")
                except Exception:  # noqa: BLE001
                    _reply_failed(site, "masked HTTP body not written back")
            return reply
        enforce(site, data if data is not None else getattr(reply, "text", ""), content_type=content_type)
        return reply
    slots = []
    _reply_slots(reply, slots)
    if not slots:
        return enforce(site, reply, content_type=content_type)
    _enforce_slots(site, slots, content_type)
    return reply


# Request fields a direct model call's ``**kwargs`` mapping may carry the user's text in. Never credentials
# (``api_key``, ``aws_access_key_id``, ``aws_secret_access_key``, ``aws_session_token`` …): only these are sent and
# written back; the model id rides along as evidence for the approved-model policies (read-only).
_REQUEST_TEXT_FIELDS = ("messages", "prompt", "input", "system", "contents", "message", "body")
_REQUEST_MODEL_FIELDS = ("model", "modelId", "model_id")
_REQUEST_EVIDENCE_KEYS = frozenset({"model", "model_source"})     # what a stub's read-only evidence may add


def enforce_request(site: "SiteDescriptor", request: Any, content_type: str = "application/json",
                    evidence: "dict | None" = None) -> Any:
    """``enforce()`` for a direct model call's request mapping (``**kwargs``): send only its message fields (plus the
    model id as evidence), write back only those fields IN PLACE and return the caller's own mapping. ``evidence``
    (read-only, from the stub) may add only ``model`` / ``model_source``. A policy block raises like ``enforce()``; a
    GR outage passes the request through unchanged; a non-mapping is returned unchanged and nothing is sent."""
    from collections.abc import Mapping

    if not isinstance(request, Mapping):
        _logger.warning("gr_stub_client.enforce_request[site_id=%s]: request is a %s, not a mapping — not sent",
                        site.site_id, type(request).__name__)
        return request
    sent: dict = {}
    for key in _REQUEST_TEXT_FIELDS:
        if key not in request:
            continue
        value = request[key]
        if key == "body":
            if isinstance(value, (bytes, bytearray)):
                value = bytes(value).decode("utf-8", errors="replace")
            elif not isinstance(value, str):
                continue
        sent[key] = value
    extra = {k: v for k, v in (evidence or {}).items()
             if k in _REQUEST_EVIDENCE_KEYS and isinstance(v, str) and v and k not in sent}
    own = {k: request[k] for k in _REQUEST_MODEL_FIELDS if isinstance(request.get(k), str)}
    if own:
        extra["model_source"] = "call_kwarg"        # the request's own model id wins over any other evidence
    elif not any(k in extra for k in _REQUEST_MODEL_FIELDS):
        extra.pop("model_source", None)              # no model found: no source either
    evidence = {**extra, **own}
    if not sent and not evidence:
        return request
    try:
        masked = enforce(site, {**sent, **evidence}, content_type=content_type)
    except GuardrailUnavailableError as exc:
        _note_outage(site, exc)
        return request
    # written back IN PLACE (review round 3 A1): the stub rebinds its variable to the returned object, which is the
    # caller's own mapping — aliases of it (and of its message list) see the same request
    # F1: enforce() wrote only the changed str leaves into the caller's own containers (in place); a top-level
    # text field that changed (a str prompt, a JSON body) is the only thing set here
    if isinstance(masked, dict):
        for key in sent:
            value = masked.get(key, sent[key]) if type(masked) is dict else sent[key]
            if value is sent[key] or type(value) is not str:
                continue
            original = request[key]
            if isinstance(original, (bytes, bytearray)):
                value = bytearray(value.encode("utf-8")) if isinstance(original, bytearray) else value.encode("utf-8")
            elif type(original) is not str:
                continue
            try:
                request[key] = value
            except Exception:  # noqa: BLE001 — a read-only mapping: a copy carries the masked fields
                request = {**request, key: value}
    elif sent:
        _reply_failed(site, f"masked request came back as {type(masked).__name__}")
    return request

# ── Model identity read by a stub at call time (review round 3 A2 / A3, user decision 2026-10-13) ──────────────
# Static reads only: an instance's own __dict__ (pydantic / dataclass / plain fields), never a property, a
# descriptor or __getattr__; everything inside try/except — a model id is evidence, it must never crash or change
# the app.

_RECEIVER_MODEL_FIELDS = ("model_name", "model", "deployment_name", "model_id", "_model_name")
_MISSING = object()


def _instance_field(obj: Any, name: str) -> Any:
    """``obj``'s own instance value for ``name``, read statically (review r3 F5): the instance ``__dict__`` only when
    the class's ``__dict__`` is the interpreter's slot (``_static_instance_dict``: no ``__dict__`` property, no dict
    subclass), via ``dict.get`` (never an overridden ``get``); a data descriptor (property) of that name on the class
    wins over the instance value in real attribute access, so then nothing is read. Never runs user code."""
    d = _static_instance_dict(obj)
    if d is None:
        return _MISSING
    try:
        for c in type(obj).__mro__:
            entry = vars(c).get(name, _MISSING)
            if entry is not _MISSING:
                if any("__set__" in vars(k) or "__delete__" in vars(k) for k in type(entry).__mro__):
                    return _MISSING          # a property / data descriptor: the attribute is not the stored value
                break
        return dict.get(d, name, _MISSING)
    except Exception:  # noqa: BLE001
        return _MISSING


def receiver_model(obj: Any, path: "tuple | list" = (), fallback: Any = None,
                   fallback_source: str = "guess") -> dict:
    """``{"model", "model_source"}`` for a direct call's receiver: ``obj`` (a plain Name the stub already holds)
    walked down ``path`` through plain instance attributes only, then its model field (``receiver_attr``); else
    ``fallback`` / ``fallback_source`` (construction literal or the app's model setting). Never invokes a property,
    a descriptor or ``__getattr__``; never raises."""
    try:
        cur = obj
        for name in path or ():
            cur = _instance_field(cur, str(name))
            if cur is _MISSING:
                raise LookupError(name)
        for field_name in _RECEIVER_MODEL_FIELDS:
            v = _instance_field(cur, field_name)
            if _is_type(v, str) and str.__len__(v):
                return {"model": str.__str__(v), "model_source": "receiver_attr"}   # a plain str, no user code
    except Exception:  # noqa: BLE001
        pass
    if type(fallback) is str and fallback:
        return {"model": fallback, "model_source": fallback_source}
    return {}


def header_model(headers: Any, name: str = "x-model") -> "str | None":
    """The ``X-Model`` header value only (case-insensitive), read statically (review r3 F4) from a ``dict`` (or dict
    subclass, through ``dict``'s own methods), an ``httpx.Headers`` (its ``_list``), a ``requests``
    ``CaseInsensitiveDict`` (its ``_store``) or a ``list`` / ``tuple`` of ``(key, value)`` pairs; ``None`` for
    anything else. Never iterates a generator / iterator, never calls ``items`` / ``__iter__`` / ``__getattr__`` on
    an arbitrary object, never raises, reads no other header."""
    try:
        pairs: Any = None
        if _is_type(headers, dict):          # type-based: no user __class__ (review r4 N6)
            pairs = list(dict.items(headers))
        elif type(headers) in (list, tuple):
            pairs = list(headers)
        else:
            mod = getattr(type(headers), "__module__", "") or ""
            fields = _static_instance_dict(headers) if mod.split(".")[0] in ("httpx", "requests") else None
            if fields is not None and type(dict.get(fields, "_list")) is list:
                pairs = [(t[1], t[2]) for t in dict.get(fields, "_list") if type(t) is tuple and len(t) == 3]
            elif fields is not None and _is_type(dict.get(fields, "_store"), dict):
                pairs = [v for v in dict.values(dict.get(fields, "_store")) if type(v) is tuple]
        for pair in pairs or ():
            if type(pair) not in (tuple, list) or len(pair) != 2:
                continue
            k, v = pair
            k = bytes(k).decode("latin-1") if _is_type(k, (bytes, bytearray)) else k
            if type(k) is str and k.lower() == name:
                v = bytes(v).decode("latin-1") if _is_type(v, (bytes, bytearray)) else v
                return v if type(v) is str and v else None
    except Exception:  # noqa: BLE001
        return None
    return None

_CURRENT_MODEL_KEYS = ("OPENROUTER_MODEL", "LLM_MODEL", "MODEL_NAME", "MODEL_ID", "OPENAI_MODEL", "ANTHROPIC_MODEL",
                       "BEDROCK_MODEL_ID")


def current_model(file: str = "") -> str:
    """The app's model setting (a module-level stub's ``_lineaje_current_model()``, review r3 F2): the first
    ``.env`` beside ``file`` or in up to 8 parents that sets one of the model keys, else the process environment;
    ``""`` when none. Reads files only; never raises."""
    try:
        from pathlib import Path as _P

        here = _P(file).resolve().parent if file else _P.cwd()
        for path in (here / ".env", *(p / ".env" for p in list(here.parents)[:8])):
            if not path.is_file():
                continue
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except OSError:
                continue
            values = {}
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                if key.strip() in _CURRENT_MODEL_KEYS:
                    values[key.strip()] = value.strip().strip(chr(34)).strip(chr(39))
            for key in _CURRENT_MODEL_KEYS:
                if values.get(key):
                    return values[key]
        return next((os.environ[k].strip() for k in _CURRENT_MODEL_KEYS if os.environ.get(k, "").strip()), "")
    except Exception:  # noqa: BLE001
        return ""


# ── Async twins (LIN-36167, STUB_API 5) ──────────────────────────────────────
# A stub inside ``async def`` awaits these instead of calling the blocking function on the event loop: the call
# runs in a worker thread (asyncio.to_thread, which copies the caller's contextvars — the interaction id and the
# process-block latch travel with it), so one slow guardrail round trip no longer stalls every other request the
# loop is serving. Same arguments, result and exceptions as the sync function.
async def aenforce(site: "SiteDescriptor", payload: Any, *args: Any, **kwargs: Any) -> Any:
    import asyncio as _asyncio
    return await _asyncio.to_thread(enforce, site, payload, *args, **kwargs)


async def aenforce_request(site: "SiteDescriptor", request: Any, *args: Any, **kwargs: Any) -> Any:
    import asyncio as _asyncio
    return await _asyncio.to_thread(enforce_request, site, request, *args, **kwargs)


async def aenforce_reply(site: "SiteDescriptor", reply: Any, *args: Any, **kwargs: Any) -> Any:
    import asyncio as _asyncio
    return await _asyncio.to_thread(enforce_reply, site, reply, *args, **kwargs)

