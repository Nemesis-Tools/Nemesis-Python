"""JWT weakness analysis — maps to account takeover / authentication bypass.

Collects JWTs from cookies, browser storage, and page content, then flags:
  * alg:none            -> signature not verified (forge any token) [CRITICAL]
  * weak HS256 secret   -> signature forgeable with a guessed key   [HIGH]
  * missing exp claim   -> tokens never expire                      [LOW]
  * sensitive claims    -> role/admin flags visible                 [INFO]

All checks are read-only; no forged token is ever sent to the server.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{4,}\.eyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{0,}")

# Small dictionary of notoriously weak/default HMAC signing secrets.
WEAK_SECRETS = ["secret", "password", "123456", "changeme", "admin", "jwt", "key",
                "test", "your-256-bit-secret", "supersecret", "s3cr3t", "private",
                "qwerty", "token", "default", "naver", "0000", "1234567890"]

SENSITIVE_CLAIMS = ["role", "roles", "admin", "is_admin", "isAdmin", "scope",
                    "scopes", "authorities", "grp", "group", "permissions", "typ_user"]


def _b64url_decode(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode())


def _parse(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None
    return header, payload, parts


def _crack_hs256(parts: list[str]) -> str | None:
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    try:
        sig = _b64url_decode(parts[2])
    except Exception:
        return None
    for secret in WEAK_SECRETS:
        expected = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        if hmac.compare_digest(expected, sig):
            return secret
    return None


@register
class JWTAnalysis(BaseModule):
    id = "jwt_analysis"
    name = "JWT Weakness Analysis"
    category = "Auth / Access Control"
    description = "Finds JWTs (cookies/storage/page) and flags alg:none, weak secrets, missing exp, sensitive claims."

    def _collect_tokens(self, ctx: ScanContext) -> dict[str, str]:
        """Return {source: token}."""
        tokens: dict[str, str] = {}

        # From HTTP session cookies (after a request).
        try:
            ctx.paced_get(ctx.target)
            for c in ctx.http.cookies:
                for m in JWT_RE.finditer(str(c.value)):
                    tokens.setdefault(f"cookie:{c.name}", m.group(0))
        except Exception:
            pass

        driver = getattr(ctx.browser, "driver", None)
        if driver is not None:
            try:
                ctx.rate_limiter.wait()
                if ctx.browser.get(ctx.target):
                    ctx.browser.dismiss_alert()
                    dump = driver.execute_script("""
                        const out = {cookie: document.cookie, ls: {}, ss: {}};
                        try { for (let i=0;i<localStorage.length;i++){const k=localStorage.key(i); out.ls[k]=localStorage.getItem(k);} } catch(e){}
                        try { for (let i=0;i<sessionStorage.length;i++){const k=sessionStorage.key(i); out.ss[k]=sessionStorage.getItem(k);} } catch(e){}
                        return out;
                    """) or {}
                    blobs = [("document.cookie", dump.get("cookie", ""))]
                    for k, v in (dump.get("ls") or {}).items():
                        blobs.append((f"localStorage:{k}", v))
                    for k, v in (dump.get("ss") or {}).items():
                        blobs.append((f"sessionStorage:{k}", v))
                    blobs.append(("page", driver.page_source or ""))
                    for src, blob in blobs:
                        for m in JWT_RE.finditer(str(blob or "")):
                            tokens.setdefault(f"{src}", m.group(0))
            except Exception:
                pass
        return tokens

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        tokens = self._collect_tokens(ctx)
        if not tokens:
            ctx.log("    no JWTs found in cookies/storage/page")
            return findings
        ctx.log(f"    analyzing {len(tokens)} JWT(s)")

        for source, token in tokens.items():
            parsed = _parse(token)
            if not parsed:
                continue
            header, payload, parts = parsed
            alg = str(header.get("alg", "")).lower()
            short = token[:24] + "…"

            if alg == "none":
                findings.append(Finding(
                    module_id=self.id, title=f"JWT 'alg:none' accepted risk ({source})",
                    severity=Severity.CRITICAL, url=ctx.target, confidence="Firm",
                    description="Token header uses alg:none. If the server honors it, any token can be forged "
                                "(full account takeover). Verify server-side signature enforcement.",
                    evidence=f"header={header}  token={short}",
                    remediation="Reject alg:none; pin the expected algorithm; verify signatures server-side."))

            if alg.startswith("hs"):
                secret = _crack_hs256(parts)
                if secret is not None:
                    findings.append(Finding(
                        module_id=self.id, title=f"JWT signed with weak secret '{secret}' ({source})",
                        severity=Severity.HIGH, url=ctx.target, confidence="Confirmed",
                        description="The HMAC signing key is a common/weak value, so valid tokens can be forged "
                                    "for any user, enabling account takeover.",
                        evidence=f"Recovered secret: {secret!r}  token={short}",
                        remediation="Use a long, random signing key from a secret manager; rotate immediately."))

            if "exp" not in payload:
                findings.append(Finding(
                    module_id=self.id, title=f"JWT has no expiry (exp) claim ({source})",
                    severity=Severity.LOW, url=ctx.target, confidence="Firm",
                    description="Token lacks an 'exp' claim, so a leaked token remains valid indefinitely.",
                    evidence=f"claims={list(payload.keys())}",
                    remediation="Add a short 'exp'; support revocation/rotation."))

            # RS256 -> HS256 algorithm-confusion candidate (asymmetric token forgeable
            # with the public key if the server accepts HS256).
            if alg.startswith("rs") or alg.startswith("es") or alg.startswith("ps"):
                findings.append(Finding(
                    module_id=self.id, title=f"JWT uses asymmetric alg '{header.get('alg')}' — test alg confusion ({source})",
                    severity=Severity.LOW, url=ctx.target, confidence="Tentative",
                    description="Asymmetric-signed token. Manually test whether the server also accepts an "
                                "HS256 token signed with the public key (algorithm-confusion → forgery).",
                    evidence=f"alg={header.get('alg')}",
                    remediation="Pin the exact expected algorithm; never let the token header choose the algorithm."))

            # Header-injection vectors: kid (path traversal / SQLi), jku / x5u (SSRF to key URL).
            if "kid" in header:
                findings.append(Finding(
                    module_id=self.id, title=f"JWT 'kid' header present — test injection ({source})",
                    severity=Severity.INFO, url=ctx.target, confidence="Tentative",
                    description="The 'kid' header selects a key; if used unsafely it may allow path traversal, "
                                "SQL injection, or forcing a known key.",
                    evidence=f"kid={header.get('kid')!r}",
                    remediation="Treat 'kid' as an opaque, validated lookup key; never use it in file paths/queries."))
            for hk in ("jku", "x5u"):
                if hk in header:
                    findings.append(Finding(
                        module_id=self.id, title=f"JWT '{hk}' header present — SSRF/key-injection risk ({source})",
                        severity=Severity.MEDIUM, url=ctx.target, confidence="Tentative",
                        description=f"The '{hk}' header points to a key URL. If not allow-listed, an attacker can "
                                    f"host their own key and forge tokens (or trigger SSRF).",
                        evidence=f"{hk}={header.get(hk)!r}",
                        remediation=f"Allow-list trusted '{hk}' hosts only; prefer static server-side keys."))

            present = [c for c in SENSITIVE_CLAIMS if c in payload]
            if present:
                findings.append(Finding(
                    module_id=self.id, title=f"JWT exposes sensitive claims ({source})",
                    severity=Severity.INFO, url=ctx.target, confidence="Firm",
                    description="Authorization-relevant claims are readable in the token (JWT payload is not encrypted).",
                    evidence="Claims: " + ", ".join(f"{c}={payload.get(c)}" for c in present),
                    remediation="Do not rely on client-visible claims for trust; enforce authz server-side."))
        return findings
