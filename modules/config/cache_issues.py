"""Web cache deception & web cache poisoning detection (modern, high-impact)."""
from __future__ import annotations

import uuid

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity

CACHE_HINT_HEADERS = ["x-cache", "cf-cache-status", "x-cache-hits", "age", "x-served-by", "x-drupal-cache"]
EVIL_HOST = "poison.example.org"


def _is_cacheable(headers: dict) -> tuple[bool, str]:
    cc = headers.get("cache-control", "").lower()
    reasons = []
    if "public" in cc:
        reasons.append("Cache-Control: public")
    if "max-age" in cc and "max-age=0" not in cc and "no-store" not in cc:
        reasons.append(cc)
    for h in CACHE_HINT_HEADERS:
        if h in headers:
            reasons.append(f"{h}: {headers[h]}")
    cacheable = bool(reasons) and "no-store" not in cc and "private" not in cc
    return cacheable, "; ".join(reasons)


@register
class CacheIssues(BaseModule):
    id = "cache_issues"
    name = "Web Cache Deception / Poisoning"
    category = "Config / Headers"
    description = "Detects cacheable personal responses (deception) and unkeyed-header reflection (poisoning)."

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        # ---- Web Cache Deception ----
        # Append a static-looking suffix; if the app still returns the page AND it
        # looks cacheable, a shared cache may store authenticated content.
        base = ctx.target.split("#")[0].split("?")[0]
        for suffix in ("/nonexistent.css", "/nonexistent.js", f"/{uuid.uuid4().hex[:8]}.css"):
            if ctx.should_stop():
                break
            url = base.rstrip("/") + suffix
            try:
                r = ctx.paced_get(url)
            except Exception:
                continue
            headers = {k.lower(): v for k, v in r.headers.items()}
            ctype = headers.get("content-type", "")
            if r.status_code == 200 and "text/html" in ctype:
                cacheable, why = _is_cacheable(headers)
                if cacheable:
                    findings.append(Finding(
                        module_id=self.id, title="Possible Web Cache Deception",
                        severity=Severity.MEDIUM, url=url, confidence="Tentative",
                        description=("A static-looking URL returned HTML with cacheable headers. A shared "
                                     "cache could store an authenticated user's page and serve it to others."),
                        evidence=f"URL: {url}\nContent-Type: {ctype}\nCache signals: {why}",
                        remediation="Cache by content-type/route, not extension; set Cache-Control: private for user pages."))
                    break

        # ---- Web Cache Poisoning (unkeyed header reflection) ----
        if not ctx.should_stop():
            marker = uuid.uuid4().hex[:10]
            for header in ("X-Forwarded-Host", "X-Forwarded-Scheme", "X-Host", "X-Forwarded-Server"):
                if ctx.should_stop():
                    break
                val = f"{EVIL_HOST}-{marker}" if "host" in header.lower() or "server" in header.lower() else "http"
                try:
                    r = ctx.paced_request("GET", ctx.target, headers={header: val})
                except Exception:
                    continue
                body = r.text or ""
                headers = {k.lower(): v for k, v in r.headers.items()}
                if val in body:
                    cacheable, why = _is_cacheable(headers)
                    sev = Severity.HIGH if cacheable else Severity.MEDIUM
                    findings.append(Finding(
                        module_id=self.id,
                        title=f"Unkeyed header reflected ({header}) — cache poisoning risk",
                        severity=sev, url=ctx.target, confidence="Firm" if cacheable else "Tentative",
                        description=("An unkeyed request header is reflected into the response. If cached, an "
                                     "attacker can poison the shared cache for all users."),
                        evidence=f"{header}: {val} reflected in body." + (f"\nCache signals: {why}" if why else ""),
                        request=f"GET {ctx.target}  ({header}: {val})",
                        remediation="Do not reflect unkeyed headers; include them in the cache key or drop them."))
                    break
        if not findings:
            ctx.log("    no cache deception/poisoning signals")
        return findings
