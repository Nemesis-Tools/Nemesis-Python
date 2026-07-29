"""Recon: scan rendered page + loaded JS for leaked secrets / API keys / endpoints."""
from __future__ import annotations

import re
from urllib.parse import urljoin

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity

# (label, severity, compiled regex)
PATTERNS = [
    ("AWS Access Key ID", Severity.HIGH, re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key", Severity.HIGH, re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Slack Token", Severity.HIGH, re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("Stripe Secret Key", Severity.HIGH, re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("GitHub Token", Severity.HIGH, re.compile(r"gh[posru]_[0-9A-Za-z]{36,}")),
    ("Private Key Block", Severity.CRITICAL, re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("JWT", Severity.LOW, re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("Generic Secret Assignment", Severity.MEDIUM,
     re.compile(r"""(?i)(api[_-]?key|secret|passwd|password|token)\s*[:=]\s*['"][0-9A-Za-z\-_]{12,}['"]""")),
]

ENDPOINT_RE = re.compile(r"""['"](/(?:api|v\d|graphql|internal|admin|rest)[/A-Za-z0-9_\-.]{2,})['"]""")


@register
class SecretsScan(BaseModule):
    id = "secrets_scan"
    name = "Secret / API-key & endpoint leakage"
    category = "Recon"
    description = "Scans the rendered DOM and inline/external JS for hardcoded secrets and API endpoints."

    def _collect_text(self, ctx: ScanContext) -> tuple[str, list[str]]:
        """Return (combined_text, list of external script URLs)."""
        driver = ctx.browser.driver
        ctx.rate_limiter.wait()
        if not ctx.browser.get(ctx.target):
            return "", []
        ctx.browser.dismiss_alert()
        try:
            page = driver.page_source or ""
        except Exception:
            page = ""
        try:
            inline = driver.execute_script(
                "return Array.from(document.scripts).filter(s=>!s.src).map(s=>s.textContent||'').join('\\n');"
            ) or ""
            srcs = driver.execute_script(
                "return Array.from(document.scripts).filter(s=>s.src).map(s=>s.src);"
            ) or []
        except Exception:
            inline, srcs = "", []
        return page + "\n" + inline, srcs

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        text, script_srcs = self._collect_text(ctx)

        # Fetch same-origin external scripts too (bounded).
        for src in script_srcs[:15]:
            if ctx.should_stop():
                break
            try:
                r = ctx.paced_get(src)
                if r.status_code == 200:
                    text += "\n" + r.text
            except Exception:
                continue

        seen: set[str] = set()
        for label, sev, rx in PATTERNS:
            for m in rx.finditer(text):
                snippet = m.group(0)
                key = label + "|" + snippet[:40]
                if key in seen:
                    continue
                seen.add(key)
                redacted = snippet if len(snippet) < 12 else snippet[:6] + "…" + snippet[-4:]
                findings.append(Finding(
                    module_id=self.id,
                    title=f"Possible secret exposed: {label}",
                    severity=sev,
                    url=ctx.target,
                    confidence="Tentative",
                    description="A secret-like string was found in client-delivered content. Verify and rotate if valid.",
                    evidence=f"Match ({label}): {redacted}",
                    remediation="Never ship secrets to the client; move to server-side; rotate any exposed key.",
                ))

        # Endpoints (informational).
        endpoints = sorted({m.group(1) for m in ENDPOINT_RE.finditer(text)})
        if endpoints:
            findings.append(Finding(
                module_id=self.id,
                title=f"{len(endpoints)} API endpoint path(s) referenced in client code",
                severity=Severity.INFO,
                url=ctx.target,
                confidence="Firm",
                description="Client code references internal API paths, useful for further authorized testing.",
                evidence="\n".join(endpoints[:40]),
                remediation="Ensure all referenced endpoints enforce authentication/authorization.",
            ))
        return findings
