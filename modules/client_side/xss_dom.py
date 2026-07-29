"""DOM-based XSS heuristics.

Statically scans loaded JavaScript for dangerous source -> sink flows and probes
common URL-fragment sinks. Findings are flagged Tentative because confirming a
DOM XSS reliably needs manual review; this surfaces candidates.
"""
from __future__ import annotations

import re

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity

SOURCES = [
    r"location\.hash", r"location\.search", r"location\.href", r"document\.URL",
    r"document\.documentURI", r"document\.referrer", r"window\.name",
    r"location\.pathname",
]
SINKS = [
    r"\.innerHTML", r"\.outerHTML", r"document\.write", r"document\.writeln",
    r"\.insertAdjacentHTML", r"eval\s*\(", r"setTimeout\s*\(", r"setInterval\s*\(",
    r"new\s+Function", r"\.setAttribute\s*\(\s*['\"]on",
]

SENTINEL = "__domxss_hit"


@register
class DomXSS(BaseModule):
    id = "xss_dom"
    name = "DOM-based XSS (heuristic)"
    category = "Client-Side"
    description = "Scans page scripts for source->sink flows and probes fragment/name sinks."

    def _scan_scripts(self, ctx: ScanContext, url: str) -> list[Finding]:
        driver = ctx.browser.driver
        findings: list[Finding] = []
        try:
            scripts = driver.execute_script(
                "return Array.from(document.scripts).map(s => s.textContent || '');"
            ) or []
        except Exception:
            return findings

        source_re = re.compile("|".join(SOURCES))
        sink_re = re.compile("|".join(SINKS))
        blob = "\n".join(scripts)
        found_sources = sorted(set(source_re.findall(blob)))
        found_sinks = sorted(set(sink_re.findall(blob)))

        if found_sources and found_sinks:
            findings.append(Finding(
                module_id=self.id,
                title="Potential DOM XSS source/sink usage in page scripts",
                severity=Severity.MEDIUM,
                url=url,
                confidence="Tentative",
                description=("Inline scripts reference both user-controllable sources and dangerous "
                             "HTML/eval sinks. Manual review required to confirm exploitability."),
                evidence=f"Sources: {found_sources}\nSinks: {found_sinks}",
                remediation="Avoid passing untrusted data to innerHTML/eval; use textContent / safe APIs; add CSP.",
            ))
        return findings

    def _probe_fragment(self, ctx: ScanContext) -> list[Finding]:
        """Try a fragment payload that many naive `location.hash -> innerHTML` sinks execute."""
        driver = ctx.browser.driver
        payload = f'#<img src=x onerror=window.{SENTINEL}=1>'
        test_url = ctx.target.split("#")[0] + payload
        ctx.rate_limiter.wait()
        if not ctx.browser.get(test_url):
            return []
        ctx.browser.dismiss_alert()
        try:
            hit = bool(driver.execute_script(f"return window.{SENTINEL} === 1;"))
        except Exception:
            hit = False
        if hit:
            return [Finding(
                module_id=self.id,
                title="DOM XSS via URL fragment (location.hash sink)",
                severity=Severity.HIGH,
                url=test_url,
                confidence="Confirmed",
                description="A URL fragment payload executed in the DOM, indicating an unsafe hash sink.",
                evidence=f"Payload executed: {payload}",
                remediation="Never write location.hash into innerHTML; sanitize/encode; add CSP.",
            )]
        return []

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        ctx.rate_limiter.wait()
        if ctx.browser.get(ctx.target):
            ctx.browser.dismiss_alert()
            findings += self._scan_scripts(ctx, ctx.target)
        if not ctx.should_stop():
            findings += self._probe_fragment(ctx)
        return findings
