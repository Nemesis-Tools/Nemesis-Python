"""JavaScript source map exposure (CWE-540) — leaks original source/paths."""
from __future__ import annotations

import re
from urllib.parse import urljoin

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.discovery import fetch_html

MAP_MARK = re.compile(r'"version"\s*:\s*3|"sources"\s*:\s*\[|"mappings"\s*:')
SMURL = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)")


@register
class SourceMapExposure(BaseModule):
    id = "source_map"
    name = "Source Map Exposure"
    category = "Recon"
    description = "Detects exposed .js.map source maps (leaks original source code and internal paths)."

    def run(self, ctx: ScanContext) -> list[Finding]:
        driver = getattr(ctx.browser, "driver", None)
        scripts = []
        if driver is not None:
            try:
                ctx.rate_limiter.wait()
                if ctx.browser.get(ctx.target):
                    ctx.browser.dismiss_alert()
                    scripts = driver.execute_script(
                        "return Array.from(document.scripts).filter(s=>s.src).map(s=>s.src);") or []
            except Exception:
                scripts = []
        if not scripts:
            html = fetch_html(ctx)
            scripts = [urljoin(ctx.target, m) for m in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html or "", re.I)]

        findings: list[Finding] = []
        checked = set()
        for src in scripts[:20]:
            if ctx.should_stop():
                break
            if not src.endswith(".js") or src in checked:
                continue
            checked.add(src)
            map_url = src + ".map"
            try:
                r = ctx.paced_get(map_url)
            except Exception:
                continue
            if r.status_code == 200 and MAP_MARK.search(r.text or ""):
                findings.append(Finding(
                    module_id=self.id, title=f"Exposed source map: {map_url.split('/')[-1]}",
                    severity=Severity.LOW, url=map_url, confidence="Firm",
                    description="A JavaScript source map is publicly accessible, disclosing original (pre-"
                                "minification) source code, comments, and internal file paths.",
                    evidence=f"GET {map_url} -> 200 (valid source map)",
                    impact="원본 소스/경로/주석 노출 → 추가 취약점 분석 용이.",
                    remediation="Do not deploy .map files to production, or restrict access."))
        if not findings:
            ctx.log("    no exposed source maps")
        return findings
