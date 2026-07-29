"""DOM Clobbering candidate detection (heuristic).

Flags pages where scripts read a global via `document.<name>` / `window.<name>`
and the HTML contains an element whose id/name equals <name> — the precondition
for DOM clobbering. Confirmation requires manual review.
"""
from __future__ import annotations

import re

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity

GLOBAL_ACCESS = re.compile(r"(?:document|window)\.([A-Za-z_][A-Za-z0-9_]{2,})")
STD_PROPS = {"getElementById", "querySelector", "querySelectorAll", "createElement", "location",
             "cookie", "body", "head", "title", "referrer", "documentElement", "addEventListener",
             "getElementsByClassName", "getElementsByTagName", "write", "forms", "images", "scripts",
             "readyState", "currentScript", "domain", "URL", "defaultView"}


@register
class DOMClobbering(BaseModule):
    id = "dom_clobbering"
    name = "DOM Clobbering Candidate"
    category = "Client-Side"
    description = "Heuristically flags document.<x>/window.<x> reads whose <x> matches an element id/name."

    def run(self, ctx: ScanContext) -> list[Finding]:
        driver = getattr(ctx.browser, "driver", None)
        if driver is None:
            return []
        ctx.rate_limiter.wait()
        if not ctx.browser.get(ctx.target):
            return []
        ctx.browser.dismiss_alert()
        try:
            scripts = driver.execute_script(
                "return Array.from(document.scripts).map(s=>s.textContent||'').join('\\n');") or ""
            ids = driver.execute_script(
                "return Array.from(document.querySelectorAll('[id],[name]')).map(e=>e.id||e.getAttribute('name')).filter(Boolean);") or []
        except Exception:
            return []

        referenced = {m for m in GLOBAL_ACCESS.findall(scripts) if m not in STD_PROPS}
        idset = {str(i) for i in ids}
        clobberable = sorted(referenced & idset)
        if not clobberable:
            ctx.log("    no DOM clobbering candidates")
            return []
        return [Finding(
            module_id=self.id, title=f"DOM clobbering candidate(s): {', '.join(clobberable[:8])}",
            severity=Severity.LOW, url=ctx.target, confidence="Tentative",
            description="Script reads a global property whose name matches an element id/name in the DOM. "
                        "An attacker-controlled element could clobber that global, potentially altering logic "
                        "or enabling DOM XSS. Manual review required.",
            evidence="Clobberable globals also present as id/name: " + ", ".join(clobberable[:20]),
            remediation="Reference DOM via getElementById with null checks; avoid trusting named globals; "
                        "use Object.freeze / explicit variable declarations.")]
