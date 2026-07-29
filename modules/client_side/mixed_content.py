"""Mixed content: HTTPS page loading insecure HTTP subresources."""
from __future__ import annotations

from urllib.parse import urlparse

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity


@register
class MixedContent(BaseModule):
    id = "mixed_content"
    name = "Mixed content (HTTP on HTTPS)"
    category = "Client-Side"
    description = "On an HTTPS page, finds subresources (script/img/link/iframe) loaded over plain HTTP."

    def run(self, ctx: ScanContext) -> list[Finding]:
        if urlparse(ctx.target).scheme != "https":
            ctx.log("    target is not HTTPS; skipping mixed-content check")
            return []

        ctx.rate_limiter.wait()
        if not ctx.browser.get(ctx.target):
            return []
        ctx.browser.dismiss_alert()
        driver = ctx.browser.driver
        try:
            insecure = driver.execute_script("""
                const out = [];
                const grab = (sel, attr) => document.querySelectorAll(sel).forEach(e => {
                    const v = e.getAttribute(attr);
                    if (v && v.toLowerCase().startsWith('http://')) out.push(e.tagName + ': ' + v);
                });
                grab('script[src]','src'); grab('img[src]','src');
                grab('link[href]','href'); grab('iframe[src]','src');
                grab('source[src]','src'); grab('audio[src]','src'); grab('video[src]','src');
                return out;
            """) or []
        except Exception:
            insecure = []

        if not insecure:
            return []
        sample = "\n".join(insecure[:25])
        return [Finding(
            module_id=self.id,
            title=f"Mixed content: {len(insecure)} insecure subresource(s) on HTTPS page",
            severity=Severity.LOW,
            url=ctx.target,
            confidence="Firm",
            description="HTTPS page references subresources over plain HTTP, weakening transport security.",
            evidence=sample,
            remediation="Load all subresources over HTTPS; add 'upgrade-insecure-requests' to CSP.",
        )]
