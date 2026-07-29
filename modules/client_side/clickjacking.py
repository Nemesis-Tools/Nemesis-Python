"""Clickjacking / framing protection check."""
from __future__ import annotations

import re

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity


@register
class Clickjacking(BaseModule):
    id = "clickjacking"
    name = "Clickjacking (framing) protection"
    category = "Client-Side"
    description = "Checks X-Frame-Options and CSP frame-ancestors to see if the page can be framed."

    def run(self, ctx: ScanContext) -> list[Finding]:
        try:
            resp = ctx.paced_get(ctx.target)
        except Exception as e:
            ctx.log(f"    request failed: {e}")
            return []

        headers = {k.lower(): v for k, v in resp.headers.items()}
        xfo = headers.get("x-frame-options", "")
        csp = headers.get("content-security-policy", "")
        has_frame_ancestors = "frame-ancestors" in csp.lower()

        protected = bool(xfo) or has_frame_ancestors
        if protected:
            ctx.log(f"    framing protection present (XFO='{xfo}', frame-ancestors={has_frame_ancestors})")
            return []

        return [Finding(
            module_id=self.id,
            title="Missing clickjacking protection (page is framable)",
            severity=Severity.MEDIUM,
            url=ctx.target,
            confidence="Firm",
            description=("Neither X-Frame-Options nor a CSP 'frame-ancestors' directive is set, so the "
                         "page can be embedded in an attacker-controlled iframe for UI redressing."),
            evidence=f"X-Frame-Options: {xfo or '(absent)'}\nCSP: {csp or '(absent)'}",
            remediation="Set 'X-Frame-Options: DENY' (or SAMEORIGIN) and/or CSP 'frame-ancestors 'none''.",
        )]
