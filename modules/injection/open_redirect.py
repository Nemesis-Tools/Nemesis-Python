"""Open redirect detection.

Injects a canary external host into redirect-looking parameters and checks
whether the server (or client) redirects off-domain to the canary.
"""
from __future__ import annotations

from urllib.parse import urlparse

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.http_utils import registrable
from core.injection_points import discover_points, send, attack_url

CANARY = "example.org"  # RFC 2606 reserved; safe, non-routable-to-you canary
CANARY_PAYLOADS = [
    f"https://{CANARY}/",
    f"//{CANARY}/",
    f"https:{CANARY}",
    f"/\\{CANARY}",
]
REDIRECT_PARAM_HINTS = {"url", "redirect", "redirect_uri", "redirect_url", "next", "return",
                        "returnurl", "return_to", "goto", "dest", "destination", "continue",
                        "target", "rurl", "u", "link", "out", "to"}


@register
class OpenRedirect(BaseModule):
    id = "open_redirect"
    name = "Open Redirect"
    category = "Injection"
    description = "Injects an external canary into redirect params and checks for off-domain redirection."

    def _lands_on_canary(self, resp) -> bool:
        final_host = registrable(resp.url)
        if final_host == CANARY:
            return True
        # Also inspect Location header of the last hop, if present.
        for hop in list(resp.history) + [resp]:
            loc = hop.headers.get("Location", "")
            if CANARY in urlparse(loc).netloc:
                return True
        return False

    def _test_point(self, ctx: ScanContext, pt) -> Finding | None:
        for payload in CANARY_PAYLOADS:
            if ctx.should_stop():
                return None
            resp = send(ctx, pt, payload, allow_redirects=True)
            if resp is None:
                continue
            if self._lands_on_canary(resp):
                return Finding(
                    module_id=self.id,
                    title=f"Open redirect via {pt.label()}",
                    severity=Severity.MEDIUM,
                    url=pt.base_url,
                    confidence="Firm",
                    description=(f"Parameter '{pt.param}' redirects to an attacker-controlled external host, "
                                 f"enabling phishing and OAuth token theft."),
                    evidence=f"Final URL: {resp.url}\nPayload: {payload}",
                    request=f"{pt.method} {pt.base_url}  ({pt.param}={payload})",
                    remediation="Allow-list redirect destinations; use relative paths or mapped identifiers.",
                    extra={"attack": {"method": pt.method, "url": attack_url(pt, payload)}},
                )
        return None

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        points = discover_points(ctx)
        if not points:
            ctx.log("    no injectable points found")
            return findings
        # Test hint-matching params first, then the rest.
        ordered = sorted(points, key=lambda p: p.param.lower() not in REDIRECT_PARAM_HINTS)
        ctx.log(f"    testing {len(ordered)} point(s)")
        for pt in ordered:
            if ctx.should_stop():
                break
            f = self._test_point(ctx, pt)
            if f:
                findings.append(f)
        return findings
