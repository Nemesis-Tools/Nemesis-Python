"""XS-Leaks candidate detection (cross-origin isolation posture).

XS-Leaks abuse cross-site *observable* side channels, which requires the resource
to be **embeddable cross-site**. To avoid false positives (nearly every site omits
COOP/COEP/CORP), this only reports when the response is BOTH framable (no
X-Frame-Options / CSP frame-ancestors) AND missing cross-origin isolation — the
actual precondition for an XS-Leaks oracle. One consolidated, low-severity finding.
"""
from __future__ import annotations

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity

_ISO = ("cross-origin-opener-policy", "cross-origin-embedder-policy", "cross-origin-resource-policy")


@register
class XSLeaks(BaseModule):
    id = "xs_leaks"
    name = "XS-Leaks isolation candidates"
    category = "Client-Side"
    default_enabled = True
    description = "Reports XS-Leaks oracle preconditions only when the page is framable AND lacks COOP/COEP/CORP."

    def run(self, ctx: ScanContext) -> list[Finding]:
        try:
            r = ctx.paced_get(ctx.target)
        except Exception:
            return []
        h = {k.lower(): v for k, v in r.headers.items()}

        # Precondition: the resource must be embeddable cross-site, or XS-Leaks don't apply.
        framable = (not h.get("x-frame-options")) and \
                   ("frame-ancestors" not in h.get("content-security-policy", "").lower())
        if not framable:
            return []
        missing = [x for x in _ISO if x not in h]
        # CORP alone often suffices to block embedding side channels; require it (plus one more) missing.
        if "cross-origin-resource-policy" not in missing or len(missing) < 2:
            return []

        return [Finding(
            module_id=self.id, title="XS-Leaks oracle preconditions present (framable + no isolation)",
            severity=Severity.LOW, url=ctx.target, confidence="Tentative",
            description=("The page is framable cross-site and sets no cross-origin isolation headers "
                         "(" + ", ".join(missing) + "). Together these are the preconditions for XS-Leaks "
                         "oracles (frame counts, load timing, error events). Real exploitability depends on "
                         "per-user state differences on this endpoint — verify manually."),
            evidence=f"framable=yes; missing isolation: {missing}",
            remediation="Set COOP: same-origin, COEP: require-corp, CORP: same-origin; add frame-ancestors 'none'/'self'.")]
