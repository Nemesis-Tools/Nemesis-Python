"""Subdomain takeover fingerprinting.

Checks the target's response for the tell-tale error pages of dangling
third-party services (S3, GitHub Pages, Heroku, etc.). A match means the host
points at an unclaimed service that an attacker could register.
"""
from __future__ import annotations

import re

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity

# (service, fingerprint regex)
FINGERPRINTS = [
    ("AWS S3", re.compile(r"NoSuchBucket|The specified bucket does not exist", re.I)),
    ("GitHub Pages", re.compile(r"There isn't a GitHub Pages site here|404.*github", re.I)),
    ("Heroku", re.compile(r"No such app|herokucdn\.com/error-pages/no-such-app", re.I)),
    ("Amazon CloudFront", re.compile(r"The request could not be satisfied.*CloudFront", re.I)),
    ("Fastly", re.compile(r"Fastly error: unknown domain", re.I)),
    ("Shopify", re.compile(r"Sorry, this shop is currently unavailable", re.I)),
    ("Bitbucket", re.compile(r"Repository not found", re.I)),
    ("Ghost", re.compile(r"The thing you were looking for is no longer here", re.I)),
    ("Zendesk", re.compile(r"Help Center Closed", re.I)),
    ("Unbounce", re.compile(r"The requested URL was not found on this server", re.I)),
    ("Surge.sh", re.compile(r"project not found", re.I)),
    ("Pantheon", re.compile(r"The gods are wise, but do not know of the site", re.I)),
    ("Azure", re.compile(r"404 Web Site not found.*azurewebsites", re.I)),
]


@register
class SubdomainTakeover(BaseModule):
    id = "subdomain_takeover"
    name = "Subdomain Takeover Fingerprint"
    category = "Recon"
    description = "Detects dangling third-party service error pages (S3/GitHub Pages/Heroku/…) indicating takeover."

    def run(self, ctx: ScanContext) -> list[Finding]:
        try:
            r = ctx.paced_get(ctx.target)
        except Exception as e:
            ctx.log(f"    request failed: {e}")
            return []
        body = r.text or ""
        for service, rx in FINGERPRINTS:
            m = rx.search(body)
            if m:
                return [Finding(
                    module_id=self.id,
                    title=f"Possible subdomain takeover ({service})",
                    severity=Severity.HIGH, url=ctx.target, confidence="Tentative",
                    description=f"The host returns a '{service}' dangling-resource error page. If the underlying "
                                f"service/bucket is unclaimed, an attacker can register it and take over the host.",
                    evidence=f"Matched fingerprint: {m.group(0)[:80]!r}",
                    impact="공격자가 해당 서브도메인을 장악 → 피싱·쿠키 탈취·콘텐츠 조작.",
                    remediation="Remove the dangling DNS record or reclaim the third-party resource.",
                )]
        ctx.log("    no takeover fingerprints")
        return []
