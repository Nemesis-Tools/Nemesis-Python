"""Recon: robots.txt / sitemap.xml / common metadata files."""
from __future__ import annotations

from urllib.parse import urljoin, urlparse

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity

PATHS = [
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/humans.txt", "/crossdomain.xml",
]


@register
class RobotsSitemap(BaseModule):
    id = "robots_sitemap"
    name = "robots.txt / sitemap / metadata"
    category = "Recon"
    description = "Fetches robots.txt, sitemap.xml and well-known metadata files; extracts disallowed paths."

    def run(self, ctx: ScanContext) -> list[Finding]:
        base = f"{urlparse(ctx.target).scheme}://{urlparse(ctx.target).netloc}"
        findings: list[Finding] = []
        for path in PATHS:
            if ctx.should_stop():
                break
            url = urljoin(base, path)
            try:
                r = ctx.paced_get(url)
            except Exception:
                continue
            if r.status_code == 200 and r.text.strip():
                body = r.text
                evidence = body[:1500]
                disallowed = [ln.split(":", 1)[1].strip()
                              for ln in body.splitlines()
                              if ln.lower().startswith("disallow:") and ":" in ln]
                extra = f"\nDisallowed entries: {disallowed[:30]}" if disallowed else ""
                findings.append(Finding(
                    module_id=self.id,
                    title=f"Accessible metadata file: {path}",
                    severity=Severity.INFO,
                    url=url,
                    confidence="Firm",
                    description="Metadata file is publicly readable; may reveal hidden paths or contacts.",
                    evidence=evidence + extra,
                    remediation="Ensure sensitive paths are not merely 'hidden' via robots.txt; enforce authz.",
                ))
        return findings
