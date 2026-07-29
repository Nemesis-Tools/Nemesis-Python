"""Directory listing exposure detection."""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity

LISTING_RE = re.compile(r"<title>Index of /|<h1>Index of /|Directory Listing For|"
                        r"\[To Parent Directory\]", re.IGNORECASE)
COMMON_DIRS = ["/", "/images/", "/img/", "/uploads/", "/files/", "/assets/", "/backup/",
               "/static/", "/media/", "/docs/", "/tmp/", "/data/", "/download/", "/logs/"]


@register
class DirectoryListing(BaseModule):
    id = "dir_listing"
    name = "Directory Listing Exposure"
    category = "Recon"
    description = "Probes common directories for auto-generated index (directory listing) pages."

    def run(self, ctx: ScanContext) -> list[Finding]:
        p = urlparse(ctx.target)
        base = f"{p.scheme}://{p.netloc}"
        findings: list[Finding] = []
        for d in COMMON_DIRS:
            if ctx.should_stop():
                break
            url = urljoin(base, d)
            try:
                r = ctx.paced_get(url)
            except Exception:
                continue
            if r.status_code == 200 and LISTING_RE.search(r.text or ""):
                findings.append(Finding(
                    module_id=self.id, title=f"Directory listing enabled: {d}",
                    severity=Severity.LOW, url=url, confidence="Firm",
                    description="An auto-generated directory index is exposed, revealing file names/structure "
                                "and potentially sensitive files.",
                    evidence=f"GET {url} -> 200, 'Index of' listing.",
                    remediation="Disable directory indexing (Options -Indexes / autoindex off).",
                ))
        if not findings:
            ctx.log("    no directory listings found")
        return findings
