"""Exposed cloud storage bucket detection (S3 / GCS / Azure Blob)."""
from __future__ import annotations

import re

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.discovery import fetch_html

BUCKET_RES = [
    re.compile(r"https?://[a-z0-9.\-]+\.s3[.\-][a-z0-9.\-]*amazonaws\.com[^\s\"'<>)]*", re.I),
    re.compile(r"https?://s3[.\-][a-z0-9.\-]*amazonaws\.com/[a-z0-9.\-_]+[^\s\"'<>)]*", re.I),
    re.compile(r"https?://storage\.googleapis\.com/[a-z0-9.\-_]+[^\s\"'<>)]*", re.I),
    re.compile(r"https?://[a-z0-9.\-]+\.blob\.core\.windows\.net[^\s\"'<>)]*", re.I),
]
PUBLIC_LISTING = re.compile(r"<ListBucketResult|<Contents>|<Blobs>|<EnumerationResults", re.I)


def _bucket_root(url: str) -> str:
    # Reduce a bucket URL to its listing root (scheme://host[/bucket]).
    m = re.match(r"(https?://[^/]+)(/[^/?#]+)?", url)
    if not m:
        return url
    host = m.group(1)
    if "storage.googleapis.com" in host or re.search(r"s3[.\-].*amazonaws", host):
        return host + (m.group(2) or "")   # path-style: bucket is first path segment
    return host                             # virtual-host style: bucket is the host


@register
class CloudStorage(BaseModule):
    id = "cloud_storage"
    name = "Exposed Cloud Storage (S3/GCS/Azure)"
    category = "Recon"
    description = "Extracts bucket URLs from the page/JS and checks whether they are publicly listable."

    def run(self, ctx: ScanContext) -> list[Finding]:
        html = fetch_html(ctx)
        blob = html or ""
        driver = getattr(ctx.browser, "driver", None)
        if driver is not None:
            try:
                blob += "\n" + (driver.execute_script(
                    "return Array.from(document.scripts).map(s=>s.textContent||'').join('\\n');") or "")
            except Exception:
                pass

        buckets = set()
        for rx in BUCKET_RES:
            for m in rx.findall(blob):
                buckets.add(_bucket_root(m))
        if not buckets:
            ctx.log("    no cloud storage buckets referenced")
            return []

        findings: list[Finding] = []
        for root in sorted(buckets)[:15]:
            if ctx.should_stop():
                break
            try:
                r = ctx.paced_get(root)
            except Exception:
                continue
            if r.status_code == 200 and PUBLIC_LISTING.search(r.text or ""):
                findings.append(Finding(
                    module_id=self.id, title=f"Publicly listable cloud bucket: {root}",
                    severity=Severity.HIGH, url=root, confidence="Firm",
                    description="A referenced cloud storage bucket allows public listing of its contents, "
                                "which may expose sensitive files.",
                    evidence=f"GET {root} → 200 with a public listing document.",
                    impact="버킷 내 파일 열람/유출 → 민감정보 노출.",
                    remediation="Block public list/read; apply least-privilege bucket policies; audit contents."))
            else:
                findings.append(Finding(
                    module_id=self.id, title=f"Cloud bucket referenced: {root}",
                    severity=Severity.INFO, url=root, confidence="Tentative",
                    description="A cloud storage bucket is referenced by the app. Manually review its ACLs "
                                "and object permissions.",
                    evidence=f"Bucket URL: {root} (HTTP {r.status_code})",
                    remediation="Review bucket/object ACLs; avoid exposing bucket URLs unnecessarily."))
        return findings
