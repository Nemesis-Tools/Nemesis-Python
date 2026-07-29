"""File upload attack-surface recon (CWE-434) — surfaces upload points.

Actual malicious uploads (web shells) are destructive and out of automated scope,
so this SURFACES file-upload forms/fields and the tests to run manually.
"""
from __future__ import annotations

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.discovery import fetch_html, parse_forms

TESTS = ("web shell (.php/.jsp/.aspx), double extension (shell.php.jpg), MIME-type spoof, "
         "magic-byte polyglot (GIF89a;<?php), null-byte (shell.php%00.jpg), SVG/XML XSS, "
         "path traversal filename (../../shell.php), Zip Slip (../ in archive entries)")


@register
class UploadRecon(BaseModule):
    id = "upload_recon"
    name = "File Upload Attack Surface"
    category = "Auth / Access Control"
    description = "Surfaces file-upload forms/inputs and the upload-bypass tests to perform manually."

    def run(self, ctx: ScanContext) -> list[Finding]:
        html = fetch_html(ctx)
        if not html:
            return []
        driver = getattr(ctx.browser, "driver", None)
        file_inputs = 0
        if driver is not None:
            try:
                file_inputs = driver.execute_script(
                    "return document.querySelectorAll('input[type=file]').length;") or 0
            except Exception:
                file_inputs = 0
        forms = parse_forms(ctx.target, html)
        upload_forms = [f for f in forms if "multipart" in (f.action or "").lower()] + \
                       [f for f in forms if any(fl.ftype == "file" for fl in f.fields)]

        if not file_inputs and not upload_forms and "type=\"file\"" not in html and "type=file" not in html:
            ctx.log("    no file upload inputs found")
            return []
        actions = sorted({f.action for f in upload_forms}) or [ctx.target]
        return [Finding(
            module_id=self.id, title=f"File upload point(s) detected ({file_inputs or len(upload_forms)})",
            severity=Severity.INFO, url=ctx.target, confidence="Firm",
            description="File upload functionality was found. Manually test the upload-bypass techniques listed "
                        "in remediation under program scope.",
            evidence="Upload endpoint(s):\n" + "\n".join(actions[:10]),
            impact="검증 미흡 시 웹셸 업로드 → RCE.",
            remediation="Tests to run: " + TESTS + ". Fix: allow-list extensions/MIME by magic bytes, "
            "store outside webroot, randomize names, disable execution in the upload dir.")]
