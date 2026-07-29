"""CRLF injection / HTTP response header splitting.

Injects an encoded CR-LF sequence that, if reflected into a response header,
adds an attacker-controlled header. Detection reads back the injected header.
"""
from __future__ import annotations

import uuid
from urllib.parse import urlencode, urlparse, urlunparse

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.injection_points import discover_points


@register
class CRLFInjection(BaseModule):
    id = "crlf"
    name = "CRLF Injection (header splitting)"
    category = "Injection"
    description = "Injects encoded CRLF into query params and checks for an injected response header."

    def _build_url(self, base_url: str, base_params: dict, param: str, raw_value: str) -> str:
        # Keep other params normally encoded; append our param with a RAW (already
        # percent-encoded) value so the CRLF survives to the server.
        pairs = [f"{k}={urlencode({'': v})[1:]}" for k, v in base_params.items() if k != param]
        pairs.append(f"{param}={raw_value}")
        p = urlparse(base_url)
        return urlunparse(p._replace(query="&".join(pairs)))

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        points = [p for p in discover_points(ctx) if p.method == "GET"]
        if not points:
            ctx.log("    no GET query points to test")
            return findings
        ctx.log(f"    testing {len(points)} GET point(s)")

        for pt in points:
            if ctx.should_stop():
                break
            token = uuid.uuid4().hex[:12]
            header_name = "X-Crlf-Test"
            # Several encodings of CRLF to bypass naive filters.
            for enc in ("%0d%0a", "%0D%0A", "%E5%98%8A%E5%98%8D", "\r\n"):
                if ctx.should_stop():
                    break
                raw_val = f"inj{enc}{header_name}: {token}"
                url = self._build_url(pt.base_url, pt.base_params, pt.param, raw_val)
                try:
                    r = ctx.paced_get(url)
                except Exception:
                    continue
                got = {k.lower(): v for k, v in r.headers.items()}
                if got.get(header_name.lower()) == token:
                    findings.append(Finding(
                        module_id=self.id,
                        title=f"CRLF injection in query parameter '{pt.param}'",
                        severity=Severity.MEDIUM,
                        url=url,
                        confidence="Confirmed",
                        description=("User input is reflected into response headers, allowing header "
                                     "injection (response splitting, cookie/CSP manipulation)."),
                        evidence=f"Injected header echoed back: {header_name}: {token}",
                        request=f"GET {url}",
                        remediation="Strip/encode CR and LF from any value placed into response headers.",
                    ))
                    break
        return findings
