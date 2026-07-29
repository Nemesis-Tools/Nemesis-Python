"""Recon: technology fingerprinting from headers, cookies, and page markers."""
from __future__ import annotations

import re

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity

HEADER_SIGNS = {
    "x-powered-by": "Powered-By",
    "server": "Server",
    "x-aspnet-version": "ASP.NET",
    "x-generator": "Generator",
    "x-drupal-cache": "Drupal",
    "x-shopify-stage": "Shopify",
}
BODY_SIGNS = [
    ("WordPress", re.compile(r"/wp-(content|includes)/", re.I)),
    ("Drupal", re.compile(r"Drupal\.settings|/sites/default/files", re.I)),
    ("Joomla", re.compile(r"/media/jui/|Joomla!", re.I)),
    ("React", re.compile(r"data-reactroot|__REACT_DEVTOOLS", re.I)),
    ("Vue.js", re.compile(r"data-v-[0-9a-f]{8}|__vue__", re.I)),
    ("Angular", re.compile(r"ng-version|ng-app", re.I)),
    ("jQuery", re.compile(r"jquery[.-]", re.I)),
    ("Next.js", re.compile(r"/_next/static/|__NEXT_DATA__", re.I)),
    ("Laravel", re.compile(r"laravel_session|XSRF-TOKEN", re.I)),
]


@register
class TechFingerprint(BaseModule):
    id = "tech_fingerprint"
    name = "Technology Fingerprint"
    category = "Recon"
    description = "Identifies server software, frameworks, and JS libraries from headers and page markers."

    def run(self, ctx: ScanContext) -> list[Finding]:
        try:
            resp = ctx.paced_get(ctx.target)
        except Exception as e:
            ctx.log(f"    request failed: {e}")
            return []
        headers = {k.lower(): v for k, v in resp.headers.items()}
        detected: dict[str, str] = {}

        for h, label in HEADER_SIGNS.items():
            if h in headers and headers[h].strip():
                detected[label] = headers[h]

        body = resp.text or ""
        for name, rx in BODY_SIGNS:
            if rx.search(body):
                detected.setdefault(name, "detected in page markup")

        if "set-cookie" in headers:
            c = headers["set-cookie"].lower()
            if "phpsessid" in c:
                detected.setdefault("PHP", "PHPSESSID cookie")
            if "asp.net" in c or "aspsessionid" in c:
                detected.setdefault("ASP.NET", "session cookie")
            if "jsessionid" in c:
                detected.setdefault("Java (JSESSIONID)", "session cookie")

        if not detected:
            ctx.log("    no obvious technology signatures")
            return []

        lines = [f"{k}: {v}" for k, v in detected.items()]
        return [Finding(
            module_id=self.id,
            title=f"Technology stack fingerprinted ({len(detected)} signal(s))",
            severity=Severity.INFO,
            url=ctx.target,
            confidence="Firm",
            description="Identified technologies help scope further authorized testing and known-CVE checks.",
            evidence="\n".join(lines),
            remediation="Minimize version disclosure; keep identified components patched.",
        )]
