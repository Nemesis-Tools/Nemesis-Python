"""Sensitive file / debug endpoint exposure checks.

Each candidate requires a content SIGNATURE match (not just HTTP 200) to avoid
false positives from SPAs that return 200 for every path.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity

# (path, severity, signature regex, human note)
CHECKS = [
    ("/.git/config", Severity.HIGH, re.compile(r"\[core\]|\[remote ", re.I), "Exposed .git repository"),
    ("/.git/HEAD", Severity.HIGH, re.compile(r"^ref:\s", re.I), "Exposed .git repository"),
    ("/.env", Severity.CRITICAL, re.compile(r"(APP_KEY|DB_PASSWORD|SECRET|API_KEY)\s*=", re.I), "Exposed .env secrets"),
    ("/.svn/entries", Severity.MEDIUM, re.compile(r"^\d+\s*$|dir\b", re.I), "Exposed SVN metadata"),
    ("/.DS_Store", Severity.LOW, re.compile(r"Bud1|\x00\x00\x00\x01Bud1", re.I), "Exposed .DS_Store"),
    ("/phpinfo.php", Severity.MEDIUM, re.compile(r"phpinfo\(\)|PHP Version", re.I), "Exposed phpinfo()"),
    ("/server-status", Severity.MEDIUM, re.compile(r"Apache Server Status|Server uptime", re.I), "Apache server-status"),
    ("/actuator", Severity.MEDIUM, re.compile(r'"_links"|"health"|"self"', re.I), "Spring Boot Actuator"),
    ("/actuator/env", Severity.HIGH, re.compile(r'"propertySources"|"systemProperties"', re.I), "Actuator env (secrets)"),
    ("/actuator/health", Severity.INFO, re.compile(r'"status"\s*:\s*"(UP|DOWN)"', re.I), "Actuator health"),
    ("/swagger.json", Severity.INFO, re.compile(r'"swagger"|"openapi"', re.I), "Swagger/OpenAPI spec"),
    ("/openapi.json", Severity.INFO, re.compile(r'"openapi"', re.I), "OpenAPI spec"),
    ("/api-docs", Severity.INFO, re.compile(r'"swagger"|"openapi"|"paths"', re.I), "API docs"),
    ("/.aws/credentials", Severity.CRITICAL, re.compile(r"aws_access_key_id", re.I), "Exposed AWS credentials"),
    ("/config.php.bak", Severity.HIGH, re.compile(r"<\?php|define\(", re.I), "Backup source file"),
    ("/wp-config.php.bak", Severity.HIGH, re.compile(r"DB_PASSWORD|<\?php", re.I), "WordPress config backup"),
    ("/.well-known/security.txt", Severity.INFO, re.compile(r"Contact:", re.I), "security.txt present"),
]


@register
class SensitiveFiles(BaseModule):
    id = "sensitive_files"
    name = "Sensitive File / Debug Endpoint Exposure"
    category = "Recon"
    description = "Probes for exposed .git/.env, actuator, phpinfo, backups, swagger, etc. (signature-verified)."

    def run(self, ctx: ScanContext) -> list[Finding]:
        base = f"{urlparse(ctx.target).scheme}://{urlparse(ctx.target).netloc}"
        findings: list[Finding] = []
        for path, sev, sig, note in CHECKS:
            if ctx.should_stop():
                break
            url = urljoin(base, path)
            try:
                r = ctx.paced_get(url)
            except Exception:
                continue
            if r.status_code != 200:
                continue
            body = r.text or ""
            if sig.search(body):
                findings.append(Finding(
                    module_id=self.id,
                    title=f"{note}: {path}",
                    severity=sev,
                    url=url,
                    confidence="Firm",
                    description=f"{note} is publicly accessible and matched a known content signature.",
                    evidence=f"GET {url} -> 200; signature matched.",
                    remediation="Remove/block public access to this resource; rotate any exposed secrets.",
                ))
        return findings
