"""TLS/SSL weakness analysis — deprecated protocols, cert issues (CWE-326/327)."""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity


def _supports(host: str, port: int, ver) -> bool:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ver
        ctx.maximum_version = ver
    except Exception:
        return False
    try:
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


@register
class TLSAnalysis(BaseModule):
    id = "tls_analysis"
    name = "TLS / SSL Weakness"
    category = "Crypto / TLS"
    description = "Checks for deprecated TLS 1.0/1.1, certificate expiry, and hostname/self-signed issues."

    def run(self, ctx: ScanContext) -> list[Finding]:
        u = urlparse(ctx.target)
        if u.scheme != "https":
            ctx.log("    target is not HTTPS; skipping TLS analysis")
            return []
        host = u.hostname
        port = u.port or 443
        findings: list[Finding] = []

        for name, ver in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
            if ctx.should_stop():
                break
            if _supports(host, port, ver):
                findings.append(Finding(
                    module_id=self.id, title=f"Deprecated protocol supported: {name}",
                    severity=Severity.MEDIUM, url=ctx.target, confidence="Firm",
                    description=f"The server negotiates {name}, which is deprecated and vulnerable to known attacks.",
                    evidence=f"{host}:{port} completed a {name} handshake.",
                    impact="다운그레이드/BEAST/POODLE 등 알려진 공격 노출.",
                    remediation="Disable TLS 1.0/1.1; allow only TLS 1.2+."))

        # Certificate inspection (verified connection).
        try:
            vctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=6) as sock:
                with vctx.wrap_socket(sock, server_hostname=host) as ss:
                    cert = ss.getpeercert()
            not_after = cert.get("notAfter")
            if not_after:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days = (exp - datetime.now(timezone.utc)).days
                if days < 0:
                    findings.append(Finding(module_id=self.id, title="Expired TLS certificate",
                        severity=Severity.HIGH, url=ctx.target, confidence="Firm",
                        description="The server's TLS certificate has expired.",
                        evidence=f"notAfter={not_after} ({-days} days ago)",
                        remediation="Renew the certificate."))
                elif days < 21:
                    findings.append(Finding(module_id=self.id, title=f"TLS certificate expiring soon ({days}d)",
                        severity=Severity.LOW, url=ctx.target, confidence="Firm",
                        description="The TLS certificate expires within 3 weeks.",
                        evidence=f"notAfter={not_after}", remediation="Renew before expiry."))
        except ssl.SSLCertVerificationError as e:
            findings.append(Finding(module_id=self.id, title="TLS certificate validation error (self-signed/mismatch)",
                severity=Severity.MEDIUM, url=ctx.target, confidence="Firm",
                description="The certificate failed validation (self-signed, wrong host, or untrusted CA).",
                evidence=str(e)[:160], remediation="Install a valid CA-signed certificate for this host."))
        except Exception:
            pass
        if not findings:
            ctx.log("    TLS configuration looks acceptable (TLS1.2+/valid cert)")
        return findings
