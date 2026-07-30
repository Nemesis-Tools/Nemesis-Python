"""HTTP Request Smuggling — CL.TE / TE.CL timing detection (expert, opt-in).

Uses the well-known differential-timing technique: an ambiguous request that a
desynced back-end will block on (waiting for more body) while a normal request
returns immediately. It only measures timing on its OWN connection and never
smuggles a prefix into another user's request, so it does not poison traffic.

Disabled by default (default_enabled = False) because malformed requests can
upset sensitive infrastructure; enable it deliberately for authorized targets.
"""
from __future__ import annotations

import socket
import ssl
import time
from urllib.parse import urlparse

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity

TIMEOUT = 9
SLOW = 5.0        # seconds — a desync stalls at least this long
FAST_MAX = 2.5    # baseline must be quick to make the comparison meaningful


def _send_raw(host: str, port: int, use_tls: bool, verify: bool, payload: bytes) -> float | None:
    """Send raw bytes, return seconds until first response byte (or TIMEOUT)."""
    start = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        if use_tls:
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(payload)
        sock.settimeout(TIMEOUT)
        try:
            data = sock.recv(64)
            if not data:
                return time.monotonic() - start
        except TimeoutError:
            return TIMEOUT
        return time.monotonic() - start
    except Exception:
        return None
    finally:
        try:
            if sock:
                sock.close()
        except Exception:
            pass


@register
class RequestSmuggling(BaseModule):
    id = "request_smuggling"
    name = "HTTP Request Smuggling (timing)"
    category = "Injection"
    description = "CL.TE/TE.CL differential-timing probe (own connection only). Disabled by default — expert use."
    default_enabled = False

    def _payloads(self, host: str, path: str) -> dict[str, bytes]:
        # CL.TE: front-end uses Content-Length, back-end uses Transfer-Encoding.
        clte = (
            f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
            "Transfer-Encoding: chunked\r\nContent-Length: 4\r\n"
            "Connection: close\r\n\r\n"
            "1\r\nA\r\nX"          # back-end (TE) waits for the next chunk → stalls
        ).encode()
        # TE.CL: front-end uses Transfer-Encoding, back-end uses Content-Length.
        tecl = (
            f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
            "Transfer-Encoding: chunked\r\nContent-Length: 6\r\n"
            "Connection: close\r\n\r\n"
            "0\r\n\r\nX"           # back-end (CL) waits for more bytes → stalls
        ).encode()
        baseline = (
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        ).encode()
        return {"baseline": baseline, "CL.TE": clte, "TE.CL": tecl}

    def run(self, ctx: ScanContext) -> list[Finding]:
        u = urlparse(ctx.target)
        host = u.hostname or ""
        if not host:
            return []
        use_tls = u.scheme == "https"
        port = u.port or (443 if use_tls else 80)
        path = u.path or "/"
        verify = ctx.options.get("verify_tls", True)
        payloads = self._payloads(host, path)

        ctx.rate_limiter.wait()
        base = _send_raw(host, port, use_tls, verify, payloads["baseline"])
        if base is None:
            ctx.log("    raw connection failed; skipping")
            return []
        if base > FAST_MAX:
            ctx.log(f"    baseline slow ({base:.1f}s) — timing test unreliable, skipping")
            return []

        findings: list[Finding] = []
        for name in ("CL.TE", "TE.CL"):
            if ctx.should_stop():
                break
            ctx.rate_limiter.wait()
            t = _send_raw(host, port, use_tls, verify, payloads[name])
            if t is not None and t >= SLOW:
                findings.append(Finding(
                    module_id=self.id, title=f"Possible HTTP request smuggling ({name})",
                    severity=Severity.HIGH, url=ctx.target, confidence="Tentative",
                    description=(f"A {name} ambiguous request stalled ({t:.1f}s vs baseline {base:.1f}s), "
                                 "suggesting front-end/back-end disagreement on request boundaries "
                                 "(request smuggling / desync). Verify manually and carefully."),
                    evidence=f"baseline={base:.1f}s  {name}={t:.1f}s (>= {SLOW}s)",
                    impact="요청 밀수로 인증 우회·캐시 오염·타 사용자 요청 탈취로 확대 가능.",
                    remediation="Front/back-end에서 CL/TE 처리를 일치시키고 모호한 요청을 거부하도록 설정."))
        if not findings:
            ctx.log("    no smuggling timing signal")
        return findings
