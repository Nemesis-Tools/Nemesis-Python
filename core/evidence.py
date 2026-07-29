"""Active-attack evidence capture — raw HTTP request/response proof artifacts.

When a module confirms a vulnerability by actually sending the exploit, this
captures the REAL request that was sent and the response that proved it, plus any
extracted data (DB version, etc.), and attaches them to the finding (extra:
raw_request / raw_response / proof). Those become attach-able report evidence and
are scored by the verification model like any other signal.
"""
from __future__ import annotations

import base64
import time
from urllib.parse import urlparse


def browser_screenshot(ctx, url: str, settle: float = 0.9) -> dict:
    """Execute a GET attack IN the real Selenium browser (visible on the live Attack
    Viewer) and capture a screenshot as visual proof. Also grabs a JS alert's text
    (XSS execution) if one pops. Returns {"screenshot_b64": str, "alert": str|None}.
    """
    out = {"screenshot_b64": "", "alert": None}
    br = getattr(ctx, "browser", None)
    drv = getattr(br, "driver", None) if br is not None else None
    if drv is None or not url:
        return out
    try:
        ctx.rate_limiter.wait()
        try:
            br.get(url)                      # navigate the browser = run the attack on screen
        except Exception:
            pass
        time.sleep(settle)
        # An XSS payload may raise a JS alert — capture its text, then dismiss.
        try:
            al = drv.switch_to.alert
            out["alert"] = al.text
            al.accept()
        except Exception:
            pass
        try:
            br.capture_frame(force=True)     # push this frame to the live viewer
        except Exception:
            pass
        try:
            out["screenshot_b64"] = base64.b64encode(drv.get_screenshot_as_png()).decode("ascii")
        except Exception:
            pass
    except Exception:
        pass
    return out


def _raw_request_from_prepared(req) -> str:
    """Reconstruct the raw HTTP request from a requests PreparedRequest."""
    if req is None:
        return ""
    p = urlparse(getattr(req, "url", "") or "")
    path = (p.path or "/") + (("?" + p.query) if p.query else "")
    lines = [f"{getattr(req, 'method', 'GET')} {path} HTTP/1.1", f"Host: {p.netloc}"]
    for k, v in (getattr(req, "headers", None) or {}).items():
        lines.append(f"{k}: {v}")
    body = getattr(req, "body", None)
    lines.append("")
    if body:
        if isinstance(body, (bytes, bytearray)):
            try:
                body = body.decode("utf-8", "replace")
            except Exception:
                body = str(body)
        lines.append(str(body)[:2000])
    return "\n".join(lines)


def build_raw_response(resp, body_limit: int = 2000) -> str:
    if resp is None:
        return ""
    try:
        reason = getattr(resp, "reason", "") or ""
        head = f"HTTP/1.1 {resp.status_code} {reason}".rstrip()
        hdrs = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        body = (resp.text or "")[:body_limit]
        return f"{head}\n{hdrs}\n\n{body}"
    except Exception:
        return ""


def from_response(finding, resp, proof: dict | None = None, body_limit: int = 2000):
    """Attach raw request/response (from the actual exploit) + optional extracted proof."""
    if finding.extra is None:
        finding.extra = {}
    if resp is not None:
        finding.extra["raw_request"] = _raw_request_from_prepared(getattr(resp, "request", None))
        finding.extra["raw_response"] = build_raw_response(resp, body_limit)
    if proof:
        finding.extra["proof"] = proof
    return finding
