"""Out-of-band (OOB) interaction helper for blind vulnerability detection.

SAFETY: OOB payloads only ever point at the user-configured *verification*
canary domain (one they control, e.g. an interactsh / self-hosted logger).
Modules that need OOB MUST skip themselves when no canary is configured, so the
scanner never induces callbacks to internal or third-party hosts.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass


@dataclass
class OOBClient:
    canary_domain: str = ""     # e.g. "abc123.oob.mydomain.com" (you control this)
    poll_url: str = ""          # optional: logger endpoint that echoes seen tokens
    session: object = None      # requests.Session for polling (optional)

    def __post_init__(self):
        self.canary_domain = (self.canary_domain or "").strip().strip("/").lstrip(".")
        self.poll_url = (self.poll_url or "").strip()

    @property
    def enabled(self) -> bool:
        return bool(self.canary_domain)

    def new_token(self, prefix: str = "t") -> str:
        """Unique per-injection token (used as a subdomain label)."""
        return f"{prefix}{uuid.uuid4().hex[:14]}"

    def host(self, token: str) -> str:
        return f"{token}.{self.canary_domain}"

    def payload_url(self, token: str, scheme: str = "http", path: str = "/") -> str:
        return f"{scheme}://{self.host(token)}{path}"

    def check(self, token: str) -> bool:
        """If a poll_url logger is configured, ask it whether `token` was seen.

        Convention: GET poll_url?token=<token>; a 200 whose body contains the
        token means the canary received an interaction. Returns False when no
        logger is configured (caller then reports the finding as needing manual
        OOB verification and prints the token to look for).
        """
        if not self.poll_url or self.session is None:
            return False
        try:
            r = self.session.get(self.poll_url, params={"token": token}, timeout=10)
            return r.status_code == 200 and token in (r.text or "")
        except Exception:
            return False
