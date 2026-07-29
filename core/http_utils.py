"""Lightweight HTTP + URL helpers used by modules.

Selenium drives the real browser for client-side checks, but for raw response
inspection (headers, CORS, redirects) a plain HTTP client is more precise. Both
are made available to modules via ScanContext.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

import requests


def same_domain(a: str, b: str) -> bool:
    return urlparse(a).netloc.split(":")[0] == urlparse(b).netloc.split(":")[0]


def registrable(url: str) -> str:
    return urlparse(url).netloc.split(":")[0]


@dataclass
class Param:
    """An injectable input point."""
    name: str
    value: str
    where: str  # "query" | "form"
    form_action: str = ""
    form_method: str = "get"
    css_hint: str = ""


def parse_query_params(url: str) -> list[Param]:
    q = urlparse(url).query
    return [Param(name=k, value=v, where="query") for k, v in parse_qsl(q, keep_blank_values=True)]


def build_url_with_param(url: str, name: str, value: str) -> str:
    """Return `url` with query parameter `name` set to `value`."""
    parts = urlparse(url)
    params = dict(parse_qsl(parts.query, keep_blank_values=True))
    params[name] = value
    new_query = urlencode(params, doseq=True)
    return urlunparse(parts._replace(query=new_query))


def parse_headers_block(text: str) -> dict[str, str]:
    """Parse a multi-line 'Name: value' block into a dict."""
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip()
        if name:
            out[name] = value.strip()
    return out


def parse_cookie_string(text: str) -> dict[str, str]:
    """Parse 'k=v; k2=v2' (or newline-separated) into a dict."""
    out: dict[str, str] = {}
    for chunk in (text or "").replace("\n", ";").split(";"):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        k, v = chunk.split("=", 1)
        k = k.strip()
        if k:
            out[k] = v.strip()
    return out


def make_session(timeout: int = 15, user_agent: str | None = None,
                 verify_tls: bool = True,
                 extra_headers: dict[str, str] | None = None,
                 cookies: dict[str, str] | None = None) -> requests.Session:
    s = requests.Session()
    s.verify = verify_tls
    s.headers.update({
        "User-Agent": user_agent or
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Nemesis/1.0 (+authorized-testing)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    # Program-issued credential headers (e.g. Authorization, X-Bug-Bounty token).
    if extra_headers:
        s.headers.update(extra_headers)
    if cookies:
        for k, v in cookies.items():
            s.cookies.set(k, v)
    # Attach a default timeout via a wrapper.
    orig = s.request

    def _request(method, url, **kwargs):
        kwargs.setdefault("timeout", timeout)
        return orig(method, url, **kwargs)

    s.request = _request  # type: ignore[assignment]
    return s
