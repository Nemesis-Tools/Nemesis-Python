"""Unified discovery of injectable points (query params + form fields) and a
single send() abstraction over GET/POST. Lets injection modules test every
surface thoroughly without each re-implementing form handling.

Discovery is cached per scan (keyed by target) in ctx.options so multiple
modules share one page load.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse, urlunparse

from core.http_utils import parse_query_params
from core.discovery import parse_forms


@dataclass
class InjectionPoint:
    method: str                       # "GET" | "POST"
    base_url: str                     # URL without query (path target for the request)
    param: str                        # the parameter being fuzzed
    base_params: dict = field(default_factory=dict)
    where: str = "query"              # "query" | "form"

    def label(self) -> str:
        return f"{self.method} {self.where}:{self.param}"


def _strip_query(url: str) -> str:
    p = urlparse(url)
    return urlunparse(p._replace(query="", fragment=""))


def discover_points(ctx, include_forms: bool = True) -> list[InjectionPoint]:
    cache_key = "_points::" + ctx.target
    cached = ctx.options.get(cache_key)
    if cached is not None:
        return cached

    points: list[InjectionPoint] = []

    # 1) Query parameters on the target URL.
    q = parse_query_params(ctx.target)
    base_q = {p.name: p.value for p in q}
    base_url = _strip_query(ctx.target)
    for p in q:
        points.append(InjectionPoint("GET", base_url, p.name, dict(base_q), "query"))

    # 2) Forms — prefer the browser-rendered DOM (catches JS-built forms).
    if include_forms:
        html = ""
        driver = getattr(ctx.browser, "driver", None)
        try:
            if driver is not None:
                ctx.rate_limiter.wait()
                if ctx.browser.get(ctx.target):
                    ctx.browser.dismiss_alert()
                    html = driver.page_source or ""
        except Exception:
            html = ""
        if not html:
            try:
                r = ctx.paced_get(ctx.target)
                html = r.text or ""
            except Exception:
                html = ""
        if html:
            for form in parse_forms(ctx.target, html):
                defaults = {f.name: (f.value or "test") for f in form.fields}
                furl = _strip_query(form.action)
                for fname in form.field_names:
                    points.append(InjectionPoint(
                        form.method.upper(), furl, fname, dict(defaults), "form"))

    ctx.options[cache_key] = points
    return points


def attack_url(point: InjectionPoint, value: str) -> str | None:
    """Full GET URL carrying `value` in `point.param` — for re-executing the confirmed
    attack inside the Selenium browser (visible on the live view) and screenshotting it.
    Returns None for non-GET points (no navigable URL)."""
    if point.method != "GET":
        return None
    params = dict(point.base_params)
    params[point.param] = value
    from urllib.parse import urlencode
    return point.base_url + ("?" + urlencode(params) if params else "")


def send(ctx, point: InjectionPoint, value: str, **kwargs):
    """Send a request with `point.param` set to `value`; returns a Response or None."""
    params = dict(point.base_params)
    params[point.param] = value
    try:
        if point.method == "POST":
            ctx.rate_limiter.wait()
            return ctx.http.post(point.base_url, data=params, **kwargs)
        ctx.rate_limiter.wait()
        return ctx.http.get(point.base_url, params=params, **kwargs)
    except Exception:
        return None
