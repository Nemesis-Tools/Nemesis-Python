"""Discover injectable surfaces (query params + HTML forms) on a page."""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin

from bs4 import BeautifulSoup


@dataclass
class FormField:
    name: str
    ftype: str = "text"
    value: str = ""


@dataclass
class DiscoveredForm:
    action: str
    method: str  # "get" | "post"
    fields: list[FormField] = field(default_factory=list)

    @property
    def field_names(self) -> list[str]:
        return [f.name for f in self.fields if f.name]


def fetch_html(ctx) -> str:
    """Return rendered page HTML, preferring the browser DOM, falling back to HTTP.

    Cached per target in ctx.options so multiple Auth/Logic modules share one load.
    """
    cache_key = "_html::" + ctx.target
    cached = ctx.options.get(cache_key)
    if cached is not None:
        return cached
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
    ctx.options[cache_key] = html
    return html


def parse_forms(page_url: str, html_source: str) -> list[DiscoveredForm]:
    soup = BeautifulSoup(html_source, "html.parser")
    forms: list[DiscoveredForm] = []
    for form in soup.find_all("form"):
        action = form.get("action") or page_url
        action = urljoin(page_url, action)
        method = (form.get("method") or "get").strip().lower()
        method = "post" if method == "post" else "get"
        fields: list[FormField] = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            ftype = (inp.get("type") or ("textarea" if inp.name == "textarea" else "text")).lower()
            if ftype in ("submit", "button", "image", "reset", "file"):
                continue
            fields.append(FormField(name=name, ftype=ftype, value=inp.get("value") or ""))
        if fields:
            forms.append(DiscoveredForm(action=action, method=method, fields=fields))
    return forms
