"""Same-origin crawler used for recursive attack-surface expansion.

Given a rendered page, extracts in-scope links and form-derived URLs (carrying
their parameters), normalizes and dedupes them, and prioritizes URLs that have
query parameters (more injectable). The scanner feeds these back into the work
queue so that finding surface leads to testing more surface — deeper coverage.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl, urlencode

from bs4 import BeautifulSoup


def registrable(url: str) -> str:
    return urlparse(url).netloc.split(":")[0].lower()


def normalize(url: str) -> str:
    """Canonical key for dedup: drop fragment, sort query params by name."""
    p = urlparse(url)
    q = sorted(parse_qsl(p.query, keep_blank_values=True))
    return urlunparse(p._replace(query=urlencode(q), fragment="")).rstrip("/")


# Skip binary/asset links that are not worth scanning.
_SKIP_EXT = re.compile(r"\.(png|jpe?g|gif|svg|webp|ico|css|js|woff2?|ttf|eot|mp4|mp3|"
                       r"pdf|zip|gz|tar|rar|7z|dmg|exe|doc[x]?|xls[x]?|ppt[x]?)(\?|$)", re.I)


def extract_links(base_url: str, html: str, scope_host: str) -> list[str]:
    soup = BeautifulSoup(html or "", "html.parser")
    out: dict[str, str] = {}  # normalized -> original

    def consider(raw: str):
        if not raw or raw.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            return
        absu = urljoin(base_url, raw)
        p = urlparse(absu)
        if p.scheme not in ("http", "https"):
            return
        if registrable(absu) != scope_host:
            return
        if _SKIP_EXT.search(p.path):
            return
        out.setdefault(normalize(absu), absu)

    for a in soup.find_all("a", href=True):
        consider(a["href"])
    for form in soup.find_all("form"):
        action = form.get("action") or base_url
        absu = urljoin(base_url, action)
        if registrable(absu) != scope_host:
            continue
        # For GET forms, synthesize a URL carrying the field names as params.
        method = (form.get("method") or "get").lower()
        if method == "get":
            names = [i.get("name") for i in form.find_all(["input", "textarea", "select"]) if i.get("name")]
            if names:
                sep = "&" if urlparse(absu).query else "?"
                consider(absu + sep + urlencode({n: "test" for n in names}))
            else:
                consider(absu)
        else:
            consider(absu)

    # Prioritize URLs that carry query parameters (more injectable).
    links = list(out.values())
    links.sort(key=lambda u: (urlparse(u).query == "", u))
    return links
