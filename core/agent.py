"""Autonomous attack agent — ML-guided target prioritization.

While crawling, the agent scores every discovered link/page for *attack value* so
the scanner walks the most promising targets first (injectable-looking parameters,
admin/api/search/upload paths, redirectors, …) rather than blindly BFS. Each chosen
page is navigated in the real Selenium browser, so the live view shows the agent
moving through the site's menus and attacking. The learned finding-verifier
(core.ml_model) still judges every result.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qsl

# Parameter names that frequently carry injectable / sensitive input.
_HIGH_PARAMS = re.compile(
    r"^(id|uid|pid|sid|user|username|file|filename|path|page|url|uri|redirect|redir|next|"
    r"return|returnurl|dest|q|query|search|keyword|cat|category|order|sort|dir|doc|item|"
    r"ref|callback|template|tpl|view|action|cmd|exec|run|load|include|inc|src|data|report)$", re.I)
# Path segments that indicate high-value functionality.
_HIGH_PATHS = re.compile(
    r"admin|login|signin|api|graphql|search|upload|account|profile|settings|user|order|"
    r"payment|checkout|cart|report|config|debug|actuator|redirect|download|file|export|"
    r"import|proxy|fetch|preview|render|callback", re.I)
# Static assets — no attack value.
_LOW_EXT = re.compile(r"\.(png|jpe?g|gif|svg|webp|ico|css|js|woff2?|ttf|eot|pdf|mp4|mp3|"
                      r"zip|gz|tar|rar|7z|dmg|exe|woff)(\?|$)", re.I)


def target_priority(url: str) -> float:
    """Attack-priority score in [0,1] for a candidate URL/link (agent policy)."""
    try:
        p = urlparse(url or "")
    except Exception:
        return 0.1
    path = p.path or "/"
    if _LOW_EXT.search(path):
        return 0.03
    params = parse_qsl(p.query, keep_blank_values=True)
    score = 0.20
    if params:
        score += 0.30                                    # has attackable parameters
        hp = sum(1 for k, _ in params if _HIGH_PARAMS.match(k or ""))
        score += min(hp * 0.20, 0.40)                    # high-value parameter names
    if _HIGH_PATHS.search(path):
        score += 0.25                                    # high-value functionality path
    depth = path.strip("/").count("/")
    if depth >= 5:
        score -= 0.05                                    # very deep pages slightly lower
    return max(0.0, min(1.0, score))


def order_frontier(frontier):
    """Sort a crawl frontier [(url, depth), ...] by descending attack priority."""
    return sorted(frontier, key=lambda it: target_priority(it[0]), reverse=True)


def rank(urls):
    """Return urls sorted most-attack-worthy first (with scores) — for logging/telemetry."""
    return sorted(((u, target_priority(u)) for u in urls), key=lambda x: x[1], reverse=True)
