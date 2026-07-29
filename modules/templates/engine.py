"""Template execution engine — turns data templates into scanner modules.

Template schema (dict):
  id, name, category, severity            (required)
  type:  "path" | "param" | "header"      (how it is delivered)
  desc                                    (optional description)
  default: bool                           (checkbox default; default True)
  # path type:
  path: "/x", paths: ["/a","/b"]          (one or many)
  # param type:
  payloads: ["'", "..."]
  # header type:
  header: "X-...", value: "..."
  # matcher (all present conditions must hold):
  match: { status:[200], regex:"...", words:["a","b"], words_mode:"all|any",
           negative_regex:"...", not_status:[404] }
  remediation, impact                     (optional)
"""
from __future__ import annotations

import re
import uuid
from urllib.parse import urljoin, urlparse

from modules.base import BaseModule, register
from core.result import Finding, Severity
from core.injection_points import discover_points, send


class _Resp:
    """Lightweight cached response for baseline comparison."""
    def __init__(self, status, text, headers):
        self.status_code = status
        self.text = text
        self.headers = headers


def _baseline(ctx):
    """Response for a guaranteed-nonexistent path, cached per origin.

    Used to detect 'catch-all 200' / soft-404 sites: if this baseline ALSO
    matches a template's matcher, the signal is not specific to the real path,
    so the finding is suppressed (false positive).
    """
    key = "_bl::" + _base(ctx.target)
    if key in ctx.options:
        return ctx.options[key]
    bl = None
    try:
        url = urljoin(_base(ctx.target), "/" + uuid.uuid4().hex + "_nx404")
        r = ctx.paced_get(url)
        bl = _Resp(r.status_code, r.text or "", dict(r.headers))
    except Exception:
        bl = None
    ctx.options[key] = bl
    return bl

_SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
        "low": Severity.LOW, "info": Severity.INFO}


def _sev(s) -> Severity:
    return _SEV.get(str(s).lower(), Severity.INFO)


def _base(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _matches(m: dict, resp) -> bool:
    if not m:
        return False
    body = resp.text or ""
    if "status" in m and resp.status_code not in m["status"]:
        return False
    if "not_status" in m and resp.status_code in m["not_status"]:
        return False
    if "regex" in m and not re.search(m["regex"], body, re.I):
        return False
    if "negative_regex" in m and re.search(m["negative_regex"], body, re.I):
        return False
    if "words" in m:
        low = body.lower()
        hits = [w for w in m["words"] if w.lower() in low]
        if m.get("words_mode", "all") == "all" and len(hits) != len(m["words"]):
            return False
        if m.get("words_mode") == "any" and not hits:
            return False
    if "header_regex" in m:
        hv = " ".join(f"{k}: {v}" for k, v in resp.headers.items())
        if not re.search(m["header_regex"], hv, re.I):
            return False
    return True


def _finding(t: dict, url: str, evidence: str, request: str = "") -> Finding:
    return Finding(
        module_id=t["id"], title=t["name"], severity=_sev(t.get("severity", "info")),
        url=url, confidence=t.get("confidence", "Firm"),
        description=t.get("desc", t["name"]), evidence=evidence, request=request,
        impact=t.get("impact", ""), remediation=t.get("remediation", ""))


def _run_path(ctx, t) -> list[Finding]:
    base = _base(ctx.target)
    out = []
    paths = t.get("paths") or [t["path"]]
    bl = _baseline(ctx)
    # If the site is a catch-all that even matches on a nonexistent path, the
    # matcher is not specific enough — skip to avoid a false positive.
    if bl is not None and _matches(t["match"], bl):
        return out
    for path in paths:
        if ctx.should_stop():
            break
        url = urljoin(base, path)
        try:
            r = ctx.paced_get(url)
        except Exception:
            continue
        if not _matches(t["match"], r):
            continue
        # Extra guard: near-identical to the soft-404 baseline body => false positive.
        if bl is not None and bl.status_code == r.status_code and \
                abs(len(bl.text) - len(r.text or "")) < 24 and len(r.text or "") > 0:
            continue
        out.append(_finding(t, url, f"GET {url} -> {r.status_code} (signature matched)", f"GET {url}"))
    return out


def _run_param(ctx, t) -> list[Finding]:
    out = []
    points = discover_points(ctx)
    if not points:
        return out
    for pt in points:
        if ctx.should_stop():
            break
        # Baseline: normal value. If the signature already appears without our
        # payload, it is inherent to the page (not injection) -> skip this point.
        base_r = send(ctx, pt, pt.base_params.get(pt.param) or "1")
        if base_r is not None and _matches(t["match"], base_r):
            continue
        hit = False
        for payload in t["payloads"]:
            if ctx.should_stop():
                break
            r = send(ctx, pt, payload)
            if r is not None and _matches(t["match"], r):
                out.append(_finding(t, pt.base_url,
                                    f"Payload {payload!r} triggered the signature on {pt.label()} "
                                    f"(absent in baseline)",
                                    f"{pt.method} {pt.base_url} ({pt.param}=<payload>)"))
                hit = True
                break
        if hit:
            break  # one confirmed point is enough per technique
    return out


def _run_header(ctx, t) -> list[Finding]:
    try:
        r = ctx.paced_request("GET", ctx.target, headers={t["header"]: t["value"]})
    except Exception:
        return []
    if _matches(t["match"], r):
        return [_finding(t, ctx.target,
                        f"Header {t['header']}: {t['value']} matched",
                        f"GET {ctx.target} ({t['header']}: {t['value']})")]
    return []


_RUNNERS = {"path": _run_path, "param": _run_param, "header": _run_header}


def make_template_module(t: dict):
    ttype = t.get("type", "path")
    runner = _RUNNERS[ttype]

    def run(self, ctx):
        try:
            return runner(ctx, t)
        except Exception:
            return []

    cls = type("Tpl_" + t["id"], (BaseModule,), {
        "id": t["id"], "name": t["name"], "category": t.get("category", "Templates"),
        "description": t.get("desc", t["name"]),
        "default_enabled": t.get("default", True),
        "scope": "page" if ttype == "param" else "origin",
        "run": run,
    })
    return register(cls)


def register_templates(templates: list[dict]) -> None:
    for t in templates:
        try:
            make_template_module(t)
        except Exception:
            # skip duplicate/broken template, keep the rest
            pass
