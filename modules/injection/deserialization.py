"""Insecure deserialization marker detection (read-only surfacing).

Confirming a deserialization RCE requires crafting gadget chains, which is manual
and destructive. This module safely surfaces serialized-object markers found in
cookies, parameters, storage, and hidden fields as high-value candidates.
"""
from __future__ import annotations

import re

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity
from core.injection_points import discover_points

# (tech, severity, signature) — detect encoded/serialized blobs.
SIGS = [
    ("Java (serialized, base64)", Severity.HIGH, re.compile(r"rO0AB[A-Za-z0-9+/=]{8,}")),
    ("Java (serialized, raw hex)", Severity.HIGH, re.compile(r"aced0005", re.IGNORECASE)),
    (".NET BinaryFormatter (base64)", Severity.HIGH, re.compile(r"AAEAAAD/////[A-Za-z0-9+/=]{8,}")),
    ("PHP serialized object", Severity.MEDIUM, re.compile(r'O:\d+:"[A-Za-z0-9_\\]+":\d+:\{')),
    ("Python pickle (base64)", Severity.HIGH, re.compile(r"\bg[AY][A-Za-z0-9+/=]{10,}")),
    ("Ruby Marshal (base64)", Severity.HIGH, re.compile(r"\bBAh[A-Za-z0-9+/=]{6,}")),
    ("Java viewstate/JSF", Severity.MEDIUM, re.compile(r"javax\.faces\.ViewState")),
]


@register
class Deserialization(BaseModule):
    id = "deserialization"
    name = "Insecure Deserialization Markers"
    category = "Injection"
    description = "Surfaces serialized-object blobs (Java/.NET/PHP/Python/Ruby) in cookies/params/storage."

    def _sources(self, ctx: ScanContext) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        # HTTP cookies.
        try:
            ctx.paced_get(ctx.target)
            for c in ctx.http.cookies:
                out.append((f"cookie:{c.name}", str(c.value)))
        except Exception:
            pass
        # Parameters (values + names).
        for pt in discover_points(ctx):
            out.append((f"param:{pt.param}", str(pt.base_params.get(pt.param, ""))))
        # Browser storage + page.
        driver = getattr(ctx.browser, "driver", None)
        if driver is not None:
            try:
                ctx.rate_limiter.wait()
                if ctx.browser.get(ctx.target):
                    ctx.browser.dismiss_alert()
                    dump = driver.execute_script("""
                        const o={c:document.cookie, ls:{}, ss:{}};
                        try{for(let i=0;i<localStorage.length;i++){const k=localStorage.key(i);o.ls[k]=localStorage.getItem(k);}}catch(e){}
                        try{for(let i=0;i<sessionStorage.length;i++){const k=sessionStorage.key(i);o.ss[k]=sessionStorage.getItem(k);}}catch(e){}
                        return o;""") or {}
                    out.append(("document.cookie", dump.get("c", "")))
                    for k, v in (dump.get("ls") or {}).items():
                        out.append((f"localStorage:{k}", v))
                    for k, v in (dump.get("ss") or {}).items():
                        out.append((f"sessionStorage:{k}", v))
                    out.append(("page", driver.page_source or ""))
            except Exception:
                pass
        return out

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for source, blob in self._sources(ctx):
            if not blob:
                continue
            for tech, sev, rx in SIGS:
                m = rx.search(blob)
                if not m:
                    continue
                key = tech + "|" + source
                if key in seen:
                    continue
                seen.add(key)
                sample = m.group(0)
                findings.append(Finding(
                    module_id=self.id, title=f"{tech} found in {source}",
                    severity=sev, url=ctx.target, confidence="Tentative",
                    description=("A serialized-object blob is exposed to the client. If the server "
                                 "deserializes attacker-controlled data, this may allow RCE. Manual "
                                 "gadget-chain testing required."),
                    evidence=f"{source}: {sample[:60]}…",
                    remediation="Never deserialize untrusted input; use signed/whitelisted formats (JSON)."))
        if not findings:
            ctx.log("    no serialized-object markers found")
        return findings
