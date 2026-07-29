"""Report generation (JSON + self-contained HTML)."""
from __future__ import annotations

import html
import json
import time
from typing import Iterable

from core.result import Finding, Severity

_SEV_COLOR = {
    "Critical": "#7b1fa2",
    "High": "#c62828",
    "Medium": "#ef6c00",
    "Low": "#f9a825",
    "Info": "#546e7a",
}


_DEFAULT_IMPACT = {
    "Critical": "공격자가 시스템/계정을 완전히 장악하거나 임의 코드 실행이 가능하여 서비스에 치명적 영향을 줄 수 있습니다.",
    "High": "민감 데이터 유출, 계정 탈취, 권한 상승 등 중대한 피해로 이어질 수 있습니다.",
    "Medium": "특정 조건에서 사용자 피해(정보 유출·요청 위조 등)로 이어질 수 있습니다.",
    "Low": "직접적 피해는 제한적이나 다른 취약점과 결합 시 위험이 커질 수 있습니다.",
    "Info": "즉각적 위험은 낮으나 공격 표면 정보로 활용될 수 있어 확인이 필요합니다.",
}


import re as _re
from urllib.parse import urlparse as _urlparse
from core.report_meta import classify


def _method_url(finding: Finding):
    req = finding.request or f"GET {finding.url}"
    m = _re.match(r"^([A-Z]+)\s+(\S+)", req)
    if m:
        return m.group(1), m.group(2), req
    return "GET", finding.url, req


def _param_of(finding: Finding) -> str:
    for src in (finding.request or "", finding.title or ""):
        m = _re.search(r"\(([A-Za-z0-9_\[\]$.\-]+)\s*=", src)
        if m:
            return m.group(1)
    m = _re.search(r"parameter '([^']+)'|query:([^\s]+)|form:([^\s]+)|in '([^']+)'", finding.title or "")
    if m:
        return next((g for g in m.groups() if g), "N/A")
    return "N/A"


def _raw_request(finding: Finding) -> str:
    method, url, note = _method_url(finding)
    p = _urlparse(url)
    path = (p.path or "/") + (f"?{p.query}" if p.query else "")
    out = [f"{method} {path} HTTP/1.1", f"Host: {p.netloc}",
           "User-Agent: Mozilla/5.0 (Nemesis/1.0)", "Accept: */*"]
    hm = _re.search(r"\(([A-Za-z0-9\-]+):\s*([^)]+)\)", note)
    if hm:
        out.append(f"{hm.group(1)}: {hm.group(2).strip()}")
    if method in ("POST", "PUT", "PATCH"):
        out.append("Content-Type: application/x-www-form-urlencoded")
        bm = _re.search(r"\(([^)]*=[^)]*)\)", note)
        out.append("")
        out.append(bm.group(1) if bm else "")
    else:
        out.append("")
    return "\n".join(out)


def finding_to_report_md(target: str, finding: Finding, index: int | None = None) -> str:
    """Render one finding as a professional (HackerOne-style) English report."""
    m = classify(finding)
    sev = finding.severity.value
    num = f"{index}. " if index is not None else ""
    param = _param_of(finding)
    method, url, _ = _method_url(finding)
    p = _urlparse(finding.url)
    score = m["score"]
    L: list[str] = []

    L.append(f"# {num}{finding.title}")
    L.append("")
    L.append("## Summary")
    L.append("")
    L.append("| Field | Value |")
    L.append("|---|---|")
    L.append(f"| Severity | {sev} (CVSS {score}) |")
    L.append(f"| CWE | {m['cwe']} — {m['name']} |")
    L.append(f"| CVSS v3.1 | `{m['vector']}` ({score}) |")
    L.append(f"| OWASP | {m['owasp']} |")
    L.append(f"| CAPEC | {m['capec']} |")
    L.append(f"| Affected Endpoint | `{p.scheme}://{p.netloc}{p.path or '/'}` |")
    L.append(f"| Affected Parameter | `{param}` |")
    L.append(f"| Authentication Required | No (unauthenticated) |")
    L.append(f"| User Interaction | {m['user_interaction']} |")
    L.append(f"| Detection Confidence | {finding.confidence} |")
    L.append("")

    L.append("## Executive Summary")
    L.append(finding.description or finding.title)
    if finding.impact:
        L.append("")
        L.append(finding.impact)
    L.append("")

    L.append("## Vulnerability Details")
    L.append("")
    L.append("### Root Cause")
    L.append(finding.description or f"The application is affected by {m['name']} ({m['cwe']}).")
    L.append("")
    L.append("### Technical Description")
    L.append(f"The endpoint `{p.path or '/'}` processes attacker-controlled input"
             + (f" via the `{param}` parameter" if param != "N/A" else "")
             + f" in a manner that results in {m['name']} ({m['cwe']}). "
             "The behaviour was observed by the scanner as documented in the Evidence section.")
    L.append("")
    L.append("### Attack Flow")
    L.append("```")
    L.append(m["flow"])
    L.append("```")
    L.append("")

    L.append("## Affected Assets")
    L.append("")
    L.append(f"- **URL:** `{finding.url}`")
    L.append(f"- **Method:** {method}")
    L.append(f"- **Parameter:** `{param}`")
    L.append(f"- **Host:** {p.netloc}")
    L.append(f"- **Authentication:** Not required")
    L.append("")

    L.append("## Proof of Concept")
    L.append("")
    L.append("```bash")
    curl_url = url if url.startswith("http") else finding.url
    L.append(f"curl -i -sk '{curl_url}'")
    L.append("```")
    L.append("")

    L.append("## HTTP Request")
    L.append("")
    L.append("```http")
    L.append(_raw_request(finding))
    L.append("```")
    L.append("")

    L.append("## HTTP Response")
    L.append("*(excerpt — sensitive data masked)*")
    L.append("")
    L.append("```")
    L.append(finding.evidence or "<see scan evidence>")
    L.append("```")
    L.append("")

    L.append("## Steps To Reproduce")
    L.append(f"1. Send the request shown in **HTTP Request** to `{p.netloc}`.")
    if param != "N/A":
        L.append(f"2. Observe that the `{param}` parameter is processed unsafely.")
    else:
        L.append(f"2. Observe the response for the vulnerable endpoint `{p.path or '/'}`.")
    L.append("3. Confirm the indicator described in **Evidence** appears in the response.")
    L.append("4. The result is reproducible on every request under the same conditions.")
    L.append("")

    L.append("## Security Impact")
    L.append("")
    vec = m["vector"]
    conf = "High" if "C:H" in vec else ("Low" if "C:L" in vec else "None")
    integ = "High" if "I:H" in vec else ("Low" if "I:L" in vec else "None")
    avail = "High" if "A:H" in vec else ("Low" if "A:L" in vec else "None")
    L.append(f"- **Confidentiality:** {conf}")
    L.append(f"- **Integrity:** {integ}")
    L.append(f"- **Availability:** {avail}")
    L.append(f"- **Business Impact:** {finding.impact or 'See Executive Summary.'}")
    L.append("")

    L.append("## Risk Assessment")
    L.append("")
    L.append("| Metric | Value |")
    L.append("|---|---|")
    L.append(f"| CVSS Vector | `{vec}` |")
    L.append(f"| Base Score | {score} ({sev}) |")
    L.append(f"| Attack Vector | {'Network' if 'AV:N' in vec else 'Adjacent/Local'} |")
    L.append(f"| Attack Complexity | {'High' if 'AC:H' in vec else 'Low'} |")
    L.append(f"| Privileges Required | {'None' if 'PR:N' in vec else ('Low' if 'PR:L' in vec else 'High')} |")
    L.append(f"| Scope | {'Changed' if 'S:C' in vec else 'Unchanged'} |")
    L.append("")

    if m.get("rc"):
        lang, code = m["rc"]
        L.append("## Root Cause Analysis")
        L.append("")
        L.append(f"Representative vulnerable pattern ({lang}):")
        L.append("")
        L.append(f"```{lang}")
        L.append(code)
        L.append("```")
        L.append("")

    L.append("## Remediation")
    L.append(finding.remediation or "Apply input validation, output encoding, and least-privilege controls appropriate to this weakness.")
    L.append("")

    L.append("## References")
    for r in m["references"]:
        L.append(f"- {r}")
    L.append("")

    L.append("## Evidence")
    L.append("")
    L.append(f"- **Request:** see HTTP Request section")
    L.append(f"- **Response indicator:** `{(finding.evidence or '')[:160]}`")
    L.append(f"- **Detection module:** `{finding.module_id}`")
    L.append("")

    L.append("## Timeline")
    L.append("")
    L.append("| Event | Date |")
    L.append("|---|---|")
    L.append(f"| Discovery | {time.strftime('%Y-%m-%d')} |")
    L.append("| Submission | Pending |")
    L.append("| Acknowledgement | Pending |")
    L.append("| Resolved | Pending |")
    L.append("| Disclosure | Pending |")
    L.append("")
    return "\n".join(L)


def findings_to_report_md(target: str, findings: Iterable[Finding]) -> str:
    findings = sorted(findings, key=lambda f: f.severity.rank, reverse=True)
    counts = _counts(list(findings))
    head = [
        f"# Security Assessment Report — {target}",
        "",
        f"- Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- Total findings: {len(findings)} "
        f"(Critical {counts['Critical']} / High {counts['High']} / Medium {counts['Medium']} "
        f"/ Low {counts['Low']} / Info {counts['Info']})",
        "",
        "> Prepared for authorized security testing. Verify each finding (especially "
        "Tentative confidence) before submission; do not overstate severity.",
        "",
        "---",
        "",
    ]
    body = []
    for i, f in enumerate(findings, start=1):
        body.append(finding_to_report_md(target, f, index=i))
        body.append("\n---\n")
    return "\n".join(head) + "\n".join(body)


def to_json(target: str, findings: Iterable[Finding]) -> str:
    findings = list(findings)
    doc = {
        "target": target,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def _counts(findings: list[Finding]) -> dict[str, int]:
    c = {s.value: 0 for s in Severity}
    for f in findings:
        c[f.severity.value] += 1
    return c


def to_html(target: str, findings: Iterable[Finding]) -> str:
    findings = sorted(findings, key=lambda f: f.severity.rank, reverse=True)
    counts = _counts(findings)
    esc = html.escape

    chips = "".join(
        f'<span class="chip" style="background:{_SEV_COLOR[s]}">{s}: {counts[s]}</span>'
        for s in ["Critical", "High", "Medium", "Low", "Info"]
    )

    rows = []
    for f in findings:
        color = _SEV_COLOR[f.severity.value]
        rows.append(f"""
        <div class="card">
          <div class="card-head" style="border-left:6px solid {color}">
            <span class="sev" style="background:{color}">{esc(f.severity.value)}</span>
            <span class="title">{esc(f.title)}</span>
            <span class="conf">{esc(f.confidence)}</span>
          </div>
          <div class="card-body">
            <div class="meta"><b>Module:</b> {esc(f.module_id)}</div>
            <div class="meta"><b>URL:</b> <code>{esc(f.url)}</code></div>
            {f'<p>{esc(f.description)}</p>' if f.description else ''}
            {f'<div class="lbl">Evidence</div><pre>{esc(f.evidence)}</pre>' if f.evidence else ''}
            {f'<div class="lbl">Request</div><pre>{esc(f.request)}</pre>' if f.request else ''}
            {f'<div class="lbl">Remediation</div><p>{esc(f.remediation)}</p>' if f.remediation else ''}
          </div>
        </div>""")

    body = "\n".join(rows) or '<p class="empty">No findings.</p>'
    generated = time.strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Bug Bounty Report — {esc(target)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; background:#f4f5f7; color:#1a1a1a; }}
  header {{ background:#1e2530; color:#fff; padding:24px 32px; }}
  header h1 {{ margin:0 0 6px; font-size:20px; }}
  header .sub {{ opacity:.8; font-size:13px; }}
  .chips {{ padding:16px 32px; display:flex; gap:8px; flex-wrap:wrap; }}
  .chip {{ color:#fff; padding:4px 12px; border-radius:20px; font-size:12px; font-weight:600; }}
  main {{ padding:8px 32px 48px; max-width:1000px; }}
  .card {{ background:#fff; border-radius:8px; margin:14px 0; box-shadow:0 1px 3px rgba(0,0,0,.12); overflow:hidden; }}
  .card-head {{ display:flex; align-items:center; gap:12px; padding:12px 16px; background:#fafbfc; }}
  .sev {{ color:#fff; font-size:11px; font-weight:700; padding:2px 8px; border-radius:4px; }}
  .title {{ font-weight:600; flex:1; }}
  .conf {{ font-size:11px; color:#666; }}
  .card-body {{ padding:12px 20px; }}
  .meta {{ font-size:13px; margin:4px 0; }}
  .lbl {{ font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:#888; margin:12px 0 4px; }}
  pre {{ background:#0d1117; color:#c9d1d9; padding:10px; border-radius:6px; overflow-x:auto; font-size:12px; }}
  code {{ background:#eee; padding:1px 5px; border-radius:4px; font-size:12px; }}
  .empty {{ color:#888; padding:32px; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background:#0d1117; color:#c9d1d9; }}
    .card {{ background:#161b22; }}
    .card-head {{ background:#1c2128; }}
    code {{ background:#30363d; color:#c9d1d9; }}
  }}
</style></head><body>
<header>
  <h1>Bug Bounty Scan Report</h1>
  <div class="sub">Target: {esc(target)} &nbsp;•&nbsp; Generated: {generated} &nbsp;•&nbsp; {len(findings)} finding(s)</div>
</header>
<div class="chips">{chips}</div>
<main>{body}</main>
</body></html>"""
