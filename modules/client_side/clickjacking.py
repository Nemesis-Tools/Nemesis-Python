"""Clickjacking / framing protection check — with active exploitability proof.

Beyond checking for X-Frame-Options / CSP frame-ancestors, this module *proves*
exploitability: it renders the target inside an attacker-controlled iframe (from a
different origin) in the real browser and captures a screenshot showing the page
framed under a bait overlay. It also surfaces sensitive actions on the page and
emits a ready-to-attach PoC HTML artifact — the evidence reviewers ask for.
"""
from __future__ import annotations

import base64
import os
import re
import tempfile
import time

from modules.base import BaseModule, ScanContext, register
from core.result import Finding, Severity

# Sensitive/state-changing UI whose one-click abuse makes clickjacking impactful.
_SENSITIVE_UI = re.compile(
    r"구독|팔로우|follow|subscribe|결제|구매|purchase|checkout|\bpay\b|송금|transfer|"
    r"후원|donate|삭제|delete|설정|settings|비밀번호|password|로그아웃|logout|"
    r"좋아요|\blike\b|신고|report|차단|block|승인|approve|권한|grant", re.I)


@register
class Clickjacking(BaseModule):
    id = "clickjacking"
    name = "Clickjacking (framing) protection"
    category = "Client-Side"
    description = ("Checks X-Frame-Options / CSP frame-ancestors AND actively proves framing by rendering "
                   "the target in an attacker iframe (screenshot + PoC HTML attached).")

    def _poc_html(self, target: str) -> str:
        """Attacker page: frames the target under a bait button (semi-transparent to prove framing)."""
        return (
            "<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\">\n"
            "<title>Clickjacking PoC</title>\n<style>\n"
            "  html,body{margin:0;height:100%;font-family:system-ui,sans-serif}\n"
            "  .stage{position:relative;width:100%;height:100vh;overflow:hidden}\n"
            "  /* Real attacks use opacity ~0.02; 0.5 here so the screenshot PROVES the target is framed. */\n"
            "  iframe{position:absolute;inset:0;width:100%;height:100%;border:0;opacity:.5}\n"
            "  .bait{position:absolute;z-index:10;top:44%;left:50%;transform:translateX(-50%);\n"
            "        padding:16px 30px;background:#e11d48;color:#fff;font-size:20px;font-weight:700;\n"
            "        border:0;border-radius:10px;cursor:pointer;box-shadow:0 6px 20px #0006}\n"
            "  .note{position:absolute;z-index:11;top:12px;left:12px;background:#000b;color:#fff;\n"
            "        padding:8px 12px;font-size:13px;border-radius:6px;max-width:80%}\n"
            "</style></head><body>\n"
            "  <div class=\"stage\">\n"
            "    <div class=\"note\">Clickjacking PoC — 대상 페이지가 외부 origin의 iframe 안에 로드됨(프레이밍 방어 부재 입증).\n"
            "      실제 공격에서는 iframe opacity≈0 으로 숨기고, 아래 미끼 버튼 위치에 대상의 민감 버튼을 정렬합니다.</div>\n"
            f"    <button class=\"bait\">🎁 무료 상품 받기 (클릭 유도)</button>\n"
            f"    <iframe src=\"{target}\"></iframe>\n"
            "  </div>\n</body></html>\n"
        )

    def _prove_framing(self, ctx: ScanContext, target: str, poc_html: str):
        """Render the PoC in the real browser and screenshot it. Returns (b64_png, ok)."""
        drv = getattr(ctx.browser, "driver", None)
        if drv is None:
            return "", False
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(suffix="_cj_poc.html")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(poc_html)
            file_url = "file:///" + tmp.replace("\\", "/")
            ctx.rate_limiter.wait()
            if not ctx.browser.get(file_url):
                return "", False
            time.sleep(1.5)                       # allow the framed target to load
            try:
                ctx.browser.dismiss_alert()
            except Exception:
                pass
            png = drv.get_screenshot_as_png()
            return base64.b64encode(png).decode("ascii"), True
        except Exception as e:
            ctx.log(f"    framing proof failed: {e}")
            return "", False
        finally:
            try:
                if tmp and os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass

    def run(self, ctx: ScanContext) -> list[Finding]:
        try:
            resp = ctx.paced_get(ctx.target)
        except Exception as e:
            ctx.log(f"    request failed: {e}")
            return []

        headers = {k.lower(): v for k, v in resp.headers.items()}
        xfo = headers.get("x-frame-options", "")
        csp = headers.get("content-security-policy", "")
        has_frame_ancestors = "frame-ancestors" in csp.lower()

        if bool(xfo) or has_frame_ancestors:
            ctx.log(f"    framing protection present (XFO='{xfo}', frame-ancestors={has_frame_ancestors})")
            return []

        # Sensitive UI on the page → raises real-world impact of clickjacking.
        body = resp.text or ""
        sensitive = sorted({m.group(0) for m in _SENSITIVE_UI.finditer(body)}, key=str.lower)[:12]

        # Active proof: render the target in an attacker iframe and screenshot it.
        poc_html = self._poc_html(ctx.target)
        ctx.log("    proving framing: rendering target inside a cross-origin iframe…")
        shot_b64, proven = self._prove_framing(ctx, ctx.target, poc_html)

        evidence = [
            f"대상 URL: {ctx.target}",
            f"X-Frame-Options: {xfo or '없음'}",
            f"Content-Security-Policy: {'frame-ancestors 미설정' if not has_frame_ancestors else csp}",
            f"프레이밍 실증: {'성공 — 대상이 외부 iframe에 렌더링됨(스크린샷 첨부)' if proven else '스크린샷 미획득(헤더 근거로 프레이밍 가능)'}",
        ]
        if sensitive:
            evidence.append("발견된 민감 기능(추정): " + ", ".join(sensitive))

        return [Finding(
            module_id=self.id,
            title="클릭재킹 방어 부재 — 페이지 프레이밍 가능(실증 포함)" if proven
                  else "Missing clickjacking protection (page is framable)",
            severity=Severity.MEDIUM,
            url=ctx.target,
            confidence="Confirmed" if proven else "Firm",
            description=("응답 헤더에 X-Frame-Options 및 CSP frame-ancestors 지시어가 없어 외부 사이트에서 "
                         "iframe으로 페이지를 삽입할 수 있습니다. 공격자는 투명/위장 iframe으로 페이지를 "
                         "삽입하고 사용자의 클릭을 유도하여 의도하지 않은 기능을 실행하게 만들 수 있습니다(UI Redressing)."),
            evidence="\n".join(evidence),
            impact=("사용자가 로그인된 상태에서 악성 페이지의 iframe을 통해 대상의 민감 기능"
                    "(설정 변경·구독·팔로우·결제 등)을 의도치 않게 실행할 수 있습니다."),
            remediation=("클릭재킹 방지를 위해 다음 중 하나 이상을 적용: "
                         "X-Frame-Options: DENY(또는 SAMEORIGIN), "
                         "그리고/또는 Content-Security-Policy: frame-ancestors 'none'(또는 'self')."),
            extra={
                "poc_html": poc_html,
                "screenshot_b64": shot_b64,
                "framing_proven": proven,
                "sensitive_actions": sensitive,
                "xfo": xfo,
                "csp": csp,
                "has_frame_ancestors": has_frame_ancestors,
            },
        )]
