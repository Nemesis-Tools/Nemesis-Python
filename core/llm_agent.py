"""Gemini-powered vulnerability-analysis agent (`/test`).

Attaches a Google Gemini agent (Google Gen AI SDK) that:

  1. Recons the target homepage (title, forms, links, tech, headers) so Gemini
     understands the actual attack surface.
  2. Receives every finding the local ML/DL verifier already produced, with its
     rule score and P(true-positive), and reasons over them as a security
     expert — judging which are real, re-rating severity, and proposing the
     next concrete attacks.
  3. Feeds Gemini's per-finding verdicts back into models/feedback.jsonl as
     training labels, so the local char-gram MLP keeps *learning from Gemini*.

The Gemini agent runs ALONGSIDE the deep-learning model, not instead of it:
the ML model does fast, offline triage on every finding; Gemini does the deep,
context-aware reasoning on demand when the operator runs `/test`.

Authorised use only. The API key is supplied by the operator (env
GEMINI_API_KEY / GOOGLE_API_KEY or the terminal `/geminikey` field) and is
never stored by the app.
"""
from __future__ import annotations

import json
import os
from urllib.parse import urljoin, urlparse

import requests
import urllib3

# Recon hits authorised targets with verify=False (bug-bounty hosts often carry
# self-signed/expired certs); silence the per-request warning.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from bs4 import BeautifulSoup
except Exception:  # pragma: no cover
    BeautifulSoup = None

try:
    from google import genai
    from google.genai import types as genai_types
except Exception:  # pragma: no cover - SDK optional until /test is used
    genai = None
    genai_types = None

MODEL = "gemini-2.5-flash"

# Human-readable JSON contract described to Gemini (response_mime_type=json).
_SCHEMA_HINT = """{
  "overall_risk": "Critical|High|Medium|Low|Info",
  "site_summary": "string",
  "attack_surface": ["string", ...],
  "findings": [
    {"index": int, "title": "string", "is_real": true/false,
     "severity": "Critical|High|Medium|Low|Info", "confidence": 0.0-1.0,
     "reasoning": "string"}
  ],
  "recommended_attacks": [
    {"technique": "string", "target": "string", "why": "string", "priority": 0.0-1.0}
  ],
  "notes": "string"
}"""

_SYSTEM = (
    "You are Nemesis, an expert offensive-security analyst assisting an AUTHORISED "
    "bug-bounty engagement. You are given (a) a recon summary of the target site and "
    "(b) findings already produced by a local machine-learning vulnerability scanner, "
    "each with a rule score and the model's estimated probability of being a true "
    "positive. Reason like a senior pentester. For EACH finding decide whether it is a "
    "genuine, exploitable vulnerability (is_real) and give a calibrated severity + "
    "confidence with concrete reasoning grounded in the recon evidence — do not just "
    "echo the scanner. Then propose the highest-value next attacks against the observed "
    "attack surface (injectable parameters, auth flows, redirectors, uploads, APIs). Be "
    "precise and evidence-based; mark a finding is_real=false when the evidence does not "
    "support exploitability (reduce false positives). Respond ONLY with a JSON object "
    "matching this shape (no markdown, no prose):\n" + _SCHEMA_HINT
)


def available() -> bool:
    """True if the Gemini agent can run (SDK importable)."""
    return genai is not None


def key_available(api_key: str | None = None) -> bool:
    """True if an API key is resolvable (explicit arg or env)."""
    return bool((api_key or "").strip()
                or os.environ.get("GEMINI_API_KEY")
                or os.environ.get("GOOGLE_API_KEY"))


# ---- recon -------------------------------------------------------------------

def recon(target: str, timeout: float = 12.0) -> dict:
    """Cheap homepage recon → compact attack-surface summary for the prompt."""
    info: dict = {"url": target, "final_url": target, "status": None,
                  "title": "", "server": "", "powered_by": "", "cookies": [],
                  "forms": [], "links": [], "scripts": [], "params": [], "html": ""}
    try:
        r = requests.get(target, timeout=timeout, allow_redirects=True, verify=False,
                         headers={"User-Agent": "Mozilla/5.0 Nemesis-recon"})
    except Exception as e:
        info["error"] = str(e)
        return info
    info["status"] = r.status_code
    info["final_url"] = r.url or target
    info["server"] = r.headers.get("Server", "")
    info["powered_by"] = r.headers.get("X-Powered-By", "")
    sc = r.headers.get("Set-Cookie", "")
    if sc:
        info["cookies"] = [c.split("=", 1)[0].strip() for c in sc.split(",") if "=" in c][:12]
    html = r.text or ""
    info["html"] = html[:4000]
    origin = urlparse(info["final_url"]).netloc
    if BeautifulSoup is None:
        return info
    try:
        soup = BeautifulSoup(html, "html.parser")
        if soup.title and soup.title.string:
            info["title"] = soup.title.string.strip()[:200]
        for f in soup.find_all("form")[:15]:
            fields = [i.get("name") or i.get("id") or i.get("type")
                      for i in f.find_all(["input", "textarea", "select"])]
            info["forms"].append({
                "action": urljoin(info["final_url"], f.get("action") or ""),
                "method": (f.get("method") or "get").upper(),
                "fields": [x for x in fields if x][:20],
            })
        seen = set()
        for a in soup.find_all("a", href=True):
            u = urljoin(info["final_url"], a["href"])
            p = urlparse(u)
            if p.netloc and p.netloc != origin:
                continue
            if u in seen:
                continue
            seen.add(u)
            if p.query:
                for kv in p.query.split("&"):
                    k = kv.split("=", 1)[0]
                    if k and k not in info["params"]:
                        info["params"].append(k)
            if len(info["links"]) < 50:
                info["links"].append(u)
        info["scripts"] = [urljoin(info["final_url"], s["src"])
                           for s in soup.find_all("script", src=True)][:20]
    except Exception:
        pass
    return info


def _findings_payload(findings) -> list[dict]:
    """Compact each finding + its ML/rule scores for the prompt."""
    try:
        from core import verifier
        from core.ml_model import score as ml_score
    except Exception:
        verifier = None
        ml_score = None
    out = []
    for i, f in enumerate(findings or []):
        rule = ml = None
        try:
            if verifier is not None:
                sf = verifier.score_finding(f)
                rule = sf[0] if isinstance(sf, tuple) else sf
            if ml_score is not None:
                ml = ml_score(f)
        except Exception:
            pass
        ev = (f.extra or {}) if hasattr(f, "extra") else {}
        proof = ev.get("proof") or {}
        out.append({
            "index": i,
            "title": getattr(f, "title", ""),
            "module": getattr(f, "module_id", ""),
            "severity": getattr(getattr(f, "severity", None), "name", str(getattr(f, "severity", ""))),
            "confidence": getattr(f, "confidence", ""),
            "detail": (getattr(f, "detail", "") or "")[:600],
            "evidence": (getattr(f, "evidence", "") or "")[:400],
            "rule_score": rule,
            "ml_true_positive_prob": round(ml, 3) if isinstance(ml, (int, float)) else ml,
            "has_active_proof": bool(proof.get("raw_request") or proof.get("raw_response")
                                     or proof.get("browser_alert") or ev.get("screenshot_b64")),
        })
    return out


def _build_prompt(rec: dict, fp: list[dict]) -> str:
    slim = {k: v for k, v in rec.items() if k != "html"}
    return (
        "AUTHORISED bug-bounty target. Analyse the site and the scanner findings.\n\n"
        "== RECON ==\n" + json.dumps(slim, ensure_ascii=False, indent=2) +
        "\n\n== HOMEPAGE HTML (truncated) ==\n" + (rec.get("html") or "")[:3500] +
        "\n\n== SCANNER FINDINGS (with local ML scores) ==\n" +
        (json.dumps(fp, ensure_ascii=False, indent=2) if fp
         else "(no findings yet — base your analysis on recon + propose attacks)") +
        "\n\nReturn the JSON analysis now."
    )


def _extract_json(text: str) -> dict | None:
    text = (text or "").strip()
    if text.startswith("```"):                 # strip ```json fences if present
        text = text.strip("`")
        if text[:4].lower() == "json":
            text = text[4:]
    try:
        return json.loads(text)
    except Exception:
        s, e = text.find("{"), text.rfind("}")
        if 0 <= s < e:
            try:
                return json.loads(text[s:e + 1])
            except Exception:
                return None
    return None


def analyze(target: str, findings, api_key: str | None = None,
            model: str = MODEL, log=None) -> dict:
    """Run the Gemini analysis. Returns {ok, analysis|error, usage}."""
    def _log(m):
        if log:
            log(m)
    if genai is None:
        return {"ok": False, "error": "google-genai SDK 미설치 (pip install google-genai)"}
    if not key_available(api_key):
        return {"ok": False, "error": "GEMINI_API_KEY 미설정", "need_key": True}

    _log("🧠 Gemini 에이전트: 대상 리컨 수집 중…")
    rec = recon(target)
    if rec.get("error"):
        _log(f"    [!] 리컨 경고: {rec['error']}")
    _log(f"    [*] 상태 {rec.get('status')}, 폼 {len(rec.get('forms', []))}개, "
         f"링크 {len(rec.get('links', []))}개, 파라미터 {len(rec.get('params', []))}개")
    fp = _findings_payload(findings)
    _log(f"🧠 Gemini 에이전트: 스캐너 결과 {len(fp)}건 + 리컨 컨텍스트를 {model} 에게 전달…")

    key = (api_key or "").strip() or os.environ.get("GEMINI_API_KEY") \
        or os.environ.get("GOOGLE_API_KEY")
    try:
        client = genai.Client(api_key=key)
        resp = client.models.generate_content(
            model=model,
            contents=_build_prompt(rec, fp),
            config=genai_types.GenerateContentConfig(
                system_instruction=_SYSTEM,
                response_mime_type="application/json",
                temperature=0.2,
                max_output_tokens=8000,
            ),
        )
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    text = getattr(resp, "text", None)
    if not text:
        # blocked / empty — surface the reason if any
        reason = ""
        try:
            fb = getattr(resp, "prompt_feedback", None)
            if fb and getattr(fb, "block_reason", None):
                reason = str(fb.block_reason)
        except Exception:
            pass
        return {"ok": False, "error": f"Gemini 응답 없음{(' ('+reason+')') if reason else ''}"}

    analysis = _extract_json(text)
    if analysis is None:
        return {"ok": False, "error": "Gemini 응답 파싱 실패", "raw": text[:800]}

    usage = getattr(resp, "usage_metadata", None)
    return {
        "ok": True,
        "analysis": analysis,
        "recon": {k: v for k, v in rec.items() if k != "html"},
        "usage": {"input": getattr(usage, "prompt_token_count", None),
                  "output": getattr(usage, "candidates_token_count", None)} if usage else {},
    }


def learn_from_llm(findings, analysis: dict, models_dir: str,
                   min_conf: float = 0.7, log=None) -> int:
    """Turn Gemini's high-confidence verdicts into ML training labels.

    Appends {features, label} rows to models/feedback.jsonl so the local
    char-gram MLP retrains toward Gemini's judgement — the model literally
    learns from Gemini. Only confident verdicts (>= min_conf) become labels.
    """
    def _log(m):
        if log:
            log(m)
    try:
        from core.ml_model import extract_features
    except Exception as e:
        _log(f"    [!] 피드백 기록 불가(모델 로드 실패): {e}")
        return 0
    rows = []
    for v in (analysis.get("findings") or []):
        try:
            idx = int(v.get("index"))
            conf = float(v.get("confidence", 0))
        except Exception:
            continue
        if conf < min_conf or not (0 <= idx < len(findings)):
            continue
        try:
            feats = extract_features(findings[idx])
        except Exception:
            continue
        rows.append({"features": feats, "label": 1 if v.get("is_real") else 0,
                     "module": getattr(findings[idx], "module_id", ""),
                     "source": "gemini"})
    if not rows:
        return 0
    try:
        os.makedirs(models_dir, exist_ok=True)
        with open(os.path.join(models_dir, "feedback.jsonl"), "a", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    except Exception as e:
        _log(f"    [!] 피드백 기록 실패: {e}")
        return 0
    _log(f"📚 Gemini 판정 {len(rows)}건을 ML 학습 라벨로 저장 (models/feedback.jsonl) — 모델이 Gemini에게 학습.")
    return len(rows)


# Backwards-compatible alias (server may call either name).
learn_from_claude = learn_from_llm


def format_report(target: str, res: dict) -> str:
    """Render the analysis as Markdown (for the terminal + downloadable report)."""
    a = res.get("analysis") or {}
    lines = [f"# Gemini AI 취약점 분석 — {target}", ""]
    lines.append(f"**종합 위험도:** {a.get('overall_risk', '-')}")
    u = res.get("usage") or {}
    if u:
        lines.append(f"**토큰:** in {u.get('input')}, out {u.get('output')}")
    lines += ["", "## 사이트 요약", a.get("site_summary", "-"), "", "## 공격 표면"]
    for s in a.get("attack_surface", []) or ["-"]:
        lines.append(f"- {s}")
    lines += ["", "## 발견 항목 검수 (Gemini)"]
    for v in a.get("findings", []):
        mark = "✅ 실제" if v.get("is_real") else "⚠️ 오탐 의심"
        lines.append(f"- [{v.get('index')}] {mark} · {v.get('severity')} "
                     f"(신뢰 {v.get('confidence')}) — {v.get('reasoning')}")
    if not a.get("findings"):
        lines.append("- (없음)")
    lines += ["", "## 권장 공격 (우선순위순)"]
    for r in sorted(a.get("recommended_attacks", []),
                    key=lambda x: x.get("priority", 0), reverse=True):
        lines.append(f"- **{r.get('technique')}** → {r.get('target')} "
                     f"(우선도 {r.get('priority')}) — {r.get('why')}")
    if not a.get("recommended_attacks"):
        lines.append("- (없음)")
    if a.get("notes"):
        lines += ["", "## 비고", a["notes"]]
    return "\n".join(lines)
