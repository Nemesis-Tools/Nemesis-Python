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

try:
    from openai import OpenAI          # OpenAI-compatible providers (Groq/Mistral/…)
except Exception:  # pragma: no cover
    OpenAI = None

MODEL = "gemini-2.5-flash"

# ---- Multi-provider registry (free-tier LLMs) --------------------------------
# Every provider except Gemini speaks the OpenAI-compatible chat-completions API,
# so one client (base_url + key) covers all of them. Model catalogs drift — use
# /model to switch and the error hints when a model 404s / is quota-zero.
PROVIDERS = {
    "gemini": {
        "label": "Google Gemini", "kind": "gemini",
        "models": ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-2.5-pro"],
        "default": "gemini-2.5-flash",
        "key_env": ["GEMINI_API_KEY", "GOOGLE_API_KEY"],
        "keys_url": "https://aistudio.google.com/app/apikey",
        "free": "무료 티어(모델별 쿼터 상이 — flash 계열 권장; pro/lite는 무료 쿼터 0일 수 있음)",
    },
    "groq": {
        "label": "Groq", "kind": "openai", "base_url": "https://api.groq.com/openai/v1",
        "models": ["llama-3.3-70b-versatile", "llama-3.1-8b-instant",
                   "openai/gpt-oss-120b", "qwen/qwen3-32b"],
        "default": "llama-3.3-70b-versatile",
        "key_env": ["GROQ_API_KEY"], "keys_url": "https://console.groq.com/keys",
        "free": "무료·신용카드 불필요, 매우 빠름(추천)",
    },
    "cerebras": {
        "label": "Cerebras", "kind": "openai", "base_url": "https://api.cerebras.ai/v1",
        "models": ["gpt-oss-120b", "llama-3.3-70b", "qwen-3-32b"],
        "default": "gpt-oss-120b",
        "key_env": ["CEREBRAS_API_KEY"], "keys_url": "https://cloud.cerebras.ai/",
        "free": "무료 ~1M 토큰/일 (카탈로그 변동 잦음)",
    },
    "mistral": {
        "label": "Mistral", "kind": "openai", "base_url": "https://api.mistral.ai/v1",
        "models": ["mistral-small-latest", "magistral-small-latest",
                   "open-mistral-nemo", "codestral-latest"],
        "default": "mistral-small-latest",
        "key_env": ["MISTRAL_API_KEY"], "keys_url": "https://console.mistral.ai/api-keys",
        "free": "무료 Experiment 티어(데이터 학습 동의 필요, 월 대량)",
    },
    "openrouter": {
        "label": "OpenRouter", "kind": "openai", "base_url": "https://openrouter.ai/api/v1",
        "models": ["deepseek/deepseek-r1:free", "meta-llama/llama-3.3-70b-instruct:free",
                   "qwen/qwen3-235b-a22b:free", "google/gemma-3-27b-it:free"],
        "default": "deepseek/deepseek-r1:free",
        "key_env": ["OPENROUTER_API_KEY"], "keys_url": "https://openrouter.ai/keys",
        "free": "무료 모델 다수(:free 접미사, 여러 모델 한 키로)",
    },
    "openai": {
        "label": "OpenAI (Codex/GPT)", "kind": "openai", "base_url": "https://api.openai.com/v1",
        "models": ["gpt-4o-mini", "gpt-4o", "o4-mini"],
        "default": "gpt-4o-mini",
        "key_env": ["OPENAI_API_KEY"], "keys_url": "https://platform.openai.com/api-keys",
        "free": "신규 계정 무료 크레딧(소진 후 유료)",
    },
}
PROVIDER_ORDER = ["gemini", "groq", "cerebras", "mistral", "openrouter", "openai"]

# Backwards-compat: the old /model command listed Gemini models.
GEMINI_MODELS = PROVIDERS["gemini"]["models"]


def providers_public() -> list[dict]:
    """Provider metadata for the UI picker (no secrets)."""
    return [{"id": p, "label": PROVIDERS[p]["label"], "kind": PROVIDERS[p]["kind"],
             "models": PROVIDERS[p]["models"], "default": PROVIDERS[p]["default"],
             "keys_url": PROVIDERS[p]["keys_url"], "free": PROVIDERS[p]["free"]}
            for p in PROVIDER_ORDER]


def _env_key(provider: str) -> str | None:
    for e in PROVIDERS.get(provider, {}).get("key_env", []):
        if os.environ.get(e):
            return os.environ[e]
    return None


def _dast_eval():
    """Held-out metrics stored in the trained DAST verifier (provenance)."""
    try:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "models", "vuln_model.json"), encoding="utf-8") as fh:
            return json.load(fh).get("eval")
    except Exception:
        return None


def model_info() -> dict:
    """Status of the locally-built models that /test composes with Gemini."""
    info = {"dast_verifier": {"present": False}, "sast": {"heuristic": True},
            "linevul": {"available": False}}
    try:
        from core import ml_model
        info["dast_verifier"] = {"present": ml_model.available(), "eval": _dast_eval()}
    except Exception:
        pass
    try:
        from core.sast import model as sm
        info["sast"] = {"heuristic": True,
                        "codebert": bool(sm.available() and sm.model_present())}
        info["linevul"] = {"available": bool(sm.available() and sm.model_present())}
    except Exception:
        pass
    return info

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


def available(provider: str = "gemini") -> bool:
    """True if the provider's SDK is importable."""
    kind = PROVIDERS.get(provider, {}).get("kind", "gemini")
    return (genai is not None) if kind == "gemini" else (OpenAI is not None)


def key_available(provider: str = "gemini", api_key: str | None = None) -> bool:
    """True if an API key for `provider` is resolvable (arg or env)."""
    # Back-compat: key_available("AIza...") — a bare key string means gemini.
    if provider not in PROVIDERS and provider:
        api_key, provider = provider, "gemini"
    return bool((api_key or "").strip() or _env_key(provider))


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


def _error_hint(msg: str, provider: str = "gemini") -> str:
    """Map common LLM-API errors to an actionable Korean hint."""
    m = (msg or "").lower()
    kp = PROVIDERS.get(provider, {})
    url = kp.get("keys_url", "")
    if "permission_denied" in m or "denied access" in m or "403" in m:
        if provider == "gemini":
            return ("Google가 이 키의 프로젝트 접근을 거부했습니다. ① 개인 Gmail 계정으로 "
                    "AI Studio에서 새 키 발급(회사 Workspace 계정은 막힐 수 있음)  ② 지역 제한 확인.")
        return f"접근 거부. 키 권한/결제 상태를 확인하세요 ({url})."
    if "api key not valid" in m or "api_key_invalid" in m or ("invalid" in m and "key" in m) \
            or "401" in m or "authentication" in m:
        return f"API 키가 유효하지 않습니다. /key 로 {provider} 키를 다시 입력하세요 ({url})."
    if "quota" in m or "resource_exhausted" in m or "429" in m or "rate limit" in m:
        return ("무료 쿼터 초과/요청 과다입니다. 잠시 후 재시도하거나 /model 로 무료 쿼터가 있는 "
                "모델로 바꾸세요. (Gemini는 flash 계열이 무료, 또는 /test 에서 Groq 선택)")
    if "not found" in m or "404" in m or "no longer available" in m:
        d = kp.get("default", "")
        return f"이 모델은 사용할 수 없습니다. /model 로 다른 모델을 선택하세요 (예: {d})."
    return ""


def _call_gemini(model, key, prompt):
    """Gemini generate_content → (json_text, usage_dict)."""
    client = genai.Client(api_key=key)
    resp = client.models.generate_content(
        model=model, contents=prompt,
        config=genai_types.GenerateContentConfig(
            system_instruction=_SYSTEM, response_mime_type="application/json",
            temperature=0.2, max_output_tokens=8000))
    text = getattr(resp, "text", None)
    u = getattr(resp, "usage_metadata", None)
    usage = {"input": getattr(u, "prompt_token_count", None),
             "output": getattr(u, "candidates_token_count", None)} if u else {}
    return text, usage


def _call_openai(base_url, model, key, prompt):
    """OpenAI-compatible chat completion → (json_text, usage_dict). Retries
    without response_format for providers that don't support JSON mode."""
    client = OpenAI(api_key=key, base_url=base_url)
    msgs = [{"role": "system", "content": _SYSTEM}, {"role": "user", "content": prompt}]
    kw = dict(model=model, messages=msgs, temperature=0.2, max_tokens=8000)
    try:
        resp = client.chat.completions.create(response_format={"type": "json_object"}, **kw)
    except Exception:
        resp = client.chat.completions.create(**kw)     # provider lacks JSON mode
    text = resp.choices[0].message.content
    u = getattr(resp, "usage", None)
    usage = {"input": getattr(u, "prompt_tokens", None),
             "output": getattr(u, "completion_tokens", None)} if u else {}
    return text, usage


def _ensemble(analysis, fp):
    """Fuse each LLM verdict with the LOCAL ML/DL verifier's P(true-positive)."""
    ml_by_idx = {f["index"]: f.get("ml_true_positive_prob") for f in fp}
    for v in (analysis.get("findings") or []):
        try:
            idx = int(v.get("index"))
        except Exception:
            continue
        ml = ml_by_idx.get(idx)
        g = float(v.get("confidence", 0.5)) if v.get("is_real") else 1.0 - float(v.get("confidence", 0.5))
        if isinstance(ml, (int, float)):
            v["ml_prob"] = round(float(ml), 3)
            v["ensemble"] = round(0.55 * g + 0.45 * float(ml), 3)
            v["agreement"] = bool(v.get("is_real")) == (float(ml) >= 0.5)
        else:
            v["ml_prob"] = None
            v["ensemble"] = round(g, 3)
            v["agreement"] = None
    return analysis


def analyze(target, findings, provider="gemini", model=None, api_key=None,
            log=None, rec=None, fp=None):
    """Run one provider's analysis, fused with the local ML model. Returns
    {ok, analysis|error, provider, model, models, usage}."""
    def _log(m):
        if log:
            log(m)
    if provider not in PROVIDERS:
        provider = "gemini"
    prov = PROVIDERS[provider]
    model = model or prov["default"]
    if not available(provider):
        pkg = "google-genai" if prov["kind"] == "gemini" else "openai"
        return {"ok": False, "error": f"{pkg} SDK 미설치 (pip install {pkg})", "provider": provider}
    if not key_available(provider, api_key):
        return {"ok": False, "error": f"{prov['label']} API 키 미설정", "need_key": True,
                "provider": provider}

    if rec is None:
        _log(f"🧠 {prov['label']}: 대상 리컨 수집 중…")
        rec = recon(target)
        if rec.get("error"):
            _log(f"    [!] 리컨 경고: {rec['error']}")
        _log(f"    [*] 상태 {rec.get('status')}, 폼 {len(rec.get('forms', []))}개, "
             f"링크 {len(rec.get('links', []))}개, 파라미터 {len(rec.get('params', []))}개")
    if fp is None:
        fp = _findings_payload(findings)
    _log(f"🧠 {prov['label']}({model}): 스캐너 결과 {len(fp)}건 + 리컨 컨텍스트 전달…")

    key = (api_key or "").strip() or _env_key(provider)
    prompt = _build_prompt(rec, fp)
    try:
        if prov["kind"] == "gemini":
            text, usage = _call_gemini(model, key, prompt)
        else:
            text, usage = _call_openai(prov["base_url"], model, key, prompt)
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}",
                "hint": _error_hint(str(e), provider), "provider": provider, "model": model}

    if not text:
        return {"ok": False, "error": f"{prov['label']} 응답 없음(안전 차단 가능)",
                "provider": provider, "model": model}
    analysis = _extract_json(text)
    if analysis is None:
        return {"ok": False, "error": f"{prov['label']} 응답 파싱 실패",
                "raw": text[:800], "provider": provider, "model": model}

    return {
        "ok": True, "analysis": _ensemble(analysis, fp),
        "provider": provider, "provider_label": prov["label"], "model": model,
        "models": model_info(),
        "recon": {k: v for k, v in rec.items() if k != "html"},
        "usage": usage,
    }


def analyze_multi(target, findings, providers, keys=None, models=None, log=None):
    """Run several providers on the SAME recon/findings and combine (전체 사용).

    `providers` is a list of provider ids (or ["all"]); `keys`/`models` are
    dicts keyed by provider id. Only providers with a resolvable key run.
    Returns {ok, results:[per-provider], recon, models}.
    """
    def _log(m):
        if log:
            log(m)
    keys = keys or {}
    models = models or {}
    if not providers or providers == ["all"] or "all" in providers:
        providers = list(PROVIDER_ORDER)
    _log("🧠 리컨 수집 중(전체 제공자 공용)…")
    rec = recon(target)
    fp = _findings_payload(findings)
    _log(f"    [*] 상태 {rec.get('status')}, 폼 {len(rec.get('forms', []))}개, "
         f"링크 {len(rec.get('links', []))}개  ·  스캐너 결과 {len(fp)}건")
    results = []
    ran = 0
    for pid in providers:
        if pid not in PROVIDERS:
            continue
        k = keys.get(pid)
        if not key_available(pid, k):
            _log(f"    · {PROVIDERS[pid]['label']}: 키 없음 → 건너뜀")
            continue
        _log(f"── {PROVIDERS[pid]['label']} 분석 ──")
        res = analyze(target, findings, provider=pid, model=models.get(pid),
                      api_key=k, log=log, rec=rec, fp=fp)
        results.append(res)
        if res.get("ok"):
            ran += 1
        else:
            _log(f"    [!] {res.get('error')}")
            if res.get("hint"):
                _log(f"      💡 {res['hint']}")
    if not ran:
        return {"ok": False, "error": "실행된 제공자가 없습니다 (키를 하나 이상 설정하세요).",
                "results": results}
    return {"ok": True, "results": results,
            "recon": {k: v for k, v in rec.items() if k != "html"}, "models": model_info()}


def _complete(provider, model, key, system, prompt, max_tokens=1000):
    """Low-level single completion → text (provider-dispatched)."""
    prov = PROVIDERS[provider]
    if prov["kind"] == "gemini":
        client = genai.Client(api_key=key)
        resp = client.models.generate_content(
            model=model, contents=prompt,
            config=genai_types.GenerateContentConfig(
                system_instruction=system, response_mime_type="application/json",
                temperature=0.2, max_output_tokens=max_tokens))
        return getattr(resp, "text", None)
    client = OpenAI(api_key=key, base_url=prov["base_url"])
    msgs = [{"role": "system", "content": system}, {"role": "user", "content": prompt}]
    kw = dict(model=model, messages=msgs, temperature=0.2, max_tokens=max_tokens)
    try:
        resp = client.chat.completions.create(response_format={"type": "json_object"}, **kw)
    except Exception:
        resp = client.chat.completions.create(**kw)
    return resp.choices[0].message.content


_GUIDE_SYS = (
    "You are a pentest co-pilot for an AUTHORISED bug-bounty scan. Given ONE page's URL, "
    "parameters, forms, and the list of scanner techniques about to run on it, output concise "
    "JSON to focus the scan on that page: "
    '{"focus_params":[...], "focus_techniques":[...], "payload_hints":[...], "note":"..."}. '
    "payload_hints are short test strings for the techniques already in the scanner (e.g. SQLi/"
    "XSS/SSTI/traversal) — defensive scanning guidance only. Be brief; JSON only."
)


def page_guidance(url, page, techniques, provider="gemini", api_key=None, model=None):
    """One quick LLM call giving per-page attack-focus guidance during /start.

    Returns {focus_params, focus_techniques, payload_hints, note} or {error:...}
    or None (no key/SDK). Fail-soft: the scan continues regardless.
    """
    if provider not in PROVIDERS or not available(provider):
        return None
    key = (api_key or "").strip() or _env_key(provider)
    if not key:
        return None
    model = model or PROVIDERS[provider]["default"]
    prompt = ("PAGE: " + url +
              "\nPARAMS: " + json.dumps((page or {}).get("params", [])) +
              "\nFORMS: " + json.dumps((page or {}).get("forms", []))[:600] +
              "\nTECHNIQUES: " + ", ".join(techniques[:40]) +
              "\nGive focused JSON guidance now.")
    try:
        text = _complete(provider, model, key, _GUIDE_SYS, prompt, max_tokens=700)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}", "hint": _error_hint(str(e), provider)}
    return _extract_json(text or "") or {"error": "파싱 실패"}


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
                     "source": "llm"})
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
    _log(f"📚 LLM 판정 {len(rows)}건을 ML 학습 라벨로 저장 (models/feedback.jsonl) — 로컬 모델이 LLM에게 학습.")
    return len(rows)


# Backwards-compatible alias (server may call either name).
learn_from_claude = learn_from_llm


def format_report(target: str, res: dict) -> str:
    """Render the analysis as Markdown (for the terminal + downloadable report)."""
    a = res.get("analysis") or {}
    plabel = res.get("provider_label", "LLM")
    lines = [f"# {plabel} + 로컬 ML/DL 앙상블 취약점 분석 — {target}", ""]
    lines.append(f"**모델:** {res.get('model', MODEL)} ({plabel}) + 로컬 검수모델(앙상블)")
    lines.append(f"**종합 위험도:** {a.get('overall_risk', '-')}")
    u = res.get("usage") or {}
    if u:
        lines.append(f"**토큰:** in {u.get('input')}, out {u.get('output')}")
    # Local model provenance (생성한 모델 구성).
    mi = res.get("models") or {}
    dv = (mi.get("dast_verifier") or {})
    ev = (dv.get("eval") or {}) if isinstance(dv.get("eval"), dict) else {}
    lines += ["", "## 구성 모델 (로컬)",
              f"- **DAST 검수모델(MLP)**: {'로드됨' if dv.get('present') else '미로드'}"
              + (f" · val F1={ev.get('f1')}, ROC-AUC={ev.get('roc_auc')}" if ev else ""),
              f"- **SAST 소스코드**: 휴리스틱 CWE 룰 + CodeBERT {'사용' if (mi.get('sast') or {}).get('codebert') else '미사용'} (/sast)",
              f"- **LineVul 라인예측**: {'사용' if (mi.get('linevul') or {}).get('available') else '미사용'}"]
    lines += ["", "## 사이트 요약", a.get("site_summary", "-"), "", "## 공격 표면"]
    for s in a.get("attack_surface", []) or ["-"]:
        lines.append(f"- {s}")
    lines += ["", f"## 발견 항목 검수 ({plabel} ⊕ 로컬 ML 앙상블)"]
    for v in a.get("findings", []):
        mark = "✅ 실제" if v.get("is_real") else "⚠️ 오탐 의심"
        ml = v.get("ml_prob")
        agr = v.get("agreement")
        agr_s = "일치" if agr else ("불일치" if agr is False else "ML없음")
        ml_s = f"ML {ml}" if ml is not None else "ML n/a"
        lines.append(f"- [{v.get('index')}] {mark} · {v.get('severity')} "
                     f"(LLM신뢰 {v.get('confidence')} · {ml_s} · 앙상블 {v.get('ensemble')} · {agr_s}) "
                     f"— {v.get('reasoning')}")
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


def format_multi_report(target: str, multi: dict) -> str:
    """Combine several providers' analyses into one report (전체 사용).

    Adds a cross-provider consensus per finding (how many LLMs marked it real)
    on top of each provider's own section."""
    oks = [r for r in (multi.get("results") or []) if r.get("ok")]
    lines = [f"# 멀티-LLM + 로컬 ML/DL 앙상블 취약점 분석 — {target}", "",
             f"**실행 제공자:** {', '.join(r.get('provider_label', r.get('provider')) for r in oks) or '(없음)'}", ""]
    # Cross-provider consensus per finding index.
    consensus = {}
    for r in oks:
        for v in (r.get("analysis") or {}).get("findings", []):
            try:
                idx = int(v.get("index"))
            except Exception:
                continue
            c = consensus.setdefault(idx, {"real": 0, "total": 0, "title": v.get("title", ""),
                                           "ml": v.get("ml_prob")})
            c["total"] += 1
            if v.get("is_real"):
                c["real"] += 1
    if consensus:
        lines += ["## 교차 합의 (제공자 간)"]
        for idx in sorted(consensus):
            c = consensus[idx]
            ml_s = f" · ML {c['ml']}" if c.get("ml") is not None else ""
            verdict = "✅ 실제(다수)" if c["real"] * 2 > c["total"] else (
                "⚠️ 의견 분분" if c["real"] else "❎ 오탐(다수)")
            lines.append(f"- [{idx}] {verdict} — {c['real']}/{c['total']} 제공자가 실제로 판정"
                         f"{ml_s}  ·  {c['title']}")
        lines.append("")
    # Per-provider full sections.
    for r in multi.get("results") or []:
        if r.get("ok"):
            lines += ["", "---", "", format_report(target, r)]
        else:
            lines += ["", f"## {PROVIDERS.get(r.get('provider'), {}).get('label', r.get('provider'))} — 실패",
                      f"- {r.get('error')}" + (f"  💡 {r['hint']}" if r.get('hint') else "")]
    return "\n".join(lines)
