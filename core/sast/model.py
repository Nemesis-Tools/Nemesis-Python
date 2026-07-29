"""Source-code vulnerability classifier — heuristic rules + optional CodeBERT.

Layer 1 (always on, no deps): a CWE-tagged insecure-pattern rule engine — a
lightweight bandit/semgrep-style static analyser giving line-level findings.

Layer 2 (optional): a fine-tuned CodeBERT / GraphCodeBERT sequence classifier
(torch + transformers) that predicts whether a snippet is vulnerable. Loaded
only if a trained model is present at models/sast_codebert/ (produced by
tools/train_sast.py). If torch/transformers or the model are absent, Layer 1
still runs — the system degrades gracefully, never breaks.
"""
from __future__ import annotations

import os
import re
import sys

try:
    import torch  # noqa: F401
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    _HAVE_TORCH = True
except Exception:  # pragma: no cover - optional heavy deps
    _HAVE_TORCH = False


# ---- Layer 1: heuristic CWE rules -------------------------------------------
# (compiled_regex, cwe, name, severity, {languages})  — "*" = all languages.
_RULES = [
    # --- Injection / RCE ---
    (r"\beval\s*\(", "CWE-95", "동적 코드 실행 (eval)", "High", {"py", "js", "php", "rb"}),
    (r"\bexec\s*\(", "CWE-95", "동적 코드 실행 (exec)", "High", {"py", "php"}),
    (r"\bnew\s+Function\s*\(", "CWE-95", "동적 코드 실행 (new Function)", "High", {"js"}),
    (r"os\.system\s*\(", "CWE-78", "OS 명령 실행 (os.system)", "High", {"py"}),
    (r"os\.popen\s*\(", "CWE-78", "OS 명령 실행 (os.popen)", "High", {"py"}),
    (r"subprocess\.(?:call|run|Popen|check_output)\([^)]*shell\s*=\s*True", "CWE-78",
     "쉘 명령 주입 (shell=True)", "High", {"py"}),
    (r"child_process\.(?:exec|execSync)\s*\(", "CWE-78", "OS 명령 실행 (child_process.exec)", "High", {"js"}),
    (r"Runtime\.getRuntime\(\)\.exec\s*\(", "CWE-78", "OS 명령 실행 (Runtime.exec)", "High", {"java"}),
    (r"\b(?:system|popen|exec[lv]p?)\s*\(", "CWE-78", "OS 명령 실행", "High", {"c", "cpp", "php"}),
    # --- SQL injection (string-built queries) ---
    (r"(?:execute|query|cursor\.execute)\s*\([^)]*(?:%[sd]|\+|\.format\(|f[\"']|\$\{)", "CWE-89",
     "SQL 문자열 조립 (SQL Injection 가능)", "High", {"py", "js", "php", "java"}),
    (r"(?:SELECT|INSERT|UPDATE|DELETE)\b[^;]*(?:\+\s*\w+|\$\{|%s|\.format\()", "CWE-89",
     "SQL 쿼리에 사용자 입력 연결", "High", {"*"}),
    (r"Statement[^;]*executeQuery\s*\([^)]*\+", "CWE-89", "JDBC Statement 문자열 연결", "High", {"java"}),
    # --- XSS / template injection ---
    (r"\.innerHTML\s*=", "CWE-79", "innerHTML 직접 대입 (DOM XSS)", "Medium", {"js"}),
    (r"document\.write\s*\(", "CWE-79", "document.write (DOM XSS)", "Medium", {"js"}),
    (r"dangerouslySetInnerHTML", "CWE-79", "React dangerouslySetInnerHTML", "Medium", {"js"}),
    (r"render_template_string\s*\(", "CWE-94", "서버측 템플릿 주입 (SSTI)", "High", {"py"}),
    (r"\|\s*safe\b", "CWE-79", "Jinja |safe 필터 (자동이스케이프 우회)", "Low", {"py"}),
    # --- Deserialization ---
    (r"pickle\.loads?\s*\(", "CWE-502", "안전하지 않은 역직렬화 (pickle)", "High", {"py"}),
    (r"yaml\.load\s*\((?![^)]*Safe)", "CWE-502", "yaml.load (SafeLoader 미사용)", "High", {"py"}),
    (r"ObjectInputStream[^;]*readObject\s*\(", "CWE-502", "Java 역직렬화 (readObject)", "High", {"java"}),
    (r"unserialize\s*\(", "CWE-502", "PHP unserialize", "High", {"php"}),
    # --- Path traversal / file ---
    (r"(?:open|readFile|file_get_contents|fopen)\s*\([^)]*(?:\.\.|\$_(?:GET|POST|REQUEST)|req\.(?:query|params|body))",
     "CWE-22", "경로 조작 (Path Traversal 가능)", "High", {"*"}),
    # --- Weak crypto / secrets / TLS ---
    (r"\b(?:md5|sha1)\s*\(", "CWE-327", "약한 해시 알고리즘 (MD5/SHA1)", "Low", {"*"}),
    (r"\b(?:3DES|DES|RC4|ECB)\b", "CWE-327", "약한 암호 알고리즘", "Medium", {"*"}),
    (r"verify\s*=\s*False", "CWE-295", "TLS 인증서 검증 비활성화", "Medium", {"py"}),
    (r"rejectUnauthorized\s*:\s*false", "CWE-295", "TLS 인증서 검증 비활성화", "Medium", {"js"}),
    (r"(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*[\"'][^\"'\s]{6,}[\"']", "CWE-798",
     "하드코딩된 자격증명/시크릿", "High", {"*"}),
    # --- Buffer / memory (C/C++) ---
    (r"\b(?:strcpy|strcat|sprintf|gets|scanf)\s*\(", "CWE-120", "안전하지 않은 버퍼 함수", "High", {"c", "cpp"}),
    # --- Randomness ---
    (r"Math\.random\s*\(", "CWE-338", "암호학적으로 안전하지 않은 난수", "Low", {"js"}),
    (r"random\.(?:random|randint|choice)\s*\(", "CWE-338", "암호학적으로 안전하지 않은 난수", "Low", {"py"}),
]
_COMPILED = [(re.compile(rx, re.I), cwe, name, sev, langs) for rx, cwe, name, sev, langs in _RULES]


def heuristic_scan(code: str, language: str = "*", filename: str = "") -> list[dict]:
    """CWE-tagged insecure-pattern findings (line-level). Pure Python, no deps."""
    out = []
    lines = (code or "").splitlines()
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        # skip obvious comment-only lines (cheap, language-agnostic)
        if stripped.startswith(("#", "//", "*", "/*")):
            continue
        for rx, cwe, name, sev, langs in _COMPILED:
            if language != "*" and "*" not in langs and language not in langs:
                continue
            if rx.search(line):
                out.append({"line": lineno, "cwe": cwe, "name": name,
                            "severity": sev, "snippet": stripped[:200],
                            "file": filename, "source": "heuristic"})
    return out


# ---- Layer 2: optional CodeBERT classifier ----------------------------------
def _model_dir() -> str | None:
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(os.path.dirname(here))
    cands = [os.path.join(root, "models", "sast_codebert")]
    mp = getattr(sys, "_MEIPASS", None)
    if mp:
        cands.insert(0, os.path.join(mp, "models", "sast_codebert"))
    for d in cands:
        if os.path.isdir(d) and os.path.exists(os.path.join(d, "config.json")):
            return d
    return None


def available() -> bool:
    """True if the CodeBERT classifier CAN run (torch + transformers installed)."""
    return _HAVE_TORCH


def model_present() -> bool:
    """True if a fine-tuned SAST model is on disk."""
    return _model_dir() is not None


_MODEL_CACHE = {"loaded": False, "tok": None, "model": None, "labels": None}


def _load_codebert():
    if _MODEL_CACHE["loaded"]:
        return _MODEL_CACHE
    _MODEL_CACHE["loaded"] = True
    d = _model_dir()
    if not _HAVE_TORCH or d is None:
        return _MODEL_CACHE
    try:
        _MODEL_CACHE["tok"] = AutoTokenizer.from_pretrained(d)
        _MODEL_CACHE["model"] = AutoModelForSequenceClassification.from_pretrained(d)
        _MODEL_CACHE["model"].eval()
        import json
        lp = os.path.join(d, "labels.json")
        if os.path.exists(lp):
            with open(lp, encoding="utf-8") as fh:
                _MODEL_CACHE["labels"] = json.load(fh)
    except Exception:
        _MODEL_CACHE["tok"] = _MODEL_CACHE["model"] = None
    return _MODEL_CACHE


def predict_codebert(code: str) -> dict | None:
    """CodeBERT verdict for a code snippet, or None if the model isn't available.

    Returns {vulnerable: bool, prob: float, label: str}.
    """
    c = _load_codebert()
    if c["model"] is None or c["tok"] is None:
        return None
    try:
        import torch
        enc = c["tok"](code, truncation=True, max_length=512, return_tensors="pt")
        with torch.no_grad():
            logits = c["model"](**enc).logits[0]
            probs = torch.softmax(logits, dim=-1).tolist()
        labels = c["labels"] or {str(i): str(i) for i in range(len(probs))}
        top = max(range(len(probs)), key=lambda i: probs[i])
        label = labels.get(str(top), str(top))
        # label "0"/"safe"/"none" ⇒ not vulnerable; anything else ⇒ vulnerable
        vulnerable = str(label).lower() not in ("0", "safe", "none", "clean")
        return {"vulnerable": vulnerable, "prob": round(float(probs[top]), 4),
                "label": label}
    except Exception:
        return None


def analyze_code(code: str, language: str = "*", filename: str = "") -> dict:
    """Combined verdict: heuristic CWE findings + (optional) CodeBERT ML label."""
    findings = heuristic_scan(code, language, filename)
    ml = predict_codebert(code) if model_present() and available() else None
    return {"file": filename, "language": language, "findings": findings,
            "ml": ml, "n_findings": len(findings)}
