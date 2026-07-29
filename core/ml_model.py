"""Learned vulnerability-finding classifier (pure-Python neural net).

A small multi-layer perceptron (MLP) that estimates P(true-positive) for a
finding from engineered features. It is trained offline by tools/train_model.py
on a curated dataset (+ user feedback) and its weights are stored as JSON, so
runtime inference needs NO third-party dependency (no numpy/torch) — it stays
lean enough to bundle in the .exe.

The verification engine blends this probability with its rule score (ensemble).
If the weights file is missing, score() returns None and the caller falls back
to the rule-based model — so the system always works, learned model or not.
"""
from __future__ import annotations

import json
import math
import os
import re
import sys

# ---- feature definitions (keep in sync; the trainer uses the same extractor) ----
# Engineered structural/functional features (HTTP-finding metadata).
_ENGINEERED = [
    "conf_confirmed", "conf_firm", "conf_tentative",
    "mod_high_precision", "mod_heuristic",
    "ev_strong", "ev_len", "ev_empty", "ev_status", "ev_token", "ev_lines",
    "has_request", "active_proof", "weak_phrasing",
    "sev_norm", "title_len", "url_has_query",
]
# Character 3-gram hashing buckets over the (decoded, normalized) evidence+title —
# the char-level textual signal used by char-CNN/BiLSTM payload classifiers, in a
# dependency-free hashing-trick form so the model can LEARN new signatures from data.
CHAR_BUCKETS = 24
FEATURES = _ENGINEERED + [f"char_{i}" for i in range(CHAR_BUCKETS)]

_HEURISTIC = {
    "xs_leaks", "mxss", "race_condition", "csrf", "supply_chain",
    "business_logic_recon", "auth_surface", "upload_recon", "prompt_injection",
    "idor_candidates", "prototype_pollution", "subdomain_takeover",
}
_HIGH_PRECISION = {
    "clickjacking", "xxe", "sqli", "command_injection", "cors", "tls_analysis",
    "security_headers", "cookies", "http_methods", "dir_listing", "source_map",
    "sensitive_files", "container_k8s_exposure", "ssrf", "rfi",
}
_STRONG_EVIDENCE = re.compile(
    r"root:.*?:0:0:|\[(fonts|extensions)\]|signature matched|matched|"
    r"canary|token|reflected|set-cookie|access-control-allow|"
    r"apiversion|podlist|nodelist|failed to open stream|allow_url_include|"
    r"metadata|framing_proven|성공|입증", re.I)
_WEAK_PHRASING = re.compile(
    r"candidate|probes? sent|payloads? sent|may (be|still)|might|추정|후보|"
    r"needs? oob|no .* reflected|가능성", re.I)
_STATUS_RE = re.compile(r"http[/ ]?\d\.?\d?\s*\d{3}|status[= ]\d{3}|\b[1-5]\d{2}\b", re.I)
_TOKEN_RE = re.compile(r"token|canary|marker|nmxss|iVBOR|base64", re.I)


def _attr(f, name, default=""):
    if isinstance(f, dict):
        return f.get(name, default)
    return getattr(f, name, default)


def _sev_rank(f) -> int:
    sev = _attr(f, "severity", None)
    if hasattr(sev, "rank"):
        return sev.rank
    return {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}.get(str(sev), 2)


def _fnv1a(s: str) -> int:
    """Deterministic 32-bit hash (NOT Python's randomized hash) for stable bucketing."""
    h = 2166136261
    for ch in s:
        h ^= ord(ch)
        h = (h * 16777619) & 0xFFFFFFFF
    return h


_DECODE = [("%20", " "), ("%27", "'"), ("%22", '"'), ("%3c", "<"), ("%3e", ">"),
           ("%2f", "/"), ("&lt;", "<"), ("&gt;", ">"), ("&amp;", "&"), ("+", " ")]


def _normalize(text: str) -> str:
    t = (text or "").lower()
    for a, b in _DECODE:                       # light URL/HTML decode (preprocessing)
        t = t.replace(a, b)
    return re.sub(r"\s+", " ", t)


def char_features(text: str) -> list[float]:
    """Normalized character-3gram hashing histogram (char-level payload signal)."""
    t = _normalize(text)
    buckets = [0.0] * CHAR_BUCKETS
    if len(t) < 3:
        return buckets
    n = 0
    for i in range(len(t) - 2):
        buckets[_fnv1a(t[i:i + 3]) % CHAR_BUCKETS] += 1.0
        n += 1
    if n:
        buckets = [b / n for b in buckets]
    return buckets


def extract_features(f) -> list[float]:
    """Turn a Finding (object or dict) into the fixed-length feature vector:
    engineered structural features ⊕ character-3gram hashing of the evidence text."""
    conf = str(_attr(f, "confidence", "Tentative"))
    mid = str(_attr(f, "module_id", ""))
    ev = str(_attr(f, "evidence", "") or "")
    title = str(_attr(f, "title", "") or "")
    req = str(_attr(f, "request", "") or "")
    url = str(_attr(f, "url", "") or "")
    ex = _attr(f, "extra", {}) or {}
    active = 1.0 if (ex.get("framing_proven") or ex.get("screenshot_b64")) else 0.0
    engineered = [
        1.0 if conf == "Confirmed" else 0.0,
        1.0 if conf == "Firm" else 0.0,
        1.0 if conf == "Tentative" else 0.0,
        1.0 if mid in _HIGH_PRECISION else 0.0,
        1.0 if mid in _HEURISTIC else 0.0,
        1.0 if _STRONG_EVIDENCE.search(ev) else 0.0,
        min(len(ev) / 400.0, 1.0),
        1.0 if not ev.strip() else 0.0,
        1.0 if _STATUS_RE.search(ev) else 0.0,
        1.0 if _TOKEN_RE.search(ev) else 0.0,
        min(ev.count("\n") / 8.0, 1.0),
        1.0 if req.strip() else 0.0,
        active,
        1.0 if _WEAK_PHRASING.search(title + " " + ev) else 0.0,
        _sev_rank(f) / 4.0,
        min(len(title) / 80.0, 1.0),
        1.0 if "?" in url else 0.0,
    ]
    return engineered + char_features(title + " " + ev)


# ---- pure-Python MLP inference --------------------------------------------------
def _model_paths() -> list[str]:
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    cands = [os.path.join(root, "models", "vuln_model.json")]
    mp = getattr(sys, "_MEIPASS", None)
    if mp:
        cands.insert(0, os.path.join(mp, "models", "vuln_model.json"))
    return cands


class _MLP:
    def __init__(self, w):
        self.W1 = w["W1"]      # [n_in][n_hid]
        self.b1 = w["b1"]      # [n_hid]
        self.W2 = w["W2"]      # [n_hid]
        self.b2 = w["b2"]      # scalar
        self.features = w.get("features", FEATURES)

    def predict_proba(self, x: list[float]) -> float:
        n_hid = len(self.b1)
        h = []
        for j in range(n_hid):
            s = self.b1[j]
            for i in range(len(x)):
                s += x[i] * self.W1[i][j]
            h.append(math.tanh(s))
        o = self.b2
        for j in range(n_hid):
            o += h[j] * self.W2[j]
        o = max(-60.0, min(60.0, o))
        return 1.0 / (1.0 + math.exp(-o))


_CACHE = {"loaded": False, "model": None}


def load_model():
    if _CACHE["loaded"]:
        return _CACHE["model"]
    _CACHE["loaded"] = True
    for p in _model_paths():
        try:
            if os.path.exists(p):
                with open(p, "r", encoding="utf-8") as fh:
                    _CACHE["model"] = _MLP(json.load(fh))
                break
        except Exception:
            _CACHE["model"] = None
    return _CACHE["model"]


def score(f) -> float | None:
    """P(true-positive) in [0,1], or None if no trained model is available."""
    m = load_model()
    if m is None:
        return None
    try:
        return m.predict_proba(extract_features(f))
    except Exception:
        return None


def available() -> bool:
    return load_model() is not None
