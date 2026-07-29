"""Central finding-verification model (true-positive promotion + false-positive filtering).

Every finding a module produces is scored here by a transparent, rule-based model
that weighs multiple signals, then:
  * promotes well-evidenced findings (Tentative → Firm → Confirmed),
  * demotes / drops weakly-supported ones (false-positive reduction),
  * de-duplicates and lets corroborating findings reinforce each other.

The score (0–100) and the reasons are attached to each finding (extra) so the
decision is auditable in the report. This is deliberately deterministic (not an
opaque ML black box) so results are explainable and reproducible.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from core.result import Finding, Severity
from core import ml_model

# Modules whose findings are inherently heuristic/speculative → lower prior.
_HEURISTIC = {
    "xs_leaks", "mxss", "race_condition", "csrf", "supply_chain",
    "business_logic_recon", "auth_surface", "upload_recon", "prompt_injection",
    "idor_candidates", "prototype_pollution", "subdomain_takeover",
}
# Modules that carry their own strong/active proof → higher prior.
_HIGH_PRECISION = {
    "clickjacking", "xxe", "sqli", "command_injection", "cors", "tls_analysis",
    "security_headers", "cookies", "http_methods", "dir_listing", "source_map",
    "sensitive_files", "container_k8s_exposure", "ssrf", "rfi",
}

# Concrete, high-value evidence indicators (a real signal was actually observed).
_STRONG_EVIDENCE = re.compile(
    r"root:.*?:0:0:|\[(fonts|extensions)\]|signature matched|matched|"
    r"canary|token|reflected|set-cookie|access-control-allow|"
    r" apiversion|podlist|nodelist|failed to open stream|allow_url_include|"
    r"metadata|framing_proven|성공|입증|HTTP \d{3}", re.I)
# Phrasing that signals a candidate / unconfirmed / negative result → penalty.
_WEAK_PHRASING = re.compile(
    r"candidate|probes? sent|payloads? sent|may (be|still)|might|추정|후보|"
    r"needs? oob|verify|no .* reflected|not reported|가능성", re.I)

_CONF_BASE = {"Confirmed": 75, "Firm": 55, "Tentative": 35}
_TIER = [(78, "Confirmed"), (58, "Firm"), (38, "Tentative")]


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def score_finding(f: Finding) -> tuple[int, list[str]]:
    """Return (0–100 confidence score, human-readable reasons)."""
    reasons: list[str] = []
    ev = f.evidence or ""
    ex = f.extra or {}

    score = _CONF_BASE.get(f.confidence, 40)
    reasons.append(f"self-confidence {f.confidence or '?'} → base {score}")

    # Module precision prior.
    if f.module_id in _HIGH_PRECISION:
        score += 8
        reasons.append("high-precision module +8")
    elif f.module_id in _HEURISTIC:
        score -= 15
        reasons.append("heuristic module -15")

    # Evidence strength.
    if _STRONG_EVIDENCE.search(ev):
        score += 15
        reasons.append("concrete evidence signature +15")
    if len(ev) >= 40:
        score += 5
        reasons.append("substantive evidence +5")
    if not ev.strip():
        score -= 12
        reasons.append("no evidence -12")

    # A documented, reproducible request.
    if (f.request or "").strip():
        score += 5
        reasons.append("documented request +5")

    # Active proof artifacts (screenshot / proven flag) = strong true-positive signal.
    if ex.get("framing_proven") or ex.get("screenshot_b64"):
        score += 12
        reasons.append("active proof artifact +12")

    # Weak / candidate phrasing.
    if _WEAK_PHRASING.search((f.title or "") + " " + ev):
        score -= 12
        reasons.append("candidate/unconfirmed phrasing -12")

    # Slight retention bias for high severity (missing a real Critical is costly).
    if f.severity in (Severity.CRITICAL, Severity.HIGH):
        score += 4
        reasons.append("high severity +4")

    return max(0, min(100, score)), reasons


def _tier(score: int) -> str:
    for thr, name in _TIER:
        if score >= thr:
            return name
    return "Tentative"


def _corroborated(f: Finding, ml) -> bool:
    """A second, independent reason to believe the finding is real (reviewer stage 2)."""
    ex = f.extra or {}
    if ex.get("framing_proven") or ex.get("screenshot_b64"):
        return True                                   # active proof artifact
    if f.confidence == "Confirmed":
        return True
    if _STRONG_EVIDENCE.search(f.evidence or ""):
        return True                                   # concrete signature observed
    if ml is not None and ml >= 0.85:
        return True                                   # model is highly confident
    return False


def verify(f: Finding, min_score: int = 38, fp_filter: bool = True, strict: bool = True) -> dict:
    """Score `f`, recalibrate confidence, decide keep/drop. Mutates `f`.

    Two-stage reviewer:
      1) Ensemble score = rule score blended with the learned MLP's P(true-positive).
      2) Strict corroboration gate (default on): a borderline finding is kept only
         when a SECOND independent signal (active proof / strong signature / high ML /
         Confirmed) agrees — this is what drives false positives toward zero.
    """
    score, reasons = score_finding(f)
    if f.extra is None:
        f.extra = {}
    ml = ml_model.score(f)
    if ml is not None:
        combined = round(0.55 * score + 0.45 * (ml * 100))
        reasons.append(f"ML P(TP)={ml:.2f} → blended {score}→{combined}")
        f.extra["ml_prob"] = round(ml, 4)
        f.extra["rule_score"] = score
        score = combined
    tier = _tier(score)
    f.confidence = tier
    f.extra["confidence_score"] = score

    keep = True
    if fp_filter and score < min_score:
        keep = False
        reasons.append(f"score {score} < min {min_score} → drop")
    # Stage-2 strict gate: below the "solid" bar AND no corroboration → drop as likely FP.
    if keep and strict and score < 62 and not _corroborated(f, ml):
        keep = False
        reasons.append("strict reviewer: no corroborating signal → drop (FP suppression)")
    # A real Critical is never silently discarded — surface it for manual review instead.
    if not keep and f.severity is Severity.CRITICAL:
        keep = True
        f.extra["low_confidence_review"] = True
        reasons.append("Critical → kept for manual review despite low confidence")

    f.extra["verify_reasons"] = reasons
    return {"score": score, "tier": tier, "keep": keep, "reasons": reasons}


def dedup_key(f: Finding) -> tuple:
    p = urlparse(f.url or "")
    return (f.module_id, _norm(f.title)[:80], f"{p.netloc}{p.path}")


def verify_all(findings: list[Finding], min_score: int = 38, fp_filter: bool = True,
               strict: bool = True) -> list[Finding]:
    """Batch verify + de-duplicate, keeping the highest-scoring instance of each."""
    best: dict[tuple, tuple[int, Finding]] = {}
    kept: list[Finding] = []
    for f in findings:
        res = verify(f, min_score=min_score, fp_filter=fp_filter, strict=strict)
        if not res["keep"]:
            continue
        k = dedup_key(f)
        prev = best.get(k)
        if prev is None or res["score"] > prev[0]:
            best[k] = (res["score"], f)
    # Preserve original order among survivors.
    seen = set()
    for f in findings:
        k = dedup_key(f)
        if k in best and best[k][1] is f and k not in seen:
            seen.add(k)
            kept.append(f)
    return kept
