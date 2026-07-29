"""Train the vulnerability-finding classifier (pure-Python MLP, no deps).

Builds a curated + augmented training set of finding feature vectors labelled
true-positive (1) / false-positive (0), trains a small MLP with backprop, and
writes core/../models/vuln_model.json (loaded by core.ml_model at runtime).

User feedback (models/feedback.jsonl, lines of {"features":[...],"label":0|1})
is merged in when present, so the model improves as findings are triaged.

    python tools/train_model.py
"""
from __future__ import annotations

import json
import math
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
MODELS = os.path.join(ROOT, "models")
os.makedirs(MODELS, exist_ok=True)

import re
import sys
sys.path.insert(0, ROOT)
from core.ml_model import FEATURES, extract_features  # noqa: E402

N_IN = len(FEATURES)
N_HID = 20
random.seed(1337)


def _load_templates():
    """Every registered template dict, so training covers ALL techniques."""
    try:
        from modules import load_all
        load_all()
        from modules.templates.engine import ALL_TEMPLATES
        return list(ALL_TEMPLATES)
    except Exception as e:
        print("  [!] could not load templates:", e)
        return []


def _tpl_evidence_tp(t: dict) -> str:
    """Realistic 'signature matched' evidence derived from a template's own matcher."""
    m = t.get("match", {}) or {}
    parts = []
    paths = t.get("paths") or ([t["path"]] if t.get("path") else [])
    if paths:
        parts.append("GET " + str(paths[0]))
    st = m.get("status", [200])
    parts.append("-> %s" % (st[0] if st else 200))
    for w in (m.get("words") or [])[:6]:
        parts.append(str(w))
    if m.get("regex"):
        parts.append(re.sub(r"[\\^$*+?()\[\]{}|]", " ", str(m["regex"]))[:90])
    if m.get("header_regex"):
        parts.append(re.sub(r"[\\^$*+?()\[\]{}|]", " ", str(m["header_regex"]))[:60])
    parts.append("(signature matched)")
    return " ".join(parts)


def _tpl_evidence_fp(t: dict) -> str:
    """Catch-all / soft-404 style negative (no real signature)."""
    paths = t.get("paths") or ([t["path"]] if t.get("path") else ["/x"])
    return ("GET %s -> 200 <!doctype html><html> application shell; matched baseline "
            "(no specific signature) — likely soft-404 / candidate" % paths[0])


# ---- curated prototypes grounded in REAL detection signatures --------------------
# Sources: real DBMS error strings, real cloud-metadata responses, real exposed-file
# fingerprints (nuclei/CVE-style), real CORS/redirect/XSS reflection evidence, and
# real disclosure patterns. label 1 = true positive, 0 = false positive (noise).
_PROTOTYPES = [
    # --- Injection: real DBMS error strings (error-based SQLi) ---
    ("sqli", "Firm", "Payload ' triggered: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version (absent in baseline)", "High", {}, 1),
    ("sqli", "Firm", "Payload ' -> PG::SyntaxError: unterminated quoted string at or near (reflected, absent in baseline)", "High", {}, 1),
    ("sqli", "Firm", "Payload ' -> Unclosed quotation mark after the character string (Microsoft SQL Server error)", "High", {}, 1),
    ("sqli", "Firm", "Payload ' -> ORA-01756: quoted string not properly terminated (Oracle)", "High", {}, 1),
    ("sqli", "Firm", "Payload ' -> SQLite3::SQLException: unrecognized token", "High", {}, 1),
    ("sqli_blind_time", "Firm", "Boolean/time payload: response delayed 5.1s on SLEEP(5), 0.2s on baseline (absent in baseline)", "High", {}, 1),
    ("command_injection", "Firm", "Payload ';id' -> uid=0(root) gid=0(root) groups=0(root) signature matched", "Critical", {}, 1),
    ("command_injection", "Firm", "Payload '|whoami' -> nt authority\\system reflected", "Critical", {}, 1),
    ("ssti", "Firm", "Payload {{7*7}} rendered as 49 (absent in baseline)", "High", {}, 1),
    ("ssti", "Firm", "Payload ${7*7} -> 49; ${T(java.lang.Runtime)} reachable", "Critical", {}, 1),
    ("path_traversal", "Firm", "Payload ../../../../etc/passwd -> root:x:0:0:root:/root:/bin/bash", "High", {}, 1),
    ("xxe", "Confirmed", "Content-Type application/xml: /etc/passwd signature returned. root:x:0:0:", "High", {}, 1),
    ("xxe", "Confirmed", "XXE Windows: c:/windows/win.ini returned [extensions] [fonts]", "High", {}, 1),
    ("crlf", "Firm", "Payload %0d%0aSet-Cookie:crlf=1 -> injected Set-Cookie reflected in response headers", "Medium", {}, 1),
    ("nosql_injection", "Firm", "Payload [$ne]=1 -> auth bypass; different result set vs baseline", "High", {}, 1),
    ("ssrf", "Firm", "payload http://169.254.169.254/latest/meta-data/iam/security-credentials/ -> AccessKeyId, SecretAccessKey returned (metadata)", "High", {}, 1),
    ("ssrf", "Firm", "payload http://metadata.google.internal/computeMetadata/v1/ -> computeMetadata project-id serviceAccounts", "High", {}, 1),
    ("rfi", "Firm", "include param -> failed to open stream: allow_url_include disabled (error-based RFI signature)", "High", {}, 1),
    ("log4shell", "Confirmed", "Canary interaction token t8f3.. received via ldap:// — JNDI lookup resolved (RCE)", "Critical", {}, 1),
    # --- Exposures: real file fingerprints ---
    ("sensitive_files", "Firm", "GET /.env -> 200 APP_KEY=base64: DB_PASSWORD= DB_USERNAME= (signature matched)", "High", {}, 1),
    ("sensitive_files", "Firm", "GET /.git/config -> 200 [core] repositoryformatversion = 0 (signature matched)", "High", {}, 1),
    ("sensitive_files", "Firm", "GET /.aws/credentials -> aws_access_key_id = AKIA... aws_secret_access_key", "Critical", {}, 1),
    ("sensitive_files", "Firm", "GET /id_rsa -> -----BEGIN RSA PRIVATE KEY----- (signature matched)", "Critical", {}, 1),
    ("sensitive_files", "Firm", "GET /wp-config.php.bak -> define('DB_PASSWORD', ...) exposed", "High", {}, 1),
    ("sensitive_files", "Firm", "GET /.htpasswd -> admin:$apr1$ hash exposed", "Medium", {}, 1),
    ("dir_listing", "Firm", "GET /uploads/ -> 200 <title>Index of /uploads</title> Directory listing", "Low", {}, 1),
    ("source_map", "Firm", "GET /app.js.map -> 200 sourcesContent webpack:// (signature matched)", "Medium", {}, 1),
    # --- Panels / misconfig: real fingerprints ---
    ("container_k8s_exposure", "Firm", "GET /version -> 200 \"ApiVersion\" \"GitCommit\" \"Os\":\"linux\" (Docker Engine API)", "Critical", {}, 1),
    ("container_k8s_exposure", "Firm", "GET /api/v1/pods -> 200 \"kind\":\"PodList\" (Kubernetes API exposed)", "Critical", {}, 1),
    ("http_methods", "Firm", "OPTIONS -> Allow: GET,POST,PUT,DELETE,TRACE; TRACE enabled (XST)", "Low", {}, 1),
    # --- Client-side / headers: real, accurate config findings (true positives) ---
    ("cors", "Firm", "Sent Origin: https://evil.example.com -> Access-Control-Allow-Origin: https://evil.example.com; Access-Control-Allow-Credentials: true", "High", {}, 1),
    ("clickjacking", "Confirmed", "framing_proven success; 대상이 외부 origin iframe에 렌더링됨 (스크린샷 첨부)", "Medium", {"framing_proven": True, "screenshot_b64": "iVBOR"}, 1),
    ("xss_reflected", "Firm", "Payload '\"><svg onload=alert(1)>' reflected unencoded in HTML body context (absent in baseline)", "High", {}, 1),
    ("xss_dom", "Firm", "location.hash flows to element.innerHTML sink; alert(1) executed in DOM", "High", {}, 1),
    ("open_redirect", "Firm", "?next=//evil.tld -> HTTP 302 Location: https://evil.tld (redirected off-site)", "Medium", {}, 1),
    ("security_headers", "Firm", "Strict-Transport-Security: absent; Content-Security-Policy: absent; X-Content-Type-Options: absent", "Low", {}, 1),
    ("cookies", "Firm", "Session cookie set without Secure and without HttpOnly flags", "Medium", {}, 1),
    ("tls_analysis", "Firm", "Certificate expired 2021-04-02; TLS 1.0/1.1 enabled; weak cipher RC4", "Medium", {}, 1),
    ("subdomain_takeover", "Firm", "CNAME -> s3.amazonaws.com; GET returns NoSuchBucket: The specified bucket does not exist (takeover)", "High", {}, 1),
    ("jwt_analysis", "Firm", "JWT accepts alg:none — forged token with admin claim accepted (auth bypass)", "High", {}, 1),
    # ---------------------------- FALSE POSITIVES / NOISE ----------------------------
    ("xs_leaks", "Tentative", "framable=yes; missing isolation: ['cross-origin-opener-policy','cross-origin-embedder-policy']", "Low", {}, 0),
    ("mxss", "Tentative", "", "Low", {}, 0),
    ("mxss", "Tentative", "sinks=['innerHTML'] libs=['jquery'] untrusted_input=False", "Low", {}, 0),
    ("csrf", "Tentative", "Action: /search  Fields: ['q','submit']", "Medium", {}, 0),
    ("csrf", "Tentative", "POST form without anti-CSRF token: /newsletter (may use SameSite)", "Medium", {}, 0),
    ("supply_chain", "Tentative", "internal/private registry or scope reference found (dependency-confusion hint)", "Low", {}, 0),
    ("race_condition", "Tentative", "action=/comment fields=['text','submit'] candidate", "Low", {}, 0),
    ("ssrf", "Tentative", "SSRF in-band probes sent — no metadata reflected", "Info", {}, 0),
    ("rfi", "Tentative", "RFI in-band probes sent — no include error surfaced", "Info", {}, 0),
    ("log4shell", "Tentative", "JNDI payloads sent — needs OOB to confirm", "Info", {}, 0),
    ("blind_xss", "Tentative", "payloads sent — no in-band reflection", "Info", {}, 0),
    ("prototype_pollution", "Tentative", "candidate: __proto__ param accepted (may be benign)", "Low", {}, 0),
    ("business_logic_recon", "Tentative", "possible workflow step exposed (추정)", "Info", {}, 0),
    ("subdomain_takeover", "Tentative", "CNAME points to provider but resolves normally — verify manually (no takeover signature)", "Medium", {}, 0),
    ("idor_candidates", "Tentative", "numeric id parameter observed — candidate only, no access-control diff", "Medium", {}, 0),
    ("xss_reflected", "Tentative", "payload reflected but HTML-encoded (&lt;svg&gt;) — not executable", "Info", {}, 0),
    ("open_redirect", "Tentative", "?next=/dashboard -> redirect stays same-origin (not exploitable)", "Info", {}, 0),
    ("auth_surface", "Tentative", "login endpoint discovered — informational", "Info", {}, 0),
    ("upload_recon", "Tentative", "file upload field present — candidate, no bypass confirmed", "Low", {}, 0),
    ("cors", "Tentative", "ACAO reflects origin but Access-Control-Allow-Credentials absent — low impact", "Low", {}, 0),
]


class _Row:
    """Adapter so extract_features can read a prototype like a Finding."""
    def __init__(self, mid, conf, ev, sev, extra):
        self.module_id, self.confidence, self.evidence = mid, conf, ev
        self.severity, self.extra = sev, extra
        self.title = mid.replace("_", " ")
        self.request = "GET /x" if random.random() < 0.5 else ""
        self.url = "https://t/a?id=1" if random.random() < 0.5 else "https://t/a"


def _augment(vec, jitter=0.05):
    # Jitter only in-range values; keep exact 0/1 and empty char-gram buckets intact.
    return [v if (v <= 0.0 or v >= 1.0)
            else min(1.0, max(0.0, v + random.uniform(-jitter, jitter))) for v in vec]


def build_dataset(n_per=10):
    X, Y = [], []
    for (mid, conf, ev, sev, extra, label) in _PROTOTYPES:
        base = extract_features(_Row(mid, conf, ev, sev, extra))
        X.append(base); Y.append(float(label))
        for _ in range(n_per):
            X.append(_augment(base)); Y.append(float(label))

    # Per-technique examples derived from EVERY template's own detection signature
    # → the model learns each of the ~250 technique signatures (covers all modules).
    templates = _load_templates()
    n_tpl = 0
    for t in templates:
        sev = t.get("severity", "info")
        # TP: the technique's real signature was observed.
        tp = _Row(t["id"], "Firm", _tpl_evidence_tp(t), sev, {})
        X.append(extract_features(tp)); Y.append(1.0)
        # FP: catch-all/soft-404 shell with no specific signature.
        fp = _Row(t["id"], "Tentative", _tpl_evidence_fp(t), sev, {})
        X.append(extract_features(fp)); Y.append(0.0)
        X.append(_augment(extract_features(tp))); Y.append(1.0)
        X.append(_augment(extract_features(fp))); Y.append(0.0)
        n_tpl += 1
    print(f"[*] template-derived techniques: {n_tpl}")
    # Merge user feedback if present.
    fb = os.path.join(MODELS, "feedback.jsonl")
    n_fb = 0
    if os.path.exists(fb):
        for line in open(fb, encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                feats = d.get("features")
                lab = d.get("label")
                if isinstance(feats, list) and len(feats) == N_IN and lab in (0, 1):
                    # weight feedback heavily (repeat) — it's real ground truth
                    for _ in range(6):
                        X.append(list(map(float, feats))); Y.append(float(lab))
                    n_fb += 1
            except Exception:
                continue
    return X, Y, n_fb


def train(X, Y, epochs=240, lr=0.15):
    def rnd():
        return random.uniform(-0.5, 0.5)
    W1 = [[rnd() for _ in range(N_HID)] for _ in range(N_IN)]
    b1 = [0.0] * N_HID
    W2 = [rnd() for _ in range(N_HID)]
    b2 = 0.0
    idx = list(range(len(X)))
    for ep in range(epochs):
        random.shuffle(idx)
        loss = 0.0
        for n in idx:
            x, y = X[n], Y[n]
            # forward
            h, hpre = [0.0] * N_HID, [0.0] * N_HID
            for j in range(N_HID):
                s = b1[j]
                for i in range(N_IN):
                    s += x[i] * W1[i][j]
                hpre[j] = s
                h[j] = math.tanh(s)
            o = b2
            for j in range(N_HID):
                o += h[j] * W2[j]
            o = max(-60.0, min(60.0, o))
            p = 1.0 / (1.0 + math.exp(-o))
            loss += -(y * math.log(p + 1e-9) + (1 - y) * math.log(1 - p + 1e-9))
            # backward
            do = p - y
            for j in range(N_HID):
                dh = do * W2[j] * (1 - h[j] * h[j])
                W2[j] -= lr * do * h[j]
                for i in range(N_IN):
                    W1[i][j] -= lr * dh * x[i]
                b1[j] -= lr * dh
            b2 -= lr * do
        if ep % 100 == 0 or ep == epochs - 1:
            print(f"  epoch {ep:4d}  loss/sample={loss/len(X):.4f}")
    return {"W1": W1, "b1": b1, "W2": W2, "b2": b2, "features": FEATURES}


def main():
    X, Y, n_fb = build_dataset()
    print(f"[*] dataset: {len(X)} samples ({int(sum(Y))} TP / {int(len(Y)-sum(Y))} FP), "
          f"feedback rows merged: {n_fb}")
    model = train(X, Y)
    # quick train accuracy
    correct = 0
    from core.ml_model import _MLP
    m = _MLP(model)
    for x, y in zip(X, Y):
        correct += int((m.predict_proba(x) >= 0.5) == (y >= 0.5))
    print(f"[*] train accuracy: {correct/len(X):.3f}")
    out = os.path.join(MODELS, "vuln_model.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(model, fh)
    print(f"[*] wrote {out}")


if __name__ == "__main__":
    main()
