"""Evaluate the trained DAST finding-verifier (models/vuln_model.json).

Reports research-standard metrics (Precision / Recall / F1 / Accuracy /
ROC-AUC) on a fresh held-out split of the synthetic signature dataset, and —
separately — agreement with the real human/Claude labels in feedback.jsonl.

    python tools/eval_model.py
"""
from __future__ import annotations

import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
MODELS = os.path.join(ROOT, "models")
sys.path.insert(0, ROOT)

from core import metrics                       # noqa: E402
from core.ml_model import load_model           # noqa: E402


def _held_out(seed: int = 4242, val_frac: float = 0.2):
    """A held-out view built with a DIFFERENT seed than training, so evaluation
    rows differ from the ones the trainer augmented into TRAIN."""
    import tools.train_model as T
    random.seed(seed)
    base = T._base_rows()
    random.shuffle(base)
    n_val = max(1, int(len(base) * val_frac))
    val = base[:n_val]
    return [f for f, _ in val], [y for _, y in val]


def _feedback_eval(model):
    fb = os.path.join(MODELS, "feedback.jsonl")
    if not os.path.exists(fb):
        return None
    yt, ys, src = [], [], {"human": 0, "claude": 0}
    for line in open(fb, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
            feats, lab = d.get("features"), d.get("label")
            if not (isinstance(feats, list) and lab in (0, 1)):
                continue
            yt.append(float(lab))
            ys.append(model.predict_proba([float(v) for v in feats]))
            src["claude" if d.get("source") == "claude" else "human"] += 1
        except Exception:
            continue
    if not yt:
        return None
    return metrics.report(yt, ys), src


def main():
    model = load_model()
    if model is None:
        print("[!] models/vuln_model.json 없음 — 먼저 python tools/train_model.py 실행")
        return
    print(f"[*] model loaded (features={len(model.features)})")

    # Stored provenance metrics (from the last training run).
    try:
        with open(os.path.join(MODELS, "vuln_model.json"), encoding="utf-8") as fh:
            ev = json.load(fh).get("eval")
        if ev:
            print(f"[*] stored val metrics @train: F1={ev.get('f1')} "
                  f"ROC-AUC={ev.get('roc_auc')} (feedback={ev.get('feedback')})")
    except Exception:
        pass

    Xv, Yv = _held_out()
    scores = [model.predict_proba(x) for x in Xv]
    print(metrics.format_report(metrics.report(Yv, scores), "held-out (fresh split)"))

    fe = _feedback_eval(model)
    if fe:
        rep, src = fe
        print(metrics.format_report(rep, f"feedback labels (in-sample, human={src['human']}, claude={src['claude']})"))
    else:
        print("[*] feedback.jsonl 라벨 없음 — 👍/👎 또는 /test(Claude) 사용 시 축적됩니다.")


if __name__ == "__main__":
    main()
