"""Pure-Python classification metrics (no numpy/sklearn).

Shared by the DAST finding-verifier trainer (tools/train_model.py,
tools/eval_model.py) and the SAST source-code classifier evaluation, so both
tracks report the same research-standard metrics: Precision, Recall, F1,
Accuracy, and ROC-AUC — the evaluation set used across the vulnerability-
detection literature (Devign, CodeBERT, VulBERTa, …).
"""
from __future__ import annotations


def confusion(y_true, y_pred) -> dict:
    """Binary confusion counts at an already-thresholded prediction."""
    tp = fp = tn = fn = 0
    for yt, yp in zip(y_true, y_pred):
        yt, yp = int(yt >= 0.5), int(yp >= 0.5)
        if yt and yp:
            tp += 1
        elif not yt and yp:
            fp += 1
        elif not yt and not yp:
            tn += 1
        else:
            fn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def prf1(y_true, y_pred) -> dict:
    """Precision / Recall / F1 / Accuracy at threshold 0.5."""
    c = confusion(y_true, y_pred)
    tp, fp, tn, fn = c["tp"], c["fp"], c["tn"], c["fn"]
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    acc = (tp + tn) / max(1, tp + fp + tn + fn)
    return {"precision": prec, "recall": rec, "f1": f1, "accuracy": acc, **c}


def _average_ranks(scores):
    """Fractional (tie-averaged) ranks, 1-based — for a rank-based AUC."""
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    ranks = [0.0] * len(scores)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1.0                 # average 1-based rank of the tie block
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    return ranks


def roc_auc(y_true, y_score) -> float:
    """ROC-AUC via the Mann–Whitney U statistic (probability a random positive
    outranks a random negative). Returns NaN if only one class is present."""
    pos = sum(1 for y in y_true if y >= 0.5)
    neg = len(y_true) - pos
    if pos == 0 or neg == 0:
        return float("nan")
    ranks = _average_ranks(list(y_score))
    sum_pos = sum(r for r, y in zip(ranks, y_true) if y >= 0.5)
    return (sum_pos - pos * (pos + 1) / 2.0) / (pos * neg)


def report(y_true, y_score, threshold: float = 0.5) -> dict:
    """Full metric bundle: threshold P/R/F1/Acc + threshold-free ROC-AUC."""
    y_pred = [1.0 if s >= threshold else 0.0 for s in y_score]
    out = prf1(y_true, y_pred)
    out["roc_auc"] = roc_auc(y_true, y_score)
    out["n"] = len(y_true)
    out["pos"] = int(sum(1 for y in y_true if y >= 0.5))
    return out


def format_report(m: dict, title: str = "metrics") -> str:
    auc = m.get("roc_auc")
    auc_s = f"{auc:.4f}" if auc == auc else "n/a"      # NaN check
    return (f"[{title}]  n={m.get('n')} (pos={m.get('pos')})  "
            f"P={m['precision']:.4f}  R={m['recall']:.4f}  F1={m['f1']:.4f}  "
            f"Acc={m['accuracy']:.4f}  ROC-AUC={auc_s}\n"
            f"          TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']}")
