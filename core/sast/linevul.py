"""LineVul-style line-level vulnerability localisation (defensive / detection).

Once the CodeBERT classifier (core.sast.model, trained by tools/train_sast.py)
predicts a snippet is vulnerable, LineVul's idea is to attribute that decision
back to individual source lines using the encoder's self-attention: tokens the
[CLS] decision attends to most are aggregated to their source lines, ranking
which LINES are most likely vulnerable. This is a *detection* aid — it tells a
reviewer WHERE to look, it does not attack anything.

Requires the optional deps (torch + transformers) and a trained model; without
them the SAST scan still runs the heuristic rule engine.
"""
from __future__ import annotations

from core.sast.model import _load_codebert, model_present, available


def _lines_from_offsets(code: str, offsets, scores):
    """Aggregate per-token attribution scores onto 1-based source lines."""
    # Precompute char-index → line number.
    line_of = []
    ln = 1
    for ch in code:
        line_of.append(ln)
        if ch == "\n":
            ln += 1
    line_of.append(ln)
    per_line: dict[int, float] = {}
    for (start, end), sc in zip(offsets, scores):
        if start == end:                      # special tokens have (0,0)
            continue
        idx = min(start, len(line_of) - 1)
        line = line_of[idx]
        per_line[line] = per_line.get(line, 0.0) + float(sc)
    return per_line


def line_scores(code: str, top_k: int = 8) -> list[dict] | None:
    """Rank the most-likely-vulnerable lines. None if model/deps unavailable.

    Returns [{line, score, text}] sorted by descending attribution, only when
    the classifier itself predicts the snippet is vulnerable.
    """
    if not (available() and model_present()):
        return None
    c = _load_codebert()
    if c["model"] is None or c["tok"] is None:
        return None
    try:
        import torch
        enc = c["tok"](code, truncation=True, max_length=512,
                       return_offsets_mapping=True, return_tensors="pt")
        offsets = enc.pop("offset_mapping")[0].tolist()
        with torch.no_grad():
            out = c["model"](**enc, output_attentions=True)
        probs = torch.softmax(out.logits[0], dim=-1).tolist()
        top = max(range(len(probs)), key=lambda i: probs[i])
        labels = c["labels"] or {}
        label = labels.get(str(top), str(top))
        if str(label).lower() in ("0", "safe", "none", "clean"):
            return []                          # model says not vulnerable
        # Last-layer attention, averaged over heads; [CLS] (row 0) → each token.
        attn = out.attentions[-1][0]           # (heads, seq, seq)
        cls_attn = attn.mean(dim=0)[0].tolist()  # (seq,)
        per_line = _lines_from_offsets(code, offsets, cls_attn)
    except Exception:
        return None
    src_lines = code.splitlines()
    ranked = sorted(per_line.items(), key=lambda kv: kv[1], reverse=True)[:top_k]
    mx = max((s for _, s in ranked), default=1.0) or 1.0
    return [{"line": ln, "score": round(s / mx, 4),
             "text": (src_lines[ln - 1].strip()[:200] if 0 < ln <= len(src_lines) else "")}
            for ln, s in ranked if s > 0]
