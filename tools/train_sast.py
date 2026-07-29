"""Fine-tune a CodeBERT source-code vulnerability classifier (SAST track).

Follows the mainstream vulnerability-detection methodology (CodeBERT /
GraphCodeBERT / VulBERTa): a pre-trained code encoder + a classification head,
fine-tuned on function-level labelled data (Devign / Big-Vul / Juliet), then
evaluated with Precision / Recall / F1 / ROC-AUC.

The trained model is written to models/sast_codebert/ and picked up
automatically at runtime by core.sast (the `/sast` command).

Requires the optional heavy deps:  pip install torch transformers

Dataset format — a JSONL or CSV with a code column and a label column:
    {"code": "<function source>", "label": 1}        # 1 = vulnerable, 0 = safe
    {"func": "...", "target": "CWE-89"}               # multi-class also supported
Column names auto-detected: code|func|function|snippet  and  label|target|vul|y.

Usage:
    python tools/train_sast.py --data path/to/devign.jsonl --epochs 3
    python tools/train_sast.py --data bigvul.csv --base microsoft/graphcodebert-base
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from core import metrics  # noqa: E402

_CODE_KEYS = ("code", "func", "function", "snippet", "source")
_LABEL_KEYS = ("label", "target", "vul", "vulnerable", "y", "cwe")

# Tiny built-in demo set so the pipeline is runnable end-to-end without a corpus
# (NOT for real use — pass --data with Devign/Big-Vul/Juliet for a usable model).
_DEMO = [
    ("int f(char*s){char b[8];strcpy(b,s);return 0;}", 1),
    ("void g(char*s){char b[64];strncpy(b,s,63);b[63]=0;}", 0),
    ("q='SELECT * FROM u WHERE id='+x; db.execute(q)", 1),
    ("db.execute('SELECT * FROM u WHERE id=%s',(x,))", 0),
    ("os.system('ping '+host)", 1),
    ("subprocess.run(['ping', host])", 0),
    ("pickle.loads(data)", 1),
    ("json.loads(data)", 0),
    ("eval(user_input)", 1),
    ("ast.literal_eval(user_input)", 0),
]


def _load_rows(path: str):
    if not path:
        print("[!] --data 미지정 → 내장 데모 데이터로 실행(실사용 아님). Devign/Big-Vul/Juliet 권장.")
        return [{"code": c, "label": y} for c, y in _DEMO]
    rows = []
    if path.endswith(".jsonl"):
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    elif path.endswith(".json"):
        data = json.load(open(path, encoding="utf-8"))
        rows = data if isinstance(data, list) else data.get("data", [])
    elif path.endswith(".csv"):
        rows = list(csv.DictReader(open(path, encoding="utf-8")))
    else:
        raise SystemExit(f"지원하지 않는 형식: {path} (.jsonl/.json/.csv)")
    return rows


def _pick(row: dict, keys):
    for k in keys:
        if k in row and row[k] not in (None, ""):
            return row[k]
    return None


def _normalize(rows):
    codes, raw_labels = [], []
    for r in rows:
        c = _pick(r, _CODE_KEYS)
        y = _pick(r, _LABEL_KEYS)
        if c is None or y is None:
            continue
        codes.append(str(c))
        raw_labels.append(str(y).strip())
    # binary 0/1 stays binary; otherwise treat as categorical (e.g. CWE-89)
    uniq = sorted(set(raw_labels))
    if uniq == ["0", "1"] or uniq == ["0"] or uniq == ["1"]:
        label2id = {"safe": 0, "vulnerable": 1}
        ids = [int(y) for y in raw_labels]
        id2label = {0: "safe", 1: "vulnerable"}
    else:
        id2label = {i: lab for i, lab in enumerate(uniq)}
        label2id = {lab: i for i, lab in id2label.items()}
        ids = [label2id[y] for y in raw_labels]
    return codes, ids, id2label


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="")
    ap.add_argument("--base", default="microsoft/codebert-base")
    ap.add_argument("--out", default=os.path.join(ROOT, "models", "sast_codebert"))
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--batch", type=int, default=8)
    ap.add_argument("--maxlen", type=int, default=256)
    ap.add_argument("--lr", type=float, default=2e-5)
    ap.add_argument("--val", type=float, default=0.15)
    args = ap.parse_args()

    try:
        import torch
        from torch.utils.data import DataLoader, TensorDataset
        from transformers import (AutoTokenizer, AutoModelForSequenceClassification,
                                  get_linear_schedule_with_warmup)
    except Exception:
        raise SystemExit("torch/transformers 필요 →  pip install torch transformers")

    rows = _load_rows(args.data)
    codes, labels, id2label = _normalize(rows)
    n_labels = len(id2label)
    print(f"[*] samples={len(codes)}  labels={id2label}")
    if len(codes) < 4:
        raise SystemExit("데이터가 너무 적습니다.")

    random.seed(1337)
    idx = list(range(len(codes)))
    random.shuffle(idx)
    n_val = max(1, int(len(idx) * args.val))
    val_i, tr_i = set(idx[:n_val]), idx[n_val:]

    tok = AutoTokenizer.from_pretrained(args.base)

    def encode(indices):
        enc = tok([codes[i] for i in indices], truncation=True, max_length=args.maxlen,
                  padding="max_length", return_tensors="pt")
        y = torch.tensor([labels[i] for i in indices])
        return TensorDataset(enc["input_ids"], enc["attention_mask"], y)

    tr = DataLoader(encode(tr_i), batch_size=args.batch, shuffle=True)
    va = DataLoader(encode(sorted(val_i)), batch_size=args.batch)

    device = "cuda" if torch.cuda.is_available() else "cpu"
    model = AutoModelForSequenceClassification.from_pretrained(args.base, num_labels=n_labels).to(device)
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr)
    steps = len(tr) * args.epochs
    sched = get_linear_schedule_with_warmup(opt, int(steps * 0.1), steps)

    for ep in range(args.epochs):
        model.train()
        tot = 0.0
        for ids_b, mask_b, y_b in tr:
            opt.zero_grad()
            out = model(input_ids=ids_b.to(device), attention_mask=mask_b.to(device),
                        labels=y_b.to(device))
            out.loss.backward()
            opt.step(); sched.step()
            tot += out.loss.item()
        print(f"  epoch {ep}  loss={tot/max(1,len(tr)):.4f}")

    # eval
    model.eval()
    y_true, y_pred, y_pos = [], [], []
    with torch.no_grad():
        for ids_b, mask_b, y_b in va:
            logits = model(input_ids=ids_b.to(device), attention_mask=mask_b.to(device)).logits
            probs = torch.softmax(logits, dim=-1).cpu().tolist()
            for p, yt in zip(probs, y_b.tolist()):
                y_true.append(yt)
                y_pred.append(max(range(len(p)), key=lambda i: p[i]))
                y_pos.append(p[1] if len(p) == 2 else p[max(range(len(p)), key=lambda i: p[i])])
    if n_labels == 2:
        print(metrics.format_report(metrics.report(y_true, y_pos), "val"))
    else:
        acc = sum(int(a == b) for a, b in zip(y_true, y_pred)) / max(1, len(y_true))
        print(f"[val] multi-class accuracy={acc:.4f} (n={len(y_true)})")

    os.makedirs(args.out, exist_ok=True)
    model.save_pretrained(args.out)
    tok.save_pretrained(args.out)
    with open(os.path.join(args.out, "labels.json"), "w", encoding="utf-8") as fh:
        json.dump({str(k): v for k, v in id2label.items()}, fh, ensure_ascii=False)
    print(f"[*] 저장 완료 → {args.out}  (core.sast 가 자동 로드)")


if __name__ == "__main__":
    main()
