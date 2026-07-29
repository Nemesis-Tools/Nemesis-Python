"""SAST (static source-code analysis) track.

White-box source-code vulnerability detection, complementing the black-box DAST
scanner. Two layers:

  * A dependency-free heuristic rule engine (CWE-tagged insecure-pattern
    detection) that always works and bundles into the .exe.
  * An optional CodeBERT / GraphCodeBERT sequence classifier (guarded torch +
    transformers) that refines/augments the heuristic verdict when a fine-tuned
    model is present — trained by tools/train_sast.py on Devign / Big-Vul /
    Juliet, following the vulnerability-detection literature.

Authorised use only: analyse source code you own or are permitted to review.
"""
from core.sast.model import (available, model_present, analyze_code,  # noqa: F401
                             predict_codebert, heuristic_scan)
from core.sast.scan import scan_path, SOURCE_EXT  # noqa: F401
