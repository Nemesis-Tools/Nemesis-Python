"""Walk a source file or directory and run the SAST analyser over each file."""
from __future__ import annotations

import os

from core.sast.model import analyze_code, model_present, available

SOURCE_EXT = {
    ".py": "py", ".js": "js", ".jsx": "js", ".ts": "js", ".tsx": "js", ".mjs": "js",
    ".php": "php", ".java": "java", ".rb": "rb", ".go": "go",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp", ".cs": "cs",
}
_SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "__pycache__",
              ".venv", "venv", "site-packages", ".idea", ".vscode"}
_MAX_BYTES = 400_000


def _iter_files(path: str, max_files: int):
    if os.path.isfile(path):
        yield path
        return
    n = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in files:
            ext = os.path.splitext(name)[1].lower()
            if ext in SOURCE_EXT:
                yield os.path.join(root, name)
                n += 1
                if n >= max_files:
                    return


def scan_path(path: str, max_files: int = 400, log=None) -> dict:
    """Scan a file or directory tree. Returns aggregated findings + ML verdicts."""
    def _log(m):
        if log:
            log(m)
    path = os.path.abspath(os.path.expanduser(path.strip().strip('"')))
    if not os.path.exists(path):
        return {"ok": False, "error": f"경로 없음: {path}"}
    _log(f"[*] SAST 대상: {path}")
    _log(f"[*] CodeBERT 사용 가능: {available()}  ·  학습 모델 존재: {model_present()}")
    files_scanned = 0
    all_findings: list[dict] = []
    ml_flagged: list[dict] = []
    for fpath in _iter_files(path, max_files):
        ext = os.path.splitext(fpath)[1].lower()
        lang = SOURCE_EXT.get(ext, "*")
        try:
            if os.path.getsize(fpath) > _MAX_BYTES:
                continue
            with open(fpath, encoding="utf-8", errors="replace") as fh:
                code = fh.read()
        except Exception:
            continue
        rel = os.path.relpath(fpath, path if os.path.isdir(path) else os.path.dirname(path))
        res = analyze_code(code, lang, rel)
        files_scanned += 1
        for f in res["findings"]:
            all_findings.append(f)
        if res.get("ml") and res["ml"].get("vulnerable"):
            ml_flagged.append({"file": rel, **res["ml"]})
        if res["findings"]:
            _log(f"    · {rel}: {len(res['findings'])}건")
    _log(f"[*] 스캔 완료: 파일 {files_scanned}개, 취약 패턴 {len(all_findings)}건, "
         f"CodeBERT 취약 판정 {len(ml_flagged)}건")
    # sort by severity
    order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
    all_findings.sort(key=lambda f: order.get(f.get("severity"), 0), reverse=True)
    return {"ok": True, "path": path, "files_scanned": files_scanned,
            "findings": all_findings, "ml": ml_flagged,
            "codebert_used": model_present() and available()}


def format_report(res: dict) -> str:
    """Markdown report of a SAST scan."""
    if not res.get("ok"):
        return f"# SAST 오류\n\n{res.get('error')}"
    lines = [f"# SAST 소스코드 분석 — {res.get('path')}", "",
             f"**스캔 파일:** {res.get('files_scanned')}개  ·  "
             f"**취약 패턴:** {len(res.get('findings', []))}건  ·  "
             f"**CodeBERT:** {'사용' if res.get('codebert_used') else '미사용(휴리스틱만)'}", ""]
    by = {}
    for f in res.get("findings", []):
        by.setdefault(f.get("severity", "Info"), []).append(f)
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        rows = by.get(sev)
        if not rows:
            continue
        lines.append(f"## {sev} ({len(rows)})")
        for f in rows:
            lines.append(f"- `{f['file']}:{f['line']}` **{f['cwe']}** {f['name']}")
            lines.append(f"  - `{f['snippet']}`")
        lines.append("")
    if res.get("ml"):
        lines.append("## CodeBERT 취약 판정 파일")
        for m in res["ml"]:
            lines.append(f"- `{m['file']}` — {m.get('label')} (p={m.get('prob')})")
        lines.append("")
    if not res.get("findings") and not res.get("ml"):
        lines.append("_탐지된 취약 패턴이 없습니다._")
    return "\n".join(lines)
