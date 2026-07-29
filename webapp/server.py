"""Flask backend for the HTML bug bounty scanner UI.

Reuses the existing Scanner/modules/report engine. A single ScanSession holds
shared state (logs, findings, latest browser frame, progress) that the front-end
polls. The live Selenium view is served as periodic screenshots via /api/frame.
"""
from __future__ import annotations

import os
import sys
import threading

from flask import Flask, jsonify, request, send_file, Response, abort

from modules import load_all
from modules.base import modules_by_category
from core.scanner import Scanner
from core.result import Finding
from core import report
from core.http_utils import parse_headers_block, parse_cookie_string
from webapp.interactive import InteractiveBrowser

HERE = os.path.dirname(os.path.abspath(__file__))
# In a PyInstaller onefile build, bundled data lives under sys._MEIPASS.
if getattr(sys, "frozen", False):
    _ROOT = getattr(sys, "_MEIPASS", HERE)
    STATIC = os.path.join(_ROOT, "webapp", "static")
else:
    _ROOT = os.path.dirname(HERE)   # project root
    STATIC = os.path.join(HERE, "static")
LOGO = os.path.join(_ROOT, "logo.png")
ICON = os.path.join(_ROOT, "logo.ico")


class ScanSession:
    """Holds the state of one running/completed scan."""

    def __init__(self):
        self.lock = threading.Lock()
        self.reset()

    def reset(self):
        with self.lock if hasattr(self, "lock") else _dummy():
            self.logs: list[str] = []
            self.findings: list[Finding] = []
            self.frame: bytes | None = None
            self.progress = {"current": 0, "total": 1, "label": ""}
            self.running = False
            self.target = ""
            self.worker: threading.Thread | None = None
            self._scanner: Scanner | None = None
            self.need_login = False
            self._cred_event = threading.Event()
            self._creds = None
            # Gemini AI agent (/test): runs alongside the ML model.
            self.llm_running = False
            self.llm_result_md = ""
            # SAST source-code analysis (/sast).
            self.sast_running = False
            self.sast_result_md = ""

    def on_need_credentials(self):
        """Blocking callback for the scanner: signal the UI to collect creds."""
        with self.lock:
            self._creds = None
            self._cred_event.clear()
            self.need_login = True
        self._cred_event.wait(timeout=300)   # wait for POST /api/credentials
        with self.lock:
            self.need_login = False
            return self._creds

    # ---- callbacks from the scanner (run on the worker thread) ----
    def on_log(self, msg: str):
        with self.lock:
            self.logs.append(msg)

    def on_finding(self, f: Finding):
        with self.lock:
            self.findings.append(f)

    def on_progress(self, c: int, t: int, name: str):
        with self.lock:
            self.progress = {"current": c, "total": t, "label": name}

    def on_frame(self, png: bytes):
        with self.lock:
            self.frame = png

    def on_done(self, findings):
        with self.lock:
            self.running = False
            self.progress["label"] = f"완료 — {len(findings)}개 발견"

    # ---- control ----
    def start(self, target: str, module_ids: list[str], options: dict) -> bool:
        with self.lock:
            if self.running:
                return False
            self.logs, self.findings, self.frame = [], [], None
            self.progress = {"current": 0, "total": 1, "label": "시작 중…"}
            self.running = True
            self.target = target
            self.need_login = False
            self._creds = None
            self._cred_event.clear()
        self._scanner = Scanner(
            target=target, module_ids=module_ids, options=options,
            on_log=self.on_log, on_finding=self.on_finding,
            on_progress=self.on_progress, on_done=self.on_done, on_frame=self.on_frame,
            on_need_credentials=self.on_need_credentials)
        self.worker = threading.Thread(target=self._scanner.run, daemon=True)
        self.worker.start()
        return True

    def stop(self):
        if self._scanner is not None:
            self._scanner.stop()

    def snapshot(self, log_since: int, find_since: int) -> dict:
        with self.lock:
            new_logs = self.logs[log_since:]
            new_finds = [{**f.to_dict(), "index": find_since + i}
                         for i, f in enumerate(self.findings[find_since:])]
            return {
                "running": self.running,
                "progress": self.progress,
                "log_total": len(self.logs),
                "find_total": len(self.findings),
                "logs": new_logs,
                "findings": new_finds,
                "target": self.target,
                "need_login": self.need_login,
                "llm_running": self.llm_running,
                "llm_result": self.llm_result_md,
                "sast_running": self.sast_running,
                "sast_result": self.sast_result_md,
            }

    def submit_credentials(self, creds: dict) -> None:
        with self.lock:
            self._creds = creds
        self._cred_event.set()

    # ---- Gemini AI agent (/test) ----
    def start_llm_test(self, target: str, cfg: dict, models_dir: str) -> bool:
        with self.lock:
            if self.running or self.llm_running:
                return False
            self.llm_running = True
            self.llm_result_md = ""
            if not self.target:
                self.target = target
            findings = list(self.findings)
        t = threading.Thread(target=self._run_llm_test,
                             args=(target, cfg, models_dir, findings), daemon=True)
        t.start()
        return True

    def _run_llm_test(self, target, cfg, models_dir, findings) -> None:
        from core import llm_agent
        provider = (cfg.get("provider") or "gemini").strip()
        keys = cfg.get("keys") or {}
        models = cfg.get("models") or {}
        try:
            self.on_log("\n########## 🤖 멀티-LLM + 로컬 ML/DL 앙상블 분석 (/test) ##########")
            self.on_log(f"[*] 대상: {target}  ·  제공자: {provider}  ·  스캐너 결과 {len(findings)}건")
            if provider == "all":
                multi = llm_agent.analyze_multi(target, findings, ["all"], keys=keys,
                                                models=models, log=self.on_log)
                if not multi.get("ok"):
                    self.on_log(f"[!] 분석 실패: {multi.get('error')}")
                    return
                md = llm_agent.format_multi_report(target, multi)
                learn_from = [r["analysis"] for r in multi["results"] if r.get("ok")]
            else:
                res = llm_agent.analyze(target, findings, provider=provider,
                                        model=models.get(provider) or None,
                                        api_key=keys.get(provider) or None, log=self.on_log)
                if not res.get("ok"):
                    self.on_log(f"[!] 분석 실패: {res.get('error')}")
                    if res.get("hint"):
                        self.on_log(f"    💡 {res['hint']}")
                    if res.get("raw"):
                        self.on_log(f"    응답: {res['raw'][:300]}")
                    return
                md = llm_agent.format_report(target, res)
                learn_from = [res["analysis"]]
            with self.lock:
                self.llm_result_md = md
            for line in md.splitlines():
                self.on_log(line)
            # The local ML/DL model learns from each LLM's high-confidence verdicts.
            for a in learn_from:
                llm_agent.learn_from_llm(findings, a, models_dir, log=self.on_log)
            self.on_log("[*] LLM 분석 완료. (딥러닝/ML 모델과 병행 동작)")
        except Exception as e:
            self.on_log(f"[!] LLM 에이전트 오류: {e}")
        finally:
            with self.lock:
                self.llm_running = False

    # ---- SAST source-code analysis (/sast) ----
    def start_sast(self, path: str) -> bool:
        with self.lock:
            if self.running or self.sast_running:
                return False
            self.sast_running = True
            self.sast_result_md = ""
        t = threading.Thread(target=self._run_sast, args=(path,), daemon=True)
        t.start()
        return True

    def _run_sast(self, path: str) -> None:
        from core.sast import scan
        try:
            self.on_log("\n########## 🔬 SAST 소스코드 취약점 분석 (/sast) ##########")
            res = scan.scan_path(path, log=self.on_log)
            md = scan.format_report(res)
            with self.lock:
                self.sast_result_md = md
            for line in md.splitlines():
                self.on_log(line)
            self.on_log("[*] SAST 분석 완료.")
        except Exception as e:
            self.on_log(f"[!] SAST 오류: {e}")
        finally:
            with self.lock:
                self.sast_running = False


class _dummy:
    def __enter__(self): return self
    def __exit__(self, *a): return False


def create_app() -> Flask:
    load_all()
    app = Flask(__name__, static_folder=None)
    session = ScanSession()
    interactive = InteractiveBrowser(on_frame=session.on_frame, on_log=session.on_log)

    @app.route("/")
    def index():
        return send_file(os.path.join(STATIC, "index.html"))

    @app.route("/logo.png")
    def logo():
        if os.path.exists(LOGO):
            return send_file(LOGO, mimetype="image/png")
        abort(404)

    @app.route("/favicon.ico")
    def favicon():
        if os.path.exists(ICON):
            return send_file(ICON, mimetype="image/x-icon")
        if os.path.exists(LOGO):
            return send_file(LOGO, mimetype="image/png")
        abort(404)

    @app.route("/api/_debug")
    def api_debug():
        from modules import LOAD_ERRORS
        from modules.base import all_modules
        return jsonify({"frozen": getattr(sys, "frozen", False),
                        "meipass": getattr(sys, "_MEIPASS", None),
                        "static": STATIC, "registered": len(all_modules()),
                        "errors": LOAD_ERRORS[:25]})

    @app.route("/api/modules")
    def api_modules():
        out = {}
        for cat, mods in sorted(modules_by_category().items()):
            out[cat] = [{"id": m.id, "name": m.name, "description": m.description,
                         "default": m.default_enabled} for m in mods]
        return jsonify(out)

    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        data = request.get_json(force=True) or {}
        target = (data.get("target") or "").strip()
        module_ids = data.get("modules") or []
        if not target:
            return jsonify({"error": "URL을 입력하세요."}), 400
        if not data.get("scope_ok"):
            return jsonify({"error": "테스트 권한 확인에 동의해야 합니다."}), 400
        if not module_ids:
            return jsonify({"error": "공격 기법을 하나 이상 선택하세요."}), 400
        o = data.get("options") or {}
        options = {
            "headless": o.get("headless", True),
            "delay": float(o.get("delay", 0.5)),
            "page_timeout": int(o.get("page_timeout", 20)),
            "http_timeout": 15,
            "verify_tls": o.get("verify_tls", False),
            "devtools": o.get("devtools", False),
            "user_agent": o.get("user_agent", "").strip(),
            "extra_headers": parse_headers_block(o.get("headers", "")),
            "cookies": parse_cookie_string(o.get("cookies", "")),
            "canary_domain": o.get("canary_domain", "").strip(),
            "oob_poll_url": o.get("oob_poll_url", "").strip(),
            "login_url": o.get("login_url", "").strip(),
            "username": o.get("username", ""),
            "password": o.get("password", ""),
            "crawl": o.get("crawl", False),
            "max_depth": int(o.get("max_depth", 2)),
            "max_pages": int(o.get("max_pages", 15)),
            "agent": o.get("agent", False),
            # /start LLM co-pilot (supports each page's techniques + final review).
            "agent_llm": o.get("agent_llm", False),
            "llm_provider": (o.get("llm_provider") or "gemini"),
            "llm_keys": o.get("llm_keys") or {},
            "llm_models": o.get("llm_models") or {},
            "guided": data.get("guided", False),
            # Verification model (true-positive promotion + false-positive filtering).
            "fp_filter": o.get("fp_filter", True),
            "min_score": int(o.get("min_score", 38)),
            "review_strict": o.get("review_strict", True),
            # Program policy: lower low-risk categories to Low (chain breaches excluded).
            "program_policy": o.get("program_policy", True),
            "sandbox_domains": o.get("sandbox_domains", ""),
            # Time-based blind SQLi (adds latency; captures raw proof + DB version).
            "sqli_time": o.get("sqli_time", True),
            "sqli_time_sec": int(o.get("sqli_time_sec", 4)),
            # Re-run confirmed GET attacks in the Selenium browser + screenshot evidence.
            "browser_evidence": o.get("browser_evidence", True),
        }
        # A scan needs its own browser; hand the live view over from any
        # interactive preview session.
        interactive.close()
        if not session.start(target, module_ids, options):
            return jsonify({"error": "이미 스캔이 진행 중입니다."}), 409
        return jsonify({"ok": True})

    @app.route("/api/stop", methods=["POST"])
    def api_stop():
        session.stop()
        return jsonify({"ok": True})

    # ---- interactive Attack Viewer (preview + click/type before scanning) ----
    @app.route("/api/browser/open", methods=["POST"])
    def api_browser_open():
        data = request.get_json(force=True) or {}
        url = (data.get("url") or "").strip()
        if not url:
            return jsonify({"error": "URL을 입력하세요."}), 400
        with session.lock:
            if session.running:
                return jsonify({"error": "스캔 중에는 뷰어를 열 수 없습니다."}), 409
        ua = (data.get("user_agent") or "").strip() or None
        try:
            st = interactive.open(url, user_agent=ua)
        except Exception as e:
            return jsonify({"error": f"뷰어 열기 실패: {e}"}), 500
        return jsonify(st)

    @app.route("/api/browser/nav", methods=["POST"])
    def api_browser_nav():
        data = request.get_json(force=True) or {}
        return jsonify(interactive.navigate((data.get("url") or "").strip()))

    @app.route("/api/browser/action", methods=["POST"])
    def api_browser_action():
        data = request.get_json(force=True) or {}
        name = (data.get("action") or "").strip()
        if name == "close":
            interactive.close()
            return jsonify({"running": False})
        return jsonify(interactive.action(name))

    @app.route("/api/browser/input", methods=["POST"])
    def api_browser_input():
        data = request.get_json(force=True) or {}
        events = data.get("events")
        if events is None:
            events = [data]
        for ev in events:
            interactive.dispatch(ev)
        return jsonify({"ok": True})

    @app.route("/api/browser/state")
    def api_browser_state():
        return jsonify(interactive.state())

    @app.route("/api/credentials", methods=["POST"])
    def api_credentials():
        data = request.get_json(force=True) or {}
        session.submit_credentials({
            "username": data.get("username", ""),
            "password": data.get("password", ""),
            "login_url": data.get("login_url", ""),
        })
        return jsonify({"ok": True})

    @app.route("/api/providers")
    def api_providers():
        """LLM providers + models for the /test picker and /model command."""
        from core import llm_agent
        return jsonify({"providers": llm_agent.providers_public()})

    @app.route("/api/test", methods=["POST"])
    def api_test():
        """Launch the multi-LLM vulnerability-analysis agent (runs with the ML model)."""
        from core import llm_agent
        data = request.get_json(force=True) or {}
        target = (data.get("target") or "").strip()
        provider = (data.get("provider") or "gemini").strip()
        keys = data.get("keys") or {}
        models = data.get("models") or {}
        # Legacy single-key field → gemini.
        if data.get("api_key") and provider != "all":
            keys.setdefault(provider, data.get("api_key"))
        if not target:
            return jsonify({"error": "대상 URL을 입력하세요."}), 400
        if provider == "all":
            has = any(llm_agent.key_available(p, keys.get(p)) for p in llm_agent.PROVIDER_ORDER)
            if not has:
                return jsonify({"error": "제공자 키가 하나도 없습니다. /key 로 키를 설정하세요.",
                                "need_key": True}), 400
        else:
            if provider not in llm_agent.PROVIDERS:
                return jsonify({"error": f"알 수 없는 제공자: {provider}"}), 400
            if not llm_agent.available(provider):
                pkg = "google-genai" if provider == "gemini" else "openai"
                return jsonify({"error": f"{pkg} SDK 미설치 — pip install {pkg}"}), 400
            if not llm_agent.key_available(provider, keys.get(provider)):
                return jsonify({"error": f"{llm_agent.PROVIDERS[provider]['label']} API 키가 필요합니다.",
                                "need_key": True, "provider": provider}), 400
        mdir = os.path.join(_ROOT, "models")
        cfg = {"provider": provider, "keys": keys, "models": models}
        if not session.start_llm_test(target, cfg, mdir):
            return jsonify({"error": "스캔/분석이 이미 진행 중입니다."}), 409
        return jsonify({"ok": True})

    @app.route("/api/models")
    def api_models():
        """Back-compat: Gemini model list for the /model command."""
        from core import llm_agent
        return jsonify({"models": llm_agent.GEMINI_MODELS, "default": llm_agent.MODEL})

    @app.route("/api/sast", methods=["POST"])
    def api_sast():
        """Launch SAST source-code analysis (heuristic CWE rules + optional CodeBERT)."""
        data = request.get_json(force=True) or {}
        path = (data.get("path") or "").strip()
        if not path:
            return jsonify({"error": "소스 파일/폴더 경로를 입력하세요 (/sast <경로>)."}), 400
        if not os.path.exists(os.path.expanduser(path.strip('"'))):
            return jsonify({"error": f"경로를 찾을 수 없습니다: {path}"}), 400
        if not session.start_sast(path):
            return jsonify({"error": "스캔/분석이 이미 진행 중입니다."}), 409
        return jsonify({"ok": True})

    @app.route("/api/state")
    def api_state():
        log_since = int(request.args.get("logs", 0))
        find_since = int(request.args.get("finds", 0))
        return jsonify(session.snapshot(log_since, find_since))

    @app.route("/api/frame")
    def api_frame():
        with session.lock:
            frame = session.frame
        if not frame:
            return ("", 204)
        return Response(frame, mimetype="image/png",
                        headers={"Cache-Control": "no-store"})

    @app.route("/api/report")
    def api_report():
        i = request.args.get("i")
        with session.lock:
            findings = list(session.findings)
            target = session.target
        if i is not None:
            idx = int(i)
            if 0 <= idx < len(findings):
                return Response(report.finding_to_report_md(target, findings[idx]),
                                mimetype="text/markdown; charset=utf-8")
            abort(404)
        return Response(report.findings_to_report_md(target, findings),
                        mimetype="text/markdown; charset=utf-8")

    @app.route("/api/feedback", methods=["POST"])
    def api_feedback():
        """Record a TP/FP label for a finding → models/feedback.jsonl (retraining data)."""
        data = request.get_json(force=True) or {}
        idx, label = data.get("index"), data.get("label")
        if label not in (0, 1):
            return jsonify({"error": "label must be 0 (FP) or 1 (TP)"}), 400
        with session.lock:
            findings = list(session.findings)
        if not isinstance(idx, int) or not (0 <= idx < len(findings)):
            return jsonify({"error": "bad index"}), 400
        try:
            import json as _json
            from core.ml_model import extract_features
            feats = extract_features(findings[idx])
            mdir = os.path.join(_ROOT, "models")
            os.makedirs(mdir, exist_ok=True)
            with open(os.path.join(mdir, "feedback.jsonl"), "a", encoding="utf-8") as fh:
                fh.write(_json.dumps({"features": feats, "label": int(label),
                                      "module": findings[idx].module_id}) + "\n")
        except Exception as e:
            return jsonify({"error": f"could not record: {e}"}), 500
        return jsonify({"ok": True})

    return app


def main(host: str = "127.0.0.1", port: int = 8733, open_browser: bool = True):
    app = create_app()
    url = f"http://{host}:{port}/"
    print(f"[*] Nemesis (web) → {url}")
    print("    AUTHORIZED USE ONLY. 권한 있는 대상만 스캔하세요.")
    if open_browser:
        try:
            import webbrowser
            threading.Timer(1.0, lambda: webbrowser.open(url)).start()
        except Exception:
            pass
    app.run(host=host, port=port, threaded=True, debug=False)


if __name__ == "__main__":
    main()
