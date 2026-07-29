#!/usr/bin/env python3
"""Standalone desktop app (native window, own taskbar icon) — Electron-style.

Runs the Flask server in the background and renders the web UI inside a native
OS window via pywebview (WebView2 on Windows). No system browser, no console.

AUTHORIZED USE ONLY.
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time
import urllib.request

WINDOW_TITLE = "Nemesis"


def _asset(name: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


def _apply_window_icon():
    """Set the native window + taskbar icon to logo.ico (Windows, ctypes only)."""
    if not sys.platform.startswith("win"):
        return
    ico = _asset("logo.ico")
    if not os.path.exists(ico):
        return
    try:
        import ctypes
        user32 = ctypes.windll.user32
        # Distinct AppUserModelID so the taskbar shows our icon (not python's).
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Nemesis.Scanner.1")
        except Exception:
            pass
        IMAGE_ICON, LR_LOADFROMFILE, LR_DEFAULTSIZE = 1, 0x0010, 0x0040
        WM_SETICON, ICON_SMALL, ICON_BIG = 0x0080, 0, 1
        hwnd = 0
        for _ in range(120):                      # wait up to ~12s for the window
            hwnd = user32.FindWindowW(None, WINDOW_TITLE)
            if hwnd:
                break
            time.sleep(0.1)
        if not hwnd:
            return
        big = user32.LoadImageW(None, ico, IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_DEFAULTSIZE)
        sm = user32.LoadImageW(None, ico, IMAGE_ICON, 16, 16, LR_LOADFROMFILE)
        if big:
            user32.SendMessageW(hwnd, WM_SETICON, ICON_BIG, big)
        if sm:
            user32.SendMessageW(hwnd, WM_SETICON, ICON_SMALL, sm)
    except Exception:
        pass


def _free_port(preferred: int = 8733) -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", preferred))
        s.close()
        return preferred
    except OSError:
        s.close()
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2.bind(("127.0.0.1", 0))
        port = s2.getsockname()[1]
        s2.close()
        return port


def _serve(port: int):
    from webapp.server import create_app
    app = create_app()
    app.run(host="127.0.0.1", port=port, threaded=True, debug=False, use_reloader=False)


def _wait(url: str, timeout: float = 15.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(url, timeout=1)
            return True
        except Exception:
            time.sleep(0.2)
    return False


def main() -> int:
    try:
        import webview
    except ModuleNotFoundError:
        print("[!] pywebview not installed. pip install pywebview")
        return 1

    port = _free_port(8733)
    url = f"http://127.0.0.1:{port}/"
    threading.Thread(target=_serve, args=(port,), daemon=True).start()
    _wait(url, 15.0)
    # Set the window/taskbar icon once the window appears.
    threading.Thread(target=_apply_window_icon, daemon=True).start()

    # Keep the pywebview Window OUT of the js_api object's attributes: pywebview
    # serializes the api object's graph, and a Window reference makes it walk into
    # window.native.browser.webview.CoreWebView2 — a COM object that may only be
    # touched on the UI thread, which intermittently crashes the process. We capture
    # the window in a closure cell instead so the api holds no window reference.
    _win = {"w": None}

    class WindowApi:
        def minimize(self):
            try:
                w = _win["w"]
                if w: w.minimize()
            except Exception:
                pass
        def close(self):
            try:
                w = _win["w"]
                if w: w.destroy()
            except Exception:
                pass

    api = WindowApi()
    window = webview.create_window(
        WINDOW_TITLE, url,
        width=1440, height=920, min_size=(1024, 660),
        frameless=True, easy_drag=False, js_api=api,
    )
    _win["w"] = window
    webview.start()   # blocks until the window is closed
    return 0


if __name__ == "__main__":
    sys.exit(main())
