"""Interactive remote-browser controller for the Attack Viewer.

Lets the user preview a target URL and click / type / scroll inside the live
Selenium view *before* (or instead of) launching a scan. Screenshots are streamed
through the shared frame slot; user input is forwarded to Chrome over the DevTools
Protocol (CDP Input domain).

The single Chrome instance is touched from two threads — the capture loop and
Flask request handlers dispatching input — so every driver call is serialized with
a lock.
"""
from __future__ import annotations

import threading
import time

from core.browser import BrowserManager

# CDP metadata for the few non-text keys we forward. Printable characters go
# through Input.insertText instead (handles IME/shift/layout correctly).
_KEYS = {
    "Enter":      dict(key="Enter", code="Enter", windowsVirtualKeyCode=13, text="\r"),
    "Backspace":  dict(key="Backspace", code="Backspace", windowsVirtualKeyCode=8),
    "Tab":        dict(key="Tab", code="Tab", windowsVirtualKeyCode=9),
    "Escape":     dict(key="Escape", code="Escape", windowsVirtualKeyCode=27),
    "Delete":     dict(key="Delete", code="Delete", windowsVirtualKeyCode=46),
    "ArrowLeft":  dict(key="ArrowLeft", code="ArrowLeft", windowsVirtualKeyCode=37),
    "ArrowUp":    dict(key="ArrowUp", code="ArrowUp", windowsVirtualKeyCode=38),
    "ArrowRight": dict(key="ArrowRight", code="ArrowRight", windowsVirtualKeyCode=39),
    "ArrowDown":  dict(key="ArrowDown", code="ArrowDown", windowsVirtualKeyCode=40),
    "Home":       dict(key="Home", code="Home", windowsVirtualKeyCode=36),
    "End":        dict(key="End", code="End", windowsVirtualKeyCode=35),
}


class InteractiveBrowser:
    """A single interactive Chrome session whose screenshots feed the live view."""

    def __init__(self, on_frame, on_log=None, user_agent: str | None = None):
        self._on_frame = on_frame
        self._on_log = on_log or (lambda m: None)
        self._user_agent = user_agent
        self.browser: BrowserManager | None = None
        self._lock = threading.Lock()          # serialize ALL driver access
        self._cap_thread: threading.Thread | None = None
        self._running = threading.Event()
        self._vw, self._vh = 1366, 900         # viewport size (CSS px)
        self.url = ""
        self.title = ""

    # ---- lifecycle -----------------------------------------------------------
    def open(self, url: str, user_agent: str | None = None) -> dict:
        self.close()
        self._user_agent = user_agent or self._user_agent
        self.browser = BrowserManager(headless=True, page_load_timeout=25,
                                      user_agent=self._user_agent)
        with self._lock:
            self.browser.start()
        self._running.set()
        self.navigate(url)
        self._cap_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._cap_thread.start()
        return self.state()

    def close(self) -> None:
        self._running.clear()
        t = self._cap_thread
        if t and t.is_alive():
            t.join(timeout=1.5)
        self._cap_thread = None
        b, self.browser = self.browser, None
        if b:
            try:
                b.quit()
            except Exception:
                pass

    @property
    def running(self) -> bool:
        return self._running.is_set() and self.browser is not None

    # ---- navigation ----------------------------------------------------------
    def navigate(self, url: str) -> dict:
        if not self.browser:
            return self.state()
        u = (url or "").strip()
        if u and "://" not in u:
            u = "https://" + u
        with self._lock:
            try:
                self.browser.driver.get(u)
            except Exception as e:
                self._on_log(f"[viewer] 이동 오류: {e}")
        self._refresh_meta()
        return self.state()

    def action(self, name: str) -> dict:
        if not self.browser:
            return self.state()
        with self._lock:
            try:
                d = self.browser.driver
                if name == "back":
                    d.execute_script("history.back()")
                elif name == "forward":
                    d.execute_script("history.forward()")
                elif name == "reload":
                    d.refresh()
            except Exception:
                pass
        time.sleep(0.25)
        self._refresh_meta()
        return self.state()

    # ---- input dispatch ------------------------------------------------------
    def dispatch(self, ev: dict) -> None:
        if not self.browser:
            return
        kind = ev.get("kind")
        drv = self.browser.driver
        try:
            if kind in ("click", "dblclick"):
                x, y = self._px(ev)
                clicks = 2 if kind == "dblclick" else 1
                with self._lock:
                    drv.execute_cdp_cmd("Input.dispatchMouseEvent",
                                        {"type": "mouseMoved", "x": x, "y": y, "button": "none"})
                    drv.execute_cdp_cmd("Input.dispatchMouseEvent",
                                        {"type": "mousePressed", "x": x, "y": y,
                                         "button": "left", "clickCount": clicks, "buttons": 1})
                    drv.execute_cdp_cmd("Input.dispatchMouseEvent",
                                        {"type": "mouseReleased", "x": x, "y": y,
                                         "button": "left", "clickCount": clicks, "buttons": 0})
            elif kind == "scroll":
                x, y = self._px(ev)
                with self._lock:
                    drv.execute_cdp_cmd("Input.dispatchMouseEvent",
                                        {"type": "mouseWheel", "x": x, "y": y,
                                         "deltaX": float(ev.get("dx", 0)),
                                         "deltaY": float(ev.get("dy", 0))})
            elif kind == "text":
                text = ev.get("text", "")
                if text:
                    with self._lock:
                        drv.execute_cdp_cmd("Input.insertText", {"text": text})
            elif kind == "key":
                self._key(ev.get("key", ""))
        except Exception as e:
            self._on_log(f"[viewer] 입력 오류: {e}")

    def _key(self, key: str) -> None:
        meta = _KEYS.get(key)
        if not meta or not self.browser:
            return
        base = {k: v for k, v in meta.items() if k != "text"}
        drv = self.browser.driver
        with self._lock:
            down = {"type": "keyDown", **base}
            if meta.get("text"):
                down["text"] = meta["text"]
            drv.execute_cdp_cmd("Input.dispatchKeyEvent", down)
            drv.execute_cdp_cmd("Input.dispatchKeyEvent", {"type": "keyUp", **base})

    def _px(self, ev: dict) -> tuple[float, float]:
        fx = min(1.0, max(0.0, float(ev.get("fx", 0))))
        fy = min(1.0, max(0.0, float(ev.get("fy", 0))))
        return fx * self._vw, fy * self._vh

    # ---- meta / frames -------------------------------------------------------
    def _refresh_meta(self) -> None:
        if not self.browser:
            return
        with self._lock:
            try:
                d = self.browser.driver
                self.url = d.current_url or self.url
                self.title = d.title or ""
                sz = d.execute_script("return [window.innerWidth, window.innerHeight]")
                if sz and sz[0] and sz[1]:
                    self._vw, self._vh = int(sz[0]), int(sz[1])
            except Exception:
                pass

    def state(self) -> dict:
        return {"running": self.running, "url": self.url, "title": self.title,
                "w": self._vw, "h": self._vh}

    def _capture_loop(self) -> None:
        i = 0
        while self._running.is_set() and self.browser:
            try:
                with self._lock:
                    png = self.browser.driver.get_screenshot_as_png()
                if png:
                    self._on_frame(png)
            except Exception:
                pass
            i += 1
            if i % 5 == 0:                     # refresh URL/title ~ every second
                self._refresh_meta()
            time.sleep(0.2)
