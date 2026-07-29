"""Scan orchestrator: origin/page module split, recursive crawl, and chaining.

Flow:
  1. Run ORIGIN-scoped modules once against the base URL (headers, recon, auth,
     TLS, etc. — things that describe the whole site).
  2. BFS over pages: run PAGE-scoped modules (injection/XSS/param-driven) on the
     base URL and, if crawling is enabled, on each same-origin page discovered
     from links/forms — up to max_depth / max_pages.
  3. Run the chain engine: escalate confirmed primitives and correlate findings
     into higher-impact chains.
"""
from __future__ import annotations

import re
import threading
import traceback
from typing import Callable, Iterable
from urllib.parse import urlparse

import requests
import urllib3

# Scheme-probing (below) intentionally hits targets with verify=False; silence the
# resulting per-request InsecureRequestWarning noise. The real scan session still
# honours the user's verify_tls setting.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.browser import BrowserManager
from core.rate_limiter import RateLimiter
from core.http_utils import make_session
from core.oob import OOBClient
from core.result import Finding, Severity
from core.crawler import extract_links, normalize, registrable
from core import chain
from modules.base import ScanContext, get_module

# Modules whose result depends on the specific URL/parameters (run per page).
# Everything else is origin-level and runs once.
PAGE_SCOPED = {
    "xss_reflected", "xss_dom", "sqli", "sqli_blind_time", "command_injection",
    "open_redirect", "ssrf", "ssti", "crlf", "path_traversal", "nosql_injection",
    "hpp", "prototype_pollution", "log4shell", "xxe", "idor_candidates",
    "business_logic_recon", "deserialization", "csti", "prompt_injection",
}


def _scheme_reachable(url: str, timeout: float = 6.0) -> bool:
    """True if `url` answers on its scheme (HTTP or HTTPS).

    Uses verify=False so an invalid/self-signed TLS cert still counts as "the
    host speaks HTTPS" — the certificate itself is separately reported by the
    TLS analysis module, not a reason to skip the whole HTTPS scan.
    """
    for method in ("head", "get"):
        try:
            requests.request(method, url, timeout=timeout,
                             allow_redirects=True, verify=False,
                             stream=(method == "get"))
            return True
        except requests.exceptions.SSLError:
            # TLS handshake reached the server (cert just didn't validate) → reachable.
            return True
        except Exception:
            continue
    return False


def normalize_target(url: str) -> str:
    """Resolve the scheme for a target, covering both HTTP and HTTPS.

    * An explicit ``http://`` / ``https://`` is always respected.
    * For a scheme-less host we probe **HTTPS first** (the modern default) and
      fall back to HTTP, so sites served only over TLS are analyzed correctly.
      If neither responds we still default to HTTPS.
    """
    url = url.strip()
    if urlparse(url).scheme in ("http", "https"):
        return url
    host = url.lstrip("/")
    if _scheme_reachable("https://" + host):
        return "https://" + host
    if _scheme_reachable("http://" + host):
        return "http://" + host
    return "https://" + host


# ---- Login / auth-wall detection ---------------------------------------------
# A target can answer HTTP 200 yet actually be a login wall (a redirect to a
# sign-in page, a JS-rendered login, HTTP 401, etc.). These heuristics catch
# that so the scan isn't silently run against the login page.
_LOGIN_URL_RE = re.compile(
    r"(?:^|[/?&=#])(?:"
    r"login|log-?in|signin|sign-?in|sign_in|logon|"
    r"auth(?:enticate|orize|orization)?|oauth2?|openid|oidc|sso|saml|adfs|idp|"
    r"account(?:s)?/(?:login|signin)|users?/sign_in|session(?:s)?/new|wp-login"
    r")\b|"
    r"accounts\.google\.|login\.microsoftonline\.|\.okta\.com|\.auth0\.com",
    re.I)
_LOGIN_PW_RE = re.compile(r"<input[^>]+type\s*=\s*[\"']?password", re.I)
_LOGIN_FORM_RE = re.compile(
    r"<form[^>]+action\s*=\s*[\"'][^\"']*"
    r"(?:login|signin|sign-?in|sign_in|auth|sso|session|oauth)", re.I)
_LOGIN_TEXT_RE = re.compile(
    r"please\s+(?:log|sign)\s?in|(?:log|sign)\s?in\s+to\s+continue|"
    r"you\s+(?:must|need)\s+to\s+(?:be\s+)?(?:log|sign)(?:ged)?\s?in|"
    r"authentication\s+required|session\s+(?:has\s+)?expired|"
    r"로그인\s*(?:이|가|후|을|를)?\s*(?:필요|해\s?주세요|하세요)|로그인이\s*필요|"
    r"인증(?:이)?\s*필요|세션이?\s*만료", re.I)


def _looks_like_login_url(url: str) -> bool:
    try:
        p = urlparse(url or "")
    except Exception:
        return False
    hay = (p.netloc or "") + (p.path or "") + ("?" + p.query if p.query else "")
    return bool(_LOGIN_URL_RE.search(hay))


def _html_login_signals(html: str) -> list[str]:
    html = html or ""
    out: list[str] = []
    if _LOGIN_PW_RE.search(html):
        out.append("비밀번호 입력 필드")
    if _LOGIN_FORM_RE.search(html):
        out.append("로그인 폼(action)")
    if _LOGIN_TEXT_RE.search(html):
        out.append("로그인/인증 요구 문구")
    return out


class Scanner:
    """Runs a scan. Designed to be driven from a background thread."""

    def __init__(self,
                 target: str,
                 module_ids: Iterable[str],
                 options: dict,
                 on_log: Callable[[str], None],
                 on_finding: Callable[[Finding], None],
                 on_progress: Callable[[int, int, str], None],
                 on_done: Callable[[list[Finding]], None],
                 on_frame: Callable[[bytes], None] | None = None,
                 on_need_credentials: Callable[[], dict | None] | None = None):
        self.target = normalize_target(target)
        self.module_ids = list(module_ids)
        self.options = options
        self.on_log = on_log
        self.on_finding = on_finding
        self.on_progress = on_progress
        self.on_done = on_done
        self.on_frame = on_frame
        # Called (blocking) when a login page is detected and no creds are set;
        # returns {"username","password","login_url"} or None.
        self.on_need_credentials = on_need_credentials
        self._stop = threading.Event()
        self.findings: list[Finding] = []
        # Populated by _auth_wall_signals(): reasons the target looks login-gated.
        self._auth_wall: list[str] = []

    def stop(self) -> None:
        self._stop.set()

    def _log(self, msg: str) -> None:
        self.on_log(msg)

    def _emit(self, results, ctx) -> int:
        for f in results or []:
            self.findings.append(f)
            self.on_finding(f)
        return len(results or [])

    def _auto_login(self, browser, http, opt) -> None:
        """Log in via the target's form, then share the authenticated cookies
        with the HTTP session so every check runs authenticated."""
        user = opt.get("username", "")
        pw = opt.get("password", "")
        if not user or not pw:
            return
        login_url = opt.get("login_url", "").strip() or self.target
        try:
            from selenium.webdriver.common.by import By
            from selenium.webdriver.common.keys import Keys
        except Exception:
            return
        self._log(f"[*] Auto-login: {login_url} (user={user})")
        try:
            if not browser.get(login_url):
                self._log("    [!] login page failed to load")
                return
            browser.dismiss_alert()
            driver = browser.driver
            pw_fields = driver.find_elements(By.CSS_SELECTOR, "input[type='password']")
            if not pw_fields:
                self._log("    [!] no password field found on login page")
                return
            pwf = pw_fields[0]
            # Username = first plausible text/email input before the password field.
            userf = None
            cands = driver.find_elements(
                By.CSS_SELECTOR,
                "input[type='text'],input[type='email'],input:not([type]),"
                "input[name*='user' i],input[name*='email' i],input[name*='login' i],"
                "input[id*='user' i],input[id*='email' i]")
            if cands:
                userf = cands[0]
            if userf is not None:
                try:
                    userf.clear()
                except Exception:
                    pass
                userf.send_keys(user)
            pwf.clear()
            pwf.send_keys(pw)
            browser.capture_frame(force=True)
            try:
                pwf.send_keys(Keys.ENTER)
            except Exception:
                pass
            # Fallback: click a submit button.
            try:
                btns = driver.find_elements(
                    By.CSS_SELECTOR, "button[type='submit'],input[type='submit'],button")
                if btns:
                    btns[0].click()
            except Exception:
                pass
            import time as _t
            _t.sleep(2.0)
            browser.capture_frame(force=True)
            # Sync browser cookies into the requests session.
            n = 0
            for c in driver.get_cookies():
                try:
                    http.cookies.set(c.get("name"), c.get("value"), domain=c.get("domain"))
                    n += 1
                except Exception:
                    continue
            self._log(f"    [*] login submitted; synced {n} cookie(s) to HTTP session")
        except Exception as e:
            self._log(f"    [!] auto-login error: {e}")

    def _validate_url(self, http) -> bool:
        """Confirm the target is reachable before scanning (and surface redirects)."""
        try:
            r = http.get(self.target, allow_redirects=True, timeout=12)
            final = r.url or self.target
            if r.history:
                hops = " → ".join(str(h.status_code) for h in r.history)
                self._log(f"    [*] {self.target} -> {hops} → HTTP {r.status_code}  (최종: {final})")
            else:
                self._log(f"    [*] {self.target} -> HTTP {r.status_code}")
            return r.status_code < 600
        except Exception as e:
            self._log(f"    [!] {e}")
            return False

    def _auth_wall_signals(self, browser, http) -> list[str]:
        """Detect whether the target — even on HTTP 200 — is actually a login/auth wall.

        Inspects the HTTP response (redirect target, status, WWW-Authenticate,
        body) *and* the live browser DOM (JS-rendered / client-side redirect
        logins). Returns human-readable signals; empty ⇒ no wall detected.
        """
        signals: list[str] = []
        base_key = normalize(self.target)
        # --- HTTP layer ---
        try:
            r = http.get(self.target, allow_redirects=True, timeout=12)
            final = r.url or self.target
            if r.status_code in (401, 407):
                signals.append(f"HTTP {r.status_code} (인증 요구)")
            if any(h.lower() == "www-authenticate" for h in r.headers):
                signals.append("WWW-Authenticate 헤더")
            if _looks_like_login_url(final):
                if normalize(final) != base_key:
                    signals.append(f"로그인 URL로 리다이렉트 → {final}")
                else:
                    signals.append(f"로그인 URL: {final}")
            signals += _html_login_signals(getattr(r, "text", "") or "")
        except Exception as e:
            self._log(f"    [!] auth-wall HTTP 검사 오류: {e}")
        # --- Browser layer (catches JS-rendered / client-side redirect logins) ---
        try:
            drv = browser.driver
            if drv is not None:
                cur = drv.current_url or ""
                if _looks_like_login_url(cur) and normalize(cur) != base_key:
                    signals.append(f"브라우저가 로그인 URL로 이동 → {cur}")
                from selenium.webdriver.common.by import By
                if drv.find_elements(By.CSS_SELECTOR, "input[type='password']"):
                    signals.append("렌더링된 페이지에 비밀번호 필드")
        except Exception:
            pass
        # dedup, keep order
        seen: set[str] = set()
        out: list[str] = []
        for s in signals:
            if s not in seen:
                seen.add(s)
                out.append(s)
        return out

    def _detect_login(self, browser) -> bool:
        """True if the current page looks like a login page (password field or login URL)."""
        try:
            from selenium.webdriver.common.by import By
            drv = browser.driver
            if drv is None:
                return False
            if drv.find_elements(By.CSS_SELECTOR, "input[type='password']"):
                return True
            return _looks_like_login_url(drv.current_url or "")
        except Exception:
            return False

    def _run_module(self, mid: str, ctx: ScanContext, label_prefix: str = "") -> list[Finding]:
        cls = get_module(mid)
        if cls is None:
            self._log(f"[!] Unknown module id: {mid}")
            return []
        mod = cls()
        self._log(f"\n=== {label_prefix}{mod.category} :: {mod.name} ===")
        try:
            return mod.run(ctx) or []
        except Exception:
            self._log(f"[!] Module '{mod.id}' crashed:\n{traceback.format_exc()}")
            return []

    def run(self) -> None:
        opt = self.options
        browser = BrowserManager(
            headless=opt.get("headless", True),
            page_load_timeout=opt.get("page_timeout", 20),
            user_agent=opt.get("user_agent") or None,
            devtools=opt.get("devtools", False),
            frame_callback=self.on_frame,
        )
        http = make_session(
            timeout=opt.get("http_timeout", 15),
            user_agent=opt.get("user_agent") or None,
            # Default OFF: bug-bounty/HTTPS targets often have self-signed/expired
            # certs, and blocking on TLS validation would skip the whole scan. The
            # certificate itself is still analyzed by the TLS module. Users can
            # re-enable strict verification via the verify_tls option.
            verify_tls=opt.get("verify_tls", False),
            extra_headers=opt.get("extra_headers") or None,
            cookies=opt.get("cookies") or None,
        )
        rl = RateLimiter(delay=opt.get("delay", 0.5))
        oob = OOBClient(canary_domain=opt.get("canary_domain", ""),
                        poll_url=opt.get("oob_poll_url", ""), session=http)

        ctx = ScanContext(target=self.target, browser=browser, http=http, rate_limiter=rl,
                          log=self._log, options=opt, should_stop=self._stop.is_set, oob=oob)

        def _is_page(mid):
            cls = get_module(mid)
            return (getattr(cls, "scope", "origin") == "page") or (mid in PAGE_SCOPED)

        origin_mods = [m for m in self.module_ids if not _is_page(m)]
        page_mods = [m for m in self.module_ids if _is_page(m)]

        crawl = opt.get("crawl", False)
        max_depth = int(opt.get("max_depth", 1))
        max_pages = int(opt.get("max_pages", 1)) if crawl else 1
        scope_host = registrable(self.target)

        try:
            self._log(f"[*] Starting browser (headless={browser.headless}, devtools={browser.devtools}) ...")
            browser.start()
            browser.apply_identity(extra_headers=opt.get("extra_headers") or None,
                                   cookies=opt.get("cookies") or None, base_url=self.target)
            # Optional authenticated scanning (non-guided): log in up front.
            if not opt.get("guided"):
                self._auto_login(browser, http, opt)
            # Seed the live view with the target page.
            if self.on_frame:
                browser.get(self.target)
                browser.capture_frame(force=True)
            self._log(f"[*] Target: {self.target}")
            if opt.get("user_agent"):
                self._log(f"[*] User-Agent: {opt['user_agent']}")
            if opt.get("extra_headers"):
                self._log(f"[*] Credential headers: {list(opt['extra_headers'].keys())}")
            self._log(f"[*] OOB canary: {oob.canary_domain or '(not set — SSRF/OOB skipped)'}")
            if crawl:
                self._log(f"[*] Recursive crawl ON (max_depth={max_depth}, max_pages={max_pages})")

            guided = bool(opt.get("guided"))
            # Module-level progress: each executed module advances the %.
            total_est = max(1, len(origin_mods) + len(page_mods) * (max_pages + (1 if guided else 0)))
            step = 0

            def _name(mid):
                cls = get_module(mid)
                return cls.name if cls else mid

            # ---- Guided: validate URL up front ----
            if guided and not self._stop.is_set():
                self._log("\n########## URL 검증 ##########")
                if not self._validate_url(http):
                    self._log("[!] URL 검증 실패 — 접근 불가한 대상. 스캔을 중단합니다.")
                    return
                self._log("[*] URL 검증 OK")

            # ---- Auth/login-wall detection (ALL modes) ----
            # A target can answer HTTP 200 yet actually be a login wall (redirect
            # to /login, HTTP 401, JS-rendered sign-in). Detect it so the scan
            # isn't silently run against the login page instead of the real app.
            if not self._stop.is_set():
                if not self.on_frame:            # ensure the browser is on target for DOM checks
                    try:
                        browser.get(self.target)
                    except Exception:
                        pass
                self._auth_wall = self._auth_wall_signals(browser, http)
                authed = bool((opt.get("username") and opt.get("password"))
                              or opt.get("cookies") or opt.get("extra_headers"))
                if self._auth_wall:
                    self._log("\n[!] 로그인/인증 벽 감지 — 대상이 로그인 뒤에 있는 것으로 보입니다 (HTTP 200이어도):")
                    for s in self._auth_wall:
                        self._log(f"      · {s}")
                    if authed:
                        self._log("    [*] 제공된 자격증명/세션으로 인증된 스캔을 계속합니다.")
                    elif not guided and self.on_need_credentials:
                        # Regular scan had no login detection before — now offer login.
                        self._log("    [*] 로그인 폼 인식 — 터미널에 아이디/비밀번호를 입력하세요 "
                                  "(미입력 시 로그인 없이 계속).")
                        creds = self.on_need_credentials()
                        if creds and (creds.get("username") or creds.get("password")):
                            opt["username"] = creds.get("username", "")
                            opt["password"] = creds.get("password", "")
                            if creds.get("login_url"):
                                opt["login_url"] = creds["login_url"]
                            self._auto_login(browser, http, opt)
                            self._auth_wall = self._auth_wall_signals(browser, http)
                            if self._auth_wall:
                                self._log("    [!] 로그인 후에도 인증 벽이 남아 있습니다 — "
                                          "자격증명/권한을 확인하세요.")
                            else:
                                self._log("    [*] 로그인 성공 — 인증된 세션으로 계속합니다.")
                        else:
                            self._log("    [*] 자격증명 미입력 — 로그인 페이지 기준으로 계속합니다.")
                    elif not guided:
                        self._log("    [!] 자격증명 미설정 — 스캔이 로그인 페이지를 대상으로 수행될 수 "
                                  "있습니다. `/login` 또는 ⚙ 인증·식별 탭에 쿠키/헤더를 설정하세요.")
                    # guided mode: the dedicated login block below prompts + logs in.

            # ---- Phase 1: origin-scoped modules (once) ----
            if origin_mods and not self._stop.is_set():
                self.on_progress(0, total_est, "시작")
                self._log(f"\n########## ORIGIN CHECKS ({len(origin_mods)}) ##########")
                for mid in origin_mods:
                    if self._stop.is_set():
                        break
                    self.on_progress(step, total_est, _name(mid))
                    n = self._emit(self._run_module(mid, ctx, "[origin] "), ctx)
                    self._log(f"    -> {n} finding(s)")
                    step += 1
                    self.on_progress(step, total_est, _name(mid))

            # ---- Guided: login-page checks → recognize form → prompt creds → login ----
            visited: set[str] = set()
            crawl_from = self.target
            if guided and not self._stop.is_set():
                try:
                    browser.get(self.target)
                    browser.capture_frame(force=True)
                except Exception:
                    pass
                if self._auth_wall or self._detect_login(browser):
                    self._log("\n########## 로그인 페이지 감지 — 로그인 폼/파라미터 취약점 검사 ##########")
                    ctx.target = self.target
                    for mid in page_mods:
                        if self._stop.is_set():
                            break
                        self.on_progress(step, total_est, f"[login] {_name(mid)}")
                        n = self._emit(self._run_module(mid, ctx, "[login] "), ctx)
                        self._log(f"    -> {n} finding(s)")
                        step += 1
                        self.on_progress(step, total_est, f"[login] {_name(mid)}")
                    visited.add(normalize(self.target))
                    # Recognize form → obtain credentials (prompt via terminal if needed).
                    if not (opt.get("username") and opt.get("password")) and self.on_need_credentials \
                            and not self._stop.is_set():
                        self._log("[*] 로그인 폼 인식됨 — 터미널에 아이디/비밀번호를 입력하세요…")
                        creds = self.on_need_credentials()
                        if creds:
                            opt["username"] = creds.get("username", "")
                            opt["password"] = creds.get("password", "")
                            if creds.get("login_url"):
                                opt["login_url"] = creds["login_url"]
                    # Log in (the login request itself is shown live).
                    if opt.get("username") and opt.get("password") and not self._stop.is_set():
                        self._auto_login(browser, http, opt)
                        try:
                            crawl_from = browser.driver.current_url or self.target
                            self._log(f"[*] 로그인 후 도착 페이지: {crawl_from}")
                        except Exception:
                            crawl_from = self.target
                    else:
                        self._log("[*] 자격증명 미입력 — 로그인 없이 계속합니다.")
                else:
                    self._log("[*] 로그인 페이지 아님 — 일반 스캔을 진행합니다.")

            # ---- Phase 2: page-scoped modules over the crawl frontier ----
            queue: list[tuple[str, int]] = [(crawl_from, 0)]
            pages_done = 0
            while queue and pages_done < max_pages and not self._stop.is_set():
                url, depth = queue.pop(0)
                key = normalize(url)
                if key in visited:
                    continue
                visited.add(key)
                pages_done += 1
                ctx.target = url
                self._log(f"\n########## PAGE {pages_done}/{max_pages} (depth {depth}): {url} ##########")

                for mid in page_mods:
                    if self._stop.is_set():
                        break
                    self.on_progress(step, total_est, f"{_name(mid)}  ·  {url}")
                    n = self._emit(self._run_module(mid, ctx, f"[p{pages_done}] "), ctx)
                    self._log(f"    -> {n} finding(s)")
                    step += 1
                    self.on_progress(step, total_est, f"{_name(mid)}  ·  {url}")

                # Expand surface for the next wave.
                if crawl and depth < max_depth and pages_done < max_pages:
                    try:
                        html = ""
                        if browser.get(url):
                            browser.dismiss_alert()
                            html = browser.driver.page_source or ""
                        links = extract_links(url, html, scope_host)
                        added = 0
                        for link in links:
                            if normalize(link) not in visited and len(queue) + pages_done < max_pages * 3:
                                queue.append((link, depth + 1))
                                added += 1
                        if added:
                            self._log(f"    [crawl] +{added} new URL(s) queued")
                    except Exception:
                        pass

            # ---- Phase 3: chaining (escalate + correlate) ----
            if not self._stop.is_set() and self.findings:
                ctx.target = self.target
                self._log(f"\n########## CHAIN ENGINE ##########")
                chained = chain.run_chains(ctx, self.findings, self.on_finding)
                self.findings.extend(chained)
                self._log(f"    -> {len(chained)} chained finding(s)")

            if self._stop.is_set():
                self._log("[!] Scan stopped by user.")
        finally:
            browser.quit()
            self._log("\n[*] Browser closed. Scan complete.")
            self.findings.sort(key=lambda f: f.severity.rank, reverse=True)
            self.on_done(self.findings)
