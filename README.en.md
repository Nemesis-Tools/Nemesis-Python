# Nemesis

<p align="center">
  <a href="README.md">한국어</a> ·
  <a href="README.en.md"><b>English</b></a> ·
  <a href="README.zh.md">中文</a> ·
  <a href="README.ja.md">日本語</a>
</p>

<p align="center">
  A Selenium-based web vulnerability scanner · <b>HTTP/HTTPS</b> · <b>323 techniques</b> · <b>HackerOne-format reports (auto CWE/CVSS)</b>
</p>

---

## Background

Web vulnerability testing usually requires stitching several tools together, and flaws that
only reproduce in a real browser (DOM XSS, postMessage, CSP weaknesses, etc.) are easily
missed by HTTP-only scanners. On top of that, turning findings into a submittable report
takes a lot of time.

**Nemesis** combines real-browser automation (Selenium) with HTTP/HTTPS checks: enter a URL, pick
the attack techniques, and it detects vulnerabilities across **323 techniques**, chains
follow-up attacks based on what it finds, then generates a **HackerOne-format report with
automatic CWE/CVSS mapping**. It ships as a **standalone desktop app** with its own logo icon.

> **Both HTTP and HTTPS are supported.** Enter a bare domain and it **tries HTTPS first, then
> falls back to HTTP** (add `http://`/`https://` explicitly to force one). HTTPS targets with
> self-signed/expired certificates are still analyzed (the certificate itself is reported as a
> separate finding by the TLS module); enable strict TLS validation via the `verify_tls` option
> when you need it.

## Purpose

- **Broad coverage** — 12 categories and 323 techniques across Injection, Client-Side,
  Auth/Access, Config, Exposures, Exposed Panels, Misconfiguration, Tech/CVE, Recon, and more.
- **Real-browser validation** — Selenium actually renders the DOM and fires events to cut
  false positives, streaming the scan screen live.
- **Chained attacks** — correlates confirmed findings (e.g. SSRF→metadata, XSS→session theft,
  exposed .git→source recovery).
- **Submission-ready output** — automatic CWE/CVSS v3.1/OWASP/CAPEC mapping, plus PoC (curl),
  raw HTTP, reproduction steps, impact, and remediation in HackerOne-format Markdown.
- **Safe defaults** — non-destructive payloads, request pacing (non-DoS), and automatic skip
  of OOB families when no canary is configured.

## Responsibility

> ⚠️ **Use only against authorized targets.** Scan only assets you own or that you have
> **explicit permission to test** (bug-bounty scope, written authorization, etc.). Unauthorized
> scanning may be illegal.

- Do not scan out-of-scope targets, and keep request intervals generous.
- All payloads are **non-destructive detection only**, with request pacing (non-DoS) and safe defaults.
- Blind families (SSRF, Log4Shell, XXE, Blind XSS, RFI, etc.) only call back to **a canary
  domain you control**. When unset they are skipped automatically (no callbacks to internal/third-party hosts).
- Check each finding's confidence (`Confirmed`/`Firm`/`Tentative`) and verify manually.
- Do not exaggerate report titles or severity (fact- and evidence-based). Leaked personal
  accounts (exposed IDs/passwords) are out of scope.

### What it does NOT automate (an honest scope)
- **DoS/DDoS/Slowloris/ReDoS/Billion Laughs** — not implemented (service disruption/abuse).
- **Brute force / credential stuffing / password spraying** — not run (account lockout/abuse);
  instead it detects the weaknesses that enable them (missing rate limiting, MFA, CAPTCHA).
- **Race conditions/TOCTOU/container-K8s escape/supply chain/XS-Leaks/mXSS** — context-dependent,
  so it only surfaces candidates; a researcher performs the real exploitation check.

## How to run

### Install
```powershell
python -m pip install -r requirements.txt
```
- Python 3.10+ (developed/verified on 3.13)
- **Chrome/Chromium** required for scanning (drivers are auto-provisioned by Selenium Manager).
- The standalone app needs the **WebView2 runtime** (built into Windows 10/11 by default).

### 1. Standalone desktop app (recommended)
```powershell
python app.py
```
- The UI opens in **its own window** (WebView2) with the logo icon. No browser or console needed.
- Distributable: `dist\Nemesis.exe` (double-click to run)

### 2. Web version
```powershell
python web.py
```
- Opens the `http://127.0.0.1:8733` UI in your default browser.
- Distributable: `dist\NemesisWeb.exe`

### 3. Desktop (PyQt) version (legacy)
```powershell
python main.py
```

### Build (.exe)
```powershell
# Standalone desktop app → dist\Nemesis.exe (logo icon, own window)
pyinstaller bugbounty_app.spec --noconfirm

# Web version → dist\NemesisWeb.exe
powershell -ExecutionPolicy Bypass -File build_web_exe.ps1
```
- Logo: `logo.png` → `logo.ico` (embedded in the build, favicon/window icon).
- After adding modules, regenerate the manifest with `python tools/gen_manifest.py` before
  rebuilding (the build scripts run it automatically).
- The exe is unsigned, so SmartScreen may warn on first launch (removable via code signing).

## Attack Viewer (interactive)

- The **Start** button no longer scans immediately — it opens the entered URL in the
  **Attack Viewer**. You can **click, type, and scroll** directly in the view (forwarded live to
  the server-side Chrome), and use the **address bar** at the top to navigate / back / forward / reload.
- The scan does **not** start on its own. Once the page is in the state you want, type **`/start`**
  in the terminal (or `/scan`, or an attack number) to run it. The viewer then switches to
  the live scan view and the address bar shows the current scan target.

## Terminal commands

Type `/` in the bottom TERMINAL to open the command popover.

| Command | Description |
|---|---|
| `/start [url]` | **Start the scan** with the selected techniques (prepare in the viewer, then run this) |
| `/attack [query]` | List techniques with numbers → **enter a number to run that attack alone** |
| `/scan [url]` | Start the scan (alias of `/start`) |
| `/login` | Interactive auto-login setup (URL → username → password) |
| `/status` | Show the current scan status |
| `/stop` | Stop the running scan |
| `/clearlogin` | Delete saved login credentials |
| `/clear` | Clear the screen (logs) |

Example: `/attack sqli` → enter `1` → runs that SQLi module against the target URL for real.

## License

This project is distributed under the **MIT License**. See the [LICENSE](LICENSE) file for the full text.

```
MIT License

Copyright (c) 2026 Nemesis

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
