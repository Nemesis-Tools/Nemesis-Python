# Nemesis

<p align="center">
  <a href="README.md"><b>한국어</b></a> ·
  <a href="README.en.md">English</a> ·
  <a href="README.zh.md">中文</a> ·
  <a href="README.ja.md">日本語</a>
</p>

<p align="center">
  Selenium 기반 웹 취약점 점검 도구 · <b>HTTP/HTTPS</b> · <b>329종</b> 기법 · <b>HackerOne 형식 리포트(CWE/CVSS 자동)</b>
</p>

---

## 배경

웹 취약점 점검은 대개 여러 도구를 조합해야 하고, 실제 브라우저에서만 재현되는 결함
(DOM XSS·postMessage·CSP 약점 등)은 HTTP 스캐너만으로는 놓치기 쉽습니다. 또한 발견한
취약점을 제보 가능한 리포트로 정리하는 데 많은 시간이 듭니다.

**Nemesis** 는 실제 브라우저(Selenium) 자동화와 HTTP/HTTPS 검사를 하나로 묶어, URL을 입력하고
공격 기법을 선택하면 **329종**의 취약점을 탐지하고, 발견 취약점을 기반으로 추가 공격(체인)
까지 수행한 뒤 **HackerOne 형식 리포트(CWE/CVSS 자동 매핑)** 를 생성합니다. 로고 아이콘을
가진 **독립 데스크톱 앱**으로 패키징됩니다.

> **HTTP · HTTPS 모두 지원.** 스킴 없이 도메인만 입력하면 **HTTPS 를 먼저 시도하고 HTTP 로
> 폴백**합니다(`http://`·`https://` 를 직접 붙이면 그대로 사용). 자체 서명·만료 인증서가 있는
> HTTPS 대상도 그대로 분석하며(인증서 자체는 TLS 모듈이 별도 취약점으로 보고), 필요 시
> `verify_tls` 옵션으로 엄격한 TLS 검증을 켤 수 있습니다.

## 목적

- **넓은 커버리지** — Injection·Client-Side·Auth/Access·Config·Exposures·Exposed Panels·
  Misconfiguration·Tech/CVE·Recon 등 12개 카테고리, 329개 기법.
- **실브라우저 검증** — Selenium으로 렌더링·DOM·이벤트를 실제 실행해 오탐을 줄이고, 스캔
  화면을 실시간 스트리밍.
- **체인 공격** — 확인된 취약점을 연계(예: SSRF→메타데이터, XSS→세션탈취, .git→소스복원).
- **바로 제보 가능한 산출물** — CWE/CVSS v3.1/OWASP/CAPEC 자동 매핑, PoC(curl)·Raw HTTP·
  재현 절차·영향·완화까지 포함한 HackerOne 형식 Markdown.
- **안전 기본값** — 비파괴 페이로드, 요청 간격 제한(비-DoS). 블라인드 계열은 카나리가 있으면 OOB로
  확정, 없으면 인밴드 탐지로 실행(자세한 내용은 [책임](#책임) 참조).

## 책임

> ⚠️ **인가된 대상에만 사용하세요.** 본인이 소유했거나 버그바운티 프로그램 스코프·서면 허가
> 등 **명시적 테스트 권한이 있는 대상**만 스캔해야 합니다. 무단 스캔은 불법일 수 있습니다.

- 스코프 밖 대상 스캔 금지, 요청 간격을 충분히 둘 것.
- 모든 페이로드는 **비파괴적 탐지용**이며, 요청 간격 제한(비-DoS)과 안전 기본값을 적용.
- **자격증명 테스트(무차별/스터핑/스프레이)** 는 인가된 대상에서만 사용하세요 — 페이싱·시도
  횟수 제한이 적용되며 **잠금/레이트리밋 신호 감지 시 즉시 중단**(실계정 잠금 방지)합니다.
  기본 비활성(opt-in)이며 명시적으로 선택해야 실행됩니다.
- 발견 항목의 신뢰도(`Confirmed`/`Firm`/`Tentative`)를 확인하고 수동 검증.
- 리포트 제목/심각도를 과장하지 말 것(사실·증거 기반). 개인 계정 유출(노출된 ID/PW)은 대상이 아님.

### 인가 시 확장 실행(고급)
> 아래는 인가된 엔지니어 요청으로 활성화된 항목입니다. 안전장치(페이싱·시도 제한·잠금 감지)를 유지하세요.
- **블라인드 계열(SSRF·Log4Shell·XXE·Blind XSS·RFI)** — 카나리 미설정 시에도 **바로 실행**됩니다.
  카나리가 있으면 OOB 콜백으로 확정하고, 없으면 **인밴드 탐지**(SSRF=클라우드 메타데이터 반사,
  RFI=include 에러, XXE=로컬 파일 노출, Blind XSS=저장/반사 마커)로 후보를 보고합니다.
- **자격증명 테스트** — `credential_testing` 모듈(브루트/스터핑/스프레이). opt-in·페이싱·잠금 감지.
- **레이스컨디션/TOCTOU · 공급망 · XS-Leaks · mXSS · 컨테이너·K8s 이스케이프** — 전용 탐지 모듈로
  후보를 표면화(비파괴). 실제 악용(병렬 요청 등)은 스코프 내에서 리서처가 검증하세요.

### 여전히 자동화하지 않는 것
- **DoS/DDoS/Slowloris/ReDoS/Billion Laughs** — 서비스 마비·남용이라 미구현.

## 실행방법

### 설치
```powershell
python -m pip install -r requirements.txt
```
- Python 3.10+ (개발/검증: 3.13)
- 스캔용 **Chrome/Chromium** 설치 필요(드라이버는 Selenium Manager가 자동 provisioning).
- 독립 앱은 **WebView2 런타임**(Windows 10/11 기본 내장) 필요.

### ① 독립 데스크톱 앱 (권장)
```powershell
python app.py
```
- 로고 아이콘의 **자체 창**(WebView2)으로 UI가 뜹니다. 브라우저/콘솔 불필요.
- 배포본: `dist\Nemesis.exe` (더블클릭 실행)

### ② 웹 버전
```powershell
python web.py
```
- 기본 브라우저에 `http://127.0.0.1:8733` UI가 열립니다.
- 배포본: `dist\NemesisWeb.exe`

### ③ 데스크톱(PyQt) 버전 (레거시)
```powershell
python main.py
```

### 빌드 (.exe)
```powershell
# 독립 데스크톱 앱 → dist\Nemesis.exe (로고 아이콘, 창)
pyinstaller bugbounty_app.spec --noconfirm

# 웹 버전 → dist\NemesisWeb.exe
powershell -ExecutionPolicy Bypass -File build_web_exe.ps1
```
- 로고: `logo.png` → `logo.ico`(빌드에 임베드, favicon·창 아이콘).
- 모듈 추가 후 재빌드 전 `python tools/gen_manifest.py` 로 매니페스트 갱신(빌드 스크립트가 자동 실행).
- 미서명 exe라 첫 실행 시 SmartScreen 경고가 뜰 수 있음(코드서명으로 제거 가능).

## Attack Viewer (대화형 뷰어)

- **Start** 버튼은 스캔을 바로 실행하지 않고, 입력한 URL을 **Attack Viewer**에 열어 줍니다.
  뷰어 화면을 **직접 클릭·타이핑·스크롤**할 수 있으며(서버 측 Chrome에 실시간 전달), 뷰어 상단
  **주소창**으로 이동·뒤로·앞으로·새로고침이 가능합니다.
- 스캔은 **자동으로 시작되지 않습니다.** 원하는 페이지 상태를 만든 뒤 터미널에 **`/start`**
  (또는 공격 번호)를 입력해야 실행됩니다. 실행하면 뷰어는 스캔 라이브 화면으로
  전환되고 주소창에는 현재 스캔 대상 URL이 표시됩니다.

## 터미널 명령어

하단 TERMINAL에 `/` 를 입력하면 명령어 팝오버가 뜹니다.

| 명령 | 설명 |
|---|---|
| `/start [url]` | **스캔 시작** — 선택된 기법으로 실행(뷰어에서 준비 후 이 명령으로 실행) |
| `/attack [검색어]` | 공격 기법을 번호와 함께 나열 → **번호 입력 시 해당 공격 단독 실행** |
| `/login` | 대화식 자동 로그인 설정(URL → 아이디 → 비밀번호) |
| `/status` | 현재 스캔 상태 확인 |
| `/stop` | 진행 중 스캔 중지 |
| `/clearlogin` | 저장된 로그인 정보 삭제 |
| `/clear` | 화면(로그) 지우기 |

예: `/attack sqli` → `1` 입력 → 해당 SQLi 모듈을 대상 URL에 실제 실행.

## 라이선스

이 프로젝트는 **MIT License** 로 배포됩니다. 전문은 [LICENSE](LICENSE) 파일을 참조하세요.

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
