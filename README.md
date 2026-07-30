# Nemesis

<p align="center">
  <a href="README.md"><b>한국어</b></a> ·
  <a href="README.en.md">English</a> ·
  <a href="README.zh.md">中文</a> ·
  <a href="README.ja.md">日本語</a>
</p>

<p align="center">
  Selenium 기반 웹 취약점 점검 도구 · <b>HTTP/HTTPS</b> · <b>329종</b> 기법 · <b>HackerOne 형식 리포트(CWE/CVSS 자동)</b><br>
  <b>로컬 ML/DL 검수 모델</b> + <b>멀티-LLM AI 분석</b>(Gemini·Groq·Cerebras·Mistral·OpenRouter·OpenAI) · <b>SAST 소스코드 분석</b>
</p>

<p align="center">
  <a href="https://github.com/Nemesis-Tools/Nemesis-Python/actions/workflows/ci.yml"><img src="https://github.com/Nemesis-Tools/Nemesis-Python/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/Nemesis-Tools/Nemesis-Python/actions/workflows/codeql.yml"><img src="https://github.com/Nemesis-Tools/Nemesis-Python/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://github.com/Nemesis-Tools/Nemesis-Python/actions/workflows/security.yml"><img src="https://github.com/Nemesis-Tools/Nemesis-Python/actions/workflows/security.yml/badge.svg" alt="Security"></a>
  <img src="https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/code%20style-ruff-000000" alt="Ruff">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License"></a>
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
| `/start [url]` | **AI 공격 에이전트 시작** — 사이트 크롤·메뉴 이동 → 로컬 ML/DL 검증 → 실제 공격·체인. 키가 있으면 각 페이지에서 **LLM이 실시간 보조** + 종료 후 전체 검수 |
| `/test [url]` | **멀티-LLM 취약점 분석** — 제공자 선택(전체/Gemini/Groq/OpenAI…) → 리컨·검수·권장공격을 로컬 ML과 **앙상블** |
| `/sast <경로>` | **소스코드 취약점 분석(SAST)** — CWE 휴리스틱 룰 + (선택)CodeBERT/LineVul |
| `/model` | 현재 제공자의 LLM 모델 목록 → 번호로 변경 |
| `/key [제공자]` | LLM 제공자 API 키 저장/삭제(`/key groq`, `/key groq clear`, `/key` 로 목록) |
| `/attack [검색어]` | 공격 기법을 번호와 함께 나열 → **번호 입력 시 해당 공격 단독 실행** |
| `/login` | 대화식 자동 로그인 설정(URL → 아이디 → 비밀번호) |
| `/status` | 대상·제공자·모델·키 보유 상태 확인 |
| `/stop` | 진행 중 스캔 중지 |
| `/clearlogin` | 저장된 로그인 정보 삭제 |
| `/clear` | 화면(로그) 지우기 |

예: `/attack sqli` → `1` 입력 → 해당 SQLi 모듈을 대상 URL에 실제 실행.

**터미널 단축키**(실제 셸과 동일): `↑`/`↓` 명령 이력(재시작 후에도 유지) · `Tab` 자동완성 ·
`Ctrl+L` 화면 지움 · `Ctrl+C` 취소 · `Ctrl+U`/`Ctrl+K` 라인 앞/뒤 삭제 · `Ctrl+W` 단어 삭제 ·
`Ctrl+A`/`Ctrl+E` 줄 처음/끝 이동.

## AI 분석 — 멀티-LLM + 로컬 ML/DL 앙상블

로컬 모델(항상 동작, 외부 의존성 0)과 클라우드 LLM(선택, 무료 티어)을 **함께** 구성해 정탐을
높이고 오탐을 줄입니다. **인가된 대상의 스캐너 코파일럿 보조**이며, 자율 익스플로잇 생성은 하지 않습니다.

- **`/test` (멀티-LLM)** — 대상 리컨 + 로컬 ML이 뽑은 발견(룰 점수·정탐확률 포함)을 LLM에 전달해
  실제 취약 여부·심각도를 재판정하고 다음 공격을 제안. **여러 제공자를 선택**하거나 **전체 사용**으로
  교차 합의(몇/몇 제공자가 실제로 판정)까지. LLM 판정은 `feedback.jsonl`에 학습 라벨로 저장 → 로컬
  모델이 LLM에게 학습.
- **제공자(무료 티어)** — Gemini(flash 무료) · **Groq**(무료·카드 불필요, 추천) · Cerebras(~1M 토큰/일) ·
  Mistral(Experiment 무료) · OpenRouter(`:free` 모델 다수) · OpenAI. 대부분 OpenAI 호환 API.
  키는 `/key <제공자>`로 브라우저에만 저장(앱은 저장 안 함), 또는 env(`GEMINI_API_KEY`/`GROQ_API_KEY`…).
- **`/start` LLM 코파일럿** — 키가 있으면 에이전트가 페이지를 이동하며 각 페이지의 공격 기법이 시작될 때
  **유망 파라미터·권장 기법·페이로드 힌트**를 실시간 보조(페이지당 1회·상한, 실패해도 스캔 계속),
  종료 시 전체 발견을 LLM+ML 앙상블로 최종 검수.

## SAST — 소스코드 취약점 분석 (`/sast`)

블랙박스(DAST) 스캐너를 보완하는 화이트박스 소스코드 분석. `/sast <파일/폴더 경로>`.

- **휴리스틱 CWE 룰 엔진**(순수 파이썬, 항상 동작) — CWE-78/89/79/94/502/22/327/295/798/120/338 등
  라인 단위 탐지(bandit/semgrep 계열).
- **CodeBERT/GraphCodeBERT 분류기**(선택, `pip install torch transformers`) — `tools/train_sast.py`로
  Devign/Big-Vul/Juliet 파인튜닝 후 `models/sast_codebert/`에 두면 자동 로드. **LineVul** 방식으로
  취약 라인까지 지목.

## Nemesis ML Model

탐지 결과를 정탐 위주로 재보정하고 오탐을 줄이는 2단계(탐지→검수) 파이프라인입니다.

- **특징(41개)**: 엔지니어링 17개(자기신뢰도·모듈정밀도·증거강도·상태코드·토큰·활성 실증·심각도 등)
  + **문자 3-gram 해싱 24버킷**(결정론적 FNV-1a, URL/HTML 디코딩·정규화 전처리) — 페이로드/시그니처
  텍스트(예: `root:x:0:0`, `ORA-01756`, DB 에러문)를 하드코딩이 아니라 **데이터로 학습**.
- **분류기**: MLP `41 → 20 → 1`(tanh 은닉 + 시그모이드 출력), **순수 파이썬 역전파**로 학습·추론
  (numpy/torch 등 외부 의존성 0). 가중치: `models/vuln_model.json`.
- **학습 데이터**: **268개 템플릿 기법 각각의 실제 탐지 시그니처** + 코드 모듈 큐레이션에서 정탐/오탐
  예시를 자동 생성(문자 특징 증강 포함). 재학습: `python tools/train_model.py`.
- **학습/검증 분할 + 지표**: 증강 전 base를 학습/검증으로 분리(증강본 누수 방지) 후 **held-out에서
  Precision·Recall·F1·ROC-AUC** 리포트(`core/metrics.py`, 순수 파이썬). 독립 평가: `python tools/eval_model.py`.
- **앙상블 검수**: 규칙 점수 ⊕ ML `P(정탐)` 을 블렌딩 → **엄격 교차검증 게이트**(2차 독립 신호가
  없으면 오탐으로 제거, Critical은 검토용 유지). 모든 finding(전 329기법)에 공통 적용.
- **피드백 학습**: 보고서의 👍정탐/👎오탐 **및 LLM(`/test`) 판정** → `models/feedback.jsonl` → 재학습 시
  실제 라벨을 가중 반영(사람 라벨 우선, LLM 라벨 보조). 모델 부재 시 규칙 기반으로 자동 폴백.

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
