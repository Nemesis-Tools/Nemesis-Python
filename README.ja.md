# Nemesis

<p align="center">
  <a href="README.md">한국어</a> ·
  <a href="README.en.md">English</a> ·
  <a href="README.zh.md">中文</a> ·
  <a href="README.ja.md"><b>日本語</b></a>
</p>

<p align="center">
  Selenium ベースの Web 脆弱性診断ツール · <b>HTTP/HTTPS</b> · <b>323 種</b>の手法 · <b>HackerOne 形式レポート（CWE/CVSS 自動）</b>
</p>

---

## 背景

Web 脆弱性診断は通常、複数のツールを組み合わせる必要があり、実ブラウザでしか再現しない
欠陥（DOM XSS・postMessage・CSP の弱点など）は HTTP スキャナだけでは見逃しがちです。さらに、
発見した脆弱性を報告可能なレポートにまとめるのに多くの時間がかかります。

**Nemesis** は実ブラウザ自動化（Selenium）と HTTP/HTTPS 検査を一つにまとめ、URL を入力して攻撃手法を
選ぶだけで **323 種**の脆弱性を検出し、発見した脆弱性を基に追加攻撃（チェイン）まで実行した上で、
**CWE/CVSS を自動マッピングした HackerOne 形式レポート**を生成します。ロゴアイコンを備えた
**独立したデスクトップアプリ**としてパッケージ化されます。

> **HTTP・HTTPS の両方に対応。** スキームなしでドメインだけ入力すると **HTTPS を先に試し、失敗
> したら HTTP にフォールバック**します（`http://`・`https://` を付ければそのまま使用）。自己署名・
> 期限切れ証明書の HTTPS 対象もそのまま分析し（証明書自体は TLS モジュールが別途脆弱性として報告）、
> 必要に応じて `verify_tls` オプションで厳格な TLS 検証を有効化できます。

## 目的

- **広いカバレッジ** —— Injection・Client-Side・Auth/Access・Config・Exposures・
  Exposed Panels・Misconfiguration・Tech/CVE・Recon など 12 カテゴリ・323 手法。
- **実ブラウザ検証** —— Selenium で DOM を実際にレンダリングしイベントを発火させて誤検知を減らし、
  スキャン画面をリアルタイムにストリーミング。
- **チェイン攻撃** —— 確認済みの脆弱性を連携（例：SSRF→メタデータ、XSS→セッション奪取、
  露出した .git→ソース復元）。
- **すぐ報告できる成果物** —— CWE/CVSS v3.1/OWASP/CAPEC の自動マッピングに加え、PoC（curl）・
  Raw HTTP・再現手順・影響・修正まで含む HackerOne 形式 Markdown。
- **安全なデフォルト** —— 非破壊的ペイロード、リクエスト間隔制限（非 DoS）、canary 未設定時は
  OOB 系を自動スキップ。

## 責任

> ⚠️ **許可された対象にのみ使用してください。** 自分が所有する、あるいは**明示的なテスト許可**
> （バグバウンティのスコープ・書面による承認など）がある対象のみをスキャンしてください。
> 無断スキャンは違法となる場合があります。

- スコープ外の対象をスキャンしないこと。リクエスト間隔は十分に空けること。
- すべてのペイロードは**非破壊的な検出用**で、リクエスト間隔制限（非 DoS）と安全なデフォルトを適用。
- SSRF・Log4Shell・XXE・Blind XSS・RFI などのブラインド系は**自分が管理する canary ドメインにのみ**
  コールバックを誘導。未設定時は自動スキップ（内部・第三者ホストへコールバックしない）。
- 各発見の信頼度（`Confirmed`/`Firm`/`Tentative`）を確認し、手動で検証すること。
- レポートのタイトルや深刻度を誇張しないこと（事実・証拠に基づく）。漏洩した個人アカウント
  （露出した ID/パスワード）は対象外。

### 自動化しないもの（正直なスコープ）
- **DoS/DDoS/Slowloris/ReDoS/Billion Laughs** —— サービス停止・濫用のため未実装。
- **総当たり/クレデンシャルスタッフィング/パスワードスプレー** —— アカウントロック・濫用のため
  実行しない（代わりにそれを可能にする弱点＝レート制限・MFA・CAPTCHA の欠如を検出）。
- **レースコンディション/TOCTOU/コンテナ・K8s エスケープ/サプライチェーン/XS-Leaks/mXSS** ——
  コンテキスト依存のため候補のみ提示し、実際の悪用検証はリサーチャーが行う。

## 実行方法

### インストール
```powershell
python -m pip install -r requirements.txt
```
- Python 3.10+（開発・検証：3.13）
- スキャンには **Chrome/Chromium** が必要（ドライバは Selenium Manager が自動プロビジョニング）。
- 独立アプリには **WebView2 ランタイム**（Windows 10/11 に標準搭載）が必要。

### ① 独立デスクトップアプリ（推奨）
```powershell
python app.py
```
- ロゴアイコン付きの**独自ウィンドウ**（WebView2）で UI が起動。ブラウザ／コンソール不要。
- 配布物：`dist\Nemesis.exe`（ダブルクリックで実行）

### ② Web 版
```powershell
python web.py
```
- 既定のブラウザで `http://127.0.0.1:8733` の UI が開きます。
- 配布物：`dist\NemesisWeb.exe`

### ③ デスクトップ（PyQt）版（レガシー）
```powershell
python main.py
```

### ビルド (.exe)
```powershell
# 独立デスクトップアプリ → dist\Nemesis.exe（ロゴアイコン、ウィンドウ）
pyinstaller bugbounty_app.spec --noconfirm

# Web 版 → dist\NemesisWeb.exe
powershell -ExecutionPolicy Bypass -File build_web_exe.ps1
```
- ロゴ：`logo.png` → `logo.ico`（ビルドに埋め込み、favicon／ウィンドウアイコン）。
- モジュール追加後、再ビルド前に `python tools/gen_manifest.py` でマニフェストを更新
  （ビルドスクリプトが自動実行）。
- 未署名の exe のため、初回起動時に SmartScreen 警告が出ることがあります（コード署名で解消可能）。

## Attack Viewer（対話型ビューア）

- **Start** ボタンはすぐにスキャンせず、入力した URL を **Attack Viewer** に開きます。ビューア上で
  **直接クリック・入力・スクロール**でき（サーバ側の Chrome にリアルタイム転送）、上部の**アドレスバー**で
  移動／戻る／進む／再読み込みができます。
- スキャンは**自動では始まりません**。ページを目的の状態にしたら、ターミナルに **`/start`**（または
  `/scan`、攻撃番号）を入力すると実行されます。ビューアはライブスキャン画面に切り替わり、
  アドレスバーには現在のスキャン対象 URL が表示されます。

## ターミナルコマンド

下部の TERMINAL に `/` を入力するとコマンドのポップオーバーが表示されます。

| コマンド | 説明 |
|---|---|
| `/start [url]` | **スキャン開始** —— 選択された手法で実行（ビューアで準備後にこのコマンドで実行） |
| `/attack [検索語]` | 攻撃手法を番号付きで一覧 → **番号を入力するとその攻撃を単独実行** |
| `/scan [url]` | スキャン開始（`/start` と同じ） |
| `/login` | 対話式の自動ログイン設定（URL → ID → パスワード） |
| `/status` | 現在のスキャン状態を確認 |
| `/stop` | 実行中のスキャンを停止 |
| `/clearlogin` | 保存済みのログイン情報を削除 |
| `/clear` | 画面（ログ）をクリア |

例：`/attack sqli` → `1` を入力 → 対象 URL に対して該当 SQLi モジュールを実際に実行。

## ライセンス

本プロジェクトは **MIT License** で配布されます。全文は [LICENSE](LICENSE) ファイルを参照してください。

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
