# Nemesis

<p align="center">
  <a href="README.md">한국어</a> ·
  <a href="README.en.md">English</a> ·
  <a href="README.zh.md">中文</a> ·
  <a href="README.ja.md"><b>日本語</b></a>
</p>

<p align="center">
  Selenium ベースの Web 脆弱性診断ツール · <b>HTTP/HTTPS</b> · <b>329 種</b>の手法 · <b>HackerOne 形式レポート（CWE/CVSS 自動）</b><br>
  <b>ローカル ML/DL 検証モデル</b> + <b>マルチ LLM AI 分析</b>（Gemini·Groq·Cerebras·Mistral·OpenRouter·OpenAI） · <b>SAST ソースコード分析</b>
</p>

---

## 背景

Web 脆弱性診断は通常、複数のツールを組み合わせる必要があり、実ブラウザでしか再現しない
欠陥（DOM XSS・postMessage・CSP の弱点など）は HTTP スキャナだけでは見逃しがちです。さらに、
発見した脆弱性を報告可能なレポートにまとめるのに多くの時間がかかります。

**Nemesis** は実ブラウザ自動化（Selenium）と HTTP/HTTPS 検査を一つにまとめ、URL を入力して攻撃手法を
選ぶだけで **329 種**の脆弱性を検出し、発見した脆弱性を基に追加攻撃（チェイン）まで実行した上で、
**CWE/CVSS を自動マッピングした HackerOne 形式レポート**を生成します。ロゴアイコンを備えた
**独立したデスクトップアプリ**としてパッケージ化されます。

> **HTTP・HTTPS の両方に対応。** スキームなしでドメインだけ入力すると **HTTPS を先に試し、失敗
> したら HTTP にフォールバック**します（`http://`・`https://` を付ければそのまま使用）。自己署名・
> 期限切れ証明書の HTTPS 対象もそのまま分析し（証明書自体は TLS モジュールが別途脆弱性として報告）、
> 必要に応じて `verify_tls` オプションで厳格な TLS 検証を有効化できます。

## 目的

- **広いカバレッジ** —— Injection・Client-Side・Auth/Access・Config・Exposures・
  Exposed Panels・Misconfiguration・Tech/CVE・Recon など 12 カテゴリ・329 手法。
- **実ブラウザ検証** —— Selenium で DOM を実際にレンダリングしイベントを発火させて誤検知を減らし、
  スキャン画面をリアルタイムにストリーミング。
- **チェイン攻撃** —— 確認済みの脆弱性を連携（例：SSRF→メタデータ、XSS→セッション奪取、
  露出した .git→ソース復元）。
- **すぐ報告できる成果物** —— CWE/CVSS v3.1/OWASP/CAPEC の自動マッピングに加え、PoC（curl）・
  Raw HTTP・再現手順・影響・修正まで含む HackerOne 形式 Markdown。
- **安全なデフォルト** —— 非破壊的ペイロード、リクエスト間隔制限（非 DoS）。ブラインド系は canary が
  あれば OOB で確定し、無ければインバンド検出で実行（詳細は[責任](#責任)を参照）。

## 責任

> ⚠️ **許可された対象にのみ使用してください。** 自分が所有する、あるいは**明示的なテスト許可**
> （バグバウンティのスコープ・書面による承認など）がある対象のみをスキャンしてください。
> 無断スキャンは違法となる場合があります。

- スコープ外の対象をスキャンしないこと。リクエスト間隔は十分に空けること。
- すべてのペイロードは**非破壊的な検出用**で、リクエスト間隔制限（非 DoS）と安全なデフォルトを適用。
- **クレデンシャルテスト（総当たり/スタッフィング/スプレー）** は許可された対象にのみ使用 —— ペース
  制御・試行回数の上限があり、**ロック/レート制限の兆候を検知したら即時停止**（実アカウントをロック
  しない）。**デフォルト無効（opt-in）** で、明示的に選択したときだけ実行されます。
- 各発見の信頼度（`Confirmed`/`Firm`/`Tentative`）を確認し、手動で検証すること。
- レポートのタイトルや深刻度を誇張しないこと（事実・証拠に基づく）。漏洩した個人アカウント
  （露出した ID/パスワード）は対象外。

### 許可時の拡張実行（高度）
> 以下は許可されたエンジニアの要請で有効化された項目です。安全策（ペース制御・試行上限・ロック検知）は維持してください。
- **ブラインド系（SSRF・Log4Shell・XXE・Blind XSS・RFI）** は canary 未設定でも**そのまま実行**されます。
  canary があれば OOB コールバックで確定し、無ければ**インバンド検出**（SSRF=クラウドメタデータ反射、
  RFI=include エラー、XXE=ローカルファイル露出、Blind XSS=保存/反射マーカー）で候補を報告します。
- **クレデンシャルテスト** —— `credential_testing` モジュール（総当たり/スタッフィング/スプレー）。opt-in・ペース制御・ロック検知。
- **レースコンディション/TOCTOU・サプライチェーン・XS-Leaks・mXSS・コンテナ/K8s エスケープ** —— 専用
  検出モジュールが候補を提示（非破壊）。実際の悪用（並列リクエスト等）はスコープ内でリサーチャーが検証。

### それでも自動化しないもの
- **DoS/DDoS/Slowloris/ReDoS/Billion Laughs** —— サービス停止・濫用のため未実装。

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
  攻撃番号）を入力すると実行されます。ビューアはライブスキャン画面に切り替わり、
  アドレスバーには現在のスキャン対象 URL が表示されます。

## ターミナルコマンド

下部の TERMINAL に `/` を入力するとコマンドのポップオーバーが表示されます。

| コマンド | 説明 |
|---|---|
| `/start [url]` | **AI 攻撃エージェント** —— サイトをクロール・巡回 → ローカル ML/DL 検証 → 実攻撃・チェーン。キーがあれば各ページの手法を **LLM がリアルタイム補助** + 終了後に全体レビュー |
| `/test [url]` | **マルチ LLM 分析** —— プロバイダ選択（全部 / Gemini / Groq / OpenAI…）→ リコン・検証・推奨攻撃をローカル ML と **アンサンブル** |
| `/sast <パス>` | **ソースコード脆弱性分析（SAST）** —— CWE ヒューリスティックルール +（任意）CodeBERT/LineVul |
| `/model` | 現在のプロバイダの LLM モデル一覧 → 番号で変更 |
| `/key [プロバイダ]` | LLM プロバイダ API キーの保存/削除（`/key groq`、`/key groq clear`、`/key` で一覧） |
| `/attack [検索語]` | 攻撃手法を番号付きで一覧 → **番号を入力するとその攻撃を単独実行** |
| `/login` | 対話式の自動ログイン設定（URL → ID → パスワード） |
| `/status` | 対象 / プロバイダ / モデル / キー保有状態を確認 |
| `/stop` | 実行中のスキャンを停止 |
| `/clearlogin` | 保存済みのログイン情報を削除 |
| `/clear` | 画面（ログ）をクリア |

例：`/attack sqli` → `1` を入力 → 対象 URL に対して該当 SQLi モジュールを実際に実行。

**ターミナルショートカット**（本物のシェルと同じ）：`↑`/`↓` コマンド履歴（再起動後も保持）· `Tab` 補完 ·
`Ctrl+L` クリア · `Ctrl+C` キャンセル · `Ctrl+U`/`Ctrl+K` 行頭/行末まで削除 · `Ctrl+W` 単語削除 ·
`Ctrl+A`/`Ctrl+E` 行頭/行末へ移動。

## AI 分析 —— マルチ LLM + ローカル ML/DL アンサンブル

ローカルモデル（常時動作・外部依存ゼロ）とクラウド LLM（任意・無料枠）を**併用**し、真陽性を高め誤検知を
減らします。**認可されたスキャンのコパイロット補助**であり、自律的なエクスプロイト生成は行いません。

- **`/test`（マルチ LLM）** —— リコン + ローカル ML の検出（ルールスコア・真陽性確率つき）を LLM に渡し、
  実際の悪用可能性・深刻度を再判定し次の攻撃を提案。**複数プロバイダの選択**や**全部使用**でクロス合意も。
  LLM の判定は `feedback.jsonl` に学習ラベルとして保存 —— ローカルモデルが LLM から学習。
- **プロバイダ（無料枠）** —— Gemini（flash 無料）· **Groq**（無料・カード不要、推奨）· Cerebras（約 100 万 tokens/日）·
  Mistral（Experiment 無料）· OpenRouter（`:free` モデル）· OpenAI。多くは OpenAI 互換 API。
  キーは `/key <プロバイダ>`（ブラウザにのみ保存）または環境変数（`GEMINI_API_KEY`/`GROQ_API_KEY`…）。
- **`/start` LLM コパイロット** —— キーがあればエージェントがページを巡回し、各ページの手法開始時に
  **有望なパラメータ/推奨手法/ペイロードヒント**をリアルタイム補助（1 ページ 1 回・上限あり・失敗しても継続）、
  終了時に全検出を LLM+ML アンサンブルで最終レビュー。

## SAST —— ソースコード脆弱性分析（`/sast`）

ブラックボックス（DAST）スキャナを補完するホワイトボックス分析。`/sast <ファイル/フォルダのパス>`。

- **ヒューリスティック CWE ルールエンジン**（純 Python・常時動作）—— CWE-78/89/79/94/502/22/327/295/798/120/338
  などを行単位で検出。
- **CodeBERT/GraphCodeBERT 分類器**（任意、`pip install torch transformers`）—— `tools/train_sast.py` で
  Devign/Big-Vul/Juliet を微調整し `models/sast_codebert/` に置くと自動ロード。**LineVul** 方式で脆弱行を特定。

## Nemesis ML Model

検出結果を真陽性寄りに再調整し誤検知を減らす、2段階（検出 → レビュー）パイプラインです。

- **特徴量（41）**: エンジニアリング17（自己信頼度・モジュール精度・証拠強度・ステータスコード・トークン・
  能動的実証・深刻度など）+ **文字3-gram ハッシュ24バケット**（決定的 FNV-1a、URL/HTML デコード・正規化）
  —— シグネチャ/ペイロードのテキスト（`root:x:0:0`、`ORA-01756`、DB エラー文など）を**データから学習**。
- **分類器**: MLP `41 → 20 → 1`（tanh 隠れ層 + sigmoid 出力）を**純 Python の誤差逆伝播**で学習・推論
  （numpy/torch 不要・外部依存ゼロ）。重み: `models/vuln_model.json`。
- **学習データ**: **268 のテンプレート技術それぞれの実検出シグネチャ** + コードモジュールのキュレーションから
  正/誤検知サンプルを自動生成。再学習: `python tools/train_model.py`。
- **アンサンブル・レビュー**: ルールスコア ⊕ ML `P(真陽性)` をブレンド → **厳格な相互検証ゲート**（第二の
  独立シグナルが無い境界例は誤検知として除去、Critical はレビュー用に保持）。全329技術の全結果に適用。
- **フィードバック学習**: レポートの 👍/👎 → `models/feedback.jsonl` → 再学習で実ラベルを加重（使うほど強化）。
  モデルが無い場合はルールモデルに自動フォールバック。

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
