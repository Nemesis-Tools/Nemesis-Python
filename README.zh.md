# Nemesis

<p align="center">
  <a href="README.md">한국어</a> ·
  <a href="README.en.md">English</a> ·
  <a href="README.zh.md"><b>中文</b></a> ·
  <a href="README.ja.md">日本語</a>
</p>

<p align="center">
  基于 Selenium 的 Web 漏洞检测工具 · <b>HTTP/HTTPS</b> · <b>323 种</b>技术 · <b>HackerOne 格式报告（自动 CWE/CVSS）</b>
</p>

---

## 背景

Web 漏洞检测通常需要拼接多种工具，而只有在真实浏览器中才能复现的缺陷（DOM XSS、
postMessage、CSP 弱点等）很容易被纯 HTTP 扫描器遗漏。此外，把发现整理成可提交的报告
也要花费大量时间。

**Nemesis** 将真实浏览器自动化（Selenium）与 HTTP/HTTPS 检测融为一体：输入 URL、选择攻击技术，
即可覆盖 **323 种**技术检测漏洞，并基于发现结果执行后续链式攻击，随后生成
**自动映射 CWE/CVSS 的 HackerOne 格式报告**。它以带有 Logo 图标的**独立桌面应用**形式打包。

> **同时支持 HTTP 与 HTTPS。** 仅输入域名时会**优先尝试 HTTPS，失败则回退到 HTTP**
> （直接加上 `http://`/`https://` 可强制指定）。即使 HTTPS 目标使用自签名/过期证书也会照常分析
> （证书本身由 TLS 模块作为单独漏洞报告）；需要时可通过 `verify_tls` 选项开启严格 TLS 校验。

## 目的

- **覆盖面广** —— 涵盖 Injection、Client-Side、Auth/Access、Config、Exposures、
  Exposed Panels、Misconfiguration、Tech/CVE、Recon 等 12 个类别、323 种技术。
- **真实浏览器验证** —— 用 Selenium 实际渲染 DOM、触发事件以降低误报，并实时推流扫描画面。
- **链式攻击** —— 关联已确认的漏洞（如 SSRF→元数据、XSS→会话窃取、暴露的 .git→源码恢复）。
- **可直接提交的产物** —— 自动映射 CWE/CVSS v3.1/OWASP/CAPEC，并在 HackerOne 格式 Markdown 中
  包含 PoC（curl）、原始 HTTP、复现步骤、影响与修复建议。
- **安全默认值** —— 非破坏性载荷、请求限速（非 DoS），未配置 canary 时自动跳过 OOB 系列。

## 责任

> ⚠️ **仅用于已授权的目标。** 只能扫描你拥有的资产，或你**拥有明确测试许可**的目标
> （漏洞赏金范围、书面授权等）。未经授权的扫描可能违法。

- 禁止扫描范围外目标，并保持足够的请求间隔。
- 所有载荷均为**非破坏性检测**，并应用请求限速（非 DoS）与安全默认值。
- SSRF、Log4Shell、XXE、Blind XSS、RFI 等盲注系列**仅回调到你自己掌控的 canary 域名**。
  未配置时自动跳过（不会回调内部/第三方主机）。
- 确认每个发现的置信度（`Confirmed`/`Firm`/`Tentative`）并进行人工验证。
- 不要夸大报告标题或严重程度（以事实与证据为准）。泄露的个人账户（暴露的账号/密码）不在范围内。

### 不会自动化的内容（诚实的范围界定）
- **DoS/DDoS/Slowloris/ReDoS/Billion Laughs** —— 会导致服务瘫痪/滥用，未实现。
- **暴力破解/凭证填充/密码喷洒** —— 会造成账户锁定/滥用，不执行；而是检测使其可能的弱点
  （缺少限速、MFA、CAPTCHA）。
- **竞态条件/TOCTOU/容器与 K8s 逃逸/供应链/XS-Leaks/mXSS** —— 依赖上下文，仅呈现候选项，
  真实利用验证由研究者完成。

## 运行方法

### 安装
```powershell
python -m pip install -r requirements.txt
```
- Python 3.10+（开发/验证环境：3.13）
- 扫描需安装 **Chrome/Chromium**（驱动由 Selenium Manager 自动置备）。
- 独立应用需要 **WebView2 运行时**（Windows 10/11 默认内置）。

### ① 独立桌面应用（推荐）
```powershell
python app.py
```
- UI 在带有 Logo 图标的**独立窗口**（WebView2）中打开，无需浏览器或控制台。
- 发行版：`dist\Nemesis.exe`（双击运行）

### ② Web 版本
```powershell
python web.py
```
- 在默认浏览器中打开 `http://127.0.0.1:8733` UI。
- 发行版：`dist\NemesisWeb.exe`

### ③ 桌面（PyQt）版本（旧版）
```powershell
python main.py
```

### 构建 (.exe)
```powershell
# 独立桌面应用 → dist\Nemesis.exe（Logo 图标、独立窗口）
pyinstaller bugbounty_app.spec --noconfirm

# Web 版本 → dist\NemesisWeb.exe
powershell -ExecutionPolicy Bypass -File build_web_exe.ps1
```
- Logo：`logo.png` → `logo.ico`（嵌入构建，用作 favicon/窗口图标）。
- 添加模块后，重新构建前请用 `python tools/gen_manifest.py` 更新清单（构建脚本会自动运行）。
- exe 未签名，首次启动时 SmartScreen 可能弹出警告（可通过代码签名消除）。

## Attack Viewer（交互式查看器）

- **Start** 按钮不再立即扫描，而是把输入的 URL 打开到 **Attack Viewer** 中。你可以在画面上
  **直接点击、输入、滚动**（实时转发到服务器端 Chrome），并使用顶部**地址栏**进行导航／后退／
  前进／刷新。
- 扫描**不会自动开始**。把页面调整到所需状态后，在终端输入 **`/start`**（或 `/scan`，
  或攻击编号）才会执行。查看器随即切换为实时扫描画面，地址栏显示当前扫描目标 URL。

## 终端命令

在底部 TERMINAL 中输入 `/` 会弹出命令面板。

| 命令 | 说明 |
|---|---|
| `/start [url]` | **开始扫描** —— 使用已选技术执行（在查看器中准备好后用此命令运行） |
| `/attack [关键字]` | 按编号列出攻击技术 → **输入编号即可单独执行该攻击** |
| `/scan [url]` | 开始扫描（`/start` 的别名） |
| `/login` | 交互式自动登录设置（URL → 账号 → 密码） |
| `/status` | 查看当前扫描状态 |
| `/stop` | 停止进行中的扫描 |
| `/clearlogin` | 删除已保存的登录信息 |
| `/clear` | 清除画面（日志） |

示例：`/attack sqli` → 输入 `1` → 对目标 URL 实际执行该 SQLi 模块。

## 许可证

本项目基于 **MIT License** 发布。完整条款请参见 [LICENSE](LICENSE) 文件。

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
