# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the STANDALONE DESKTOP app (native window via pywebview).

Build:  pyinstaller bugbounty_app.spec --noconfirm
Output: dist/Nemesis.exe  (own window + taskbar icon, no browser/console)
"""
import importlib.util as _ilu
from PyInstaller.utils.hooks import collect_all, collect_submodules, collect_data_files

_spec = _ilu.spec_from_file_location("_bb_manifest", "modules/_manifest.py")
_mani = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_mani)
MODULE_LEAVES = list(_mani.MODULE_MODULES)

datas = [("webapp/static/index.html", "webapp/static"), ("logo.png", "."), ("logo.ico", "."),
         ("models/vuln_model.json", "models")]
binaries = []
hiddenimports = []

# selenium (bundled driver manager) + TLS roots
_d, _b, _h = collect_all("selenium")
datas += _d; binaries += _b; hiddenimports += _h
datas += collect_data_files("certifi")

# pywebview + .NET backend (pythonnet); Gemini AI agent (/test, optional)
for pkg in ("webview", "pythonnet", "clr_loader",
            "google.genai", "google.auth", "websockets", "openai", "pydantic",
            "pydantic_core", "anyio", "sniffio", "certifi"):
    try:
        _d, _b, _h = collect_all(pkg)
        datas += _d; binaries += _b; hiddenimports += _h
    except Exception:
        pass

# Our packages (explicit — avoids empty-__init__ / dynamic-import misses)
hiddenimports += collect_submodules("core")
hiddenimports += collect_submodules("webapp")
hiddenimports += ["modules", "modules.auth", "modules.client_side", "modules.config",
                  "modules.injection", "modules.recon", "modules.ai_llm",
                  "modules.templates", "modules._manifest", "core", "webapp"]
hiddenimports += MODULE_LEAVES
hiddenimports += ["clr", "webview.platforms.winforms", "webview.platforms.edgechromium",
                  "bs4", "trio", "trio_websocket",
                  "flask", "jinja2", "werkzeug", "click", "itsdangerous", "markupsafe", "blinker"]

a = Analysis(
    ["app.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["PyQt5", "tkinter", "matplotlib", "numpy", "pandas"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="Nemesis",
    debug=False, bootloader_ignore_signals=False, strip=False, upx=True,
    upx_exclude=[], runtime_tmpdir=None, console=False,
    disable_windowed_traceback=False, argv_emulation=False, target_arch=None,
    codesign_identity=None, entitlements_file=None, icon="logo.ico",
)
