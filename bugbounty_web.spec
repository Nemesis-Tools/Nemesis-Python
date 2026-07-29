# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the WEB (HTML) build — a single .exe that launches the
local server and opens the browser UI (Electron-style packaging).

Build:  pyinstaller bugbounty_web.spec --noconfirm
Output: dist/NemesisWeb.exe
"""
import importlib.util as _ilu
from PyInstaller.utils.hooks import collect_all, collect_submodules, collect_data_files

# Explicit list of every technique module (from the generated manifest) so the
# onefile archive definitely contains them (collect_submodules can miss them).
_spec = _ilu.spec_from_file_location("_bb_manifest", "modules/_manifest.py")
_mani = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_mani)
MODULE_LEAVES = list(_mani.MODULE_MODULES)

datas = [("webapp/static/index.html", "webapp/static"), ("logo.png", "."), ("logo.ico", "."),
         ("models/vuln_model.json", "models")]
binaries = []
hiddenimports = []

# selenium (bundled Selenium Manager binary + data)
_d, _b, _h = collect_all("selenium")
datas += _d
binaries += _b
hiddenimports += _h

datas += collect_data_files("certifi")

# Dynamically-loaded technique modules + our packages
hiddenimports += collect_submodules("modules")
hiddenimports += collect_submodules("core")
hiddenimports += collect_submodules("webapp")
# Explicit parent packages (empty __init__ subpackages can otherwise be skipped)
hiddenimports += ["modules", "modules.auth", "modules.client_side", "modules.config",
                  "modules.injection", "modules.recon", "modules.ai_llm",
                  "modules._manifest", "core", "webapp"]
hiddenimports += MODULE_LEAVES              # every technique module, explicitly
hiddenimports += collect_submodules("core")
hiddenimports += ["bs4", "trio", "trio_websocket",
                  "flask", "jinja2", "werkzeug", "click", "itsdangerous",
                  "markupsafe", "blinker"]

# Gemini AI agent (/test) — optional. Bundle google-genai + its deps if installed.
for _pkg in ("google.genai", "google.auth", "websockets", "openai", "pydantic",
             "pydantic_core", "anyio", "sniffio", "certifi"):
    try:
        _d, _b, _h = collect_all(_pkg)
        datas += _d; binaries += _b; hiddenimports += _h
    except Exception:
        pass

a = Analysis(
    ["web.py"],
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
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="NemesisWeb",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,         # hidden — no cmd window on launch
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="logo.ico",
)
