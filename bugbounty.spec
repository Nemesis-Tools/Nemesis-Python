# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for Nemesis (legacy PyQt build).

Build:  pyinstaller bugbounty.spec --noconfirm
Output: dist/NemesisQt.exe  (onefile, windowed)

Notes:
 * Technique modules are imported dynamically, so they are force-included via
   collect_submodules('modules') + the generated modules/_manifest.py.
 * selenium's bundled Selenium Manager binary + data are pulled via collect_all.
"""
import importlib.util as _ilu
from PyInstaller.utils.hooks import collect_all, collect_submodules, collect_data_files

_spec = _ilu.spec_from_file_location("_bb_manifest", "modules/_manifest.py")
_mani = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_mani)
MODULE_LEAVES = list(_mani.MODULE_MODULES)

datas = []
binaries = []
hiddenimports = []

# selenium (includes the Selenium Manager driver-provisioning binary)
_d, _b, _h = collect_all("selenium")
datas += _d
binaries += _b
hiddenimports += _h

# TLS roots for requests
datas += collect_data_files("certifi")

# Our dynamically-loaded packages
hiddenimports += collect_submodules("modules")
hiddenimports += collect_submodules("core")
hiddenimports += collect_submodules("gui")
hiddenimports += ["modules", "modules.auth", "modules.client_side", "modules.config",
                  "modules.injection", "modules.recon", "modules.ai_llm",
                  "modules._manifest", "core", "gui"]
hiddenimports += MODULE_LEAVES
hiddenimports += ["PyQt5.QtSvg", "PyQt5.QtPrintSupport", "bs4", "trio", "trio_websocket"]

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "numpy", "pandas"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="NemesisQt",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # set True temporarily to see startup errors
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
