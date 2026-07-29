"""Module package with auto-discovery.

Calling `load_all()` imports every technique module under this package so its
`@register` decorator runs and it appears in the registry / GUI. To add a new
technique, drop a new .py file in any subpackage — no wiring required.
"""
from __future__ import annotations

import importlib
import pkgutil

LOAD_ERRORS: list[str] = []


def load_all() -> None:
    names: set[str] = set()
    LOAD_ERRORS.clear()

    # 1) Filesystem discovery (works from source; auto-picks up new files).
    try:
        package = importlib.import_module(__name__)
        for mod_info in pkgutil.walk_packages(package.__path__, prefix=__name__ + "."):
            if mod_info.name.endswith(".base") or mod_info.name.endswith("._manifest"):
                continue
            names.add(mod_info.name)
    except Exception:
        pass

    # 2) Explicit manifest (reliable inside PyInstaller-frozen apps where
    #    pkgutil discovery does not see archived submodules).
    try:
        from modules._manifest import MODULE_MODULES
        names.update(MODULE_MODULES)
    except Exception as e:
        LOAD_ERRORS.append(f"manifest: {e!r}")

    for name in sorted(names):
        try:
            importlib.import_module(name)
        except Exception as e:
            # A single broken module shouldn't abort loading the rest.
            LOAD_ERRORS.append(f"{name}: {e!r}")
