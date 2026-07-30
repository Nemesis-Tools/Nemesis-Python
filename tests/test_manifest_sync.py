"""Guard: the checked-in module manifest must stay in sync with disk.

The PyInstaller build imports every module listed in modules/_manifest.py.
If a technique file is added/removed without regenerating the manifest, the
frozen .exe would silently miss it. This test fails loudly in that case.
Run `python tools/gen_manifest.py` to fix.
"""
import importlib.util
import os

from modules._manifest import MODULE_MODULES

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)


def _load_gen_manifest():
    path = os.path.join(_ROOT, "tools", "gen_manifest.py")
    spec = importlib.util.spec_from_file_location("_gen_manifest", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_manifest_matches_disk():
    gen = _load_gen_manifest()
    discovered = gen.discover()
    assert discovered == list(MODULE_MODULES), (
        "modules/_manifest.py is stale — run `python tools/gen_manifest.py`"
    )


def test_all_manifest_modules_are_importable():
    import importlib
    for name in MODULE_MODULES:
        importlib.import_module(name)
