"""Tests for the module registry — the backbone of the scanner/GUI.

These guard the invariants every technique module must satisfy so a broken
module can't silently disappear from the scan tree.
"""
import modules
from modules.base import BaseModule, all_modules, modules_by_category


def test_load_all_registers_modules():
    modules.load_all()
    mods = all_modules()
    assert len(mods) > 50, "expected the full technique set to register"


def test_every_module_subclasses_base_and_has_metadata():
    modules.load_all()
    for cls in all_modules():
        assert issubclass(cls, BaseModule)
        assert cls.id and cls.id != "base", f"{cls.__name__} missing unique id"
        assert cls.name, f"{cls.__name__} missing name"
        assert cls.category, f"{cls.__name__} missing category"
        assert cls.scope in ("origin", "page"), f"{cls.__name__} bad scope {cls.scope!r}"


def test_module_ids_are_unique():
    modules.load_all()
    ids = [c.id for c in all_modules()]
    dupes = {i for i in ids if ids.count(i) > 1}
    assert not dupes, f"duplicate module ids: {dupes}"


def test_every_module_defines_run():
    modules.load_all()
    for cls in all_modules():
        assert "run" in dir(cls)
        assert callable(cls.run)


def test_modules_by_category_covers_all_modules():
    modules.load_all()
    grouped = modules_by_category()
    total = sum(len(v) for v in grouped.values())
    assert total == len(all_modules())
