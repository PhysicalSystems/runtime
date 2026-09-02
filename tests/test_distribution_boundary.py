from __future__ import annotations

import re
from pathlib import Path

import tinyedge_runtime


FORBIDDEN_IMPORT = re.compile(
    r"^\s*(?:from|import)\s+(tinyedge_agent|tinyedge_benchmarks|tinyedge_platform)\b",
    re.MULTILINE,
)


def test_runtime_package_has_no_private_tinyedge_imports():
    package_root = Path(tinyedge_runtime.__file__).parent
    for source_path in package_root.rglob("*.py"):
        source = source_path.read_text(encoding="utf-8")
        assert FORBIDDEN_IMPORT.search(source) is None, source_path


def test_distribution_and_import_versions_match():
    assert tinyedge_runtime.__version__ == "0.2.0"
