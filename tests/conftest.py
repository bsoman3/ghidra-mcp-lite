"""Shared pytest configuration.

Unit tests use fakes and need no Ghidra. Tests marked ``integration`` need a Ghidra
12.1+ install; set GHIDRA_INSTALL_DIR to its root to run them, e.g.::

    GHIDRA_INSTALL_DIR=../../my-ghidra/ghidra_12.1.4_PUBLIC pytest -m integration
"""

import os

import pytest


def pytest_collection_modifyitems(config, items):
    if os.environ.get("GHIDRA_INSTALL_DIR"):
        return
    skip = pytest.mark.skip(reason="needs GHIDRA_INSTALL_DIR (a Ghidra 12.1+ install)")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip)


@pytest.fixture
def anyio_backend():
    return "asyncio"
