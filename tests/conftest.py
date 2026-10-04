"""Shared pytest configuration.

Unit tests use fakes and need no Ghidra. Tests marked ``integration`` need a Ghidra
12.1+ install; set GHIDRA_INSTALL_DIR to its root to run them, e.g.::

    GHIDRA_INSTALL_DIR=../../my-ghidra/ghidra_12.1.4_PUBLIC pytest -m integration

Tests marked ``gui`` launch the Ghidra GUI (GUI mode) and need a display; they also need
GHIDRA_MCP_GUI_TESTS=1.
"""

import os

import pytest


def pytest_collection_modifyitems(config, items):
    has_ghidra = bool(os.environ.get("GHIDRA_INSTALL_DIR"))
    gui_enabled = has_ghidra and os.environ.get("GHIDRA_MCP_GUI_TESTS") == "1"
    skip_ghidra = pytest.mark.skip(reason="needs GHIDRA_INSTALL_DIR (a Ghidra 12.1+ install)")
    skip_gui = pytest.mark.skip(reason="GUI smoke suite: set GHIDRA_MCP_GUI_TESTS=1 (needs a display)")
    for item in items:
        if "gui" in item.keywords and not gui_enabled:
            item.add_marker(skip_gui)
        elif "integration" in item.keywords and not has_ghidra:
            item.add_marker(skip_ghidra)


@pytest.fixture
def anyio_backend():
    return "asyncio"
