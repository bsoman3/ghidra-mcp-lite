"""Category guards in other segments that keep messages visible under the failure mapping.

Without them, these RuntimeErrors would be reported as "[stop] Internal error" and their
(useful) messages withheld. Gate categories are covered in tests/test_lifecycle.py.
"""

import sys
import types

import pytest

from ghidra_mcp.errors import Stop
from ghidra_mcp.tools import GhidraTools


def _bare_tools():
    tools = object.__new__(GhidraTools)
    tools.program = None
    tools.project = None
    return tools


@pytest.fixture
def stub_ghidra_modules(monkeypatch):
    """Provide the ghidra.* modules imported inside the variable tools."""
    for name, attrs in {
        "ghidra": {},
        "ghidra.program": {},
        "ghidra.program.model": {},
        "ghidra.program.model.pcode": {"HighFunctionDBUtil": object()},
        "ghidra.program.model.symbol": {"SourceType": types.SimpleNamespace(USER_DEFINED="U")},
        "ghidra.util": {},
        "ghidra.util.task": {"ConsoleTaskMonitor": lambda: None},
    }.items():
        monkeypatch.setitem(sys.modules, name, types.SimpleNamespace(**attrs))


class _FailingDecompiler:
    def decompileFunction(self, func, timeout, monitor):  # noqa: N802 - Java naming
        return types.SimpleNamespace(getErrorMessage=lambda: "Low-level Error: bad stack")


class _Func:
    def getName(self):  # noqa: N802 - Java naming
        return "FUN_00401000"


# @spec WB-014
@pytest.mark.parametrize(
    ("method", "args"),
    [
        ("rename_variable", ("FUN_00401000", "local_10", "count")),
        ("set_local_variable_type", ("FUN_00401000", "local_10", "int")),
    ],
)
def test_variable_tool_decompile_failure_is_stop_with_the_decompiler_message(
    stub_ghidra_modules, monkeypatch, method, args
):
    tools = _bare_tools()
    tools.decompiler = _FailingDecompiler()
    monkeypatch.setattr(tools, "find_function", lambda *_a, **_k: _Func())
    monkeypatch.setattr(tools, "_resolve_data_type", lambda *_a: object())
    with pytest.raises(Stop, match="Low-level Error: bad stack"):
        getattr(tools, method)(*args)


# @spec QRY-025
def test_callgraph_without_ghidrecomp_is_stop_naming_the_requirement(monkeypatch):
    monkeypatch.setitem(sys.modules, "ghidrecomp.callgraph", None)  # forces ImportError
    with pytest.raises(Stop, match="ghidrecomp is required"):
        _bare_tools().gen_callgraph("main")
