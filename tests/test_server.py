"""Server segment: failure reporting, tool surface, and CLI behavior (no Ghidra needed)."""

import inspect
import logging
import re
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner
from mcp import Client
from mcp.server.mcpserver.exceptions import ToolError

from ghidra_mcp import __version__, server
from ghidra_mcp.context import AnalysisOptions, Status
from ghidra_mcp.errors import FixInput, RetryLater, Stop
from ghidra_mcp.tools import GhidraTools, handle_exceptions
from tests.fakes import FakeContext, FakeProgramInfo

EXPECTED_TOOLS = {
    "list_project_binaries", "list_project_binary_metadata", "import_binary",
    "delete_project_binary", "list_functions", "list_segments", "list_data_items",
    "list_classes", "list_namespaces", "get_function_by_address", "disassemble_function",
    "decompile_function", "search_symbols", "list_imports", "list_exports",
    "list_cross_references", "get_xrefs_from", "search_strings", "read_bytes",
    "set_disassembly_comment", "set_decompiler_comment", "rename_function",
    "rename_function_by_address", "rename_data", "rename_variable",
    "set_function_prototype", "set_local_variable_type", "gen_callgraph", "reanalyze_binary",
    "get_function_callers", "get_function_callees", "diff_functions", "find_similar_functions_fuzzy",
    "get_function_pcode", "analyze_dataflow",
}


@pytest.fixture
def fake_ctx(monkeypatch):
    ctx = FakeContext()
    monkeypatch.setattr(server.mcp, "_ghidra_context", ctx, raising=False)
    return ctx


async def _call(name, arguments):
    async with Client(server.mcp) as client:
        return await client.call_tool(name, arguments)


def _text(result):
    return "".join(getattr(block, "text", "") for block in result.content)


# ── Failure reporting ────────────────────────────────────────────────────────


# @spec SRV-025, SRV-032, SRV-036
@pytest.mark.parametrize(
    ("exc", "category"),
    [
        (FixInput("bad"), "fix_input"),
        (ValueError("bad"), "fix_input"),
        (re.error("bad"), "fix_input"),
        (FileNotFoundError("bad"), "fix_input"),
        (RetryLater("bad"), "retry_later"),
        (Stop("bad"), "stop"),
    ],
)
def test_err_tags_anticipated_failures(exc, category):
    err = server._err(exc)
    assert isinstance(err, ToolError)
    assert str(err) == f"[{category}] bad"


# @spec SRV-027
def test_err_withholds_unexpected_exception_text(caplog):
    caplog.set_level(logging.ERROR)
    err = server._err(RuntimeError("secret /internal/path"))
    assert isinstance(err, ToolError)
    assert str(err).startswith("[stop] Internal error")
    assert "secret" not in str(err)
    assert "secret /internal/path" in caplog.text


# @spec SRV-025, SRV-036
@pytest.mark.anyio
async def test_fix_input_failure_reaches_the_model_with_its_tag(fake_ctx):
    fake_ctx.get_program_info_error = FixInput("Binary 'nope' not found.")
    result = await _call("list_functions", {"binary_name": "nope"})
    assert result.is_error
    assert "[fix_input] Binary 'nope' not found." in _text(result)


# @spec SRV-031
@pytest.mark.anyio
async def test_retry_later_failure_reaches_the_model_with_its_tag(fake_ctx):
    fake_ctx.get_program_info_error = RetryLater("Analysis not yet complete for 'a'.")
    result = await _call("decompile_function", {"binary_name": "a", "name_or_address": "main"})
    assert result.is_error
    assert "[retry_later] Analysis not yet complete" in _text(result)


# @spec SRV-027
@pytest.mark.anyio
async def test_unexpected_failure_is_reported_as_stop_without_internals(fake_ctx):
    fake_ctx.get_program_info_error = RuntimeError("secret /internal/path")
    result = await _call("list_segments", {"binary_name": "a"})
    assert result.is_error
    assert "[stop] Internal error" in _text(result)
    assert "secret" not in _text(result)


# @spec SRV-027
@pytest.mark.anyio
async def test_list_project_binaries_failures_are_categorized(fake_ctx, monkeypatch):
    class Exploding(dict):
        def values(self):
            raise RuntimeError("boom")

    fake_ctx.programs = Exploding()
    result = await _call("list_project_binaries", {})
    assert result.is_error
    assert "[stop] Internal error" in _text(result)


# @spec SRV-024
@pytest.mark.anyio
async def test_failed_delete_is_a_stop_failure_carrying_the_reason(fake_ctx):
    fake_ctx.delete_error = Stop("Could not delete 'a': file is locked")
    result = await _call("delete_project_binary", {"binary_name": "a"})
    assert result.is_error
    assert "[stop] Could not delete 'a': file is locked" in _text(result)


# @spec SRV-028
@pytest.mark.parametrize(
    ("exc", "level"),
    [
        (FixInput("x"), logging.DEBUG),
        (RetryLater("x"), logging.DEBUG),
        (Stop("x"), logging.WARNING),
        (RuntimeError("x"), logging.ERROR),
    ],
)
def test_tool_failures_are_logged_by_category(exc, level, caplog):
    @handle_exceptions
    def boom():
        raise exc

    caplog.set_level(logging.DEBUG, logger="ghidra_mcp.tools")
    with pytest.raises(type(exc)):
        boom()
    records = [r for r in caplog.records if "boom" in r.getMessage()]
    assert records, caplog.text
    assert records[0].levelno == level
    if level == logging.ERROR:
        assert records[0].exc_info


# ── Tool surface ─────────────────────────────────────────────────────────────


# @spec SRV-018
@pytest.mark.anyio
async def test_registers_the_29_tools(fake_ctx):
    async with Client(server.mcp) as client:
        listed = await client.list_tools()
    assert {tool.name for tool in listed.tools} == EXPECTED_TOOLS
    assert all(tool.description for tool in listed.tools)


# @spec SRV-037, SRV-021
@pytest.mark.anyio
async def test_project_listing_is_structured_and_carries_status_failures_warnings_and_metadata(fake_ctx):
    fake_ctx.programs = {
        "/a-123456": FakeProgramInfo("a-123456", file_path="/tmp/a", metadata={"Processor": "AARCH64"},
                                     warnings=["Unknown analysis option 'X'; not set."]),
        "/b-222222": FakeProgramInfo("b-222222", status=Status.FAILED, failure="Import failed: bad"),
        "/c-333333": FakeProgramInfo("c-333333", status=Status.IMPORTING),
    }
    async with Client(server.mcp) as client:
        listed = await client.list_tools()
        result = await client.call_tool("list_project_binaries", {})
    schemas = {tool.name: tool.output_schema for tool in listed.tools}
    assert schemas["list_project_binaries"]
    assert not result.is_error
    rows = {p["name"]: p for p in result.structured_content["programs"]}
    assert rows["a-123456"]["status"] == "ready" and rows["a-123456"]["metadata"] == {"Processor": "AARCH64"}
    assert rows["a-123456"]["warnings"] == ["Unknown analysis option 'X'; not set."]
    assert rows["b-222222"]["status"] == "failed" and rows["b-222222"]["failure"] == "Import failed: bad"
    assert rows["c-333333"]["status"] == "importing"


# @spec SRV-022
@pytest.mark.anyio
async def test_metadata_is_returned_without_the_analysis_gate(fake_ctx):
    fake_ctx.programs["/a-1"] = FakeProgramInfo("a-1", status=Status.ANALYZING, metadata={"Compiler": "gcc"})
    result = await _call("list_project_binary_metadata", {"binary_name": "/a-1"})
    assert not result.is_error
    assert ("get_metadata", "/a-1") in fake_ctx.calls
    assert not any(c[0] == "get_program_info" for c in fake_ctx.calls)


# @spec SRV-023
@pytest.mark.anyio
async def test_import_binary_passes_its_analysis_options(fake_ctx, tmp_path):
    gdt = tmp_path / "win.gdt"
    gdt.write_bytes(b"gdt")
    result = await _call("import_binary", {
        "binary_path": str(tmp_path / "app.exe"), "gdts": [str(gdt)],
        "analyzer_options": {"Stack": False}, "no_symbols": True,
    })
    assert not result.is_error, _text(result)
    (_, path, options), = [c for c in fake_ctx.calls if c[0] == "import_binary_backgrounded"]
    assert options == AnalysisOptions(no_symbols=True, gdts=(gdt,), analyzer_options={"Stack": False})


# @spec SRV-023, LIFE-010
@pytest.mark.anyio
async def test_import_binary_says_when_a_binary_is_already_in_the_project(fake_ctx, tmp_path):
    fake_ctx.already_imported = {"app.exe"}
    result = await _call("import_binary", {"binary_path": str(tmp_path / "app.exe"), "no_symbols": True})
    assert not result.is_error, _text(result)
    text = _text(result)
    assert "already in the project" in text.lower() and "app.exe" in text
    assert "reanalyze_binary" in text
    assert "Importing" not in text


# @spec SRV-023, LIFE-046
@pytest.mark.anyio
async def test_import_binary_rejects_a_missing_pdb_as_fix_input(fake_ctx, tmp_path):
    result = await _call("import_binary", {"binary_path": "/x", "pdb_path": str(tmp_path / "nope.pdb")})
    assert result.is_error
    assert "[fix_input] File not found" in _text(result)


# @spec SRV-044
@pytest.mark.anyio
async def test_reanalyze_binary_delegates_with_its_options(fake_ctx):
    result = await _call("reanalyze_binary", {"binary_name": "a-1", "analyzer_options": {"Stack": True}})
    assert not result.is_error, _text(result)
    assert ("reanalyze_binary", "a-1", AnalysisOptions(analyzer_options={"Stack": True})) in fake_ctx.calls


# @spec SRV-044, LIFE-045
@pytest.mark.anyio
async def test_reanalyze_binary_while_pending_is_retry_later(fake_ctx):
    fake_ctx.reanalyze_error = RetryLater("'a-1' is already being imported or analyzed")
    result = await _call("reanalyze_binary", {"binary_name": "a-1"})
    assert "[retry_later]" in _text(result)


# @spec SRV-038
def test_every_tool_is_synchronous_so_the_sdk_runs_it_off_the_event_loop():
    for name in EXPECTED_TOOLS:
        assert not inspect.iscoroutinefunction(getattr(server, name)), name


# @spec SRV-039
def test_gen_callgraph_exposes_all_implementation_parameters_with_equal_defaults():
    wrapper = inspect.signature(server.gen_callgraph).parameters
    impl = inspect.signature(GhidraTools.gen_callgraph).parameters
    mapping = {
        "direction": "cg_direction",
        "display_type": "cg_display_type",
        "include_refs": "include_refs",
        "max_depth": "max_depth",
        "max_run_time": "max_run_time",
        "condense_threshold": "condense_threshold",
        "top_layers": "top_layers",
        "bottom_layers": "bottom_layers",
    }
    for wrapper_name, impl_name in mapping.items():
        assert wrapper_name in wrapper, wrapper_name
        assert wrapper[wrapper_name].default == impl[impl_name].default, wrapper_name


# @spec SRV-039
@pytest.mark.parametrize(
    ("wrapper", "impl", "params"),
    [
        (server.list_functions, GhidraTools.list_functions, ["query", "offset", "limit"]),
        (server.list_data_items, GhidraTools.list_data_items, ["offset", "limit"]),
        (server.list_classes, GhidraTools.list_classes, ["offset", "limit"]),
        (server.list_namespaces, GhidraTools.list_namespaces, ["offset", "limit"]),
        (server.search_symbols, GhidraTools.search_symbols_by_name, ["offset", "limit"]),
        (server.list_imports, GhidraTools.list_imports, ["query", "offset", "limit"]),
        (server.list_exports, GhidraTools.list_exports, ["query", "offset", "limit"]),
        (server.search_strings, GhidraTools.search_strings, ["limit"]),
        (server.read_bytes, GhidraTools.read_bytes, ["size"]),
    ],
)
def test_wrapper_defaults_equal_implementation_defaults(wrapper, impl, params):
    w = inspect.signature(wrapper).parameters
    i = inspect.signature(impl).parameters
    for name in params:
        assert w[name].default == i[name].default, name


# ── CLI ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def cli(monkeypatch):
    ctx = FakeContext()
    runs = []
    monkeypatch.setattr(server.pyghidra, "start", lambda *a, **k: None)
    monkeypatch.setattr(server, "GhidraContext", lambda **kw: ctx.configure(**kw))
    monkeypatch.setattr(server.mcp, "run", lambda *a, **k: runs.append((a, k)))
    return ctx, runs, CliRunner()


# @spec SRV-002
def test_sse_transport_is_rejected(cli):
    _, runs, runner = cli
    result = runner.invoke(server.main, ["--transport", "sse"])
    assert result.exit_code != 0
    assert runs == []


# @spec SRV-014, SRV-015
def test_serving_answers_the_handshake_without_waiting_for_analysis(cli):
    ctx, runs, runner = cli
    result = runner.invoke(
        server.main,
        ["--wait-for-analysis", "--transport", "streamable-http", "--host", "0.0.0.0", "--port", "9000"],
    )
    assert result.exit_code == 0, result.output
    assert ("analyze_project", False) in ctx.calls
    assert runs == [((), {"transport": "streamable-http", "host": "0.0.0.0", "port": 9000})]
    assert ctx.calls[-1] == ("close",)


# @spec SRV-015
def test_stdio_is_the_default_transport(cli):
    _, runs, runner = cli
    result = runner.invoke(server.main, [])
    assert result.exit_code == 0, result.output
    assert runs == [((), {"transport": "stdio"})]


# @spec SRV-012, SRV-033
def test_cli_delete_reporting_failure_says_so_and_exits_nonzero(cli):
    ctx, runs, runner = cli
    ctx.delete_result = False
    result = runner.invoke(server.main, ["--delete-project-binary", "x"])
    assert result.exit_code == 1
    assert "Deleted" not in result.stdout
    assert "x" in result.stderr
    assert runs == []


# @spec SRV-011, SRV-033
def test_cli_delete_raising_prints_the_error_and_exits_nonzero(cli):
    ctx, _, runner = cli
    ctx.delete_error = ValueError("Binary 'x' not found.")
    result = runner.invoke(server.main, ["--delete-project-binary", "x"])
    assert result.exit_code == 1
    assert "Binary 'x' not found." in result.stderr


# @spec SRV-010
def test_cli_delete_success(cli):
    _, runs, runner = cli
    result = runner.invoke(server.main, ["--delete-project-binary", "x"])
    assert result.exit_code == 0
    assert "Deleted: x" in result.stdout
    assert runs == []


# @spec SRV-033
def test_cli_list_failure_exits_nonzero(cli):
    ctx, _, runner = cli
    ctx.list_error = RuntimeError("project unreadable")
    result = runner.invoke(server.main, ["--list-project-binaries"])
    assert result.exit_code == 1
    assert "project unreadable" in result.stderr


# @spec SRV-035, SRV-033
def test_analyze_only_reports_each_status_and_exits_nonzero_when_any_failed(cli, tmp_path):
    ctx, runs, runner = cli
    binary = tmp_path / "bin"
    binary.write_bytes(b"\0")
    ctx.programs = {
        "/a-111111": FakeProgramInfo("a-111111", complete=True),
        "/b-222222": FakeProgramInfo("b-222222", status=Status.FAILED, failure="bad stack"),
    }
    result = runner.invoke(server.main, ["--analyze-only", str(binary)])
    assert ("import_binaries", [binary]) in ctx.calls
    assert ("analyze_project", True) in ctx.calls
    assert "a-111111: ready" in result.stdout
    assert "b-222222: failed (bad stack)" in result.stdout
    assert result.exit_code == 1
    assert runs == []


# @spec SRV-035
def test_analyze_only_exits_zero_when_every_binary_is_ready(cli):
    ctx, runs, runner = cli
    ctx.programs = {"/a-111111": FakeProgramInfo("a-111111", complete=True)}
    result = runner.invoke(server.main, ["--analyze-only"])
    assert result.exit_code == 0, result.output
    assert runs == []


# @spec SRV-043
@pytest.mark.parametrize(
    "flag",
    [["--force-analysis"], ["--no-symbols"], ["--sym-file-path", "x.pdb"], ["--gdt", "x.gdt"],
     ["--program-options", "o.json"]],
)
def test_per_binary_analysis_flags_are_not_accepted(cli, flag):
    _, runs, runner = cli
    result = runner.invoke(server.main, flag)
    assert result.exit_code != 0
    assert "No such option" in result.output
    assert runs == []


# @spec SRV-008
def test_waiting_is_on_by_default_and_only_process_options_reach_the_context(cli):
    ctx, _, runner = cli
    runner.invoke(server.main, [])
    assert ctx.kwargs["wait_for_analysis"] is True
    assert set(ctx.kwargs) == {"project_name", "project_path", "verbose_analysis",
                               "wait_for_analysis", "symbols_path"}
    runner.invoke(server.main, ["--no-wait-for-analysis"])
    assert ctx.kwargs["wait_for_analysis"] is False


# @spec SRV-030
def test_version_flag_reports_the_package_version():
    result = CliRunner().invoke(server.main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


# @spec SRV-042
@pytest.mark.anyio
async def test_sdk_argument_rejection_carries_fix_input(fake_ctx):
    result = await _call("list_functions", {})
    assert result.is_error
    text = _text(result)
    assert "[fix_input]" in text
    assert "binary_name" in text


# @spec SRV-042
@pytest.mark.anyio
async def test_unknown_tool_carries_fix_input(fake_ctx):
    result = await _call("no_such_tool", {})
    assert result.is_error
    assert _text(result).startswith("[fix_input] Unknown tool")


# @spec SRV-042
@pytest.mark.anyio
async def test_categorized_failures_are_not_tagged_twice(fake_ctx):
    fake_ctx.get_program_info_error = FixInput("nope")
    result = await _call("list_segments", {"binary_name": "a"})
    assert _text(result).count("[fix_input]") == 1


# @spec SRV-003
def test_gpr_path_gives_the_project_directory_and_name(cli, tmp_path):
    ctx, runs, runner = cli
    gpr = tmp_path / "work" / "mine.gpr"
    result = runner.invoke(
        server.main, ["--project-path", str(gpr), "--project-name", "ignored", "--list-project-binaries"]
    )
    assert result.exit_code == 0, result.output
    assert ctx.kwargs["project_path"] == str(gpr.parent.resolve())
    assert ctx.kwargs["project_name"] == "mine"


# @spec SRV-004
def test_default_project_location(cli):
    ctx, _, runner = cli
    result = runner.invoke(server.main, ["--list-project-binaries"])
    assert result.exit_code == 0, result.output
    assert ctx.kwargs["project_path"] == str((Path.cwd() / "ghidra_projects").resolve())
    assert ctx.kwargs["project_name"] == "my_project"


# @spec SRV-050
def test_project_path_expands_home_and_resolves_dotdot(cli, tmp_path, monkeypatch):
    ctx, _, runner = cli
    monkeypatch.setenv("HOME", str(tmp_path))
    result = runner.invoke(server.main, ["--project-path", "~/a/../b/proj.gpr", "--list-project-binaries"])
    assert result.exit_code == 0, result.output
    assert ctx.kwargs["project_path"] == str((tmp_path / "b").resolve())
    assert ctx.kwargs["project_name"] == "proj"
    result = runner.invoke(server.main, ["--project-path", "../analyses", "--list-project-binaries"])
    assert result.exit_code == 0, result.output
    resolved = Path(ctx.kwargs["project_path"])
    assert resolved.is_absolute() and ".." not in resolved.parts


# @spec SRV-051
def test_a_project_data_folder_is_rejected_naming_the_gpr(cli, monkeypatch, tmp_path):
    _, runs, runner = cli
    started = []
    monkeypatch.setattr(server.pyghidra, "start", lambda *a, **k: started.append(True))
    result = runner.invoke(server.main, ["--project-path", str(tmp_path / "go-1.rep")])
    assert result.exit_code == 2
    assert "go-1.gpr" in result.output
    assert started == [] and runs == []


# @spec SRV-005
def test_missing_input_path_is_rejected_before_ghidra_starts(cli, monkeypatch, tmp_path):
    _, runs, runner = cli
    started = []
    monkeypatch.setattr(server.pyghidra, "start", lambda *a, **k: started.append(True))
    result = runner.invoke(server.main, [str(tmp_path / "missing")])
    assert result.exit_code == 2
    assert started == [] and runs == []


# @spec SRV-007, SRV-013
def test_startup_starts_the_jvm_then_imports_then_analyzes_then_serves(cli, monkeypatch, tmp_path):
    ctx, _, runner = cli
    events = ctx.calls  # the context's own calls interleave with the steps below
    monkeypatch.setattr(server.pyghidra, "start", lambda *a, **k: events.append(("jvm",)))
    monkeypatch.setattr(
        server, "GhidraContext", lambda **kw: events.append(("context",)) or ctx.configure(**kw)
    )
    monkeypatch.setattr(server.mcp, "run", lambda *a, **k: events.append(("serve",)))
    binary = tmp_path / "bin"
    binary.write_bytes(b"\0")
    result = runner.invoke(server.main, [str(binary)])
    assert result.exit_code == 0, result.output
    assert [e[0] for e in events] == [
        "jvm", "context", "import_binaries", "analyze_project", "serve", "close",
    ]


# @spec SRV-009
def test_list_project_binaries_prints_pathnames_and_exits_without_serving(cli):
    ctx, runs, runner = cli
    ctx.programs = {"/a-111111": None, "/b-222222": None}
    result = runner.invoke(server.main, ["--list-project-binaries"])
    assert result.exit_code == 0, result.output
    assert "- /a-111111" in result.output and "- /b-222222" in result.output
    assert runs == [] and ctx.calls[-1] == ("close",)
    ctx.programs = {}
    result = runner.invoke(server.main, ["--list-project-binaries"])
    assert "No binaries in project." in result.output


# @spec SRV-016
def test_context_is_closed_when_the_server_stops_abnormally(cli, monkeypatch):
    ctx, _, runner = cli

    def transport_dies(*args, **kwargs):
        raise RuntimeError("transport died")

    monkeypatch.setattr(server.mcp, "run", transport_dies)
    result = runner.invoke(server.main, [])
    assert result.exit_code != 0
    assert ctx.calls[-1] == ("close",)


# @spec SRV-017
def test_log_output_goes_to_stderr():
    code = "import logging\nfrom ghidra_mcp import server\nlogging.getLogger('probe').info('probe-line')\n"
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    assert "probe-line" in result.stderr and "probe-line" not in result.stdout


# @spec SRV-019
@pytest.mark.anyio
async def test_the_lifespan_shares_the_one_ghidra_context(fake_ctx):
    async with server._lifespan(server.mcp) as shared:
        assert shared is fake_ctx
    fake_ctx.programs = {}
    async with Client(server.mcp) as client:
        await client.call_tool("import_binary", {"binary_path": "/x/one"})
        await client.call_tool("import_binary", {"binary_path": "/x/two"})
    assert [c[1] for c in fake_ctx.calls if c[0] == "import_binary_backgrounded"] == ["/x/one", "/x/two"]


# @spec SRV-020
@pytest.mark.anyio
@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("list_functions", {"binary_name": "x"}),
        ("rename_function", {"binary_name": "x", "name_or_address": "f", "new_name": "g"}),
    ],
)
async def test_program_tools_resolve_through_the_gate_before_delegating(fake_ctx, monkeypatch, tool, arguments):
    fake_ctx.get_program_info_error = RetryLater("'x' is queued for analysis")
    constructed = []
    monkeypatch.setattr(server, "GhidraTools", lambda *a, **k: constructed.append(a))
    result = await _call(tool, arguments)
    assert result.is_error and "[retry_later]" in _text(result)
    assert ("get_program_info", "x") in fake_ctx.calls
    assert constructed == []


# ── GUI mode (gui-host) ──────────────────────────────────────────────────────


@pytest.fixture
def gui_cli(monkeypatch):
    calls = {}
    started = []
    monkeypatch.setattr(server.gui, "check_port", lambda host, port: calls.setdefault("port", (host, port)))
    monkeypatch.setattr(server.gui, "ensure_project", lambda d, n: calls.setdefault("project", (d, n)))
    monkeypatch.setattr(server.gui, "launch", lambda **kw: calls.setdefault("launch", kw))
    monkeypatch.setattr(server.pyghidra, "start", lambda *a, **k: started.append(True))
    return calls, started, CliRunner()


# @spec SRV-045, GUI-001, GUI-006
def test_gui_mode_serves_over_streamable_http_and_returns_when_the_gui_exits(gui_cli, tmp_path):
    calls, started, runner = gui_cli
    result = runner.invoke(server.main, ["--gui", "--project-path", str(tmp_path / "p"), "--port", "8123"])
    assert result.exit_code == 0, result.output
    assert calls["port"] == ("127.0.0.1", 8123)
    launch = calls["launch"]
    assert (launch["host"], launch["port"]) == ("127.0.0.1", 8123)
    assert launch["project_name"] == "my_project" and started == []  # the GUI launcher starts the JVM


# @spec GUI-002
@pytest.mark.parametrize("extra", [["--transport", "stdio"], ["--analyze-only"], ["--list-project-binaries"],
                                   ["--delete-project-binary", "x"]])
def test_gui_mode_rejects_stdio_and_one_shots(gui_cli, extra):
    calls, started, runner = gui_cli
    result = runner.invoke(server.main, ["--gui", *extra])
    assert result.exit_code == 2
    assert "launch" not in calls and started == []


# @spec GUI-003
def test_gui_mode_fails_fast_when_the_port_is_taken(gui_cli, monkeypatch):
    calls, _, runner = gui_cli

    def taken(host, port):
        raise OSError("address already in use")

    monkeypatch.setattr(server.gui, "check_port", taken)
    result = runner.invoke(server.main, ["--gui"])
    assert result.exit_code == 1 and "address already in use" in result.stderr
    assert "launch" not in calls and "project" not in calls


# @spec GUI-004
def test_a_missing_project_is_created_headlessly_before_launch(monkeypatch, tmp_path):
    from ghidra_mcp import gui

    runs = []
    monkeypatch.setattr(gui.subprocess, "run", lambda cmd, **kw: runs.append(cmd))
    gui.ensure_project(str(tmp_path), "fresh")
    assert runs and runs[0][1:3] == ["-m", "ghidra_mcp"]
    assert ["--project-path", str(tmp_path), "--project-name", "fresh"] == runs[0][3:7]
    (tmp_path / "fresh.gpr").write_text("")
    runs.clear()
    gui.ensure_project(str(tmp_path), "fresh")
    assert runs == []


# @spec GUI-026
@pytest.mark.anyio
async def test_gui_only_tools_are_registered_only_on_request(fake_ctx):
    async with Client(server.mcp) as client:
        headless = {t.name for t in (await client.list_tools()).tools}
    assert not {"get_current_address", "get_current_function", "go_to"} & headless
    server.register_gui_tools()
    try:
        async with Client(server.mcp) as client:
            listed = {t.name for t in (await client.list_tools()).tools}
        assert {"get_current_address", "get_current_function", "go_to"} <= listed
    finally:
        for name in ("get_current_address", "get_current_function", "go_to"):
            server.mcp.remove_tool(name)


# @spec SRV-050, SRV-051
def test_gui_mode_uses_the_resolved_project_path_and_rejects_rep(gui_cli, tmp_path):
    calls, started, runner = gui_cli
    result = runner.invoke(server.main, ["--gui", "--project-path", str(tmp_path / "x" / ".." / "p.gpr")])
    assert result.exit_code == 0, result.output
    assert calls["project"] == (str(tmp_path.resolve()), "p")
    assert calls["launch"]["project_dir"] == str(tmp_path.resolve())
    calls.clear()
    result = runner.invoke(server.main, ["--gui", "--project-path", str(tmp_path / "p.rep")])
    assert result.exit_code == 2 and "p.gpr" in result.output and "launch" not in calls
