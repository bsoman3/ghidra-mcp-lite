"""End-to-end checks against a real Ghidra install (set GHIDRA_INSTALL_DIR).

These build tiny C binaries with the system compiler, so they also need `cc`.
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from mcp import Client

pytestmark = pytest.mark.integration

SOURCE = "int add(int a, int b) { return a + b; }\nint main(void) { return add(1, 2); }\n"
SOURCE_2 = "int mul(int a, int b) { return a * b; }\nint main(void) { return mul(2, 3); }\n"


def _compile(work: Path, name: str, source: str) -> Path:
    src = work / f"{name}.c"
    src.write_text(source)
    exe = work / name
    subprocess.run(["cc", "-O0", "-o", str(exe), str(src)], check=True)
    return exe


@pytest.fixture(scope="module")
def binaries(tmp_path_factory):
    if shutil.which("cc") is None:
        pytest.skip("needs a C compiler (cc)")
    work = tmp_path_factory.mktemp("bin")
    return _compile(work, "hello", SOURCE), _compile(work, "hello2", SOURCE_2)


def _text(result):
    return "".join(getattr(block, "text", "") for block in result.content)


# @spec SRV-035, SRV-033
def test_analyze_only_analyzes_and_reports_ready(binaries, tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "ghidra_mcp", "--analyze-only",
         "--project-path", str(tmp_path / "proj"), str(binaries[0])],
        capture_output=True, text=True, timeout=900, env=dict(os.environ),
    )
    assert result.returncode == 0, result.stderr[-4000:]
    assert re.search(r"hello-[0-9a-f]{6}: ready", result.stdout), result.stdout


@pytest.fixture(scope="module")
def live_server(binaries, tmp_path_factory):
    """Start the JVM in-process, analyze one binary, and attach a real context to the server."""
    import pyghidra

    pyghidra.start()
    from ghidra_mcp import server
    from ghidra_mcp.context import AnalysisOptions, GhidraContext

    ctx = GhidraContext(project_name="itest", project_path=tmp_path_factory.mktemp("proj"))
    ctx.import_binaries([binaries[0]], AnalysisOptions(no_symbols=True))
    ctx.analyze_project(wait=True)
    server.mcp._ghidra_context = ctx
    yield server, ctx
    ctx.close()


def _name_of(ctx, stem):
    (name,) = [e.name for e in ctx.list_entries() if e.name.startswith(f"{stem}-")]
    return name


# @spec SRV-038, QRY-001
@pytest.mark.anyio
async def test_tool_calls_run_on_sdk_worker_threads_against_ghidra(live_server):
    server, ctx = live_server
    async with Client(server.mcp) as client:
        result = await client.call_tool("list_functions", {"binary_name": _name_of(ctx, "hello")})
    assert not result.is_error, result.content
    names = [f["name"] for f in result.structured_content["functions"]]
    assert any("add" in name for name in names), names


# @spec SRV-025
@pytest.mark.anyio
async def test_unknown_function_is_fix_input_end_to_end(live_server):
    server, ctx = live_server
    async with Client(server.mcp) as client:
        result = await client.call_tool(
            "decompile_function",
            {"binary_name": _name_of(ctx, "hello"), "name_or_address": "no_such_function"},
        )
    assert result.is_error
    assert "[fix_input]" in _text(result)


def _clib_gdt() -> Path:
    root = Path(os.environ["GHIDRA_INSTALL_DIR"])
    return root / "Ghidra/Features/Base/data/typeinfo/generic/generic_clib_64.gdt"


# @spec SRV-023, LIFE-039, LIFE-043, ACFG-003, ACFG-010, ACFG-016, ACFG-020
@pytest.mark.anyio
async def test_imported_binary_is_usable_by_waiting_and_carries_its_options(live_server, binaries):
    server, ctx = live_server
    gdt = _clib_gdt()
    async with Client(server.mcp) as client:
        imported = await client.call_tool("import_binary", {
            "binary_path": str(binaries[1]), "gdts": [str(gdt)], "no_symbols": True,
            "analyzer_options": {"Decompiler Parameter ID": False},
        })
        assert not imported.is_error, _text(imported)
        name = _name_of(ctx, "hello2")
        # The default 45 s wait covers this small binary's import and analysis.
        functions = await client.call_tool("list_functions", {"binary_name": name})
        assert not functions.is_error, _text(functions)
        listing = await client.call_tool("list_project_binaries", {})
    row = next(p for p in listing.structured_content["programs"] if p["name"] == name)
    assert row["status"] == "ready", row
    assert row["warnings"] == [], row["warnings"]
    entry = next(e for e in ctx.list_entries() if e.name == name)
    stored = ctx._stored_options(entry.program)
    assert stored.gdts == (gdt,) and stored.analyzer_options == {"Decompiler Parameter ID": False}


# @spec SRV-044, LIFE-044, ACFG-015
@pytest.mark.anyio
async def test_reanalysis_with_an_unknown_option_reports_a_warning(live_server):
    server, ctx = live_server
    name = _name_of(ctx, "hello")
    async with Client(server.mcp) as client:
        result = await client.call_tool("reanalyze_binary", {
            "binary_name": name, "no_symbols": True, "analyzer_options": {"No Such Analyzer": True},
        })
        assert not result.is_error, _text(result)
        functions = await client.call_tool("list_functions", {"binary_name": name})  # waits
        assert not functions.is_error, _text(functions)
        listing = await client.call_tool("list_project_binaries", {})
    row = next(p for p in listing.structured_content["programs"] if p["name"] == name)
    assert row["status"] == "ready"
    assert any("No Such Analyzer" in w for w in row["warnings"]), row["warnings"]


# @spec LIFE-001
def test_project_is_created_then_reopened_with_its_binaries(live_server, binaries, tmp_path):
    from ghidra_mcp.context import AnalysisOptions, GhidraContext

    root = tmp_path / "new" / "nested"
    first = GhidraContext(project_name="reopen", project_path=root)
    first.import_binaries([binaries[0]], AnalysisOptions(no_symbols=True))
    names = first.list_binaries()
    first.close()
    assert (root / "reopen.gpr").exists() and len(names) == 1
    second = GhidraContext(project_name="reopen", project_path=root)
    try:
        assert second.list_binaries() == names
    finally:
        second.close()


# @spec QRY-016, QRY-018, QRY-019, QRY-021, QRY-029, QRY-037, RES-003, RES-020
@pytest.mark.anyio
async def test_read_tools_against_ghidra(live_server):
    server, ctx = live_server
    name = _name_of(ctx, "hello")
    async with Client(server.mcp) as client:
        async def call(tool, **arguments):
            result = await client.call_tool(tool, {"binary_name": name, **arguments})
            assert not result.is_error, (tool, _text(result))
            return result.structured_content

        functions = (await call("list_functions", query="add"))["functions"]
        add = next(f for f in functions if f["name"].lstrip("_") == "add")
        decompiled = await call("decompile_function", name_or_address=add["address"])
        assert "return" in decompiled["code"] and decompiled["resolution"] is None
        disassembly = await call("disassemble_function", name_or_address=add["address"])
        assert disassembly["instructions"] and not disassembly["partial"]
        inside = hex(int(add["address"], 16) + 4)
        loose = await call("disassemble_function", name_or_address=inside)
        assert "address inside the function" in loose["resolution"]
        xrefs = await call("list_cross_references", name_or_address=add["address"])
        # main calls add (Ghidra names a Mach-O main "entry")
        assert any(r["type"].endswith("CALL") and r["function_name"] for r in xrefs["cross_references"])
        raw = await call("read_bytes", address=add["address"], size=4)
        assert raw["size"] == 4 and not raw["partial"]
        await call("search_strings", query="a")
        await call("list_data_items")


SOURCE_3 = "int sub(int a, int b) { return a - b; }\nint main(void) { return sub(5, 3); }\n"


# @spec WB-001, WB-003, WB-006, WB-009, WB-016, WB-017, WB-018, WB-026, WB-027
@pytest.mark.anyio
async def test_write_tools_against_ghidra(live_server, binaries, tmp_path):
    from ghidra_mcp.context import AnalysisOptions

    server, ctx = live_server
    ctx.import_binaries([_compile(tmp_path, "hello3", SOURCE_3)], AnalysisOptions(no_symbols=True))
    ctx.analyze_project(wait=True)
    name = _name_of(ctx, "hello3")
    async with Client(server.mcp) as client:
        async def call(tool, **arguments):
            result = await client.call_tool(tool, {"binary_name": name, **arguments})
            assert not result.is_error, (tool, _text(result))
            return result.structured_content if result.structured_content else _text(result)

        functions = (await call("list_functions", query="sub"))["functions"]
        sub = next(f for f in functions if f["name"].lstrip("_") == "sub")
        entry = sub["address"]

        await call("set_function_prototype", name_or_address=entry, prototype="int sub(int a, int b)")
        assert "int a" in (await call("decompile_function", name_or_address=entry))["signature"]

        await call("rename_variable", function_name_or_address=entry, old_var_name="a", new_var_name="lhs")
        await call("set_local_variable_type", function_name_or_address=entry, var_name="b", new_type="long")
        signature = (await call("decompile_function", name_or_address=entry))["signature"]
        assert "lhs" in signature and "long b" in signature, signature

        await call("rename_function_by_address", address=entry, new_name="subtract")
        assert (await call("list_functions", query="subtract"))["functions"]

        await call("set_disassembly_comment", address=entry, comment="entry of subtract")
        first = (await call("disassemble_function", name_or_address=entry))["instructions"][0]
        assert first["comment"] == "entry of subtract"
        await call("set_disassembly_comment", address=entry, comment="")
        first = (await call("disassemble_function", name_or_address=entry))["instructions"][0]
        assert first["comment"] is None
        await call("set_decompiler_comment", address=entry, comment="computes a - b")


def _ensure_imported(ctx, path):
    from ghidra_mcp.context import AnalysisOptions

    ctx.import_binaries([path], AnalysisOptions(no_symbols=True))
    ctx.analyze_project(wait=True)


# @spec QRY-039, QRY-040, QRY-042, QRY-044, QRY-045, QRY-046, QRY-048, QRY-050, QRY-052, QRY-009
@pytest.mark.anyio
async def test_analysis_tools_against_ghidra(live_server, binaries):
    server, ctx = live_server
    _ensure_imported(ctx, binaries[1])
    hello, hello2 = _name_of(ctx, "hello"), _name_of(ctx, "hello2")
    async with Client(server.mcp) as client:
        async def call(tool, **arguments):
            result = await client.call_tool(tool, arguments)
            assert not result.is_error, (tool, _text(result))
            return result.structured_content

        add = next(f for f in (await call("list_functions", binary_name=hello, query="add"))["functions"]
                   if f["name"].lstrip("_") == "add")
        callers = await call("get_function_callers", binary_name=hello, name_or_address=add["address"])
        caller = next(c for c in callers["callers"] if c["name"])
        assert caller["call_sites"]
        callees = await call("get_function_callees", binary_name=hello, name_or_address=caller["address"])
        assert any(c["address"] == add["address"] for c in callees["callees"])

        mul = next(f for f in (await call("list_functions", binary_name=hello2, query="mul"))["functions"]
                   if f["name"].lstrip("_") == "mul")
        same = await call("diff_functions", binary_name=hello, function_a=add["address"], function_b=add["address"])
        assert same["identical"] and same["similarity"] == 1.0
        diff = await call("diff_functions", binary_name=hello, function_a=add["address"],
                          function_b=mul["address"], other_binary_name=hello2)
        assert not diff["identical"] and 0 < diff["similarity"] < 1 and diff["diff"].startswith("---")
        asm = await call("diff_functions", binary_name=hello, function_a=add["address"],
                         function_b=mul["address"], other_binary_name=hello2, view="disassembly")
        assert asm["view"] == "disassembly"

        similar = await call("find_similar_functions_fuzzy", binary_name=hello2, name_or_address=mul["address"],
                             target_binary_name=hello, min_similarity=0.3)
        assert any(c["address"] == add["address"] for c in similar["candidates"]), similar

        raw = await call("get_function_pcode", binary_name=hello, name_or_address=add["address"])
        assert raw["ops"] and raw["total_ops"] >= len(raw["ops"])
        high = await call("get_function_pcode", binary_name=hello, name_or_address=add["address"], form="high")
        assert any(op["mnemonic"] in ("INT_ADD", "RETURN") for op in high["ops"]), high["ops"][:5]

        flow = await call("analyze_dataflow", binary_name=hello, function_name_or_address=add["address"],
                          variable="param_1", direction="forward")
        assert flow["ops"] and "param_1" in flow["variables"], flow

        # list_exports lists Ghidra's external entry points: exports and the program entry.
        exports = await call("list_exports", binary_name=hello, limit=50)
        assert any(e["name"] in ("entry", "_start") for e in exports["exports"]), exports
