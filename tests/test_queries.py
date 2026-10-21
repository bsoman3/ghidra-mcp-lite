"""Queries: listings, searches, code views, references, call graphs, disclosure, partial results."""

import pytest
from mcp import Client

from ghidra_mcp import server, tools as tools_module
from ghidra_mcp.errors import Stop
from ghidra_mcp.models import CallGraphDirection, CallGraphDisplayType, CrossReferenceInfo
from tests.program_fakes import (
    Addr,
    Data,
    DecompileResult,
    FakeDecompiler,
    FakeProgram,
    Function,
    Instruction,
    MemoryBlock,
    Reference,
    Symbol,
    install_modules,
    tools_for,
)
from tests.fakes import FakeContext

EXT_PUTS = Function("puts", Addr(0x20, "EXTERNAL"), namespace="libc.so.6", external=True)
EOL = "EOL"

QUERY_TOOLS = [
    "list_functions", "list_segments", "list_data_items", "list_classes", "list_namespaces",
    "get_function_by_address", "decompile_function", "disassemble_function", "search_symbols",
    "list_imports", "list_exports", "list_cross_references", "get_xrefs_from", "search_strings",
    "read_bytes", "gen_callgraph",
]


def make_program():
    return FakeProgram(
        functions=[
            Function("main", 0x401000, size=0x10),
            Function("helper", 0x401100, size=0x20),
            Function("puts", 0x401200, thunk_of=EXT_PUTS),
            EXT_PUTS,
            Function("method", 0x401300, namespace="Foo"),
        ],
        symbols=[
            Symbol("Foo", 0x0, symbol_type="Class"),
            Symbol("std", 0x0, symbol_type="Namespace"),
            Symbol("libc.so.6", 0x0, symbol_type="Library"),
            Symbol("_start", 0x401400, entry_point=True),
            Symbol("_init", 0x401500, entry_point=True),
            Symbol("g_count", 0x404000),
        ],
        memory=[
            MemoryBlock(".text", 0x401000, 0x1000, perms="rx"),
            MemoryBlock(".data", 0x404000, 0x2000, perms="rw"),
            MemoryBlock(".bss", 0x406000, 0x100, perms="rw", initialized=False),
            MemoryBlock(".none", 0x407000, 0x100, perms=""),
        ],
        defined_data=[
            Data(0x404000, label="g_count", value=5, type_name="int"),
            Data(0x404010, label=None, value=None, type_name="undefined4"),
            Data(0x404020, label="g_bad", value=RuntimeError("corrupt value")),
            Data(0x404030, label="g_last", value="x", type_name="char"),
        ],
        instructions=[
            Instruction(0x401000, b"\x55", "PUSH", ("RBP",)),
            Instruction(0x401001, b"\x48\x89\xe5", "MOV", ("RBP", "RSP")),
            Instruction(0x401004, RuntimeError("no bytes"), "RET", RuntimeError("no operands")),
            Instruction(0x401100, b"\xc3", "RET"),
        ],
        comments={
            (EOL, Addr(0x401001)): "set up frame",
            (EOL, Addr(0x401004)): RuntimeError("comment unreadable"),
        },
        references=[
            Reference(0x401005, 0x401100),
            Reference(0x401105, 0x404000, "READ"),
            Reference(0x401106, 0x404000, "WRITE"),
        ],
        strings=[
            Data(0x405000, value="Hello World"),
            Data(0x405010, value="hello again"),
            Data(0x405020, value=RuntimeError("bad encoding")),
            Data(0x405030, value="other"),
        ],
    )


@pytest.fixture
def program():
    return make_program()


@pytest.fixture
def decompiler():
    return FakeDecompiler()


@pytest.fixture
def ghidra_stubs(monkeypatch, program):
    """Ghidra classes the query tools import, stubbed without a JVM."""
    iterator_calls = []

    def for_program(prog):
        iterator_calls.append(prog)
        return iter(prog.strings)

    install_modules(monkeypatch, {
        "ghidra.util.task": {"ConsoleTaskMonitor": lambda: "monitor", "TaskMonitor": object},
        "ghidra.program.model.listing": {"CommentType": type("CommentType", (), {"EOL": EOL})},
        "ghidra.program.util": {"DefinedStringIterator": type("DSI", (), {"forProgram": staticmethod(for_program)})},
    })

    class FakeJByte:
        def __getitem__(self, size):
            return [0] * size

    monkeypatch.setattr(tools_module, "JByte", FakeJByte())
    return iterator_calls


@pytest.fixture
def tools(program, decompiler, ghidra_stubs):
    return tools_for(program, decompiler)


# ── Listings ─────────────────────────────────────────────────────────────────


# @spec QRY-001
def test_function_listing_excludes_externals_and_thunks(tools):
    functions, total = tools.list_functions()
    assert [(f.name, f.address) for f in functions] == [
        ("main", "00401000"), ("helper", "00401100"), ("Foo::method", "00401300"),
    ]
    assert functions[0].signature == "undefined main(void)" and total == 3


# @spec QRY-002
def test_function_listing_filters_by_qualified_name(tools):
    functions, total = tools.list_functions(query="FOO::")
    assert [f.name for f in functions] == ["Foo::method"] and total == 1


# @spec QRY-003
def test_function_listing_pages_and_reports_the_total(tools):
    functions, total = tools.list_functions(offset=1, limit=1)
    assert [f.name for f in functions] == ["helper"] and total == 3


def _many_functions(count):
    return FakeProgram(functions=[Function(f"f{i:04d}", 0x401000 + 0x10 * i, size=0x10) for i in range(count)])


# @spec QRY-003
def test_function_listing_pages_100_by_default_and_is_empty_past_the_end():
    tools = tools_for(_many_functions(150))
    functions, total = tools.list_functions()
    assert len(functions) == 100 and total == 150
    functions, total = tools.list_functions(offset=150)
    assert functions == [] and total == 150


# @spec QRY-053
def test_function_listing_accepts_a_page_of_500():
    functions, total = tools_for(_many_functions(600)).list_functions(limit=500)
    assert len(functions) == 500 and total == 600


# @spec QRY-053
@pytest.mark.parametrize("limit", [0, -1, 501, 6000])
def test_a_function_page_outside_1_to_500_is_rejected_pointing_to_offset(tools, limit):
    with pytest.raises(ValueError, match="offset"):
        tools.list_functions(limit=limit)


# @spec QRY-053
@pytest.mark.anyio
async def test_an_oversized_function_page_reaches_the_model_as_fix_input(monkeypatch, program):
    ctx = FakeContext()
    ctx.programs = {"prog": tools_for(program).program_info}
    monkeypatch.setattr(server.mcp, "_ghidra_context", ctx, raising=False)
    async with Client(server.mcp) as client:
        result = await client.call_tool("list_functions", {"binary_name": "prog", "limit": 6000})
    text = "".join(getattr(block, "text", "") for block in result.content)
    assert result.is_error and "[fix_input]" in text and "offset" in text, text


# @spec QRY-004
def test_segments(tools):
    segments = {s.name: s for s in tools.list_segments()}
    text = segments[".text"]
    assert (text.start, text.end, text.size, text.permissions, text.initialized) == (
        "00401000", "00401fff", 0x1000, "rx", True,
    )
    assert segments[".none"].permissions == "-" and not segments[".bss"].initialized


# @spec QRY-005
def test_data_items_with_label_fallback_and_total(tools):
    result = tools.list_data_items(offset=0, limit=2)
    assert [(i.label, i.address, i.type, i.value) for i in result.items] == [
        ("g_count", "00404000", "int", "5"),
        ("00404010", "00404010", "undefined4", ""),
    ]
    assert result.total == 3  # the unreadable item is reported as a failure, not counted


# @spec QRY-031
def test_an_unreadable_data_item_is_listed_as_a_failure(tools):
    result = tools.list_data_items()
    assert result.partial
    assert [(f.address, f.error) for f in result.failures] == [("00404020", "corrupt value")]
    assert [i.label for i in result.items] == ["g_count", "00404010", "g_last"]


# @spec QRY-006
def test_classes(tools):
    classes, total = tools.list_classes()
    assert [(c.name, c.type, c.parent) for c in classes] == [("Foo", "Class", "Global")] and total == 1


# @spec QRY-007
def test_namespaces_classes_and_libraries(tools):
    namespaces, total = tools.list_namespaces()
    assert {(n.name, n.type) for n in namespaces} == {
        ("Foo", "Class"), ("std", "Namespace"), ("libc.so.6", "Library"),
    }
    assert total == 3


# @spec QRY-008
def test_imports_are_external_symbols_with_their_library(tools):
    imports = tools.list_imports(query="^PUT")
    assert [(i.name, i.library) for i in imports] == [("puts", "libc.so.6")]


# @spec QRY-009
def test_exports_are_external_entry_points(tools):
    exports = tools.list_exports()
    assert [(e.name, e.address) for e in exports] == [("_start", "00401400"), ("_init", "00401500")]
    assert [e.name for e in tools.list_exports(query="star", limit=5)] == ["_start"]
    assert [e.name for e in tools.list_exports(offset=1)] == ["_init"]


# ── Searches ─────────────────────────────────────────────────────────────────


# @spec QRY-010
def test_string_search_is_case_insensitive_with_a_total_beyond_the_limit(tools):
    result = tools.search_strings("HELLO", limit=1)
    assert [(s.value, s.address) for s in result.strings] == [("Hello World", "00405000")]
    assert result.total == 2


# @spec QRY-011
def test_string_search_uses_defined_string_iterator(tools, ghidra_stubs, program):
    tools.search_strings("o")
    assert ghidra_stubs == [program]


# @spec QRY-032
def test_an_unreadable_string_is_listed_as_a_failure(tools):
    result = tools.search_strings("o")
    assert result.partial
    assert [(f.address, f.error) for f in result.failures] == [("00405020", "bad encoding")]


# @spec QRY-012
def test_an_empty_symbol_query_is_rejected(tools):
    with pytest.raises(ValueError):
        tools.search_symbols_by_name("")


# @spec QRY-013
def test_symbol_search_fields_reference_counts_and_paging(tools):
    results = tools.search_symbols_by_name("g_count")
    (only,) = results
    assert (only.name, only.address, only.type, only.namespace, only.source, only.external, only.refcount) == (
        "g_count", "00404000", "Label", "Global", "ANALYSIS", False, 2,
    )
    assert len(tools.search_symbols_by_name("_", offset=0, limit=1)) == 1


# ── Code views ───────────────────────────────────────────────────────────────


# @spec QRY-014
def test_function_by_address_at_or_containing(tools):
    assert tools.get_function_by_address("0x401100").name == "helper"
    info = tools.get_function_by_address("401105")
    assert (info.name, info.address, info.signature, info.external) == (
        "helper", "00401100", "undefined helper(void)", False,
    )


# @spec QRY-015
def test_no_function_at_the_address_is_value_error(tools):
    with pytest.raises(ValueError):
        tools.get_function_by_address("0x404000")


# @spec QRY-016, QRY-038
def test_decompilation_returns_code_signature_and_full_label_within_120_seconds(program, ghidra_stubs):
    long_name = "a_function_name_that_is_much_longer_than_fifty_characters_in_total"
    program.functions.append(Function(long_name, 0x401600))
    decompiler = FakeDecompiler()
    result = tools_for(program, decompiler).decompile_function_by_name_or_addr(long_name)
    assert result.code == "int main(void) { return 0; }" and result.signature == "int main(void)"
    assert result.name == f"{long_name}-00401600"
    assert decompiler.calls == [(long_name, 120)]
    assert result.resolution is None


# @spec QRY-017
def test_a_decompiler_failure_is_stop_with_its_message(program, ghidra_stubs):
    decompiler = FakeDecompiler(DecompileResult(error="Decompiler timed out"))
    with pytest.raises(Stop, match="Decompiler timed out"):
        tools_for(program, decompiler).decompile_function_by_name_or_addr("main")


# @spec QRY-035
def test_a_decompiler_result_without_function_or_error_is_stop(program, ghidra_stubs):
    decompiler = FakeDecompiler(DecompileResult(code=None, error=""))
    with pytest.raises(Stop, match="no result"):
        tools_for(program, decompiler).decompile_function_by_name_or_addr("main")


# @spec QRY-018, QRY-037
def test_disassembly_lists_instructions_with_bytes_operands_and_comments(tools):
    result = tools.disassemble_function("main")
    assert (result.function_name, result.address) == ("main", "00401000")
    first, second = result.instructions[:2]
    assert (first.address, first.bytes, first.mnemonic, first.operands, first.comment) == (
        "00401000", "55", "PUSH", "RBP", None,
    )
    assert (second.bytes, second.operands, second.comment) == ("4889e5", "RBP, RSP", "set up frame")
    assert len(result.instructions) == 3


# @spec QRY-030
def test_disassembly_marks_unreadable_fields(tools):
    result = tools.disassemble_function("main")
    assert result.partial
    last = result.instructions[-1]
    assert last.mnemonic == "RET"
    assert [e.split(":")[0] for e in last.errors] == ["bytes", "operands", "comment"]
    assert all(not line.errors for line in result.instructions[:2])


# @spec QRY-019
def test_read_bytes(tools):
    result = tools.read_bytes("0x404000", 4)
    assert (result.address, result.size, result.data, result.requested_size, result.partial) == (
        "00404000", 4, "00010203", 4, False,
    )


# @spec QRY-020
@pytest.mark.parametrize(("address", "size"), [("0x404000", 0), ("0x404000", 8193), ("0x500000", 4)])
def test_read_bytes_rejects_bad_sizes_and_unmapped_addresses(tools, address, size):
    with pytest.raises(ValueError):
        tools.read_bytes(address, size)


# @spec QRY-033
def test_a_short_read_is_marked_partial_with_both_sizes(tools):
    result = tools.read_bytes("0x405ffe", 8)  # two bytes before the end of .data
    assert (result.size, result.requested_size, result.partial) == (2, 8, True)


# @spec QRY-034
def test_reading_uninitialized_memory_is_value_error(tools):
    with pytest.raises(ValueError, match="uninitialized"):
        tools.read_bytes("0x406000", 4)


# ── References ───────────────────────────────────────────────────────────────


# @spec QRY-021
def test_references_to_a_target(tools):
    result = tools.list_cross_references("helper")
    assert [(r.function_name, r.from_address, r.to_address, r.type) for r in result.cross_references] == [
        ("main", "00401005", "00401100", "UNCONDITIONAL_CALL"),
    ]
    assert result.resolution is None


# @spec QRY-022
def test_references_from_an_address(tools):
    refs = tools.get_xrefs_from("0x401105")
    assert [(r.from_address, r.to_address, r.type) for r in refs] == [("00401105", "00404000", "READ")]


# @spec QRY-023
def test_function_name_is_documented_per_direction():
    description = CrossReferenceInfo.model_fields["function_name"].description
    assert "list_cross_references" in description and "get_xrefs_from" in description
    assert "target" in description and "source" in description
    assert "target" in server.get_xrefs_from.__doc__


# ── Call graphs ──────────────────────────────────────────────────────────────


@pytest.fixture
def callgraph(monkeypatch):
    calls = []

    def gen_callgraph(func, **kwargs):
        calls.append((str(func), kwargs))
        graphs = [
            ("mermaid_url", "https://mermaid.live/view#abc\nsecond line"),
            ("svg", "<svg/>"),
            ("flow", "flowchart TD\n a-->b"),
            ("mind", "mindmap\n root"),
        ]
        return kwargs["name"], kwargs["direction"], None, graphs

    install_modules(monkeypatch, {"ghidrecomp.callgraph": {"gen_callgraph": gen_callgraph}})
    return calls


# @spec QRY-024
def test_call_graph_in_the_requested_direction_and_display_type(tools, callgraph):
    result = tools.gen_callgraph("main", CallGraphDirection.CALLED, CallGraphDisplayType.FLOW)
    assert result.function_name == "main" and result.direction is CallGraphDirection.CALLED
    assert result.graph.startswith("flowchart") and result.mermaid_url == "https://mermaid.live/view#abc"
    assert callgraph[0][1]["direction"] == "called"


# @spec QRY-026
def test_a_missing_display_type_is_value_error(tools, monkeypatch):
    install_modules(monkeypatch, {"ghidrecomp.callgraph": {
        "gen_callgraph": lambda func, **kw: (kw["name"], kw["direction"], None, [("flow", "x")]),
    }})
    with pytest.raises(ValueError, match="mind"):
        tools.gen_callgraph("main", cg_display_type=CallGraphDisplayType.MIND)


# @spec QRY-036
def test_entries_that_are_not_display_types_are_ignored(tools, callgraph):
    result = tools.gen_callgraph("main", cg_display_type=CallGraphDisplayType.MIND)
    assert result.graph.startswith("mindmap")


# ── Disclosure ───────────────────────────────────────────────────────────────


# @spec QRY-029
def test_loose_matches_are_disclosed_in_the_result(tools, callgraph):
    assert tools.decompile_function_by_name_or_addr("help").resolution == (
        "'help' resolved to helper @ 00401100 (partial name match)"
    )
    assert "address inside the function" in tools.disassemble_function("0x401004").resolution
    assert "partial name match" in tools.gen_callgraph("elpe").resolution
    assert tools.list_cross_references("g_cou").resolution == (
        "'g_cou' resolved to g_count @ 00404000 (partial name match)"
    )


# ── Query contract ───────────────────────────────────────────────────────────


# @spec QRY-027
def test_queries_never_modify_the_program(tools, program, callgraph):
    tools.list_functions()
    tools.list_segments()
    tools.list_data_items()
    tools.list_classes()
    tools.list_namespaces()
    tools.get_function_by_address("0x401000")
    tools.decompile_function_by_name_or_addr("main")
    tools.disassemble_function("main")
    tools.search_symbols_by_name("main")
    tools.list_imports()
    tools.list_exports()
    tools.list_cross_references("helper")
    tools.get_xrefs_from("0x401005")
    tools.search_strings("o")
    tools.read_bytes("0x404000", 4)
    tools.gen_callgraph("main")
    assert program.transactions == [] and tools.project.saved == 0


# @spec QRY-028
@pytest.mark.anyio
async def test_every_query_tool_returns_a_typed_model(monkeypatch):
    monkeypatch.setattr(server.mcp, "_ghidra_context", FakeContext(), raising=False)
    async with Client(server.mcp) as client:
        listed = {t.name: t for t in (await client.list_tools()).tools}
    for name in QUERY_TOOLS:
        assert listed[name].output_schema, name
