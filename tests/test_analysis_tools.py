"""Queries: call relations, function comparison, fuzzy similarity, p-code, and data flow."""

import types
from collections import Counter

import pytest
from mcp import Client

from ghidra_mcp import server
from ghidra_mcp.context import AnalysisOptions, LoadedProgram
from ghidra_mcp.tools import (
    GhidraTools,
    diff_texts,
    mnemonic_grams,
    multiset_jaccard,
    normalize_listing,
    rank_similar,
)
from tests.fakes import FakeContext, HarnessContext, settled, wait_until
from tests.program_fakes import (
    Addr,
    DecompileResult,
    FakeDecompiler,
    FakeProgram,
    Function,
    Instruction,
    MemoryBlock,
    Reference,
    install_modules,
    tools_for,
)

EXT_PUTS = Function("puts", Addr(0x20, "EXTERNAL"), namespace="libc.so.6", external=True)


class PcodeOp:
    def __init__(self, seq, mnemonic, text):
        self.seq, self.mnemonic, self.text = seq, mnemonic, text

    def getSeqnum(self):  # noqa: N802
        return types.SimpleNamespace(getTime=lambda: self.seq, getTarget=lambda: None)

    def getMnemonic(self):  # noqa: N802
        return self.mnemonic

    def __str__(self):
        return self.text


class PcodeInstruction(Instruction):
    def __init__(self, address, mnemonic, ops):
        super().__init__(address, mnemonic=mnemonic)
        self.ops = ops

    def getPcode(self):  # noqa: N802
        return self.ops


@pytest.fixture
def program():
    helper = Function("helper", 0x401100, size=0x20)
    return FakeProgram(
        functions=[
            Function("main", 0x401000, size=0x20),
            helper,
            Function("helper_thunk", 0x401200, size=0x8, thunk_of=helper),
            Function("caller2", 0x401300, size=0x20),
            Function("puts", 0x401400, size=0x8, thunk_of=EXT_PUTS),
            EXT_PUTS,
            Function("twin_a", 0x402000, size=0x20),
            Function("twin_b", 0x402100, size=0x20),
            Function("other", 0x402200, size=0x20),
        ],
        memory=[MemoryBlock(".text", 0x400000, 0x10000, perms="rx")],
        instructions=[
            Instruction(0x401000, mnemonic="CALL", flow="UNCONDITIONAL_CALL"),
            Instruction(0x401004, mnemonic="CALL", flow="UNCONDITIONAL_CALL"),
            Instruction(0x401008, mnemonic="CALL", flow="COMPUTED_CALL"),  # indirect, unresolved
            Instruction(0x40100C, mnemonic="CALL", flow="UNCONDITIONAL_CALL"),
            Instruction(0x401010, mnemonic="RET", flow="TERMINATOR"),
            *[Instruction(0x402000 + 4 * i, mnemonic=m) for i, m in enumerate(["PUSH", "MOV", "ADD", "MOV", "POP", "RET"])],
            *[Instruction(0x402100 + 4 * i, mnemonic=m) for i, m in enumerate(["PUSH", "MOV", "ADD", "MOV", "POP", "RET"])],
            *[Instruction(0x402200 + 4 * i, mnemonic=m) for i, m in enumerate(["NOP", "NOP", "NOP", "NOP", "NOP", "NOP"])],
        ],
        references=[
            Reference(0x401000, 0x401100),  # main → helper
            Reference(0x401004, 0x401400),  # main → puts (thunk)
            Reference(0x40100C, 0x401100),  # main → helper again
            Reference(0x401305, 0x401200),  # caller2 → helper through its thunk
            Reference(0x405000, 0x401100),  # a call from outside any function
            Reference(0x401106, 0x401100, "READ"),  # not a call
        ],
    )


@pytest.fixture
def tools(program):
    return tools_for(program, FakeDecompiler())


# ── Call relations ───────────────────────────────────────────────────────────


# @spec QRY-039
def test_callers_include_calls_through_thunks_grouped_by_caller(tools):
    result = tools.get_function_callers("helper")
    callers = {(c.name, c.address): c.call_sites for c in result.callers}
    assert callers == {
        ("main", "00401000"): ["00401000", "0040100c"],
        ("caller2", "00401300"): ["00401305"],
        (None, None): ["00405000"],
    }
    assert (result.function, result.address) == ("helper", "00401100")


# @spec QRY-040, QRY-041
def test_callees_grouped_by_target_with_thunk_targets_and_indirect_calls(tools):
    result = tools.get_function_callees("main")
    callees = {c.name: (c.address, c.call_sites, c.thunk_of) for c in result.callees}
    assert callees == {
        "helper": ("00401100", ["00401000", "0040100c"], None),
        "puts": ("00401400", ["00401004"], "libc.so.6::puts"),
    }
    assert result.indirect_call_sites == ["00401008"]


# ── Comparison helpers ───────────────────────────────────────────────────────


# @spec QRY-043
def test_normalization_masks_address_derived_names_literals_and_own_names():
    text = "undefined FUN_00401a20(void) { DAT_00404010 = 0x401000; goto LAB_00401a30; return my_add(3); }"
    assert normalize_listing(text, own_names=["my_add"]) == (
        "undefined FUN_*(void) { DAT_* = 0x*; goto LAB_*; return <self>(3); }"
    )


# @spec QRY-044
def test_diff_reports_unified_diff_similarity_and_identity():
    diff, ratio, identical = diff_texts("a\nb\nc", "a\nB\nc", "left", "right", context_lines=1)
    assert diff.splitlines()[:2] == ["--- left", "+++ right"]
    assert "-b" in diff and "+B" in diff and not identical
    assert 0 < ratio < 1
    assert diff_texts("x\ny", "x\ny", "l", "r", 3) == ("", 1.0, True)


# @spec QRY-045
def test_similarity_is_multiset_jaccard_of_mnemonic_trigrams():
    a = mnemonic_grams(["PUSH", "MOV", "ADD", "RET"])
    assert a == Counter({("PUSH", "MOV", "ADD"): 1, ("MOV", "ADD", "RET"): 1})
    assert mnemonic_grams(["RET"]) == Counter({("RET",): 1})
    b = mnemonic_grams(["PUSH", "MOV", "SUB", "RET"])
    assert multiset_jaccard(a, a) == 1.0 and multiset_jaccard(a, b) == 0.0
    assert multiset_jaccard(Counter({"x": 2}), Counter({"x": 1})) == 0.5


# @spec QRY-046
def test_ranking_filters_by_size_and_score_then_orders():
    q = Counter({("A", "B", "C"): 2})
    candidates = [
        ("tie_late", 10, Counter({("A", "B", "C"): 2})),
        ("tie_early", 10, Counter({("A", "B", "C"): 2})),
        ("weak", 10, Counter({("A", "B", "C"): 1, ("X", "Y", "Z"): 3})),
        ("too_big", 30, Counter({("A", "B", "C"): 2})),
    ]
    ranked = rank_similar(10, q, candidates, limit=5, min_similarity=0.5, order=lambda key: key)
    assert [key for key, _, _ in ranked] == ["tie_early", "tie_late"]
    assert rank_similar(10, q, candidates, limit=1, min_similarity=0.0, order=lambda key: key)[0][0] == "tie_early"


# @spec QRY-045, QRY-046
def test_fuzzy_search_finds_the_twin_and_reports_its_method(tools):
    result = tools.find_similar_functions_fuzzy("twin_a")
    assert [c.name for c in result.candidates] == ["twin_b"]
    assert result.candidates[0].similarity == 1.0 and result.candidates[0].instruction_count == 6
    assert "3-gram" in result.method and result.scanned >= 2


# @spec QRY-047
def test_similarity_features_are_cached_until_the_binary_is_analyzed(tools, program, tmp_path):
    tools.find_similar_functions_fuzzy("twin_a")
    index = tools.program_info.similarity_index
    assert index
    program.instructions[-1].mnemonic = "XOR"  # not seen: features are cached
    tools.find_similar_functions_fuzzy("twin_a")
    assert tools.program_info.similarity_index is index

    ctx = HarnessContext([], tmp_path=tmp_path)
    binary = tmp_path / "b"
    binary.write_bytes(b"1")
    (name,), _ = ctx.import_binary_backgrounded(binary)
    entry = ctx.programs[f"/{name}"]
    wait_until(lambda: settled(entry))
    entry.similarity_index = {"stale": True}
    entry = ctx.reanalyze_binary(name, AnalysisOptions())
    wait_until(lambda: settled(entry))
    assert entry.similarity_index is None


# ── P-code and data flow ─────────────────────────────────────────────────────


# @spec QRY-048, QRY-049
def test_raw_pcode_lists_each_instructions_ops_and_truncates(program):
    program.functions.append(Function("tiny", 0x403000, size=0x8))
    program.instructions += [
        PcodeInstruction(0x403000, "ADD", [PcodeOp(0, "INT_ADD", "(register, 0x0, 4) INT_ADD a, b")]),
        PcodeInstruction(0x403004, "RET", [PcodeOp(0, "COPY", "c = COPY a"), PcodeOp(1, "RETURN", "RETURN c")]),
    ]
    tools = tools_for(program, FakeDecompiler())
    result = tools.get_function_pcode("tiny")
    assert [(o.address, o.seq, o.mnemonic) for o in result.ops] == [
        ("00403000", 0, "INT_ADD"), ("00403004", 0, "COPY"), ("00403004", 1, "RETURN"),
    ]
    assert result.total_ops == 3 and not result.truncated and result.form == "raw"
    cut = tools.get_function_pcode("tiny", max_ops=2)
    assert len(cut.ops) == 2 and cut.total_ops == 3 and cut.truncated


# @spec QRY-049
@pytest.mark.parametrize(("method", "kwargs"), [
    ("get_function_pcode", {"name_or_address": "main", "max_ops": 0}),
    ("get_function_pcode", {"name_or_address": "main", "max_ops": 20001}),
    ("analyze_dataflow", {"function_name_or_address": "main", "variable": "x", "max_ops": 5001}),
])
def test_out_of_range_max_ops_is_value_error(tools, method, kwargs):
    with pytest.raises(ValueError, match="max_ops"):
        getattr(tools, method)(**kwargs)


# @spec QRY-051
def test_dataflow_on_an_unknown_or_flowless_variable_is_value_error(program, monkeypatch):
    install_modules(monkeypatch, {"ghidra.util.task": {"ConsoleTaskMonitor": lambda: "monitor"}})
    result = DecompileResult("code", "sig", locals_=("param_1", "local_10"))
    tools = tools_for(program, FakeDecompiler(result))
    with pytest.raises(ValueError) as raised:
        tools.analyze_dataflow("main", "param_9")
    assert "param_1" in str(raised.value) and "local_10" in str(raised.value)
    result.locals[0].getHighVariable = lambda: None
    with pytest.raises(ValueError, match="no data flow"):
        tools.analyze_dataflow("main", "param_1")


# ── Two binaries ─────────────────────────────────────────────────────────────


# @spec QRY-052
@pytest.mark.anyio
async def test_two_binary_calls_gate_both_and_hold_both_locks_in_pathname_order(monkeypatch):
    ctx = FakeContext()
    a = LoadedProgram(name="b-1", pathname="/b-1", project=None)
    b = LoadedProgram(name="a-1", pathname="/a-1", project=None)
    ctx.programs = {"b-1": a, "a-1": b}
    monkeypatch.setattr(server.mcp, "_ghidra_context", ctx, raising=False)
    order = []
    real_acquire = {}

    for entry in (a, b):
        lock = entry.lock

        class Recording:
            def __init__(self, inner, name):
                self.inner, self.name = inner, name

            def __enter__(self):
                order.append(self.name)
                return self.inner.__enter__()

            def __exit__(self, *exc):
                return self.inner.__exit__(*exc)

            def acquire(self, *args, **kwargs):
                return self.inner.acquire(*args, **kwargs)

            def release(self):
                return self.inner.release()

        entry.lock = Recording(lock, entry.pathname)
        real_acquire[entry.pathname] = lock

    seen = {}

    def fake_diff(self, function_a, function_b, other=None, **kwargs):
        seen["owned"] = {p: lock._is_owned() for p, lock in real_acquire.items()}
        from ghidra_mcp.models import FunctionDiff
        return FunctionDiff(binary_a="b-1", function_a="f", binary_b="a-1", function_b="g", view="decompiled",
                            normalized=True, identical=True, similarity=1.0, diff="")

    monkeypatch.setattr(GhidraTools, "diff_functions", fake_diff)
    async with Client(server.mcp) as client:
        result = await client.call_tool("diff_functions", {
            "binary_name": "b-1", "function_a": "f", "function_b": "g", "other_binary_name": "a-1"})
    assert not result.is_error, result.content
    assert ("get_program_info", "b-1") in ctx.calls and ("get_program_info", "a-1") in ctx.calls
    assert order == ["/a-1", "/b-1"]
    assert seen["owned"] == {"/b-1": True, "/a-1": True}


# @spec QRY-029
def test_new_target_taking_tools_disclose_loose_matches(tools):
    assert "partial name match" in tools.get_function_callers("aller2").resolution
    assert "partial name match" in tools.get_function_callees("mai").resolution
    assert "partial name match" in tools.find_similar_functions_fuzzy("win_a").resolution
    diff = tools.diff_functions("twin_a", "twin_b", view="disassembly")
    assert diff.identical and diff.resolution_a is None
    loose = tools.diff_functions("0x402004", "twin_b", view="disassembly")
    assert "address inside the function" in loose.resolution_a
