"""Write-back: transactions, comments, renames, local variables, prototypes, outcomes."""

import types

import pytest

from ghidra_mcp import server
from ghidra_mcp.errors import FIX_INPUT, Stop, classify
from tests.program_fakes import (
    Addr,
    Data,
    DataType,
    DecompileResult,
    FakeDecompiler,
    FakeJavaException,
    FakeProgram,
    Function,
    Symbol,
    install_modules,
    tools_for,
)

EOL, PRE = "EOL", "PRE"
EXT_PUTS = Function("puts", Addr(0x20, "EXTERNAL"), namespace="libc.so.6", external=True)


class FunctionDefinitionDataType:
    def __init__(self, name):
        self.name = name


class Recorder:
    def __init__(self):
        self.db_updates = []
        self.cparser_inputs = []
        self.applied = []
        self.apply_result = True
        self.status = ""
        self.parse = lambda text: FunctionDefinitionDataType(text.split("(")[0].split()[-1])


@pytest.fixture
def rec(monkeypatch):
    rec = Recorder()

    class CParser:
        def __init__(self, dtm):
            pass

        def parse(self, text):
            rec.cparser_inputs.append(text)
            return rec.parse(text)

    class ApplyFunctionSignatureCmd:
        def __init__(self, entry, signature, source):
            self.entry, self.signature, self.source = entry, signature, source

        def applyTo(self, program, monitor):  # noqa: N802
            rec.applied.append((self.entry, self.signature.name, self.source))
            if rec.apply_result:
                func = program.getFunctionManager().getFunctionAt(self.entry)
                if func.getName().startswith("FUN_"):  # RENAME_IF_DEFAULT
                    func.setName(self.signature.name, "USER_DEFINED")
            return rec.apply_result

        def getStatusMsg(self):  # noqa: N802
            return rec.status

    install_modules(monkeypatch, {
        "ghidra.program.model.listing": {"CommentType": types.SimpleNamespace(EOL=EOL, PRE=PRE)},
        "ghidra.program.model.symbol": {"SourceType": types.SimpleNamespace(USER_DEFINED="USER_DEFINED")},
        "ghidra.program.model.pcode": {"HighFunctionDBUtil": types.SimpleNamespace(
            updateDBVariable=lambda sym, name, dt, source: rec.db_updates.append((sym.getName(), name, dt, source)),
        )},
        "ghidra.program.model.data": {"FunctionDefinitionDataType": FunctionDefinitionDataType},
        "ghidra.util.task": {"ConsoleTaskMonitor": lambda: "monitor"},
        "ghidra.app.util.cparser.C": {"CParser": CParser},
        "ghidra.app.cmd.function": {"ApplyFunctionSignatureCmd": ApplyFunctionSignatureCmd},
    })
    return rec


@pytest.fixture
def program():
    return FakeProgram(
        functions=[
            Function("main", 0x401000),
            Function("FUN_00401100", 0x401100),
            Function("puts", 0x401200, thunk_of=EXT_PUTS),
            EXT_PUTS,
        ],
        symbols=[Symbol("g_named", 0x404000), Symbol("DAT_00404010", 0x404010, dynamic=True)],
        defined_data=[
            Data(0x404000, primary=None),
            Data(0x404010, primary=None),
            Data(0x404020, primary=None),
        ],
        data_types=[DataType("MyStruct", "/mine")],
    )


@pytest.fixture
def decompiler():
    return FakeDecompiler(DecompileResult("code", "sig", locals_=("local_10", "iVar1")))


@pytest.fixture
def tools(program, decompiler, rec):
    program.defined_data[0].primary = program.symbols[-2]  # g_named
    program.defined_data[1].primary = program.symbols[-1]  # DAT_00404010 (dynamic)
    return tools_for(program, decompiler)


# ── Transaction contract ─────────────────────────────────────────────────────


# @spec WB-001, WB-003, WB-004, WB-021
def test_a_write_runs_in_one_committed_transaction_saves_and_confirms(tools, program):
    message = tools.rename_function("main", "start")
    assert program.transactions == ["Rename function main → start"] and program.commits == [True]
    assert tools.project.saved == 1
    assert program.functions[0].symbol.source == "USER_DEFINED"
    assert message == "Renamed 'main' → 'start'"


# @spec WB-002
def test_a_failing_mutation_rolls_back_and_is_not_saved(tools, program):
    program.functions[0].symbol.reject = RuntimeError("database locked")
    with pytest.raises(RuntimeError):
        tools.rename_function("main", "start")
    assert program.commits == [False] and tools.project.saved == 0


# @spec WB-005
def test_input_errors_never_open_a_transaction(tools, program, rec):
    rec.parse = lambda text: (_ for _ in ()).throw(RuntimeError("not a declaration"))
    with pytest.raises(ValueError):
        tools.rename_function("no_such_function", "x")
    with pytest.raises(ValueError):
        tools.set_local_variable_type("main", "local_10", "NoSuchType")
    assert program.transactions == []


# @spec WB-022
def test_a_save_failure_after_commit_is_stop_saying_the_edit_is_applied(tools, program):
    tools.project.save_error = RuntimeError("disk full")
    with pytest.raises(Stop) as raised:
        tools.rename_function("main", "start")
    assert "applied" in str(raised.value) and "not saved" in str(raised.value)
    assert "disk full" in str(raised.value)
    assert program.commits == [True]


# ── Comments ─────────────────────────────────────────────────────────────────


# @spec WB-006, WB-026
def test_disassembly_comment_is_the_eol_comment(tools, program):
    assert tools.set_disassembly_comment("0x401000", "entry") == "Set disassembly comment at 0x401000"
    assert program.comments == {(EOL, Addr(0x401000)): "entry"}


# @spec WB-007, WB-026
def test_decompiler_comment_is_the_pre_comment(tools, program):
    tools.set_decompiler_comment("401000", "decrypts the config")
    assert program.comments == {(PRE, Addr(0x401000)): "decrypts the config"}


# @spec WB-025
@pytest.mark.parametrize("method", ["set_disassembly_comment", "set_decompiler_comment"])
def test_a_comment_outside_memory_is_rejected_before_a_transaction(tools, program, method):
    with pytest.raises(ValueError, match="not in"):
        getattr(tools, method)("0x900000", "x")
    assert program.transactions == []


# @spec WB-027
def test_empty_comment_text_removes_the_comment(tools, program):
    tools.set_disassembly_comment("0x401000", "entry")
    message = tools.set_disassembly_comment("0x401000", "")
    assert program.comments == {} and "Removed" in message
    for tool in (server.set_disassembly_comment, server.set_decompiler_comment):
        assert "empty" in tool.__doc__.lower()


# ── Renames ──────────────────────────────────────────────────────────────────


# @spec WB-008
def test_rename_function_resolves_in_write_mode(tools):
    with pytest.raises(ValueError, match="thunk"):
        tools.rename_function("puts", "my_puts")
    with pytest.raises(ValueError, match="not found"):
        tools.rename_function("mai", "start")  # a partial match is not enough for a write


# @spec WB-009
def test_rename_function_by_address_uses_the_exact_entry_point(tools, program):
    assert tools.rename_function_by_address("0x401000", "start") == (
        "Renamed function at 0x401000: 'main' → 'start'"
    )
    assert program.functions[0].getName() == "start"


# @spec WB-010
@pytest.mark.parametrize("address", ["0x401010", "0x404000"])
def test_rename_function_by_address_needs_an_entry_point(tools, address):
    with pytest.raises(ValueError):
        tools.rename_function_by_address(address, "x")


# @spec WB-011
def test_rename_data_renames_a_named_primary_symbol_else_creates_a_label(tools, program):
    tools.rename_data("0x404000", "g_config")
    assert program.symbols[-2].getName() == "g_config"
    tools.rename_data("0x404010", "g_table")  # dynamic primary symbol: label created
    assert program.symbols[-1].getName() == "g_table" and program.symbols[-1].source == "USER_DEFINED"
    assert any(s.getName() == "DAT_00404010" for s in program.symbols)
    tools.rename_data("0x404020", "g_flags")  # no primary symbol: label created
    assert program.symbols[-1].getName() == "g_flags"
    with pytest.raises(ValueError, match="No defined data"):
        tools.rename_data("0x404030", "x")


# @spec WB-012
def test_rename_data_documents_the_defined_data_requirement():
    doc = server.rename_data.__doc__.lower()
    assert "defined data" in doc and "creates a new label if none exists" not in doc
    readme = (server.Path(__file__).resolve().parents[1] / "README.md").read_text()
    row = next(line for line in readme.splitlines() if line.startswith("| `rename_data`"))
    assert "defined data" in row


# @spec WB-023
def test_a_name_ghidra_rejects_is_fix_input_and_rolled_back(tools, program):
    program.functions[0].symbol.reject = FakeJavaException(
        "ghidra.util.exception.DuplicateNameException", "Symbol 'start' already exists"
    )
    with pytest.raises(FakeJavaException) as raised:
        tools.rename_function("main", "start")
    assert classify(raised.value) == FIX_INPUT and program.commits == [False]


# ── Local variables ──────────────────────────────────────────────────────────


# @spec WB-013, WB-016
def test_rename_variable_finds_the_exact_name_with_a_30_second_decompile(tools, decompiler, rec):
    message = tools.rename_variable("main", "local_10", "count")
    assert decompiler.calls == [("main", 30)]
    assert rec.db_updates == [("local_10", "count", None, "USER_DEFINED")]
    assert message == "Renamed variable 'local_10' → 'count' in function 'main'"


# @spec WB-013, WB-015
def test_variable_names_match_exactly_and_misses_list_the_available_names(tools):
    with pytest.raises(ValueError) as raised:
        tools.rename_variable("main", "LOCAL_10", "count")
    assert "local_10" in str(raised.value) and "iVar1" in str(raised.value)


# @spec WB-014
def test_a_decompile_failure_during_a_variable_edit_is_stop(program, rec):
    tools = tools_for(program, FakeDecompiler(DecompileResult(error="bad stack")))
    with pytest.raises(Stop, match="bad stack"):
        tools.rename_variable("main", "local_10", "count")


# @spec WB-017
def test_set_local_variable_type_resolves_the_type_and_updates_it(tools, program, rec):
    rec.parse = lambda text: (_ for _ in ()).throw(RuntimeError("not a declaration"))
    tools.set_local_variable_type("main", "iVar1", "MyStruct")
    (update,) = rec.db_updates
    assert update[:2] == ("iVar1", None) and update[2].getPathName() == "/mine/MyStruct"
    assert update[3] == "USER_DEFINED"


# ── Prototypes ───────────────────────────────────────────────────────────────


# @spec WB-018
def test_set_function_prototype_parses_and_applies_the_declaration(tools, rec):
    message = tools.set_function_prototype("main", "int main(int argc, char **argv)")
    assert rec.cparser_inputs == ["int main(int argc, char **argv);"]
    assert rec.applied == [(Addr(0x401000), "main", "USER_DEFINED")]
    assert message.startswith("Set prototype for 'main'")


# @spec WB-019
def test_unparseable_or_non_function_prototypes_are_value_errors(tools, rec):
    rec.parse = lambda text: (_ for _ in ()).throw(RuntimeError("syntax error"))
    with pytest.raises(ValueError, match="syntax error"):
        tools.set_function_prototype("main", "int (")
    rec.parse = lambda text: DataType("int")
    with pytest.raises(ValueError, match="function"):
        tools.set_function_prototype("main", "int x")


# @spec WB-020
def test_a_failed_prototype_application_rolls_back_as_stop(tools, program, rec):
    rec.apply_result, rec.status = False, "Parameter storage conflict"
    with pytest.raises(Stop, match="Parameter storage conflict"):
        tools.set_function_prototype("main", "int main(int argc)")
    assert program.commits == [False] and tools.project.saved == 0


# @spec WB-024
def test_a_prototype_that_renames_a_default_named_function_says_so(tools, program):
    message = tools.set_function_prototype("FUN_00401100", "int process(char *buf)")
    assert program.functions[1].getName() == "process"
    assert "renamed" in message.lower() and "'process'" in message
    assert "renamed" not in tools.set_function_prototype("main", "int main(void)").lower()
