"""analysis-config: per-binary options, typed option setting, symbols, GDTs, configuration warnings.

Ghidra classes are stubbed through sys.modules, so no JVM is needed.
"""

import logging
import sys
import types
from pathlib import Path

import pytest

from ghidra_mcp.context import AnalysisOptions, GhidraContext, LoadedProgram
from tests.fakes import HarnessContext


class FakeOptions:
    def __init__(self, types_by_name, enums=None):
        self.types = types_by_name
        self.enums = enums or {}
        self.values = {}

    def getType(self, name):  # noqa: N802
        return self.types.get(name, "NO_TYPE")

    def _set(kind):
        def setter(self, name, value):
            self.values[name] = (kind, value)

        return setter

    setInt = _set("int")  # noqa: N815
    setLong = _set("long")  # noqa: N815
    setString = _set("string")  # noqa: N815
    setDouble = _set("double")  # noqa: N815
    setFloat = _set("float")  # noqa: N815
    setBoolean = _set("boolean")  # noqa: N815
    setEnum = _set("enum")  # noqa: N815

    def getEnum(self, name, default):  # noqa: N802
        return self.enums.get(name, default)


class OptionsProgram:
    def __init__(self, types_by_name=None, enums=None):
        self.options = FakeOptions(types_by_name or {}, enums)
        self.transactions = []
        self.name = "prog"

    def getOptions(self, category):  # noqa: N802
        return self.options

    def startTransaction(self, description):  # noqa: N802
        self.transactions.append(("start", description))
        return len(self.transactions)

    def endTransaction(self, tx, commit):  # noqa: N802
        self.transactions.append(("end", commit))


@pytest.fixture
def stub_listing(monkeypatch):
    for name in ("ghidra", "ghidra.program", "ghidra.program.model"):
        monkeypatch.setitem(sys.modules, name, types.SimpleNamespace())
    monkeypatch.setitem(
        sys.modules, "ghidra.program.model.listing",
        types.SimpleNamespace(Program=types.SimpleNamespace(ANALYSIS_PROPERTIES="Analyzers")),
    )


@pytest.fixture
def ctx(tmp_path):
    return HarnessContext(tmp_path=tmp_path)


def entry_for(program):
    entry = LoadedProgram(name="prog", pathname="/prog", project=None)
    entry.program = program
    return entry


@pytest.fixture
def fake_ghidrecomp(monkeypatch):
    calls = []
    module = types.SimpleNamespace(
        set_pdb=lambda program, path: calls.append(("set_pdb", path)),
        setup_symbol_server=lambda path: calls.append(("setup_symbol_server", path)),
        set_remote_pdbs=lambda program, enabled: calls.append(("set_remote_pdbs", enabled)),
        get_pdb=lambda program: calls.append(("get_pdb",)) or None,
    )
    monkeypatch.setitem(sys.modules, "ghidrecomp", types.SimpleNamespace(utility=module))
    monkeypatch.setitem(sys.modules, "ghidrecomp.utility", module)
    return module, calls


# ── Typed option setting ─────────────────────────────────────────────────────


# @spec ACFG-011
@pytest.mark.parametrize(
    ("option_type", "value", "expected"),
    [
        ("INT_TYPE", "5", ("int", 5)),
        ("LONG_TYPE", 7, ("long", 7)),
        ("STRING_TYPE", 5, ("string", "5")),
        ("DOUBLE_TYPE", "1.5", ("double", 1.5)),
        ("FLOAT_TYPE", 2, ("float", 2.0)),
    ],
)
def test_values_are_coerced_to_the_options_type(ctx, stub_listing, option_type, value, expected):
    program = OptionsProgram({"Opt": option_type})
    assert ctx.set_analysis_option(program, "Opt", value) is None
    assert program.options.values["Opt"] == expected


# @spec ACFG-012
@pytest.mark.parametrize(("value", "expected"), [("TRUE", True), ("no", False), (0, False), (1, True)])
def test_boolean_options(ctx, stub_listing, value, expected):
    program = OptionsProgram({"Opt": "BOOLEAN_TYPE"})
    ctx.set_analysis_option(program, "Opt", value)
    assert program.options.values["Opt"] == ("boolean", expected)


class _Const:
    def __init__(self, text):
        self.text = text

    def toString(self):  # noqa: N802
        return self.text


class _EnumValue:
    def __init__(self, constants):
        self._constants = constants

    def getClass(self):  # noqa: N802
        return "EnumClass"

    def values(self):
        return self._constants


@pytest.fixture
def stub_java_enum(monkeypatch):
    def value_of(cls, name):
        raise ValueError("no constant with that name")

    monkeypatch.setitem(sys.modules, "java", types.SimpleNamespace())
    monkeypatch.setitem(sys.modules, "java.lang", types.SimpleNamespace(Enum=types.SimpleNamespace(valueOf=value_of)))


# @spec ACFG-013
def test_enum_options_fall_back_to_the_constants_display_text(ctx, stub_listing, stub_java_enum):
    constants = [_Const("Process All"), _Const("Data Types Only")]
    program = OptionsProgram({"Control": "ENUM_TYPE"}, enums={"Control": _EnumValue(constants)})
    assert ctx.set_analysis_option(program, "Control", "Data Types Only") is None
    assert program.options.values["Control"] == ("enum", constants[1])


# @spec ACFG-014
def test_enum_options_without_a_match_or_current_value_produce_warnings(ctx, stub_listing, stub_java_enum):
    program = OptionsProgram({"Control": "ENUM_TYPE", "Empty": "ENUM_TYPE"},
                             enums={"Control": _EnumValue([_Const("Process All")])})
    assert "Control" in ctx.set_analysis_option(program, "Control", "Bogus")
    assert "Empty" in ctx.set_analysis_option(program, "Empty", "x")
    assert program.options.values == {}


# @spec ACFG-015
@pytest.mark.parametrize("option_type", ["NO_TYPE", "COLOR_TYPE"])
def test_unknown_or_unsupported_options_produce_a_warning_and_are_left_unchanged(ctx, stub_listing, option_type):
    program = OptionsProgram({"Weird": option_type})
    warning = ctx.set_analysis_option(program, "Weird", 1)
    assert "Weird" in warning
    assert program.options.values == {}


# @spec ACFG-019
def test_a_value_that_cannot_be_coerced_produces_a_warning(ctx, stub_listing):
    program = OptionsProgram({"Count": "INT_TYPE"})
    warning = ctx.set_analysis_option(program, "Count", "abc")
    assert "Count" in warning and "abc" in warning
    assert program.options.values == {}


# ── Configuration (symbols + analyzer options) ───────────────────────────────


# @spec ACFG-010, ACFG-019
def test_analyzer_options_apply_in_a_transaction_even_with_no_symbols(ctx, stub_listing):
    program = OptionsProgram({"Count": "INT_TYPE", "Stack": "BOOLEAN_TYPE"})
    entry = entry_for(program)
    options = AnalysisOptions(no_symbols=True, analyzer_options={"Count": "abc", "Stack": False})
    ctx._configure_analysis(entry, options)
    assert program.options.values == {"Stack": ("boolean", False)}
    assert any("Count" in w for w in entry.warnings)
    assert program.transactions[0][0] == "start" and program.transactions[-1] == ("end", True)


# @spec ACFG-005
def test_no_symbols_disables_pdb_universal_where_it_is_registered(ctx, stub_listing, caplog):
    caplog.set_level(logging.WARNING)
    program = OptionsProgram({"PDB Universal": "BOOLEAN_TYPE"})
    entry = entry_for(program)
    ctx._configure_analysis(entry, AnalysisOptions(no_symbols=True))
    assert program.options.values == {"PDB Universal": ("boolean", False)}
    assert entry.warnings == []
    assert "Symbols disabled" in caplog.text


# @spec ACFG-005
def test_no_symbols_is_silent_for_formats_without_pdb_universal(ctx, stub_listing, caplog):
    caplog.set_level(logging.WARNING)
    program = OptionsProgram({})  # e.g. ELF or Mach-O: PDB Universal reports NO_TYPE
    entry = entry_for(program)
    ctx._configure_analysis(entry, AnalysisOptions(no_symbols=True))
    assert program.options.values == {}
    assert entry.warnings == []
    assert "Unsupported" not in caplog.text and "Unknown" not in caplog.text


# @spec ACFG-018, ACFG-009
def test_missing_ghidrecomp_is_a_configuration_warning(ctx, stub_listing, monkeypatch):
    monkeypatch.setitem(sys.modules, "ghidrecomp.utility", None)
    program = OptionsProgram({"Stack": "BOOLEAN_TYPE"})
    entry = entry_for(program)
    ctx._configure_analysis(entry, AnalysisOptions(analyzer_options={"Stack": True}))
    assert any("ghidrecomp" in w for w in entry.warnings)
    assert program.options.values == {"Stack": ("boolean", True)}


# @spec ACFG-006
def test_a_binarys_pdb_path_is_configured_for_that_binary(ctx, stub_listing, fake_ghidrecomp, tmp_path):
    _, calls = fake_ghidrecomp
    pdb = tmp_path / "app.pdb"
    pdb.write_bytes(b"pdb")
    ctx._configure_analysis(entry_for(OptionsProgram()), AnalysisOptions(pdb_path=pdb))
    assert ("set_pdb", pdb) in calls
    assert not any(c[0] == "setup_symbol_server" for c in calls)


# @spec ACFG-007, ACFG-001
def test_without_a_pdb_path_the_symbol_server_is_configured(ctx, stub_listing, fake_ghidrecomp):
    _, calls = fake_ghidrecomp
    ctx._configure_analysis(entry_for(OptionsProgram()), AnalysisOptions())
    assert ("setup_symbol_server", ctx.symbols_path) in calls
    assert ("set_remote_pdbs", True) in calls
    assert ctx.symbols_path == ctx.project_path / "symbols"


# @spec ACFG-008
def test_pdb_outcome_is_logged(ctx, stub_listing, fake_ghidrecomp, caplog):
    module, _ = fake_ghidrecomp
    caplog.set_level(logging.INFO)
    ctx._configure_analysis(entry_for(OptionsProgram()), AnalysisOptions())
    assert "No PDB found" in caplog.text
    module.get_pdb = lambda program: "/symbols/app.pdb"
    ctx._configure_analysis(entry_for(OptionsProgram()), AnalysisOptions())
    assert "PDB loaded: /symbols/app.pdb" in caplog.text


# @spec ACFG-021
def test_failed_symbol_setup_is_a_warning_and_analysis_configuration_continues(
    ctx, stub_listing, fake_ghidrecomp
):
    module, _ = fake_ghidrecomp
    module.setup_symbol_server = lambda path: (_ for _ in ()).throw(OSError("no network"))
    program = OptionsProgram({"Stack": "BOOLEAN_TYPE"})
    entry = entry_for(program)
    ctx._configure_analysis(entry, AnalysisOptions(analyzer_options={"Stack": True}))
    assert any("no network" in w for w in entry.warnings)
    assert program.options.values == {"Stack": ("boolean", True)}


# ── GDT archives ─────────────────────────────────────────────────────────────


# @spec ACFG-002, ACFG-017
def test_gdts_apply_in_order_and_failures_become_warnings(ctx, monkeypatch):
    applied = []

    def fake_apply(program, path):
        applied.append(Path(path).name)
        if path.name == "bad.gdt":
            return False, "conflicting data type"
        if path.name == "boom.gdt":
            raise OSError("cannot read archive")
        return True, ""

    monkeypatch.setattr(ctx, "apply_gdt", fake_apply)
    entry = entry_for(object())
    options = AnalysisOptions(gdts=(Path("a.gdt"), Path("bad.gdt"), Path("boom.gdt"), Path("z.gdt")))
    ctx._apply_gdts(entry, options)
    assert applied == ["a.gdt", "bad.gdt", "boom.gdt", "z.gdt"]
    assert any("bad.gdt" in w and "conflicting data type" in w for w in entry.warnings)
    assert any("boom.gdt" in w and "cannot read archive" in w for w in entry.warnings)


# @spec ACFG-003, ACFG-016, ACFG-020
def test_apply_gdt_runs_in_a_transaction_keeps_user_signatures_and_closes_the_archive(monkeypatch):
    created = {}

    class Archive:
        closed = False

        def close(self):
            Archive.closed = True

    class Cmd:
        def __init__(self, archives, address_set, source, always_replace, bookmarks):
            created.update(source=source, always_replace=always_replace, bookmarks=bookmarks,
                           address_set=address_set)

        def applyTo(self, program, monitor):  # noqa: N802
            return True

        def getStatusMsg(self):  # noqa: N802
            return None

    stubs = {
        "ghidra.app.cmd.function": types.SimpleNamespace(ApplyFunctionDataTypesCmd=Cmd),
        "ghidra.program.model.data": types.SimpleNamespace(
            FileDataTypeManager=types.SimpleNamespace(openFileArchive=lambda f, rw: Archive())),
        "ghidra.program.model.symbol": types.SimpleNamespace(
            SourceType=types.SimpleNamespace(USER_DEFINED="USER_DEFINED")),
        "ghidra.util.task": types.SimpleNamespace(TaskMonitor=types.SimpleNamespace(DUMMY="dummy")),
        "java.io": types.SimpleNamespace(File=str),
        "java.util": types.SimpleNamespace(List=types.SimpleNamespace(of=lambda *a: list(a))),
    }
    for name in ("ghidra", "ghidra.app", "ghidra.app.cmd", "ghidra.program", "ghidra.program.model",
                 "ghidra.util", "java"):
        monkeypatch.setitem(sys.modules, name, types.SimpleNamespace())
    for name, module in stubs.items():
        monkeypatch.setitem(sys.modules, name, module)

    program = OptionsProgram()
    ok, status = HarnessContext.apply_gdt(program, Path("types.gdt"))
    assert ok is True
    assert created == {"source": "USER_DEFINED", "always_replace": False, "bookmarks": True, "address_set": None}
    assert program.transactions[0][0] == "start" and program.transactions[-1] == ("end", True)
    assert Archive.closed


# ── Order around analyzeAll ──────────────────────────────────────────────────


@pytest.fixture
def stub_analysis_modules(monkeypatch):
    events = []

    class Monitor:
        def __init__(self, *args):
            self.args = args

    class ConsoleTaskMonitor(Monitor):
        pass

    class TaskMonitorAdapter(Monitor):
        pass

    class FlatProgramAPI:
        def __init__(self, program, monitor):
            self.monitor = monitor

        def analyzeAll(self, program):  # noqa: N802
            events.append(("analyzeAll", type(self.monitor).__name__, self.monitor.args))

    script_util = types.SimpleNamespace(
        acquireBundleHostReference=lambda: events.append(("acquire",)),
        releaseBundleHostReference=lambda: events.append(("release",)),
    )
    utilities = types.SimpleNamespace(markProgramAnalyzed=lambda p: events.append(("markProgramAnalyzed",)))
    for name, attrs in {
        "ghidra": {},
        "ghidra.app": {},
        "ghidra.app.script": {"GhidraScriptUtil": script_util},
        "ghidra.program": {},
        "ghidra.program.flatapi": {"FlatProgramAPI": FlatProgramAPI},
        "ghidra.program.util": {"GhidraProgramUtilities": utilities},
        "ghidra.util": {},
        "ghidra.util.task": {"ConsoleTaskMonitor": ConsoleTaskMonitor, "TaskMonitorAdapter": TaskMonitorAdapter},
    }.items():
        monkeypatch.setitem(sys.modules, name, types.SimpleNamespace(**attrs))
    return events


# @spec ACFG-004, LIFE-021
@pytest.mark.parametrize(("verbose", "monitor"), [(True, "ConsoleTaskMonitor"), (False, "TaskMonitorAdapter")])
def test_configuration_runs_immediately_before_analyze_all(ctx, stub_analysis_modules, monkeypatch, verbose, monitor):
    events = stub_analysis_modules
    ctx.verbose_analysis = verbose
    monkeypatch.setattr(ctx, "_apply_gdts", lambda e, o: events.append(("gdts",)))
    monkeypatch.setattr(ctx, "_configure_analysis", lambda e, o: events.append(("configure",)))
    GhidraContext._run_analysis(ctx, entry_for(OptionsProgram()), AnalysisOptions())
    assert [e[0] for e in events] == ["acquire", "gdts", "configure", "analyzeAll", "markProgramAnalyzed", "release"]
    analyze = events[3]
    assert analyze[1] == monitor
    if not verbose:
        assert analyze[2] == (True,)  # a cancellable monitor
