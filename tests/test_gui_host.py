"""gui-host: the GUI-mode context, write runner, and GUI-only tools, against a fake GuiServices."""

import logging
import threading
import time
import types
from pathlib import Path

import pytest

from ghidra_mcp import gui
from ghidra_mcp.context import AnalysisOptions, Status
from ghidra_mcp.errors import RetryLater, Stop
from ghidra_mcp.gui import GuiGhidraContext
from ghidra_mcp.tools import GhidraTools
from tests.fakes import FakeDecompiler, settled, wait_until
from tests.program_fakes import Addr, FakeProgram as ListingProgram, Function, install_modules


# ── Fakes ────────────────────────────────────────────────────────────────────


class GuiDomainFile:
    def __init__(self, pathname, *, analyzed=False):
        self.pathname = pathname
        self.analyzed = analyzed
        self.exists_ = True
        self.deleted = False

    def getPathname(self):  # noqa: N802
        return self.pathname

    def getName(self):  # noqa: N802
        return Path(self.pathname).name

    def getMetadata(self):  # noqa: N802
        return {"Executable Location": f"/bins{self.pathname}"}

    def delete(self):
        self.deleted = True
        self.exists_ = False


class GuiProgram:
    def __init__(self, domain_file):
        self.domain_file = domain_file
        self.changed = False
        self.transactions = []  # (description, committed)
        self.stored_options = None

    def getName(self):  # noqa: N802
        return self.domain_file.getName()

    def getDomainFile(self):  # noqa: N802
        return self.domain_file

    def getMetadata(self):  # noqa: N802
        return {"Program Name": self.getName()}

    def isChanged(self):  # noqa: N802
        return self.changed

    def startTransaction(self, description):  # noqa: N802
        self.transactions.append([description, None])
        return len(self.transactions)

    def endTransaction(self, tx, commit):  # noqa: N802
        self.transactions[tx - 1][1] = commit


class FakeProject:
    def __init__(self, name="proj"):
        self.name = name

    def getName(self):  # noqa: N802
        return self.name


class FakeGuiServices:
    """Records GUI interactions; analysis behavior is scripted per test."""

    def __init__(self, files=(), tmp_path=Path("/tmp")):
        self.project = FakeProject()
        self.active = self.project
        self.files = list(files)
        self.tmp_path = tmp_path
        self.programs = {}
        self.events = []
        self.analyzing = set()
        self.open_tx = {}
        self.browser = "codebrowser"
        self.location = None
        self.swing_calls = 0
        # Default analysis: starts, then ends uncancelled.
        self.analysis = lambda program, on_end: on_end(False)

    # project
    def active_project(self):
        return self.active

    def wait_for_project(self, timeout):
        return self.active_project()

    def project_dir(self, project):
        return self.tmp_path

    def same_project(self, a, b):
        return a is not None and a is b

    def domain_files(self, project):
        return [f for f in self.files if f.exists_]

    def file_exists(self, domain_file):
        return domain_file.exists_

    # threads
    def run_on_swing(self, fn):
        self.swing_calls += 1
        return fn()

    # programs
    def open_program(self, domain_file):
        program = self.programs.setdefault(domain_file.pathname, GuiProgram(domain_file))
        self.events.append(("open_program", domain_file.getName()))
        return program

    def release(self, program):
        self.events.append(("release", program.getName()))

    def import_program(self, project, path, name):
        df = GuiDomainFile(f"/{name}")
        self.files.append(df)
        self.events.append(("import", name))
        return self.open_program(df), df

    # CodeBrowser
    def code_browser(self, launch, domain_file=None):
        if self.browser is None and launch and domain_file is not None:
            self.browser = "launched-codebrowser"
            self.events.append(("launch_codebrowser",))
        return self.browser

    def open_in_code_browser(self, tool, program, current):
        self.events.append(("open_in_codebrowser", program.getName(), current))

    def close_in_code_browsers(self, program):
        self.events.append(("close_in_codebrowsers", program.getName()))

    def current_location(self, tool):
        return self.location

    def go_to(self, tool, program, address):
        self.events.append(("go_to", program.getName(), str(address)))
        return True

    # analysis
    def mark_not_to_ask(self, program):
        self.events.append(("mark_not_to_ask", program.getName()))

    def mark_analyzed(self, program):
        self.events.append(("mark_analyzed", program.getName(), self.open_tx.get(program.getName())))
        program.domain_file.analyzed = True

    def is_analyzed(self, program):
        return program.domain_file.analyzed

    def start_analysis(self, program, on_end):
        self.events.append(("start_analysis", program.getName()))
        threading.Thread(target=self.analysis, args=(program, on_end), daemon=True).start()

    def is_analyzing(self, program):
        return program.getName() in self.analyzing

    def open_transaction(self, program):
        return self.open_tx.get(program.getName())


class GuiHarness(GuiGhidraContext):
    """GuiGhidraContext with the remaining Ghidra-touching seams faked."""

    def __init__(self, services, **kwargs):
        self.config_applied = []
        super().__init__(services, **kwargs)
        self.wait_seconds = 0.2
        self.analysis_start_timeout = 0.5
        self.poll_seconds = 0.01
        self.transaction_settle_timeout = 1.0

    def _setup_decompiler(self, program):
        return FakeDecompiler()

    def _apply_gdts(self, entry, options):
        self.config_applied.append(("gdts", entry.name))
        self.services.events.append(("apply_options", entry.name))

    def _configure_analysis(self, entry, options):
        self.config_applied.append(("configure", entry.name))

    def _store_options(self, program, options):
        program.stored_options = options

    def _stored_options(self, program):
        return program.stored_options or AnalysisOptions()


def make(*files, tmp_path=Path("/tmp")):
    services = FakeGuiServices(files, tmp_path=tmp_path)
    return GuiHarness(services), services


def names(events, kind):
    return [e for e in events if e[0] == kind]


# ── Project and programs ─────────────────────────────────────────────────────


# @spec GUI-009
def test_binds_to_the_guis_active_project():
    ctx, services = make(GuiDomainFile("/a", analyzed=True))
    assert ctx.project is services.project
    assert [e.pathname for e in ctx.list_entries()] == ["/a"]


# @spec GUI-010
def test_a_changed_project_fails_every_call_with_stop():
    ctx, services = make(GuiDomainFile("/a", analyzed=True))
    services.active = FakeProject("other")
    with pytest.raises(Stop, match="restart"):
        ctx.get_program_info("/a")
    with pytest.raises(Stop, match="restart"):
        ctx.list_entries()


# @spec GUI-011
def test_the_registry_follows_files_added_and_removed_in_the_gui():
    a = GuiDomainFile("/a", analyzed=True)
    ctx, services = make(a)
    b = GuiDomainFile("/b", analyzed=True)
    services.files.append(b)
    assert {e.pathname for e in ctx.list_entries()} == {"/a", "/b"}
    a.exists_ = False
    assert {e.pathname for e in ctx.list_entries()} == {"/b"}
    services.files.append(GuiDomainFile("/c", analyzed=True))
    assert ctx.get_program_info("c").pathname == "/c"  # a resolution miss refreshes


# @spec GUI-012
def test_a_program_added_without_analysis_is_failed_and_not_analyzed():
    ctx, services = make()
    services.files.append(GuiDomainFile("/raw"))
    with pytest.raises(Stop) as raised:
        ctx.get_program_info("raw")
    assert "Not analyzed" in str(raised.value) and "reanalyze_binary" in str(raised.value)
    assert not names(services.events, "start_analysis")


# @spec GUI-013
def test_tool_calls_share_the_guis_program_without_opening_codebrowser():
    ctx, services = make(GuiDomainFile("/a", analyzed=True))
    entry = ctx.get_program_info("/a")
    assert entry.program is services.programs["/a"]
    assert not names(services.events, "open_in_codebrowser")


# @spec GUI-014, GUI-017
def test_import_loads_into_the_project_then_analyzes_through_ghidra(tmp_path):
    binary = tmp_path / "tool.exe"
    binary.write_bytes(b"MZ")
    ctx, services = make(tmp_path=tmp_path)
    (name,), _ = ctx.import_binary_backgrounded(binary, AnalysisOptions(no_symbols=True))
    entry = ctx.programs[f"/{name}"]
    wait_until(lambda: settled(entry))
    assert entry.status is Status.READY, entry.failure
    kinds = [e[0] for e in services.events]
    assert kinds.index("import") < kinds.index("mark_not_to_ask") < kinds.index("apply_options")
    assert kinds.index("apply_options") < kinds.index("open_in_codebrowser") < kinds.index("start_analysis")
    assert ("open_in_codebrowser", name, False) in services.events  # visible, not current


# @spec GUI-015
def test_deletion_refuses_unsaved_changes_else_closes_releases_and_deletes():
    a = GuiDomainFile("/a", analyzed=True)
    ctx, services = make(a)
    entry = ctx.get_program_info("/a")
    entry.program.changed = True
    with pytest.raises(Stop, match="unsaved"):
        ctx.delete_program("/a")
    entry.program.changed = False
    assert ctx.delete_program("/a")
    assert a.deleted and ("close_in_codebrowsers", "a") in services.events
    assert ("release", "a") in services.events


# @spec GUI-016
def test_gui_mode_never_saves():
    ctx, services = make(GuiDomainFile("/a"))
    ctx.analyze_project(wait=True)
    entry = ctx.programs["/a"]
    assert entry.status is Status.READY
    ctx._save(entry.program)  # the headless save seam is a no-op in GUI mode


# ── Analysis ─────────────────────────────────────────────────────────────────


# @spec GUI-018
def test_analysis_that_never_starts_fails():
    ctx, services = make(GuiDomainFile("/a"))
    services.analysis = lambda program, on_end: None  # never runs, never ends
    ctx.analyze_project(wait=True)
    entry = ctx.programs["/a"]
    assert entry.status is Status.FAILED and "did not start" in entry.failure


# @spec GUI-018
def test_analysis_that_stops_without_reporting_its_end_counts_as_ended():
    ctx, services = make(GuiDomainFile("/a"))

    def run(program, on_end):
        services.analyzing.add("a")
        time.sleep(0.05)
        services.analyzing.discard("a")  # e.g. the analyst closed the tab

    services.analysis = run
    ctx.analyze_project(wait=True)
    assert ctx.programs["/a"].status is Status.READY


# @spec GUI-019
def test_marking_analyzed_waits_for_ghidras_analysis_transaction_to_close():
    ctx, services = make(GuiDomainFile("/a"))

    def run(program, on_end):
        services.open_tx["a"] = "Auto Analysis"
        on_end(False)
        time.sleep(0.05)
        services.open_tx.pop("a")

    services.analysis = run
    ctx.analyze_project(wait=True)
    entry = ctx.programs["/a"]
    assert entry.status is Status.READY
    assert names(services.events, "mark_analyzed") == [("mark_analyzed", "a", None)]


# @spec GUI-020
def test_cancelled_analysis_fails_the_binary():
    ctx, services = make(GuiDomainFile("/a"))
    services.analysis = lambda program, on_end: on_end(True)
    ctx.analyze_project(wait=True)
    entry = ctx.programs["/a"]
    assert entry.status is Status.FAILED and "cancelled in the Ghidra GUI" in entry.failure


# @spec GUI-021
def test_analysis_the_analyst_starts_reads_as_analyzing():
    ctx, services = make(GuiDomainFile("/a", analyzed=True))
    ctx.get_program_info("/a")
    services.analyzing.add("a")
    (listed,) = ctx.list_entries()
    assert listed.status is Status.ANALYZING
    with pytest.raises(RetryLater, match="started in the GUI"):
        ctx.get_program_info("/a")
    with pytest.raises(RetryLater):
        ctx.reanalyze_binary("/a", AnalysisOptions())
    with pytest.raises(RetryLater):
        ctx.delete_program("/a")
    services.analyzing.discard("a")
    assert ctx.get_program_info("/a").status is Status.READY


# ── Writes ───────────────────────────────────────────────────────────────────


def _rename_body(entry):
    tools = GhidraTools(entry)
    return tools, lambda: "Renamed 'main' → 'start'"


# @spec GUI-023, GUI-025, WB-028
def test_writes_run_on_the_swing_thread_as_their_own_unsaved_transaction():
    ctx, services = make(GuiDomainFile("/a", analyzed=True))
    entry = ctx.get_program_info("/a")
    tools, body = _rename_body(entry)
    before = services.swing_calls
    message = tools._with_transaction("Rename function main → start", body)
    assert services.swing_calls == before + 1
    assert entry.program.transactions == [["Rename function main → start", True]]
    assert message.startswith("Renamed 'main' → 'start'") and "not saved" in message


# @spec GUI-024
def test_a_write_while_ghidra_has_a_transaction_open_is_retry_later():
    ctx, services = make(GuiDomainFile("/a", analyzed=True))
    entry = ctx.get_program_info("/a")
    services.open_tx["a"] = "Auto Analysis"
    tools, body = _rename_body(entry)
    with pytest.raises(RetryLater, match="Auto Analysis"):
        tools._with_transaction("Rename", body)
    assert entry.program.transactions == []


# @spec GUI-023
def test_a_failing_write_rolls_back_and_propagates_its_error():
    ctx, services = make(GuiDomainFile("/a", analyzed=True))
    entry = ctx.get_program_info("/a")

    def body():
        raise ValueError("bad name")

    with pytest.raises(ValueError, match="bad name"):
        GhidraTools(entry)._with_transaction("Rename", body)
    assert entry.program.transactions == [["Rename", False]]


# ── GUI-only tools ───────────────────────────────────────────────────────────


def _located(ctx, services, address):
    entry = ctx.get_program_info("/a")
    listing = ListingProgram(functions=[Function("main", 0x401000, size=0x40)])
    program = types.SimpleNamespace(
        getDomainFile=lambda: entry.domain_file,
        getName=lambda: "a",
        getFunctionManager=listing.getFunctionManager,
    )
    services.location = (program, Addr(address))
    return entry


# @spec GUI-027
def test_current_address_names_binary_address_and_function():
    ctx, services = make(GuiDomainFile("/a", analyzed=True))
    _located(ctx, services, 0x401010)
    assert ctx.current_location() == {"binary_name": "a", "address": "00401010", "function_name": "main"}


# @spec GUI-028
def test_current_function_or_stop_outside_functions():
    ctx, services = make(GuiDomainFile("/a", analyzed=True))
    _located(ctx, services, 0x401010)
    binary, function = ctx.current_function()
    assert binary == "a" and function.getName() == "main"
    _located(ctx, services, 0x404000)
    with pytest.raises(Stop, match="00404000"):
        ctx.current_function()


# @spec GUI-029
def test_current_tools_without_a_codebrowser_or_program_are_stop():
    ctx, services = make(GuiDomainFile("/a", analyzed=True))
    services.browser = None
    with pytest.raises(Stop, match="CodeBrowser"):
        ctx.current_location()
    services.browser = "codebrowser"
    services.location = None
    with pytest.raises(Stop, match="no program"):
        ctx.current_location()


# @spec GUI-030
def test_go_to_resolves_opens_as_current_and_navigates(monkeypatch):
    ctx, services = make(GuiDomainFile("/a", analyzed=True))
    services.browser = None
    entry = ctx.get_program_info("/a")
    monkeypatch.setattr(
        GhidraTools, "resolve_reference_target",
        lambda self, query: types.SimpleNamespace(target=Addr(0x401000), note="'mai' resolved to main @ 00401000 (partial name match)"),
    )
    message = ctx.go_to("/a", "mai")
    assert ("launch_codebrowser",) in services.events
    assert ("open_in_codebrowser", "a", True) in services.events
    assert ("go_to", "a", "00401000") in services.events
    assert "00401000" in message and "partial name match" in message
    assert entry.program is services.programs["/a"]


# ── Services, launch, and serving ────────────────────────────────────────────


# @spec GUI-031
def test_an_unresponsive_swing_thread_is_stop(monkeypatch):
    class UnableToSwingException(Exception):
        pass

    def run_now(runnable, timeout, unit):
        raise UnableToSwingException("timed out")

    install_modules(monkeypatch, {
        "ghidra.util": {"Swing": types.SimpleNamespace(runNow=run_now)},
        "java.util.concurrent": {"TimeUnit": types.SimpleNamespace(SECONDS="SECONDS")},
    })
    services = object.__new__(gui.GuiServices)
    services.swing_timeout = 30
    with pytest.raises(Stop, match="not responding"):
        services.run_on_swing(lambda: 1)


# @spec GUI-007
def test_wrapped_streams_get_isatty():
    class Wrapper:
        def write(self, text):
            return len(text)

    stream = Wrapper()
    gui.ensure_isatty(stream)
    assert stream.isatty() is False


# @spec GUI-005
def test_serving_builds_the_context_imports_analyzes_registers_and_runs(monkeypatch, tmp_path):
    from ghidra_mcp import server

    services = FakeGuiServices(tmp_path=tmp_path)
    order = []
    monkeypatch.setattr(server, "register_gui_tools", lambda: order.append("register"))
    monkeypatch.setattr(server.mcp, "run", lambda **kw: order.append(("run", kw)))
    monkeypatch.setattr(GuiHarness, "import_binaries", lambda self, paths, options=None: order.append("import"))
    monkeypatch.setattr(GuiHarness, "analyze_project", lambda self, wait=False: order.append("analyze"))
    gui.serve_when_ready(
        services=services, context_factory=GuiHarness, input_paths=("bin",),
        host="127.0.0.1", port=8123, wait_for_analysis=True, verbose_analysis=False, symbols_path=None,
    )
    assert order == ["import", "analyze", "register", ("run", {"transport": "streamable-http", "host": "127.0.0.1", "port": 8123})]
    assert isinstance(server.mcp._ghidra_context, GuiHarness)


# @spec GUI-008
def test_a_server_failure_after_launch_is_logged_and_does_not_raise(caplog):
    caplog.set_level(logging.ERROR)

    class Broken(FakeGuiServices):
        def active_project(self):
            raise RuntimeError("boom")

    gui.serve_when_ready(
        services=Broken(), context_factory=GuiHarness, input_paths=(),
        host="127.0.0.1", port=8124, wait_for_analysis=True, verbose_analysis=False, symbols_path=None,
    )
    assert "GUI stays open" in caplog.text and "boom" in caplog.text
