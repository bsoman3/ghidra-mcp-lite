"""program-lifecycle: registry, lazy opening, status and gate, imports, re-analysis, deletion, shutdown.

Runs the real GhidraContext logic over fakes (tests/fakes.py HarnessContext); no Ghidra needed.
"""

import logging
import threading
import time
from pathlib import Path

import pytest

from ghidra_mcp.context import AnalysisOptions, GhidraContext, Status
from ghidra_mcp.errors import RetryLater, Stop
from ghidra_mcp.tools import GhidraTools, handle_exceptions
from tests.fakes import FakeDomainFile, FakeMonitor, HarnessContext, settled, wait_until


def make_ctx(*pathnames, analyzed=(), tmp_path=None, **kwargs):
    files = [FakeDomainFile(p, analyzed=p in analyzed) for p in pathnames]
    return HarnessContext(files, tmp_path=tmp_path, **kwargs)


@pytest.fixture
def gate():
    event = threading.Event()
    yield event
    event.set()


# ── Registration and lazy opening ────────────────────────────────────────────


# @spec LIFE-002
def test_construction_registers_program_files_without_opening_them(tmp_path):
    ctx = make_ctx("/a-111111", "/b-222222", tmp_path=tmp_path)
    assert set(ctx.programs) == {"/a-111111", "/b-222222"}
    assert all(e.program is None for e in ctx.list_entries())
    assert all(e.status is Status.ANALYZING for e in ctx.list_entries())


# @spec LIFE-042
def test_listing_metadata_of_unopened_programs_comes_from_the_project_file(tmp_path):
    ctx = make_ctx("/a-111111", tmp_path=tmp_path)
    (entry,) = ctx.list_entries()
    assert entry.program is None
    assert entry.metadata["Executable Location"] == "/bins/a-111111"
    assert entry.file_path == Path("/bins/a-111111")


# @spec LIFE-038, LIFE-004, LIFE-005
def test_first_use_opens_the_program_with_a_decompiler_and_metadata(tmp_path):
    ctx = make_ctx("/a-111111", analyzed={"/a-111111"}, tmp_path=tmp_path)
    entry = ctx.get_program_info("/a-111111")
    assert entry.program is not None
    assert entry.decompiler is not None
    assert entry.metadata == {"Program Name": "a-111111"}


# ── Analysis scheduling and status ───────────────────────────────────────────


# @spec LIFE-016, LIFE-022, LIFE-024
def test_analysis_pass_runs_every_binary_on_one_background_worker(tmp_path):
    ctx = make_ctx("/a", "/b", tmp_path=tmp_path)
    threads = []
    ctx.analysis_behavior = lambda e, o: threads.append(threading.current_thread())
    ctx.analyze_project(wait=True)
    assert [e.status for e in ctx.list_entries()] == [Status.READY, Status.READY]
    assert len(set(threads)) == 1 and threads[0] is not threading.main_thread()
    assert ctx._executor._max_workers == 1


# @spec LIFE-017
def test_analysis_started_for_serving_returns_immediately(tmp_path, gate):
    ctx = make_ctx("/a", tmp_path=tmp_path)
    ctx.analysis_behavior = lambda e, o: gate.wait(5)
    started = time.monotonic()
    ctx.analyze_project()
    assert time.monotonic() - started < 1


# @spec LIFE-019
def test_an_already_analyzed_program_skips_auto_analysis(tmp_path):
    ctx = make_ctx("/a", analyzed={"/a"}, tmp_path=tmp_path)
    ctx.analyze_project(wait=True)
    assert ctx.analyses == []
    assert ctx.programs["/a"].status is Status.READY


# @spec LIFE-020
def test_a_completed_analysis_saves_the_program(tmp_path):
    ctx = make_ctx("/a", tmp_path=tmp_path)
    ctx.analyze_project(wait=True)
    assert ctx.programs["/a"].program.saved == 1


# @spec LIFE-023
def test_a_tool_gets_an_already_analyzed_program_without_waiting_for_the_pass(tmp_path):
    ctx = make_ctx("/a", analyzed={"/a"}, tmp_path=tmp_path)
    entry = ctx.get_program_info("/a")  # the background pass hasn't started
    assert entry.status is Status.READY
    assert ctx.analyses == []


# @spec LIFE-031, LIFE-040, LIFE-018
def test_a_failed_analysis_is_recorded_not_saved_and_the_pass_continues(tmp_path):
    ctx = make_ctx("/a", "/b", tmp_path=tmp_path)

    def behavior(entry, options):
        if entry.name == "a":
            raise RuntimeError("analyzer exploded")

    ctx.analysis_behavior = behavior
    ctx.analyze_project(wait=True)
    a, b = ctx.programs["/a"], ctx.programs["/b"]
    assert a.status is Status.FAILED and "analyzer exploded" in a.failure
    assert a.program.saved == 0
    assert b.status is Status.READY


# @spec LIFE-037
def test_status_failure_and_warnings_are_exposed_on_listed_entries(tmp_path):
    ctx = make_ctx("/a", tmp_path=tmp_path)
    ctx.analysis_behavior = lambda e, o: e.warnings.append("GDT 'x.gdt' could not be applied")
    ctx.analyze_project(wait=True)
    (entry,) = ctx.list_entries()
    assert entry.status is Status.READY and entry.failure is None
    assert entry.warnings == ["GDT 'x.gdt' could not be applied"]


# ── The gate ─────────────────────────────────────────────────────────────────


# @spec LIFE-032
def test_gate_refuses_a_failed_binary_with_stop_and_its_reason(tmp_path):
    ctx = make_ctx("/a", tmp_path=tmp_path)
    ctx.analysis_behavior = lambda e, o: (_ for _ in ()).throw(RuntimeError("bad pdb"))
    ctx.analyze_project(wait=True)
    with pytest.raises(Stop, match="bad pdb") as raised:
        ctx.get_program_info("/a")
    assert "Analysis failed" in str(raised.value) and "reanalyze_binary" in str(raised.value)


# @spec LIFE-032
def test_gate_refuses_a_failed_import_with_stop_naming_import_binary(tmp_path):
    binary = tmp_path / "junk.bin"
    binary.write_bytes(b"\x00")
    ctx = make_ctx(tmp_path=tmp_path)
    ctx.import_error = RuntimeError("No load spec found")
    (name,), _ = ctx.import_binary_backgrounded(binary)
    wait_until(lambda: settled(ctx.programs[f"/{name}"]))
    with pytest.raises(Stop, match="No load spec found") as raised:
        ctx.get_program_info(name)
    message = str(raised.value)
    assert "Import failed" in message and "import_binary" in message
    assert "Analysis failed" not in message


# @spec LIFE-039, LIFE-008
def test_gate_waits_then_reports_how_long_analysis_has_been_running(tmp_path, gate):
    ctx = make_ctx("/a", tmp_path=tmp_path, wait_seconds=0.3)
    ctx.analysis_behavior = lambda e, o: gate.wait(5)
    ctx.analyze_project()
    wait_until(lambda: ctx.programs["/a"].work_started is not None)
    started = time.monotonic()
    with pytest.raises(RetryLater, match="has been running for"):
        ctx.get_program_info("/a")
    assert time.monotonic() - started >= 0.25


# @spec LIFE-039
def test_gate_returns_as_soon_as_analysis_finishes_within_the_wait(tmp_path):
    ctx = make_ctx("/a", tmp_path=tmp_path, wait_seconds=5)
    ctx.analysis_behavior = lambda e, o: time.sleep(0.2)
    ctx.analyze_project()
    started = time.monotonic()
    assert ctx.get_program_info("/a").status is Status.READY
    assert time.monotonic() - started < 3


# @spec LIFE-008
def test_gate_reports_queue_position(tmp_path, gate):
    ctx = make_ctx("/a", "/b", "/c", tmp_path=tmp_path, wait_seconds=0.05)
    ctx.analysis_behavior = lambda e, o: gate.wait(5)
    ctx.analyze_project()
    wait_until(lambda: ctx.programs["/a"].work_started is not None)
    with pytest.raises(RetryLater, match="behind 1 other binary"):
        ctx.get_program_info("/b")
    with pytest.raises(RetryLater, match="behind 2 other binaries"):
        ctx.get_program_info("/c")


# @spec LIFE-039
def test_without_waiting_the_gate_refuses_at_once(tmp_path, gate):
    ctx = make_ctx("/a", tmp_path=tmp_path, wait_for_analysis=False, wait_seconds=5)
    ctx.analysis_behavior = lambda e, o: gate.wait(5)
    ctx.analyze_project()
    started = time.monotonic()
    with pytest.raises(RetryLater):
        ctx.get_program_info("/a")
    assert time.monotonic() - started < 1


# @spec LIFE-039
def test_waiting_is_on_by_default_with_a_45_second_cap():
    import inspect

    assert inspect.signature(GhidraContext.__init__).parameters["wait_for_analysis"].default is True
    from ghidra_mcp.context import WAIT_FOR_ANALYSIS_SECONDS

    assert WAIT_FOR_ANALYSIS_SECONDS == 45


# @spec LIFE-006, LIFE-007, LIFE-030
def test_resolution_by_pathname_basename_and_ambiguity(tmp_path):
    ctx = make_ctx("/a-111111", "/x/dup-1", "/y/dup-1",
                   analyzed={"/a-111111", "/x/dup-1", "/y/dup-1"}, tmp_path=tmp_path)
    assert ctx.get_program_info("a-111111").pathname == "/a-111111"
    with pytest.raises(ValueError, match="not found"):
        ctx.get_program_info("nope")
    with pytest.raises(ValueError, match=r"/x/dup-1.*/y/dup-1"):
        ctx.get_program_info("dup-1")


# ── Imports ──────────────────────────────────────────────────────────────────


# @spec LIFE-014, LIFE-033, LIFE-043
def test_background_import_is_listed_as_importing_then_analyzed_with_its_options(tmp_path, gate):
    binary = tmp_path / "tool.exe"
    binary.write_bytes(b"MZ\x90\x00")
    ctx = make_ctx(tmp_path=tmp_path)
    ctx.import_behavior = lambda e: gate.wait(5)
    options = AnalysisOptions.create(no_symbols=True, analyzer_options={"Stack": False})
    (name,), _ = ctx.import_binary_backgrounded(binary, options)
    (entry,) = ctx.list_entries()
    assert entry.status is Status.IMPORTING and entry.source_path == binary and entry.name == name
    gate.set()
    wait_until(lambda: settled(entry))
    assert entry.status is Status.READY
    assert ctx.analyses[-1][:2] == (name, options)
    assert entry.program.stored_options == options


# @spec LIFE-034
def test_failed_background_import_is_listed_as_failed_with_its_reason(tmp_path):
    binary = tmp_path / "junk.bin"
    binary.write_bytes(b"\x00")
    ctx = make_ctx(tmp_path=tmp_path)
    ctx.import_error = RuntimeError("No load spec found")
    ctx.import_binary_backgrounded(binary)
    (entry,) = ctx.list_entries()
    wait_until(lambda: settled(entry))
    assert entry.status is Status.FAILED
    assert "No load spec found" in entry.failure


# @spec LIFE-015
def test_background_import_logs_its_success_or_failure(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="ghidra_mcp.context")
    good, bad = tmp_path / "good", tmp_path / "bad"
    good.write_bytes(b"1")
    bad.write_bytes(b"2")
    ctx = make_ctx(tmp_path=tmp_path)
    (good_name,), _ = ctx.import_binary_backgrounded(good)
    wait_until(lambda: settled(ctx.programs[f"/{good_name}"]))
    assert f"Import complete: {good_name}" in caplog.text
    ctx.import_error = RuntimeError("No load spec found")
    (bad_name,), _ = ctx.import_binary_backgrounded(bad)
    wait_until(lambda: settled(ctx.programs[f"/{bad_name}"]))
    assert "Failed to import" in caplog.text and "No load spec found" in caplog.text


# @spec LIFE-014
def test_background_import_of_a_missing_path_raises_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        make_ctx(tmp_path=tmp_path).import_binary_backgrounded(tmp_path / "missing")


# @spec LIFE-046
def test_missing_pdb_or_gdt_paths_are_rejected_before_anything_is_queued(tmp_path):
    with pytest.raises(ValueError, match="nope.pdb"):
        AnalysisOptions.create(pdb_path=tmp_path / "nope.pdb")
    with pytest.raises(ValueError, match="nope.gdt"):
        AnalysisOptions.create(gdts=[tmp_path / "nope.gdt"])


# @spec LIFE-009, LIFE-010
def test_import_names_by_content_hash_and_skips_a_reimport(tmp_path):
    binary = tmp_path / "hello"
    binary.write_bytes(b"hello world")
    ctx = make_ctx(tmp_path=tmp_path)
    (name,), _ = ctx.import_binary_backgrounded(binary, AnalysisOptions(no_symbols=True))
    assert name == "hello-2aae6c"  # sha1("hello world")[:6]
    entry = ctx.programs[f"/{name}"]
    wait_until(lambda: settled(entry))
    queued, existing = ctx.import_binary_backgrounded(binary, AnalysisOptions())
    assert queued == [] and existing == [name]
    assert len(ctx.list_entries()) == 1
    assert entry.program.stored_options == AnalysisOptions(no_symbols=True)  # unchanged


# @spec LIFE-012
def test_directory_import_queues_every_file_beneath_it(tmp_path):
    root = tmp_path / "bins"
    (root / "sub").mkdir(parents=True)
    (root / "one").write_bytes(b"1")
    (root / "sub" / "two").write_bytes(b"2")
    ctx = make_ctx(tmp_path=tmp_path)
    queued, existing = ctx.import_binary_backgrounded(root)
    assert len(queued) == 2 and existing == []


# @spec LIFE-011, LIFE-013
def test_command_line_import_continues_past_a_failure_and_records_it(tmp_path):
    good, bad = tmp_path / "good", tmp_path / "bad"
    good.write_bytes(b"good")
    bad.write_bytes(b"bad")
    ctx = make_ctx(tmp_path=tmp_path)
    original = ctx._import_program

    def importer(entry):
        if entry.source_path == bad:
            raise RuntimeError("unsupported format")
        return original(entry)

    ctx._import_program = importer
    ctx.import_binaries([bad, good])
    statuses = {e.source_path.name: e.status for e in ctx.list_entries()}
    assert statuses == {"bad": Status.FAILED, "good": Status.ANALYZING}


# ── Re-analysis ──────────────────────────────────────────────────────────────


# @spec LIFE-044, LIFE-019
def test_reanalysis_replaces_options_clears_failure_and_forces_a_pass(tmp_path, gate):
    ctx = make_ctx("/a", analyzed={"/a"}, tmp_path=tmp_path)
    entry = ctx.get_program_info("/a")
    entry.warnings = ["stale warning"]
    entry.failure = "stale failure"
    ctx.analysis_behavior = lambda e, o: gate.wait(5)
    new = AnalysisOptions.create(analyzer_options={"Decompiler Parameter ID": False})
    ctx.reanalyze_binary("a", new)
    assert entry.status is Status.ANALYZING
    assert entry.warnings == [] and entry.failure is None
    gate.set()
    wait_until(lambda: settled(entry))
    assert entry.status is Status.READY
    assert ctx.analyses[-1] == ("a", new, True)
    assert entry.program.stored_options == new


# @spec LIFE-044
def test_reanalysis_recovers_a_failed_binary(tmp_path):
    ctx = make_ctx("/a", tmp_path=tmp_path)
    ctx.analysis_behavior = lambda e, o: (_ for _ in ()).throw(RuntimeError("first try"))
    ctx.analyze_project(wait=True)
    ctx.analysis_behavior = lambda e, o: None
    entry = ctx.reanalyze_binary("/a", AnalysisOptions())
    wait_until(lambda: settled(entry))
    assert entry.status is Status.READY


# @spec LIFE-048
def test_reanalysis_of_a_failed_import_is_stop_directing_to_import_binary(tmp_path):
    binary = tmp_path / "junk.bin"
    binary.write_bytes(b"\x00")
    ctx = make_ctx(tmp_path=tmp_path)
    ctx.import_error = RuntimeError("No load spec found")
    (name,), _ = ctx.import_binary_backgrounded(binary)
    wait_until(lambda: settled(ctx.programs[f"/{name}"]))
    with pytest.raises(Stop, match="import"):
        ctx.reanalyze_binary(name, AnalysisOptions())


# @spec LIFE-045
def test_reanalysis_is_refused_while_the_binary_is_pending(tmp_path, gate):
    ctx = make_ctx("/a", tmp_path=tmp_path)
    ctx.analysis_behavior = lambda e, o: gate.wait(5)
    ctx.analyze_project()
    with pytest.raises(RetryLater, match="already"):
        ctx.reanalyze_binary("/a", AnalysisOptions())


# ── Deletion ─────────────────────────────────────────────────────────────────


# @spec LIFE-026, LIFE-035
def test_delete_closes_the_program_disposes_its_decompiler_and_unregisters_it(tmp_path):
    ctx = make_ctx("/a", analyzed={"/a"}, tmp_path=tmp_path)
    entry = ctx.get_program_info("/a")
    program, decompiler, domain_file = entry.program, entry.decompiler, entry.domain_file
    assert ctx.delete_program("a") is True
    assert "/a" not in ctx.programs
    assert program in ctx.project.closed_programs
    assert decompiler.disposed and domain_file.deleted


# @spec LIFE-027
def test_deleting_an_unknown_binary_raises_value_error(tmp_path):
    with pytest.raises(ValueError, match="not found"):
        make_ctx(tmp_path=tmp_path).delete_program("nope")


# @spec LIFE-036, LIFE-028
def test_a_failed_delete_leaves_the_binary_unopened_and_reports_why(tmp_path):
    domain_file = FakeDomainFile("/a", analyzed=True, delete_error=OSError("file is locked"))
    ctx = HarnessContext([domain_file], tmp_path=tmp_path)
    ctx.get_program_info("/a")
    with pytest.raises(Stop, match="file is locked"):
        ctx.delete_program("/a")
    entry = ctx.programs["/a"]
    assert entry.program is None
    assert ctx.get_program_info("/a").program is not None  # reopened on next use


# @spec LIFE-047
def test_deleting_a_binary_under_analysis_is_retry_later(tmp_path, gate):
    ctx = make_ctx("/a", tmp_path=tmp_path)
    ctx.analysis_behavior = lambda e, o: gate.wait(5)
    ctx.analyze_project()
    with pytest.raises(RetryLater):
        ctx.delete_program("/a")
    assert "/a" in ctx.programs and not ctx.programs["/a"].domain_file.deleted


# ── Concurrency and shutdown ─────────────────────────────────────────────────


# @spec LIFE-025, LIFE-041
def test_listing_is_safe_while_background_imports_mutate_the_registry(tmp_path):
    ctx = make_ctx(tmp_path=tmp_path)
    for i in range(40):
        f = tmp_path / f"bin{i}"
        f.write_bytes(str(i).encode())
        ctx.import_binary_backgrounded(f)
    for _ in range(200):
        [e.status for e in ctx.list_entries()]
    wait_until(lambda: all(settled(e) for e in ctx.list_entries()))


# @spec LIFE-041
def test_tool_methods_run_under_their_programs_lock(tmp_path):
    ctx = make_ctx("/a", analyzed={"/a"}, tmp_path=tmp_path)
    entry = ctx.get_program_info("/a")

    class Probe(GhidraTools):
        @handle_exceptions
        def probe(self):
            return self.program_info.lock._is_owned()

    assert Probe(entry).probe() is True


# @spec LIFE-029, LIFE-035
def test_close_cancels_running_analysis_closes_programs_and_disposes_decompilers(tmp_path):
    ctx = make_ctx("/a", "/b", analyzed={"/b"}, tmp_path=tmp_path)
    monitor = FakeMonitor()

    def behavior(entry, options):
        ctx._monitor = monitor
        if not monitor.cancelled.wait(5):
            raise AssertionError("analysis was not cancelled")
        raise RuntimeError("cancelled")

    ctx.analysis_behavior = behavior
    b = ctx.get_program_info("/b")
    ctx.analyze_project()
    wait_until(lambda: ctx.programs["/a"].work_started is not None)
    ctx.close()
    assert monitor.cancelled.is_set()
    assert b.decompiler is None and b.program is None
    assert ctx.project.closed
