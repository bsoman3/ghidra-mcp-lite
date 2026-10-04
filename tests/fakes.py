"""Test doubles: a FakeContext for server tests, and a HarnessContext that runs the real
GhidraContext logic with every Ghidra-touching seam replaced by in-memory fakes."""

import threading
import time
from pathlib import Path

from ghidra_mcp.context import AnalysisOptions, GhidraContext, LoadedProgram, Status


# ── For server tests ─────────────────────────────────────────────────────────


class FakeProgramInfo:
    def __init__(self, name, *, complete=True, file_path=None, load_time=0.0, metadata=None,
                 status=None, failure=None, warnings=None):
        self.name = name
        self.pathname = f"/{name}"
        self.status = status or (Status.READY if complete else Status.FAILED)
        self.file_path = Path(file_path) if file_path else None
        self.load_time = load_time
        self.metadata = metadata or {}
        self.failure = failure
        self.warnings = warnings or []

    @property
    def analysis_complete(self):
        return self.status is Status.READY


class FakeContext:
    """Records calls; behavior is steered by the public attributes."""

    def __init__(self):
        self.programs = {}
        self.calls = []
        self.kwargs = {}
        self.get_program_info_error = None
        self.delete_result = True
        self.delete_error = None
        self.list_error = None
        self.reanalyze_error = None
        self.already_imported: set[str] = set()

    def configure(self, **kwargs):
        self.kwargs = kwargs
        return self

    def list_entries(self):
        if self.list_error is not None:
            raise self.list_error
        return list(self.programs.values())

    def get_program_info(self, binary_name):
        self.calls.append(("get_program_info", binary_name))
        if self.get_program_info_error is not None:
            raise self.get_program_info_error
        return self.programs[binary_name]

    def get_metadata(self, binary_name):
        self.calls.append(("get_metadata", binary_name))
        if self.get_program_info_error is not None:
            raise self.get_program_info_error
        return self.programs[binary_name].metadata

    def import_binary_backgrounded(self, binary_path, options=None):
        self.calls.append(("import_binary_backgrounded", binary_path, options))
        name = Path(binary_path).name
        return ([], [name]) if name in self.already_imported else ([name], [])

    def reanalyze_binary(self, binary_name, options=None):
        self.calls.append(("reanalyze_binary", binary_name, options))
        if self.reanalyze_error is not None:
            raise self.reanalyze_error
        return self.programs.get(binary_name)

    def import_binaries(self, binary_paths, options=None):
        self.calls.append(("import_binaries", list(binary_paths)))

    def analyze_project(self, wait=False):
        self.calls.append(("analyze_project", wait))

    def delete_program(self, program_name):
        self.calls.append(("delete_program", program_name))
        if self.delete_error is not None:
            raise self.delete_error
        return self.delete_result

    def list_binaries(self):
        if self.list_error is not None:
            raise self.list_error
        return list(self.programs)

    def close(self):
        self.calls.append(("close",))


# ── For lifecycle tests: the real GhidraContext over fakes ───────────────────


class FakeProgram:
    def __init__(self, name, *, analyzed=False):
        self.name = name
        self.analyzed = analyzed
        self.stored_options = None
        self.saved = 0


class FakeDecompiler:
    def __init__(self):
        self.disposed = False

    def dispose(self):
        self.disposed = True


class FakeProject:
    def __init__(self):
        self.closed_programs = []
        self.closed = False

    def close(self, program=None):
        if program is None:
            self.closed = True
        else:
            self.closed_programs.append(program)


class FakeDomainFile:
    def __init__(self, pathname, *, metadata=None, analyzed=False, delete_error=None):
        self.pathname = pathname
        self.metadata = metadata if metadata is not None else {"Executable Location": f"/bins{pathname}"}
        self.analyzed = analyzed
        self.delete_error = delete_error
        self.deleted = False

    def getPathname(self):  # noqa: N802 - Ghidra naming
        return self.pathname

    def getName(self):  # noqa: N802 - Ghidra naming
        return Path(self.pathname).name

    def delete(self):
        if self.delete_error is not None:
            raise self.delete_error
        self.deleted = True


class FakeMonitor:
    def __init__(self):
        self.cancelled = threading.Event()

    def cancel(self):
        self.cancelled.set()


class HarnessContext(GhidraContext):
    """The real GhidraContext with its Ghidra seams replaced by fakes."""

    def __init__(self, domain_files=(), *, wait_for_analysis=True, wait_seconds=0.2, tmp_path=None):
        self._fake_files = list(domain_files)
        self.analyses = []  # (name, options, forced)
        self.analysis_behavior = lambda entry, options: None
        self.import_behavior = lambda entry: None
        self.import_error = None
        super().__init__(
            "test",
            project_path=tmp_path or Path("/tmp/ghidra-mcp-harness"),
            wait_for_analysis=wait_for_analysis,
        )
        self.wait_seconds = wait_seconds

    # Ghidra seams ------------------------------------------------------------
    def _get_or_create_project(self):
        return FakeProject()

    def list_binary_domain_files(self):
        return list(self._fake_files)

    def _domain_metadata(self, domain_file):
        return dict(domain_file.metadata)

    def _open_program(self, entry):
        analyzed = bool(entry.domain_file is not None and getattr(entry.domain_file, "analyzed", False))
        return FakeProgram(entry.name, analyzed=analyzed)

    def _setup_decompiler(self, program):
        return FakeDecompiler()

    def _program_metadata(self, program):
        return {"Program Name": program.name}

    def _needs_analysis(self, entry):
        return not entry.program.analyzed

    def _run_analysis(self, entry, options):
        self.analyses.append((entry.name, options, entry.reanalysis_requested))
        self.analysis_behavior(entry, options)
        entry.program.analyzed = True

    def _import_program(self, entry):
        self.import_behavior(entry)
        if self.import_error is not None:
            raise self.import_error
        program = FakeProgram(entry.name)
        self._store_options(program, entry.options or AnalysisOptions())
        return program, FakeDomainFile(entry.pathname)

    def _store_options(self, program, options):
        program.stored_options = options

    def _stored_options(self, program):
        return program.stored_options or AnalysisOptions()

    def _save(self, program):
        program.saved += 1


def wait_until(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    raise AssertionError("condition not reached in time")


def settled(entry: LoadedProgram) -> bool:
    return entry.status in (Status.READY, Status.FAILED)
