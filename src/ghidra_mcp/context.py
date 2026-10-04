"""
Ghidra project and program lifecycle management, and per-binary analysis configuration.
No ChromaDB, no ML/embedding — native Ghidra only.

See docs/intent/program-lifecycle/ and docs/intent/analysis-config/ for the design.

Locking (acquire only in this order): a program's own lock → the project-operations lock →
the registry lock. The registry lock is held only briefly; no lock is held while a tool call
waits for a binary to become ready.
"""

import concurrent.futures
import hashlib
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from ghidra_mcp.errors import FixInput, RetryLater, Stop, describe

if TYPE_CHECKING:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.base.project import GhidraProject
    from ghidra.framework.model import DomainFile
    from ghidra.program.model.listing import Program

logger = logging.getLogger(__name__)

# How long a tool call waits for a pending binary before answering retry_later.
WAIT_FOR_ANALYSIS_SECONDS = 45

# Program-options category and key under which a binary's analysis options are persisted.
OPTIONS_CATEGORY = "ghidra-mcp"
OPTIONS_KEY = "analysis-options"

PDB_ANALYZER = "PDB Universal"


class Status(str, Enum):
    IMPORTING = "importing"
    ANALYZING = "analyzing"  # queued for or undergoing analysis
    READY = "ready"
    FAILED = "failed"


@dataclass(frozen=True)
class AnalysisOptions:
    """A binary's analysis options (program-lifecycle LIFE-043; the inputs of analysis-config)."""

    no_symbols: bool = False
    pdb_path: Path | None = None
    gdts: tuple[Path, ...] = ()
    analyzer_options: dict[str, Any] = field(default_factory=dict)

    # @spec LIFE-046
    @classmethod
    def create(
        cls,
        *,
        no_symbols: bool = False,
        pdb_path: str | Path | None = None,
        gdts: list[str | Path] | tuple[str | Path, ...] | None = None,
        analyzer_options: dict[str, Any] | None = None,
    ) -> "AnalysisOptions":
        """Build options supplied by a caller, rejecting PDB or GDT paths that don't exist."""
        options = cls(
            no_symbols=bool(no_symbols),
            pdb_path=Path(pdb_path) if pdb_path else None,
            gdts=tuple(Path(g) for g in (gdts or ())),
            analyzer_options=dict(analyzer_options or {}),
        )
        for path in ([options.pdb_path] if options.pdb_path else []) + list(options.gdts):
            if not path.is_file():
                raise FixInput(f"File not found: {path}")
        return options

    def to_json(self) -> str:
        return json.dumps(
            {
                "no_symbols": self.no_symbols,
                "pdb_path": str(self.pdb_path) if self.pdb_path else None,
                "gdts": [str(g) for g in self.gdts],
                "analyzer_options": self.analyzer_options,
            }
        )

    @classmethod
    def from_json(cls, text: str) -> "AnalysisOptions":
        data = json.loads(text)
        return cls(
            no_symbols=bool(data.get("no_symbols", False)),
            pdb_path=Path(data["pdb_path"]) if data.get("pdb_path") else None,
            gdts=tuple(Path(g) for g in data.get("gdts", ())),
            analyzer_options=dict(data.get("analyzer_options", {})),
        )


@dataclass(eq=False)
class LoadedProgram:
    """Runtime state for one binary in the project. The program itself is opened lazily."""

    name: str
    pathname: str
    project: "GhidraProject | None"
    status: Status = Status.ANALYZING
    domain_file: "DomainFile | None" = None
    program: "Program | None" = None
    decompiler: "DecompInterface | None" = None
    metadata: dict = field(default_factory=dict)
    file_path: Path | None = None
    load_time: float = field(default_factory=time.time)
    options: AnalysisOptions | None = None  # None: read the persisted options when analyzing
    source_path: Path | None = None  # set for imports
    failure: str | None = None
    warnings: list[str] = field(default_factory=list)
    reanalysis_requested: bool = False
    work_started: float | None = None  # when the current import/analysis began
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    settled: threading.Event = field(default_factory=threading.Event, repr=False)

    @property
    def analysis_complete(self) -> bool:
        return self.status is Status.READY


def _executable_location(metadata: dict) -> Path | None:
    location = metadata.get("Executable Location")
    return Path(location) if location else None


def _duration(seconds: float) -> str:
    minutes, secs = divmod(int(seconds), 60)
    return f"{minutes}m {secs:02d}s" if minutes else f"{secs}s"


class GhidraContext:
    """
    Manages a Ghidra project: registration, lazy opening, import, analysis, status, and cleanup.
    Deliberately omits ChromaDB — all search uses native Ghidra iterators.
    """

    def __init__(
        self,
        project_name: str,
        project_path: str | Path,
        verbose_analysis: bool = False,
        wait_for_analysis: bool = True,
        symbols_path: str | Path | None = None,
    ):
        self.project_name = project_name
        self.project_path = Path(project_path)
        self.verbose_analysis = verbose_analysis
        self.wait_for_analysis = wait_for_analysis
        self.wait_seconds: float = WAIT_FOR_ANALYSIS_SECONDS
        self.symbols_path = Path(symbols_path) if symbols_path else self.project_path / "symbols"

        self._registry_lock = threading.RLock()
        self._project_ops_lock = threading.RLock()
        self._queue: list[str] = []  # pathnames waiting for or under background work, in order
        # @spec LIFE-024: one background worker for imports and analysis.
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self._monitor = None  # task monitor of the running analysis; cancelled by close()
        self._closing = False

        self.programs: dict[str, LoadedProgram] = {}
        self.project: "GhidraProject" = self._get_or_create_project()
        self._register_project_programs()

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    # @spec LIFE-029, LIFE-035
    def close(self):
        """Cancel in-flight analysis, then close every opened program without saving and the project.

        Edits and completed analyses are saved when they happen, and GhidraProject.close discards
        anything unsaved.
        """
        self._closing = True
        monitor = self._monitor
        if monitor is not None:
            try:
                monitor.cancel()
            except Exception as e:
                logger.warning(f"Could not cancel analysis: {e}")
        self._executor.shutdown(wait=True, cancel_futures=True)
        for entry in self.list_entries():
            self._close_program(entry)
        self.project.close()
        logger.info(f"Project '{self.project_name}' closed.")

    # -------------------------------------------------------------------------
    # Project and registry
    # -------------------------------------------------------------------------

    def _get_or_create_project(self) -> "GhidraProject":
        from ghidra.base.project import GhidraProject
        from ghidra.framework.model import ProjectLocator

        self.project_path.mkdir(exist_ok=True, parents=True)
        proj_dir = str(self.project_path.absolute())
        locator = ProjectLocator(proj_dir, self.project_name)

        if locator.exists():
            logger.info(f"Opening existing project: {self.project_name}")
            return GhidraProject.openProject(proj_dir, self.project_name, True)
        logger.info(f"Creating new project: {self.project_name}")
        return GhidraProject.createProject(proj_dir, self.project_name, False)

    # @spec LIFE-002, LIFE-042
    def _register_project_programs(self) -> None:
        """Register every Program file in the project without opening it."""
        for df in self.list_binary_domain_files():
            metadata = self._domain_metadata(df)
            entry = LoadedProgram(
                name=df.getName(),
                pathname=df.getPathname(),
                project=self.project,
                domain_file=df,
                metadata=metadata,
                file_path=_executable_location(metadata),
            )
            self.programs[entry.pathname] = entry

    def list_binary_domain_files(self) -> list["DomainFile"]:
        """Return DomainFile objects for all Program-type files in the project."""

        def _walk(folder) -> list:
            files = []
            for sub in folder.getFolders():
                files.extend(_walk(sub))
            files.extend(f for f in folder.getFiles() if f.getContentType() == "Program")
            return files

        return _walk(self.project.getRootFolder())

    def list_binaries(self) -> list[str]:
        """Return the project pathnames of all registered programs."""
        return [entry.pathname for entry in self.list_entries()]

    # @spec LIFE-025
    def list_entries(self) -> list[LoadedProgram]:
        """A snapshot of every binary the context knows about, including in-progress imports."""
        with self._registry_lock:
            return list(self.programs.values())

    # @spec LIFE-006, LIFE-007, LIFE-030
    def _resolve(self, binary_name: str) -> LoadedProgram:
        with self._registry_lock:
            entry = self.programs.get(binary_name)
            if entry is not None:
                return entry
            matches = [e for path, e in self.programs.items() if Path(path).name == binary_name]
            if len(matches) > 1:
                candidates = ", ".join(sorted(e.pathname for e in matches))
                raise FixInput(f"Binary '{binary_name}' is ambiguous. Did you mean: {candidates}")
            if not matches:
                raise FixInput(
                    f"Binary '{binary_name}' not found. Available: {list(self.programs.keys())}"
                )
            return matches[0]

    # @spec LIFE-008, LIFE-023, LIFE-032, LIFE-039
    def get_program_info(self, binary_name: str) -> LoadedProgram:
        """Resolve a binary for a tool call: open it if needed, and refuse it unless it is ready."""
        entry = self._resolve(binary_name)
        self._ready_if_already_analyzed(entry)
        if entry.status in (Status.IMPORTING, Status.ANALYZING) and self.wait_for_analysis:
            entry.settled.wait(self.wait_seconds)  # holds no lock
        if entry.status is Status.FAILED:
            raise Stop(self._failed_message(entry))
        if entry.status is not Status.READY:
            raise RetryLater(self._pending_message(entry))
        self._ensure_open(entry)
        return entry

    # @spec SRV-022
    def get_metadata(self, binary_name: str) -> dict:
        """A registered binary's Ghidra metadata, whatever its analysis state."""
        entry = self._resolve(binary_name)
        if entry.status is Status.IMPORTING:
            raise RetryLater(self._pending_message(entry))
        return dict(entry.metadata)

    def _ready_if_already_analyzed(self, entry: LoadedProgram) -> None:
        """A program Ghidra already marks as analyzed is ready without waiting for the pass."""
        if entry.status is not Status.ANALYZING or entry.reanalysis_requested:
            return
        if entry.work_started is not None or entry.domain_file is None:
            return
        if not entry.lock.acquire(blocking=False):  # being analyzed right now
            return
        try:
            if entry.status is Status.ANALYZING and not entry.reanalysis_requested:
                self._ensure_open(entry)
                if not self._needs_analysis(entry):
                    self._settle(entry, Status.READY)
        finally:
            entry.lock.release()

    @staticmethod
    def _failed_message(entry: LoadedProgram) -> str:
        if entry.domain_file is None:  # never made it into the project
            step = "Check the file and call import_binary again."
        else:
            step = "Call reanalyze_binary to retry, optionally with different analysis options."
        return f"'{entry.name}' is unusable. {entry.failure} {step}"

    def _pending_message(self, entry: LoadedProgram) -> str:
        action = "Import" if entry.status is Status.IMPORTING else "Analysis"
        if entry.work_started is not None:
            elapsed = _duration(time.time() - entry.work_started)
            return f"{action} of '{entry.name}' has been running for {elapsed}; retry later."
        with self._registry_lock:
            queue = list(self._queue)
        ahead = queue.index(entry.pathname) if entry.pathname in queue else len(queue)
        noun = "binary" if ahead == 1 else "binaries"
        return (
            f"'{entry.name}' is queued for {action.lower()} behind {ahead} other {noun}; "
            "retry later."
        )

    def _settle(self, entry: LoadedProgram, status: Status) -> None:
        entry.status = status
        entry.settled.set()

    def _warn(self, entry: LoadedProgram, message: str) -> None:
        entry.warnings.append(message)
        logger.warning(f"{entry.name}: {message}")

    # -------------------------------------------------------------------------
    # Opening and closing programs
    # -------------------------------------------------------------------------

    # @spec LIFE-038, LIFE-004, LIFE-005
    def _ensure_open(self, entry: LoadedProgram) -> None:
        with entry.lock:
            if entry.program is not None:
                return
            with self._project_ops_lock:
                program = self._open_program(entry)
            entry.program = program
            entry.decompiler = self._setup_decompiler(program)
            entry.metadata = self._program_metadata(program)
            entry.file_path = _executable_location(entry.metadata)

    def _close_program(self, entry: LoadedProgram) -> None:
        with entry.lock:
            if entry.decompiler is not None:
                try:
                    entry.decompiler.dispose()
                except Exception as e:
                    logger.warning(f"Could not dispose decompiler for {entry.name}: {e}")
                entry.decompiler = None
            if entry.program is not None:
                try:
                    self.project.close(entry.program)
                except Exception as e:
                    logger.warning(f"Could not close {entry.name}: {e}")
                entry.program = None

    # -------------------------------------------------------------------------
    # Deletion
    # -------------------------------------------------------------------------

    # @spec LIFE-026, LIFE-027, LIFE-028, LIFE-036
    def delete_program(self, program_name: str) -> bool:
        """Remove a binary from the project. Raises Stop with the reason if the delete fails."""
        entry = self._resolve(program_name)
        if entry.status in (Status.IMPORTING, Status.ANALYZING):
            raise RetryLater(f"'{entry.name}' is being imported or analyzed; retry when it finishes.")
        with entry.lock:
            self._close_program(entry)
            if entry.domain_file is not None:
                with self._project_ops_lock:
                    try:
                        entry.domain_file.delete()
                    except Exception as e:
                        logger.error(f"Error deleting '{entry.pathname}': {e}")
                        raise Stop(f"Could not delete '{entry.name}': {describe(e)}") from e
            with self._registry_lock:
                self.programs.pop(entry.pathname, None)
        logger.info(f"Deleted program: {entry.pathname}")
        return True

    # -------------------------------------------------------------------------
    # Import
    # -------------------------------------------------------------------------

    @staticmethod
    def _unique_name(path: Path) -> str:
        """Generate a unique program name: <filename>-<sha1[:6]>."""
        sha1 = hashlib.sha1()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha1.update(chunk)
        return f"{path.name}-{sha1.hexdigest()[:6]}"

    def _new_import_entry(self, path: Path, options: AnalysisOptions | None) -> LoadedProgram | None:
        """Register an import, or return None if that file is already in the project."""
        name = self._unique_name(path)
        pathname = f"/{name}"
        with self._registry_lock:
            existing = self.programs.get(pathname)
            if existing is not None and not (
                existing.status is Status.FAILED and existing.domain_file is None
            ):
                logger.info(f"Already imported: {name}")
                return None
            entry = LoadedProgram(
                name=name,
                pathname=pathname,
                project=self.project,
                status=Status.IMPORTING,
                source_path=path,
                options=options,
            )
            self.programs[pathname] = entry
            return entry

    @staticmethod
    def _files_under(path: Path) -> list[Path]:
        return sorted(f for f in path.rglob("*") if f.is_file()) if path.is_dir() else [path]

    # @spec LIFE-014, LIFE-033, LIFE-012, LIFE-010
    def import_binary_backgrounded(
        self, binary_path: str | Path, options: AnalysisOptions | None = None
    ) -> tuple[list[str], list[str]]:
        """Queue import and analysis of a file (or every file under a directory).

        Returns (names queued for import, names already in the project). A binary already in
        the project is not re-imported and keeps its stored analysis options.
        """
        path = Path(binary_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {binary_path}")
        queued, existing = [], []
        for file in self._files_under(path):
            entry = self._new_import_entry(file, options)
            if entry is None:
                existing.append(self._unique_name(file))
                continue
            with self._registry_lock:
                self._queue.append(entry.pathname)
            self._executor.submit(self._import_job, entry)
            queued.append(entry.name)
        return queued, existing

    # @spec LIFE-011, LIFE-013
    def import_binaries(
        self, binary_paths: list[str | Path], options: AnalysisOptions | None = None
    ) -> None:
        """Import binaries synchronously (command-line inputs); analysis is queued separately."""
        for p in binary_paths:
            path = Path(p)
            try:
                files = self._files_under(path)
            except Exception as e:
                logger.error(f"Failed to import {p}: {e}")
                continue
            for file in files:
                try:
                    entry = self._new_import_entry(file, options)
                except Exception as e:
                    logger.error(f"Failed to import {file}: {e}")
                    continue
                if entry is not None:
                    self._import_into_project(entry)

    def _import_into_project(self, entry: LoadedProgram) -> bool:
        """Import an entry's file into the project; on failure record it and return False."""
        logger.info(f"Importing: {entry.name} from {entry.source_path}")
        try:
            with self._project_ops_lock:
                program, domain_file = self._import_program(entry)
        except Exception as e:
            logger.error(f"Failed to import {entry.source_path}: {e}")
            entry.failure = f"Import failed: {describe(e)}"
            self._settle(entry, Status.FAILED)  # @spec LIFE-034
            return False
        with entry.lock:
            entry.program = program
            entry.domain_file = domain_file
            entry.decompiler = self._setup_decompiler(program)
            entry.metadata = self._program_metadata(program)
            entry.file_path = _executable_location(entry.metadata) or entry.source_path
            entry.status = Status.ANALYZING
        logger.info(f"Import complete: {entry.name}")
        return True

    def _import_job(self, entry: LoadedProgram) -> None:
        entry.work_started = time.time()
        if self._import_into_project(entry):
            self._analyze_job(entry)
        else:
            self._dequeue(entry)

    # -------------------------------------------------------------------------
    # Analysis scheduling
    # -------------------------------------------------------------------------

    # @spec LIFE-016, LIFE-017
    def analyze_project(self, wait: bool = False) -> list[concurrent.futures.Future] | None:
        """
        Queue an analysis pass for every binary awaiting analysis, one job per binary.
        With wait=True (used by --analyze-only) the call blocks until the pass finishes;
        when serving it returns immediately so the MCP handshake is never delayed.
        """
        with self._registry_lock:
            pending = [
                e for e in self.programs.values()
                if e.status is Status.ANALYZING and e.pathname not in self._queue
            ]
            self._queue.extend(e.pathname for e in pending)
        logger.info(f"Starting analysis for {len(pending)} binaries")
        futures = [self._executor.submit(self._analyze_job, e) for e in pending]
        if wait:
            logger.info("Waiting for analysis to complete...")
            concurrent.futures.wait(futures)
            return None
        return futures

    # @spec LIFE-044
    def reanalyze_binary(self, binary_name: str, options: AnalysisOptions | None = None) -> LoadedProgram:
        """Re-run analysis of one binary with new options; returns immediately."""
        options = options or AnalysisOptions()
        entry = self._resolve(binary_name)
        self._refuse_if_pending(entry)
        with entry.lock:
            self._refuse_if_pending(entry)
            if entry.domain_file is None:
                raise Stop(f"'{entry.name}' was never imported successfully; import it again.")
            self._ensure_open(entry)
            self._persist_options(entry.program, options)
            entry.options = options
            entry.failure = None
            entry.warnings = []
            entry.reanalysis_requested = True
            entry.settled.clear()
            entry.status = Status.ANALYZING
        with self._registry_lock:
            self._queue.append(entry.pathname)
        self._executor.submit(self._analyze_job, entry)
        return entry

    # @spec LIFE-045
    def _refuse_if_pending(self, entry: LoadedProgram) -> None:
        if entry.status in (Status.IMPORTING, Status.ANALYZING):
            raise RetryLater(
                f"'{entry.name}' is already being imported or analyzed; retry when it finishes."
            )

    def _dequeue(self, entry: LoadedProgram) -> None:
        with self._registry_lock:
            if entry.pathname in self._queue:
                self._queue.remove(entry.pathname)

    # @spec LIFE-018, LIFE-019, LIFE-020, LIFE-022, LIFE-031, LIFE-040, LIFE-043
    def _analyze_job(self, entry: LoadedProgram) -> None:
        try:
            with entry.lock:
                if self._closing:
                    return
                if entry.status is Status.READY and not entry.reanalysis_requested:
                    return  # became ready on first use (already analyzed)
                entry.work_started = entry.work_started or time.time()
                try:
                    self._ensure_open(entry)
                    options = entry.options or self._stored_options(entry.program)
                    if entry.reanalysis_requested or self._needs_analysis(entry):
                        logger.info(f"Analyzing: {entry.name}")
                        entry.warnings = []
                        self._run_analysis(entry, options)
                        self._save(entry.program)  # only after a successful pass
                    else:
                        logger.info(f"Already analyzed — skipping: {entry.name}")
                    entry.metadata = self._program_metadata(entry.program)
                    entry.failure = None
                    self._settle(entry, Status.READY)
                    logger.info(f"Analysis done: {entry.name}")
                except Exception as e:
                    logger.error(f"Analysis failed for {entry.name}: {e}", exc_info=True)
                    entry.failure = f"Analysis failed: {describe(e) or type(e).__name__}"
                    self._settle(entry, Status.FAILED)
                finally:
                    entry.reanalysis_requested = False
                    entry.work_started = None
        finally:
            self._dequeue(entry)

    # -------------------------------------------------------------------------
    # Ghidra operations (each is a seam that tests replace with fakes)
    # -------------------------------------------------------------------------

    def _domain_metadata(self, domain_file: "DomainFile") -> dict:
        return dict(domain_file.getMetadata())

    def _open_program(self, entry: LoadedProgram) -> "Program":
        df = entry.domain_file
        return self.project.openProgram(df.getParent().getPathname(), df.getName(), False)

    def _setup_decompiler(self, program: "Program") -> "DecompInterface":
        from ghidra.app.decompiler import DecompileOptions, DecompInterface

        options = DecompileOptions()
        options.grabFromProgram(program)
        options.setMaxPayloadMBytes(100)

        decomp = DecompInterface()
        decomp.setOptions(options)
        decomp.openProgram(program)
        return decomp

    def _program_metadata(self, program: "Program") -> dict:
        return dict(program.getMetadata())

    def _import_program(self, entry: LoadedProgram) -> tuple["Program", "DomainFile"]:
        program = self.project.importProgram(entry.source_path)
        if program is None:
            raise Stop(f"Ghidra could not import {entry.source_path}")
        program.setName(entry.name)
        self._store_options(program, entry.options or AnalysisOptions())
        self.project.saveAs(program, "/", entry.name, True)
        return program, program.getDomainFile()

    def _needs_analysis(self, entry: LoadedProgram) -> bool:
        from ghidra.program.util import GhidraProgramUtilities

        return bool(GhidraProgramUtilities.shouldAskToAnalyze(entry.program))

    def _run_analysis(self, entry: LoadedProgram, options: AnalysisOptions) -> None:
        """Apply the binary's configuration and run Ghidra auto-analysis (no save)."""
        from ghidra.app.script import GhidraScriptUtil
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.program.util import GhidraProgramUtilities
        from ghidra.util.task import ConsoleTaskMonitor, TaskMonitorAdapter

        program = entry.program
        monitor = ConsoleTaskMonitor() if self.verbose_analysis else TaskMonitorAdapter(True)
        self._monitor = monitor
        GhidraScriptUtil.acquireBundleHostReference()
        try:
            self._apply_gdts(entry, options)
            self._configure_analysis(entry, options)
            FlatProgramAPI(program, monitor).analyzeAll(program)
            GhidraProgramUtilities.markProgramAnalyzed(program)
        finally:
            GhidraScriptUtil.releaseBundleHostReference()
            self._monitor = None

    def _store_options(self, program: "Program", options: AnalysisOptions) -> None:
        self._in_transaction(
            program,
            "Store analysis options",
            lambda: program.getOptions(OPTIONS_CATEGORY).setString(OPTIONS_KEY, options.to_json()),
        )

    def _persist_options(self, program: "Program", options: AnalysisOptions) -> None:
        self._store_options(program, options)
        self._save(program)

    def _stored_options(self, program: "Program") -> AnalysisOptions:
        text = program.getOptions(OPTIONS_CATEGORY).getString(OPTIONS_KEY, None)
        return AnalysisOptions.from_json(str(text)) if text else AnalysisOptions()

    def _save(self, program: "Program") -> None:
        self.project.save(program)

    @staticmethod
    def _in_transaction(program: "Program", description: str, body: Callable[[], Any]) -> Any:
        tx = program.startTransaction(description)
        ok = False
        try:
            result = body()
            ok = True
            return result
        finally:
            program.endTransaction(tx, ok)

    # -------------------------------------------------------------------------
    # Analysis configuration (analysis-config segment)
    # -------------------------------------------------------------------------

    # @spec ACFG-002, ACFG-017
    def _apply_gdts(self, entry: LoadedProgram, options: AnalysisOptions) -> None:
        for gdt in options.gdts:
            logger.info(f"Applying GDT: {gdt}")
            try:
                ok, status = self.apply_gdt(entry.program, gdt)
            except Exception as e:
                self._warn(entry, f"GDT '{gdt}' could not be applied: {describe(e)}")
                continue
            if not ok:
                self._warn(entry, f"GDT '{gdt}' was not applied: {status or 'no reason given'}")

    # @spec ACFG-010, ACFG-019
    def _configure_analysis(self, entry: LoadedProgram, options: AnalysisOptions) -> None:
        """Apply symbol configuration and analyzer options, inside one transaction."""
        program = entry.program

        def body():
            self._configure_symbols(entry, options)
            for name, value in options.analyzer_options.items():
                warning = self.set_analysis_option(program, name, value)
                if warning:
                    self._warn(entry, warning)
                else:
                    logger.info(f"Set analysis option for {entry.name}: {name} = {value}")

        self._in_transaction(program, "Configure analysis", body)

    # @spec ACFG-005, ACFG-006, ACFG-007, ACFG-008, ACFG-009, ACFG-018, ACFG-021
    def _configure_symbols(self, entry: LoadedProgram, options: AnalysisOptions) -> None:
        program = entry.program
        if options.no_symbols:
            if self._has_analysis_option(program, PDB_ANALYZER):
                logger.warning(f"Symbols disabled for {entry.name}")
                self.set_analysis_option(program, PDB_ANALYZER, False)
            else:
                logger.debug(f"No {PDB_ANALYZER} analyzer for {entry.name}; nothing to disable")
            return
        try:
            from ghidrecomp.utility import get_pdb, set_pdb, set_remote_pdbs, setup_symbol_server
        except ImportError:
            self._warn(entry, "Symbol configuration skipped: ghidrecomp is not installed.")
            return
        try:
            if options.pdb_path:
                set_pdb(program, options.pdb_path)
            else:
                setup_symbol_server(self.symbols_path)
                set_remote_pdbs(program, True)
            pdb = get_pdb(program)
            if pdb:
                logger.info(f"PDB loaded: {pdb}")
            else:
                logger.warning(f"No PDB found for {entry.name}")
        except Exception as e:
            self._warn(entry, f"Symbol configuration failed: {describe(e)}")

    @staticmethod
    def _analysis_options(program: "Program"):
        from ghidra.program.model.listing import Program

        return program.getOptions(Program.ANALYSIS_PROPERTIES)

    def _has_analysis_option(self, program: "Program", option_name: str) -> bool:
        return str(self._analysis_options(program).getType(option_name)) != "NO_TYPE"

    # @spec ACFG-011, ACFG-012, ACFG-013, ACFG-014, ACFG-015, ACFG-019
    def set_analysis_option(self, prog: "Program", option_name: str, value: Any) -> str | None:
        """Set a typed Ghidra analysis option. Returns a warning if it was left unchanged."""
        opts = self._analysis_options(prog)
        option_type = str(opts.getType(option_name))
        try:
            match option_type:
                case "INT_TYPE":
                    opts.setInt(option_name, int(value))
                case "LONG_TYPE":
                    opts.setLong(option_name, int(value))
                case "STRING_TYPE":
                    opts.setString(option_name, str(value))
                case "DOUBLE_TYPE":
                    opts.setDouble(option_name, float(value))
                case "FLOAT_TYPE":
                    opts.setFloat(option_name, float(value))
                case "BOOLEAN_TYPE":
                    if isinstance(value, str):
                        opts.setBoolean(option_name, value.lower() == "true")
                    else:
                        opts.setBoolean(option_name, bool(value))
                case "ENUM_TYPE":
                    from java.lang import Enum  # type: ignore

                    enum_cur = opts.getEnum(option_name, None)
                    if enum_cur is None:
                        return f"Analysis option '{option_name}' has no current value; not set."
                    try:
                        new_val = Enum.valueOf(enum_cur.getClass(), value)
                    except Exception:
                        new_val = next(
                            (e for e in enum_cur.values() if e.toString() == value), None
                        )
                    if new_val is None:
                        return f"Analysis option '{option_name}' has no value '{value}'; not set."
                    opts.setEnum(option_name, new_val)
                case "NO_TYPE":
                    return f"Unknown analysis option '{option_name}'; not set."
                case _:
                    return (
                        f"Analysis option '{option_name}' has unsupported type {option_type}; "
                        "not set."
                    )
        except (TypeError, ValueError) as e:
            return f"Analysis option '{option_name}' could not be set to {value!r}: {e}"
        return None

    # @spec ACFG-003, ACFG-016, ACFG-020
    @staticmethod
    def apply_gdt(program: "Program", gdt_path: str | Path) -> tuple[bool, str]:
        """Apply a GDT archive's function data types inside a transaction, keeping
        USER_DEFINED signatures. Returns (applied, Ghidra's status message)."""
        from ghidra.app.cmd.function import ApplyFunctionDataTypesCmd
        from ghidra.program.model.data import FileDataTypeManager
        from ghidra.program.model.symbol import SourceType
        from ghidra.util.task import TaskMonitor
        from java.io import File  # type: ignore
        from java.util import List  # type: ignore

        archive = FileDataTypeManager.openFileArchive(File(str(gdt_path)), False)
        try:
            cmd = ApplyFunctionDataTypesCmd(
                List.of(archive),
                None,  # type: ignore  # the whole program
                SourceType.USER_DEFINED,
                False,  # always_replace: never overwrite a USER_DEFINED signature
                True,  # create_bookmarks
            )
            tx = program.startTransaction(f"Apply GDT {gdt_path}")
            ok = False
            try:
                ok = bool(cmd.applyTo(program, TaskMonitor.DUMMY))
            finally:
                program.endTransaction(tx, ok)
            return ok, str(cmd.getStatusMsg() or "")
        finally:
            archive.close()
