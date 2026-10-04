"""
GUI mode: host the Ghidra GUI in this process and serve MCP alongside it.

See docs/intent/gui-host/ for the design. Every Ghidra GUI call goes through GuiServices, so
GuiGhidraContext (the GUI host for program-lifecycle) can be exercised with a fake.
"""

import dataclasses
import logging
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

from ghidra_mcp.context import GhidraContext, LoadedProgram, Status
from ghidra_mcp.errors import FixInput, RetryLater, Stop

logger = logging.getLogger(__name__)

SWING_TIMEOUT_SECONDS = 30
ANALYSIS_START_TIMEOUT_SECONDS = 30
TRANSACTION_SETTLE_TIMEOUT_SECONDS = 60
PROJECT_WAIT_SECONDS = 300
POLL_SECONDS = 0.25


def gpr_path(project_dir: str | Path, project_name: str) -> Path:
    return Path(project_dir) / f"{project_name}.gpr"


# @spec GUI-003
def check_port(host: str, port: int) -> None:
    """Raise OSError if the HTTP host and port cannot be bound."""
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))


# @spec GUI-004
def ensure_project(project_dir: str, project_name: str) -> None:
    """Create a missing project in a headless child process (the GUI can only open one)."""
    if gpr_path(project_dir, project_name).exists():
        return
    logger.info(f"Creating project {project_name} in {project_dir}")
    subprocess.run(
        [sys.executable, "-m", "ghidra_mcp", "--project-path", str(project_dir),
         "--project-name", project_name, "--list-project-binaries"],
        check=True, capture_output=True,
    )


# @spec GUI-007
def ensure_isatty(stream: Any) -> None:
    """pyghidra's GUI launcher wraps the standard streams without isatty(), which the HTTP
    server's logging setup calls."""
    if not hasattr(stream, "isatty"):
        type(stream).isatty = lambda self: False


class GuiServices:
    """Adapter over the Ghidra GUI APIs used in GUI mode."""

    def __init__(self, swing_timeout: float = SWING_TIMEOUT_SECONDS):
        from java.lang import Object  # type: ignore

        self.swing_timeout = swing_timeout
        self.consumer = Object()

    # -- project ---------------------------------------------------------------

    def active_project(self):
        from ghidra.framework.main import AppInfo

        return AppInfo.getActiveProject()

    def wait_for_project(self, timeout: float):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            project = self.active_project()
            if project is not None:
                return project
            time.sleep(POLL_SECONDS)
        raise Stop("The Ghidra GUI did not open the project.")

    def project_dir(self, project) -> Path:
        return Path(str(project.getProjectLocator().getLocation()))

    def same_project(self, a, b) -> bool:
        return a is not None and b is not None and bool(a.getProjectLocator().equals(b.getProjectLocator()))

    def domain_files(self, project) -> list:
        def walk(folder) -> list:
            files = []
            for sub in folder.getFolders():
                files.extend(walk(sub))
            files.extend(f for f in folder.getFiles() if f.getContentType() == "Program")
            return files

        return walk(project.getProjectData().getRootFolder())

    def file_exists(self, domain_file) -> bool:
        return bool(domain_file.exists())

    # -- threads ---------------------------------------------------------------

    # @spec GUI-031
    def run_on_swing(self, fn: Callable[[], Any]) -> Any:
        """Run fn on the Swing thread and return its result; Stop if the GUI does not respond."""
        from ghidra.util import Swing
        from java.util.concurrent import TimeUnit  # type: ignore

        outcome: dict = {}

        def run():
            try:
                outcome["value"] = fn()
            except BaseException as e:  # re-raised on the calling thread
                outcome["error"] = e

        try:
            Swing.runNow(run, int(self.swing_timeout), TimeUnit.SECONDS)
        except Exception as e:
            raise Stop(f"The Ghidra GUI is not responding ({e}).") from e
        if "error" in outcome:
            raise outcome["error"]
        return outcome.get("value")

    # -- programs --------------------------------------------------------------

    def import_program(self, project, path: Path, name: str):
        from ghidra.app.util.importer import ProgramLoader
        from ghidra.util.task import TaskMonitor
        from java.io import File  # type: ignore

        results = (
            ProgramLoader.builder().source(File(str(path))).project(project)
            .projectFolderPath("/").name(name).monitor(TaskMonitor.DUMMY).load()
        )
        try:
            results.save(TaskMonitor.DUMMY)  # creates the program's project file
            program = results.getPrimaryDomainObject(self.consumer)
        finally:
            results.close()
        return program, program.getDomainFile()

    def open_program(self, domain_file):
        from ghidra.util.task import TaskMonitor

        return domain_file.getDomainObject(self.consumer, False, False, TaskMonitor.DUMMY)

    def release(self, program) -> None:
        program.release(self.consumer)

    # -- CodeBrowser -----------------------------------------------------------

    def _code_browsers(self) -> list:
        from ghidra.app.services import ProgramManager

        project = self.active_project()
        if project is None:
            return []
        return [t for t in project.getToolManager().getRunningTools() if t.getService(ProgramManager) is not None]

    def code_browser(self, launch: bool, domain_file=None):
        """The CodeBrowser that most recently had focus, or the first running one; launches
        the default tool on domain_file if none runs and launch is set (Ghidra requires a file)."""

        def find():
            from docking import DockingWindowManager
            from ghidra.app.services import ProgramManager
            from java.util import List  # type: ignore

            active = DockingWindowManager.getActiveInstance()
            tool = active.getTool() if active is not None else None
            if tool is not None and tool.getService(ProgramManager) is not None:
                return tool
            browsers = self._code_browsers()
            if browsers:
                return browsers[0]
            if launch and domain_file is not None:
                return self.active_project().getToolServices().launchDefaultTool(List.of(domain_file))
            return None

        return self.run_on_swing(find)

    def open_in_code_browser(self, tool, program, current: bool) -> None:
        from ghidra.app.services import ProgramManager

        def open_it():
            manager = tool.getService(ProgramManager)
            state = ProgramManager.OPEN_CURRENT if current else ProgramManager.OPEN_VISIBLE
            manager.openProgram(program, state)
            if current:
                manager.setCurrentProgram(program)

        self.run_on_swing(open_it)

    def close_in_code_browsers(self, program) -> None:
        from ghidra.app.services import ProgramManager

        def close_it():
            for tool in self._code_browsers():
                manager = tool.getService(ProgramManager)
                if program in list(manager.getAllOpenPrograms()):
                    manager.closeProgram(program, True)

        self.run_on_swing(close_it)

    def current_location(self, tool):
        from ghidra.app.services import CodeViewerService

        def read():
            viewer = tool.getService(CodeViewerService)
            location = viewer.getCurrentLocation() if viewer is not None else None
            if location is None or location.getAddress() is None:
                return None
            return location.getProgram(), location.getAddress()

        return self.run_on_swing(read)

    def go_to(self, tool, program, address) -> bool:
        from ghidra.app.services import GoToService
        from ghidra.program.util import ProgramLocation

        return bool(self.run_on_swing(lambda: tool.getService(GoToService).goTo(ProgramLocation(program, address))))

    # -- analysis --------------------------------------------------------------

    def mark_not_to_ask(self, program) -> None:
        from ghidra.program.util import GhidraProgramUtilities

        GhidraProgramUtilities.markProgramNotToAskToAnalyze(program)

    def mark_analyzed(self, program) -> None:
        from ghidra.program.util import GhidraProgramUtilities

        GhidraProgramUtilities.markProgramAnalyzed(program)

    def is_analyzed(self, program) -> bool:
        from ghidra.program.util import GhidraProgramUtilities

        return bool(GhidraProgramUtilities.isAnalyzed(program))

    def start_analysis(self, program, on_end: Callable[[bool], None]) -> None:
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager, AutoAnalysisManagerListener
        from jpype import JImplements, JOverride

        manager = AutoAnalysisManager.getAnalysisManager(program)

        @JImplements(AutoAnalysisManagerListener)
        class Listener:
            @JOverride
            def analysisEnded(self, mgr, cancelled):  # noqa: N802
                mgr.removeListener(self)
                on_end(bool(cancelled))

        manager.addListener(Listener())
        manager.reAnalyzeAll(None)
        manager.startBackgroundAnalysis()

    def is_analyzing(self, program) -> bool:
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager

        return bool(
            AutoAnalysisManager.hasAutoAnalysisManager(program)
            and AutoAnalysisManager.getAnalysisManager(program).isAnalyzing()
        )

    def open_transaction(self, program) -> str | None:
        info = program.getCurrentTransactionInfo()
        return str(info.getDescription()) if info is not None else None


class GuiGhidraContext(GhidraContext):
    """program-lifecycle's context with gui-host's GUI host: the GUI's project and programs,
    Ghidra's analysis manager, Swing-thread writes, and no saving."""

    def __init__(self, services, *, wait_for_analysis: bool = True, verbose_analysis: bool = False,
                 symbols_path: str | Path | None = None):
        self.services = services
        self.analysis_start_timeout: float = ANALYSIS_START_TIMEOUT_SECONDS
        self.transaction_settle_timeout: float = TRANSACTION_SETTLE_TIMEOUT_SECONDS
        self.poll_seconds: float = POLL_SECONDS
        self._bound_project = services.active_project()  # @spec GUI-009
        if self._bound_project is None:
            raise Stop("The Ghidra GUI has no open project.")
        super().__init__(
            project_name=str(self._bound_project.getName()),
            project_path=services.project_dir(self._bound_project),
            verbose_analysis=verbose_analysis,
            wait_for_analysis=wait_for_analysis,
            symbols_path=symbols_path,
        )

    # -- project and registry --------------------------------------------------

    def _get_or_create_project(self):
        return self._bound_project

    def list_binary_domain_files(self) -> list:
        return self.services.domain_files(self.project)

    # @spec GUI-010
    def _check_project(self) -> None:
        if not self.services.same_project(self.services.active_project(), self.project):
            raise Stop(
                f"The Ghidra GUI closed project '{self.project_name}'; restart ghidra-mcp --gui."
            )

    # @spec GUI-011
    def refresh_registry(self) -> None:
        """Follow programs the analyst added, renamed, or deleted through the GUI."""
        files = self.list_binary_domain_files()
        with self._registry_lock:
            for df in files:
                if str(df.getPathname()) not in self.programs:
                    metadata = self._domain_metadata(df)
                    self.programs[str(df.getPathname())] = LoadedProgram(
                        name=str(df.getName()), pathname=str(df.getPathname()), project=self.project,
                        domain_file=df, metadata=metadata,
                        file_path=Path(metadata["Executable Location"]) if metadata.get("Executable Location") else None,
                    )
            gone = [
                e for e in self.programs.values()
                if e.domain_file is not None and e.status is not Status.IMPORTING
                and not self.services.file_exists(e.domain_file)
            ]
            for entry in gone:
                self.programs.pop(entry.pathname, None)
        for entry in gone:
            if entry.program is not None:
                try:
                    self.services.release(entry.program)
                except Exception as e:
                    logger.warning(f"Could not release {entry.name}: {e}")

    # @spec GUI-021
    def _gui_analyzing(self, entry: LoadedProgram) -> bool:
        return (
            entry.status is Status.READY and entry.program is not None
            and self.services.is_analyzing(entry.program)
        )

    def list_entries(self) -> list[LoadedProgram]:
        self._check_project()
        self.refresh_registry()
        entries = super().list_entries()
        return [dataclasses.replace(e, status=Status.ANALYZING) if self._gui_analyzing(e) else e for e in entries]

    def _resolve(self, binary_name: str) -> LoadedProgram:
        try:
            return super()._resolve(binary_name)
        except FixInput:
            self.refresh_registry()
            return super()._resolve(binary_name)

    def get_program_info(self, binary_name: str) -> LoadedProgram:
        self._check_project()
        entry = self._resolve(binary_name)
        if self._gui_analyzing(entry):
            deadline = time.monotonic() + (self.wait_seconds if self.wait_for_analysis else 0)
            while self._gui_analyzing(entry) and time.monotonic() < deadline:
                time.sleep(self.poll_seconds)
            if self._gui_analyzing(entry):
                raise RetryLater(f"Ghidra is analyzing '{entry.name}' (started in the GUI); retry later.")
        entry = super().get_program_info(binary_name)
        entry.mutation_runner = self.run_mutation  # @spec WB-028
        return entry

    # @spec GUI-012
    def _ready_if_already_analyzed(self, entry: LoadedProgram) -> None:
        super()._ready_if_already_analyzed(entry)
        if (entry.status is not Status.ANALYZING or entry.reanalysis_requested
                or entry.work_started is not None or entry.program is None):
            return
        with self._registry_lock:
            queued = entry.pathname in self._queue
        if not queued and self._needs_analysis(entry):
            entry.failure = "Not analyzed yet: it was added through the Ghidra GUI without analysis."
            self._settle(entry, Status.FAILED)

    def _refuse_if_pending(self, entry: LoadedProgram) -> None:
        super()._refuse_if_pending(entry)
        if self._gui_analyzing(entry):
            raise RetryLater(f"Ghidra is analyzing '{entry.name}' (started in the GUI); retry when it finishes.")

    # @spec GUI-015
    def delete_program(self, program_name: str) -> bool:
        self._check_project()
        entry = self._resolve(program_name)
        self._refuse_if_pending(entry)
        if entry.program is not None and entry.program.isChanged():
            raise Stop(
                f"'{entry.name}' has unsaved changes in the Ghidra GUI; save or discard them in Ghidra first."
            )
        return super().delete_program(program_name)

    # -- programs ----------------------------------------------------------------

    # @spec GUI-013
    def _open_program(self, entry: LoadedProgram):
        return self.services.open_program(entry.domain_file)

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
                    self.services.close_in_code_browsers(entry.program)
                    self.services.release(entry.program)
                except Exception as e:
                    logger.warning(f"Could not close {entry.name}: {e}")
                entry.program = None

    # @spec GUI-014
    def _import_program(self, entry: LoadedProgram):
        from ghidra_mcp.context import AnalysisOptions

        program, domain_file = self.services.import_program(self.project, entry.source_path, entry.name)
        self._store_options(program, entry.options or AnalysisOptions())
        return program, domain_file

    # @spec GUI-016
    def _save(self, program) -> None:
        """GUI mode never saves: the analyst saves their program, with the agent's edits."""

    def _needs_analysis(self, entry: LoadedProgram) -> bool:
        return not self.services.is_analyzed(entry.program)

    def close(self):
        """The process ends with the GUI; only stop the background worker."""
        self._closing = True
        self._executor.shutdown(wait=False, cancel_futures=True)

    # -- analysis ----------------------------------------------------------------

    # @spec GUI-017, GUI-018, GUI-019, GUI-020
    def _run_analysis(self, entry: LoadedProgram, options) -> None:
        services, program = self.services, entry.program
        services.mark_not_to_ask(program)
        self._apply_gdts(entry, options)
        self._configure_analysis(entry, options)
        tool = services.code_browser(launch=True, domain_file=entry.domain_file)
        services.open_in_code_browser(tool, program, current=False)
        ended, outcome = threading.Event(), {}

        def on_end(cancelled: bool) -> None:
            outcome["cancelled"] = cancelled
            ended.set()

        services.start_analysis(program, on_end)
        self._wait_for_analysis_end(program, ended)
        if outcome.get("cancelled"):
            raise Stop("analysis was cancelled in the Ghidra GUI")
        self._wait_for_no_transaction(program)
        services.mark_analyzed(program)

    def _wait_for_analysis_end(self, program, ended: threading.Event) -> None:
        started, t0 = False, time.monotonic()
        while not ended.is_set():
            if self._closing:
                raise Stop("the server is shutting down")
            if self.services.is_analyzing(program):
                started = True
            elif started:
                return  # analysis stopped without reporting its end (e.g. its tab was closed)
            elif time.monotonic() - t0 > self.analysis_start_timeout:
                raise Stop("Ghidra did not start analysis")
            ended.wait(self.poll_seconds)

    def _wait_for_no_transaction(self, program) -> None:
        deadline = time.monotonic() + self.transaction_settle_timeout
        while self.services.open_transaction(program) is not None:
            if time.monotonic() > deadline:
                raise Stop(f"Ghidra kept '{self.services.open_transaction(program)}' open after analysis")
            time.sleep(self.poll_seconds)

    # -- writes ------------------------------------------------------------------

    # @spec GUI-023, GUI-024, GUI-025
    def run_mutation(self, program, description: str, body: Callable[[], Any]) -> Any:
        """Apply a write on the Swing thread as its own transaction, only if the program is idle;
        never save."""
        outcome: dict = {}

        def apply():
            busy = self.services.open_transaction(program)
            if busy is not None:
                outcome["busy"] = busy
                return
            tx = program.startTransaction(description)
            ok = False
            try:
                outcome["result"] = body()
                ok = True
            except BaseException as e:
                outcome["error"] = e
            finally:
                program.endTransaction(tx, ok)

        self.services.run_on_swing(apply)
        if "busy" in outcome:
            raise RetryLater(f"Ghidra is busy with '{outcome['busy']}' on '{program.getName()}'; retry shortly.")
        if "error" in outcome:
            raise outcome["error"]
        return f"{outcome['result']}. Applied but not saved: save the program in Ghidra to keep it."

    # -- GUI-only tools ----------------------------------------------------------

    def _location(self):
        self._check_project()
        tool = self.services.code_browser(launch=False)
        if tool is None:
            raise Stop("No CodeBrowser is running in the Ghidra GUI.")
        located = self.services.current_location(tool)
        if located is None:
            raise Stop("The CodeBrowser has no program open.")
        program, address = located
        pathname = str(program.getDomainFile().getPathname())
        entry = self.programs.get(pathname)
        if entry is None:
            self.refresh_registry()
            entry = self.programs.get(pathname)
        binary = entry.name if entry is not None else str(program.getName())
        return binary, program, address

    # @spec GUI-027, GUI-029
    def current_location(self) -> dict:
        binary, program, address = self._location()
        function = program.getFunctionManager().getFunctionContaining(address)
        return {
            "binary_name": binary,
            "address": str(address),
            "function_name": str(function.getName(True)) if function is not None else None,
        }

    # @spec GUI-028, GUI-029
    def current_function(self):
        binary, program, address = self._location()
        function = program.getFunctionManager().getFunctionContaining(address)
        if function is None:
            raise Stop(f"The cursor in CodeBrowser is at {address} in '{binary}', which is not inside a function.")
        return binary, function

    # @spec GUI-030
    def go_to(self, binary_name: str, name_or_address: str) -> str:
        from ghidra_mcp.tools import GhidraTools

        entry = self.get_program_info(binary_name)
        with entry.lock:
            resolved = GhidraTools(entry).resolve_reference_target(name_or_address)
            tool = self.services.code_browser(launch=True, domain_file=entry.domain_file)
            self.services.open_in_code_browser(tool, entry.program, current=True)
            if not self.services.go_to(tool, entry.program, resolved.target):
                raise Stop(f"CodeBrowser could not go to {resolved.target} in '{entry.name}'.")
        message = f"CodeBrowser is at {resolved.target} in '{entry.name}'."
        return f"{message} {resolved.note}." if resolved.note else message


# @spec GUI-005, GUI-008
def serve_when_ready(*, services=None, context_factory=GuiGhidraContext, input_paths=(), host: str,
                     port: int, wait_for_analysis: bool, verbose_analysis: bool,
                     symbols_path: str | None) -> None:
    """Once the GUI has the project open: build the GUI-mode context, import the inputs, start
    analysis, register the GUI-only tools, and serve over streamable HTTP."""
    try:
        from ghidra_mcp import server

        services = services or _services_when_jvm_ready()
        services.wait_for_project(PROJECT_WAIT_SECONDS)
        ensure_isatty(sys.stdout)
        ensure_isatty(sys.stderr)
        ctx = context_factory(
            services, wait_for_analysis=wait_for_analysis, verbose_analysis=verbose_analysis,
            symbols_path=symbols_path,
        )
        if input_paths:
            ctx.import_binaries([Path(p) for p in input_paths])
        ctx.analyze_project()
        server.mcp._ghidra_context = ctx  # type: ignore[attr-defined]
        server.register_gui_tools()
        logger.info(f"Serving GUI mode on http://{host}:{port}/mcp")
        server.mcp.run(transport="streamable-http", host=host, port=port)
    except Exception as e:
        logger.error(f"The GUI-mode server failed; the Ghidra GUI stays open: {e}", exc_info=True)


def _services_when_jvm_ready() -> GuiServices:
    """The JVM reports started before JPype's import hooks are ready; retry until they are."""
    deadline = time.monotonic() + PROJECT_WAIT_SECONDS
    while True:
        try:
            from ghidra.framework.main import AppInfo  # noqa: F401

            return GuiServices()
        except Exception:
            if time.monotonic() > deadline:
                raise
            time.sleep(POLL_SECONDS)


# @spec GUI-005, GUI-006
def launch(*, project_dir: str, project_name: str, input_paths=(), host: str, port: int,
           wait_for_analysis: bool, verbose_analysis: bool, symbols_path: str | None) -> None:
    """Launch the Ghidra GUI in this process with the project open; returns when the GUI exits."""
    from pyghidra.launcher import GuiPyGhidraLauncher

    launcher = GuiPyGhidraLauncher(verbose=verbose_analysis)
    launcher.args = [str(gpr_path(project_dir, project_name))]
    threading.Thread(
        target=serve_when_ready,
        kwargs=dict(input_paths=input_paths, host=host, port=port, wait_for_analysis=wait_for_analysis,
                    verbose_analysis=verbose_analysis, symbols_path=symbols_path),
        name="ghidra-mcp-gui-server",
        daemon=True,
    ).start()
    launcher.start()
