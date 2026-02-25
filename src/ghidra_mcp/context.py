"""
Ghidra project and program lifecycle management.
No ChromaDB, no ML/embedding — native Ghidra only.
"""

import concurrent.futures
import hashlib
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Union

if TYPE_CHECKING:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.base.project import GhidraProject
    from ghidra.framework.model import DomainFile
    from ghidra.program.model.listing import Program

    GhidraProjectT = "GhidraProject"

logger = logging.getLogger(__name__)


@dataclass
class ProgramInfo:
    """Runtime state for a single loaded Ghidra program."""

    name: str
    program: "Program"
    project: "GhidraProject"
    decompiler: "DecompInterface"
    metadata: dict
    ghidra_analysis_complete: bool
    file_path: Path | None = None
    load_time: float | None = None

    @property
    def analysis_complete(self) -> bool:
        return self.ghidra_analysis_complete


class GhidraContext:
    """
    Manages a Ghidra project: creation, import, analysis, and cleanup.
    Deliberately omits ChromaDB — all search uses native Ghidra iterators.
    """

    def __init__(
        self,
        project_name: str,
        project_path: str | Path,
        force_analysis: bool = False,
        verbose_analysis: bool = False,
        no_symbols: bool = False,
        gdts: list | None = None,
        program_options: dict | None = None,
        wait_for_analysis: bool = False,
        symbols_path: str | Path | None = None,
        sym_file_path: str | Path | None = None,
    ):
        from ghidra.base.project import GhidraProject  # noqa: F401 — triggers JVM init check

        self.project_name = project_name
        self.project_path = Path(project_path)
        self.project: "GhidraProject" = self._get_or_create_project()
        self.programs: dict[str, ProgramInfo] = {}
        self._init_project_programs()

        self.force_analysis = force_analysis
        self.verbose_analysis = verbose_analysis
        self.no_symbols = no_symbols
        self.gdts: list[str] = gdts or []
        self.program_options = program_options
        self.wait_for_analysis = wait_for_analysis
        self.symbols_path = Path(symbols_path) if symbols_path else self.project_path / "symbols"
        self.sym_file_path = Path(sym_file_path) if sym_file_path else None

        # Single-worker executors: one for analysis, one for background imports.
        # Single workers avoid concurrent Ghidra project access issues.
        self._analysis_executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self._import_executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    def close(self):
        """Save and close all open programs, then close the project."""
        for pi in self.programs.values():
            try:
                self.project.close(pi.program)
            except Exception as e:
                logger.warning(f"Could not close {pi.name}: {e}")

        self._analysis_executor.shutdown(wait=False)
        self._import_executor.shutdown(wait=False)
        self.project.close()
        logger.info(f"Project '{self.project_name}' closed.")

    # -------------------------------------------------------------------------
    # Project management
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
        else:
            logger.info(f"Creating new project: {self.project_name}")
            return GhidraProject.createProject(proj_dir, self.project_name, False)

    def _init_project_programs(self):
        """Open all programs already stored in the project."""
        from ghidra.program.model.listing import Program

        for pathname in self.list_binaries():
            p = Path(pathname)
            program: Program = self.project.openProgram(str(p.parent), p.name, False)
            self.programs[pathname] = self._init_program_info(program)

    def list_binaries(self) -> list[str]:
        """Return Ghidra project pathnames for all programs in the project."""

        def _walk(folder) -> list[str]:
            names: list[str] = []
            for sub in folder.getFolders():
                names.extend(_walk(sub))
            names.extend(f.getPathname() for f in folder.getFiles())
            return names

        return _walk(self.project.getRootFolder())

    def list_binary_domain_files(self) -> list["DomainFile"]:
        """Return DomainFile objects for all Program-type files in the project."""

        def _walk(folder) -> list:
            files = []
            for sub in folder.getFolders():
                files.extend(_walk(sub))
            files.extend(f for f in folder.getFiles() if f.getContentType() == "Program")
            return files

        return _walk(self.project.getRootFolder())

    def delete_program(self, program_name: str) -> bool:
        """Remove a program from the project by its Ghidra pathname or display name."""
        pi = self.programs.get(program_name)
        if not pi:
            # Fall back to matching by display name
            by_name = {Path(k).name: k for k in self.programs}
            key = by_name.get(program_name)
            if key:
                pi = self.programs[key]
                program_name = key

        if not pi:
            raise ValueError(
                f"Binary '{program_name}' not found. "
                f"Available: {list(self.programs.keys())}"
            )

        try:
            df = pi.program.getDomainFile()
            self.project.close(pi.program)
            df.delete()
            del self.programs[program_name]
            logger.info(f"Deleted program: {program_name}")
            return True
        except Exception as e:
            logger.error(f"Error deleting '{program_name}': {e}")
            return False

    def get_program_info(self, binary_name: str) -> ProgramInfo:
        """Resolve a program by Ghidra pathname or display name. Raises if not found or not analyzed."""
        pi = self.programs.get(binary_name)
        if not pi:
            by_name = {Path(k).name: v for k, v in self.programs.items()}
            pi = by_name.get(binary_name)

        if not pi:
            raise ValueError(
                f"Binary '{binary_name}' not found. "
                f"Available: {list(self.programs.keys())}"
            )

        if not pi.analysis_complete:
            raise RuntimeError(
                f"Analysis not yet complete for '{binary_name}'. "
                "Wait a moment and retry, or use --wait-for-analysis on startup."
            )

        return pi

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

    def import_binary(self, binary_path: str | Path, analyze: bool = False) -> None:
        """Import a single binary into the project, optionally analyzing it immediately."""
        from ghidra.program.model.listing import Program

        binary_path = Path(binary_path)
        if binary_path.is_dir():
            self.import_binaries(
                [f for f in binary_path.rglob("*") if f.is_file()],
                analyze=analyze,
            )
            return

        program_name = self._unique_name(binary_path)
        full_path = f"/{program_name}"

        if self.programs.get(full_path):
            logger.info(f"Already imported: {program_name}")
            return

        logger.info(f"Importing: {program_name} from {binary_path}")
        program: Program = self.project.importProgram(binary_path)
        program.name = program_name
        self.project.saveAs(program, "/", program_name, True)

        pi = self._init_program_info(program)
        self.programs[program.getDomainFile().pathname] = pi

        if analyze:
            self.analyze_program(program)

        logger.info(f"Import complete: {program_name}")

    def import_binaries(self, binary_paths: list[str | Path], analyze: bool = False) -> None:
        """Import a list of binaries sequentially."""
        for p in binary_paths:
            try:
                self.import_binary(p, analyze=analyze)
            except Exception as e:
                logger.error(f"Failed to import {p}: {e}")

    def import_binary_backgrounded(self, binary_path: str | Path) -> None:
        """Submit an import+analyze task to the background import executor."""
        if not Path(binary_path).exists():
            raise FileNotFoundError(f"File not found: {binary_path}")

        def _done(future: concurrent.futures.Future):
            exc = future.exception()
            if exc:
                logger.error(f"Background import failed for {binary_path}: {exc}")
            else:
                logger.info(f"Background import complete: {binary_path}")

        future = self._import_executor.submit(self.import_binary, binary_path, True)
        future.add_done_callback(_done)

    # -------------------------------------------------------------------------
    # Analysis
    # -------------------------------------------------------------------------

    def analyze_project(self) -> concurrent.futures.Future | None:
        """
        Submit project analysis to the background executor.
        With --wait-for-analysis the call blocks until all binaries are analyzed.
        """
        future = self._analysis_executor.submit(self._analyze_project)

        def _done(f: concurrent.futures.Future):
            exc = f.exception()
            if exc:
                logger.error(f"Analysis failed: {exc}", exc_info=exc)
            else:
                logger.info("All binaries analyzed.")

        future.add_done_callback(_done)

        if self.wait_for_analysis:
            logger.info("Waiting for analysis to complete...")
            future.result()  # blocks; re-raises on error
            return None

        return future

    def _analyze_project(self) -> None:
        domain_files = self.list_binary_domain_files()
        logger.info(f"Starting analysis for {len(domain_files)} binaries")
        for df in domain_files:
            try:
                self.analyze_program(df)
            except Exception as e:
                logger.error(f"Analysis failed for {df.getName()}: {e}", exc_info=True)

    def analyze_program(
        self,
        df_or_prog: Union["DomainFile", "Program"],
    ) -> "DomainFile | Program":
        """Run Ghidra auto-analysis on a single program."""
        from ghidra.app.script import GhidraScriptUtil
        from ghidra.framework.model import DomainFile
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.program.model.listing import Program
        from ghidra.program.util import GhidraProgramUtilities
        from ghidra.util.task import ConsoleTaskMonitor

        # Resolve DomainFile / Program
        df = df_or_prog if isinstance(df_or_prog, DomainFile) else df_or_prog.getDomainFile()

        if self.programs.get(df.pathname):
            program = self.programs[df.pathname].program
        else:
            program = self.project.openProgram(
                df.getParent().pathname, df_or_prog.getName(), False
            )
            self.programs[df.pathname] = self._init_program_info(program)

        assert isinstance(program, Program)
        logger.info(f"Analyzing: {program.name}")

        for gdt in self.gdts:
            logger.info(f"Applying GDT: {gdt}")
            self.apply_gdt(program, gdt)

        if self.verbose_analysis:
            flat_api = FlatProgramAPI(program, ConsoleTaskMonitor())
        else:
            flat_api = FlatProgramAPI(program)

        if (
            GhidraProgramUtilities.shouldAskToAnalyze(program)
            or self.force_analysis
        ):
            GhidraScriptUtil.acquireBundleHostReference()
            try:
                self._configure_analysis_options(program)
                flat_api.analyzeAll(program)
                if hasattr(GhidraProgramUtilities, "setAnalyzedFlag"):
                    GhidraProgramUtilities.setAnalyzedFlag(program, True)
                elif hasattr(GhidraProgramUtilities, "markProgramAnalyzed"):
                    GhidraProgramUtilities.markProgramAnalyzed(program)
                else:
                    raise RuntimeError("Cannot find GhidraProgramUtilities analyzed-flag method.")
            finally:
                GhidraScriptUtil.releaseBundleHostReference()
                self.project.save(program)
        else:
            logger.info(f"Already analyzed — skipping: {program.name}")

        self.programs[df.pathname].ghidra_analysis_complete = True
        logger.info(f"Analysis done: {program.name}")
        return df_or_prog

    def _configure_analysis_options(self, program: "Program") -> None:
        """Apply symbol and analyzer configuration before running analyzeAll."""
        if self.no_symbols:
            logger.warning("Symbols disabled (--no-symbols)")
            self.set_analysis_option(program, "PDB Universal", False)
            return

        try:
            from ghidrecomp.utility import get_pdb, set_pdb, set_remote_pdbs, setup_symbol_server

            if self.sym_file_path:
                set_pdb(program, self.sym_file_path)
            else:
                setup_symbol_server(self.symbols_path)
                set_remote_pdbs(program, True)

            pdb = get_pdb(program)
            if pdb:
                logger.info(f"PDB loaded: {pdb}")
            else:
                logger.warning(f"No PDB found for {program.name}")
        except ImportError:
            logger.debug("ghidrecomp not available — skipping symbol server setup")

        if self.program_options:
            analyzers = self.program_options.get("program_options", {}).get("Analyzers", {})
            for k, v in analyzers.items():
                logger.info(f"Setting analysis option: {k} = {v}")
                self.set_analysis_option(program, k, v)

    def set_analysis_option(self, prog: "Program", option_name: str, value: Any) -> None:
        """Set a typed Ghidra analysis option on the program."""
        from ghidra.program.model.listing import Program

        opts = prog.getOptions(Program.ANALYSIS_PROPERTIES)
        option_type = str(opts.getType(option_name))

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
                    logger.warning(f"Cannot set ENUM option {option_name}: no existing value")
                    return
                try:
                    new_val = Enum.valueOf(enum_cur.getClass(), value)
                except Exception:
                    new_val = next(
                        (e for e in enum_cur.values() if e.toString() == value), None
                    )
                if new_val is not None:
                    opts.setEnum(option_name, new_val)
                else:
                    logger.warning(f"Unknown enum value '{value}' for option {option_name}")
            case _:
                logger.warning(f"Unsupported option type '{option_type}' for '{option_name}' — skipping")

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def apply_gdt(self, program: "Program", gdt_path: str | Path) -> None:
        """Apply a GDT (Ghidra Data Type) archive to the program."""
        from ghidra.app.cmd.function import ApplyFunctionDataTypesCmd
        from ghidra.program.model.data import FileDataTypeManager
        from ghidra.program.model.symbol import SourceType
        from ghidra.util.task import ConsoleTaskMonitor
        from java.io import File  # type: ignore
        from java.util import List  # type: ignore

        archive = FileDataTypeManager.openFileArchive(File(str(gdt_path)), False)
        cmd = ApplyFunctionDataTypesCmd(
            List.of(archive),
            None,  # type: ignore
            SourceType.USER_DEFINED,
            True,   # always_replace
            True,   # create_bookmarks
        )
        cmd.applyTo(program, ConsoleTaskMonitor().DUMMY_MONITOR)

    def get_metadata(self, program: "Program") -> dict:
        return dict(program.getMetadata())

    def setup_decompiler(self, program: "Program") -> "DecompInterface":
        from ghidra.app.decompiler import DecompileOptions, DecompInterface

        options = DecompileOptions()
        options.grabFromProgram(program)
        options.setMaxPayloadMBytes(100)

        decomp = DecompInterface()
        decomp.setOptions(options)
        decomp.openProgram(program)
        return decomp

    def _init_program_info(self, program: "Program") -> ProgramInfo:
        metadata = self.get_metadata(program)
        exec_loc = metadata.get("Executable Location")
        return ProgramInfo(
            name=program.name,
            program=program,
            project=self.project,
            decompiler=self.setup_decompiler(program),
            metadata=metadata,
            ghidra_analysis_complete=False,
            file_path=Path(exec_loc) if exec_loc else None,
            load_time=time.time(),
        )
