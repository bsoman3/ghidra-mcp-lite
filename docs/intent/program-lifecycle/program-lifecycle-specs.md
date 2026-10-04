# Program Lifecycle Specs

**LLD**: docs/intent/program-lifecycle/program-lifecycle-design.md
**Implementing artifacts**:
- src/ghidra_mcp/context.py (`AnalysisOptions`, `LoadedProgram`, `GhidraContext`: project, registry, lazy opening, import, analysis scheduling, program status and gate, per-binary options and re-analysis, locks, deletion, shutdown)
- src/ghidra_mcp/tools.py (`handle_exceptions`: tool calls under the program lock)

Status markers: `[x]` implemented · `[ ]` active gap · `[D]` deferred

*Tests: `tests/test_lifecycle.py`, with end-to-end checks in `tests/integration/test_ghidra_smoke.py`. `LIFE-003` is retired (merged into `LIFE-002`).*

---

## Project and Startup

- [x] **LIFE-001**: When the Ghidra context is constructed in headless mode, the system shall open the project named by the project name in the project directory if it exists, and otherwise create it, creating the directory if needed.
- [x] **LIFE-002**: When the Ghidra context is constructed, the system shall register every Program-type file in the project under its project pathname without opening it.
- [x] **LIFE-004**: When a program is opened or imported, the system shall create a dedicated decompiler for that program, configured from the program's options with a 100 MB maximum payload.
- [x] **LIFE-005**: When a program is opened or imported, the system shall record its Ghidra metadata, its source file path (from the `Executable Location` metadata, when present), and the time it was opened.

## Lazy Opening and Listing

- [x] **LIFE-038**: When a tool or the analysis pass first needs a registered program that is not open, the system shall open it read-write, under that program's lock.
- [x] **LIFE-042**: The system shall provide the project listing with an unopened program's Ghidra metadata read from its project file, without opening the program.

## Binary Resolution and the Analysis Gate

- [x] **LIFE-006**: When a binary is requested by name (by a tool or for deletion), the system shall resolve it by exact project pathname, falling back to matching the pathname's basename.
- [x] **LIFE-007**: If a binary requested by a tool matches no registered program, then the system shall raise a `ValueError` naming the binary and listing the registered pathnames.
- [x] **LIFE-008**: If a binary requested by a tool is importing, or is queued for or undergoing analysis, and is still pending after any wait required by LIFE-039, then the system shall refuse it with a `retry_later` failure (SRV-031) stating how long its analysis has been running, or that it is queued and behind how many binaries.
- [x] **LIFE-030**: If a binary name matches no exact pathname and its basename matches more than one registered program, then the system shall raise a `ValueError` listing the matching pathnames.
- [x] **LIFE-032**: If a binary requested by a tool has failed import or analysis, then the system shall refuse it with a `stop` failure carrying the recorded failure reason and the next step: calling `import_binary` again for a failed import, or `reanalyze_binary` for a failed analysis.
- [x] **LIFE-039**: Unless `--no-wait-for-analysis` is set, when a tool requests a binary that is importing or analyzing, the system shall wait up to 45 seconds for it to become ready or failed before applying LIFE-008 or LIFE-032, without holding any lock while waiting.

## Import

- [x] **LIFE-009**: When importing a binary file, the system shall name the program `<filename>-<first 6 hex characters of the file's SHA-1>`.
- [x] **LIFE-010**: When importing a binary file whose unique name is already registered at the project root, the system shall skip the import, leave that binary's stored analysis options unchanged, and report the binary to the caller as already present.
- [x] **LIFE-011**: When importing a binary file that is not yet registered, the system shall import it into the project root under its unique name, save it, and register it.
- [x] **LIFE-012**: When the import path is a directory, the system shall import every file beneath it recursively, without filtering by file type.
- [x] **LIFE-013**: When importing a batch of paths, the system shall import them sequentially, and if one import fails, log the error, record it as a `failed` entry (LIFE-034), and continue with the rest.
- [x] **LIFE-014**: When a background import is requested, the system shall raise `FileNotFoundError` immediately if the path does not exist. Otherwise it shall return without waiting, and import and analyze the binary on a background worker with the analysis options supplied for it (LIFE-043).
- [x] **LIFE-015**: When a background import finishes, the system shall log its success or its failure.
- [x] **LIFE-033**: While a background import is in progress, the system shall expose it to the project listing with status `importing` and its source path.
- [x] **LIFE-034**: If an import fails, then the system shall record the failure, with the source path and reason, and expose it to the project listing with status `failed`.

## Analysis Scheduling and Status

- [x] **LIFE-016**: When project analysis is started, the system shall run one analysis pass over every Program-type file in the project, on a single background worker.
- [x] **LIFE-017**: When project analysis is started for serving, the system shall return immediately while the pass runs in the background. When it is started for `--analyze-only`, it shall block until the pass finishes.
- [x] **LIFE-018**: If analysis of one program fails during a project analysis pass, then the system shall log the error and continue with the remaining programs.
- [x] **LIFE-019**: When analyzing a program, the system shall run Ghidra auto-analysis only if Ghidra does not mark the program as analyzed, or re-analysis was requested for that program (LIFE-044), and shall otherwise skip auto-analysis.
- [x] **LIFE-020**: When Ghidra auto-analysis of a program completes in headless mode, the system shall mark the program as analyzed in Ghidra (`markProgramAnalyzed`) and save the program.
- [x] **LIFE-021**: Where `--verbose-analysis` is set in headless mode, the system shall run auto-analysis with a console task monitor.
- [x] **LIFE-022**: When an analysis pass over a program finishes without error, whether auto-analysis ran or was skipped, the system shall mark the program analysis-complete so that tools may use it.
- [x] **LIFE-023**: When a tool requests a registered program that Ghidra already marks as analyzed, and no re-analysis is pending for it, the system shall treat the program as ready without waiting for the background analysis pass.
- [x] **LIFE-031**: If an analysis pass over a program raises, then the system shall mark the program `failed` and record the failure reason.
- [x] **LIFE-037**: The system shall expose each registered program's status (`analyzing`, `ready`, or `failed`), failure reason, and recorded configuration warnings to the project listing.
- [x] **LIFE-040**: If an analysis pass over a program raises, then the system shall not save the program.

## Concurrency

- [x] **LIFE-024**: The system shall run background imports and analysis on a single background worker, so that no two background jobs perform Ghidra project operations at the same time.
- [x] **LIFE-025**: While background work is adding entries to the program registry, the system shall let tool handlers read the registry without error.
- [x] **LIFE-041**: The system shall serialize every Ghidra operation on a program (opening, analysis, each tool call, saving, and deletion) with a per-program lock, shall serialize Ghidra project calls that add, open, or remove project files with a project-operations lock, and shall guard the registry and background queue with a registry lock, acquiring these locks only in the order program lock, project-operations lock, registry lock.

## Per-binary Analysis Options and Re-analysis

- [x] **LIFE-043**: The system shall keep each binary's analysis options (`pdb_path`, `gdts`, `analyzer_options`, `no_symbols`) with that binary, store them with the program in the project (persisted when the program is saved: immediately in headless mode, by the analyst in GUI mode), and provide them to analysis-config whenever the binary is analyzed. Binaries given on the command line or found in the project shall use default options.
- [x] **LIFE-044**: When `reanalyze_binary` is called for a registered binary, the system shall replace its stored analysis options with those supplied (omitted ones reverting to defaults), clear any recorded failure and configuration warnings, set its status to `analyzing`, queue a forced analysis pass on the background worker, and return immediately.
- [x] **LIFE-045**: If re-analysis is requested for a binary that is importing, or is queued for or undergoing analysis, then the system shall refuse with a `retry_later` failure.
- [x] **LIFE-046**: If an analysis option names a PDB file or GDT archive that does not exist, then the system shall raise a `ValueError` naming the path before importing or queuing anything.
- [x] **LIFE-048**: If re-analysis is requested for a binary whose import failed, then the system shall refuse with a `stop` failure directing the caller to import the binary again.

## Deletion

- [x] **LIFE-026**: When deleting a binary, the system shall resolve it by exact pathname or basename, close the program, delete its project file, and remove it from the registry.
- [x] **LIFE-027**: If a binary to delete matches no registered program, then the system shall raise a `ValueError` naming the binary and listing the registered pathnames.
- [x] **LIFE-028**: If closing or deleting a resolved binary raises an error, then the system shall log the error and fail the deletion with a `stop` failure carrying the reason.
- [x] **LIFE-036**: If deleting a binary fails after its program was closed, then the system shall return the binary to the unopened state, to be reopened on next use, and make the failure reason available to the caller.
- [x] **LIFE-047**: If deletion is requested for a binary that is importing, or is queued for or undergoing analysis, then the system shall refuse with a `retry_later` failure and leave the binary unchanged.

## Shutdown and Resources

- [x] **LIFE-029**: When the context is closed in headless mode, the system shall cancel any in-flight analysis, wait for the background worker to stop, close each opened program without saving (logging and continuing past failures), and close the project.
- [x] **LIFE-035**: When a program is deleted, or the context is closed, the system shall dispose of that program's decompiler.
