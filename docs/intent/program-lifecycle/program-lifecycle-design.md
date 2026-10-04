---
parent: high-level-design
prefix: LIFE
---

# Program Lifecycle

*Code references name symbols in `src/ghidra_mcp/context.py` unless another file is given.*

## Context and Design Philosophy

Every tool in the server acts on a Ghidra `Program` that lives in a Ghidra project on disk. This component owns that project and the set of binaries in it. It gets binaries into the project, gets them analyzed, and keeps tools away from a binary until its analysis has finished.

`GhidraContext` is the single long-lived object. The server's CLI constructs it once per process (`server.py` `main`) and shares it with every MCP request through the server lifespan.

Principles:

- **Serve early, gate per binary.** The server accepts connections before analysis finishes. A tool call for an unfinished binary waits a bounded time for it, then fails with `retry_later` (README § How It Works).
- **Persist and reuse analysis.** The project lives on disk, and a binary that Ghidra already considers analyzed is not re-analyzed unless re-analysis is requested for it with `reanalyze_binary`.
- **One background worker.** Imports and analysis run in order on a single worker, so no two background jobs touch the project at once.
- **Open lazily, serialize per program.** Programs are registered at startup but opened only when first needed. Every Ghidra operation on a program runs under that program's lock, so the server's parallel tool calls (SDK 2.x worker threads) never touch one program concurrently (see Concurrency Model).
- **Status is always visible** (HLD tenet *Explicit over silent*). Every binary, including one still importing or one whose analysis failed, has a status a client can see, and a refusal at the gate names its recovery: `retry_later` while work is pending, `stop` once it has failed (see Program Status).

Analysis *configuration* (symbols, GDTs, analyzer options) belongs to analysis-config; this component stores each binary's analysis options and hands them over when the binary is analyzed. Name and address resolution *inside* a program belongs to resolution. This component resolves only *binary* names.

## Runtime Record: `LoadedProgram`

`LoadedProgram` is a dataclass with one instance per binary the context knows about, including a background import that has not reached the project yet:

| Field | Meaning |
|---|---|
| `name`, `pathname` | Program name and project pathname (e.g. `/ls-a1b2c3`); the registry key is the pathname |
| `status` | `importing`, `analyzing`, `ready`, or `failed` (see Program Status) |
| `domain_file` | The project file; `None` until an import reaches the project |
| `program`, `decompiler` | The open `Program` and its `DecompInterface`; `None` until first opened |
| `metadata` | Ghidra metadata, read from the project file at registration and refreshed when the program is opened or analyzed |
| `file_path` | Metadata `Executable Location`, else the import's source path |
| `source_path` | The file a background import came from |
| `load_time` | When this process registered or imported the binary |
| `options` | Analysis options supplied in this process; `None` means "read the options stored with the program" |
| `failure`, `warnings` | Failure reason (status `failed`); configuration warnings recorded during the last analysis |
| `reanalysis_requested`, `work_started` | A forced pass is pending; when the current import or analysis began |
| `lock`, `settled` | The per-program re-entrant lock; an event set when the binary becomes `ready` or `failed` |

Per-program setup (`_ensure_open`, `_setup_decompiler`): the decompiler takes its options from the program (`grabFromProgram`), allows a 100 MB payload (`setMaxPayloadMBytes(100)`), and is opened on the program immediately. The server's response model `models.ProgramInfo` is a separate type that the project listing builds from these records.

## Project Open / Create

`_get_or_create_project`:

1. Create `project_path` with parents if missing.
2. If `ProjectLocator(abs(project_path), project_name).exists()`, open it with `GhidraProject.openProject(dir, name, True)`.
3. Otherwise create it with `GhidraProject.createProject(dir, name, False)`.

Translating a `.gpr` path into a directory and name happens in the server's CLI.

## Program Registry and Binary Resolution

**Registry:** `programs: dict[str, LoadedProgram]`, keyed by project pathname, guarded by the registry lock. Readers take snapshots (`list_entries`), so iteration never races a background import adding an entry.

**Startup registration** (`_register_project_programs`): construction registers every Program-type file in the project (`list_binary_domain_files`) without opening it, with status `analyzing` and metadata read by `DomainFile.getMetadata()`, which reads the stored file without opening the program (verified against Ghidra's `GhidraFileData`).

**Lazy opening** (`_ensure_open`): a program and its decompiler are opened read-write the first time a tool or the analysis pass needs them, under the program's lock. Programs stay open once opened. When a tool first requests a program that Ghidra already marks as analyzed, and no re-analysis is pending for it, the program becomes `ready` at once, without waiting for its turn in the background pass (`_ready_if_already_analyzed`). Lazy opening therefore mainly speeds startup and one-shot commands, rather than lowering steady-state memory.

**Resolution** (`_resolve`):

```
resolve(binary_name):
  exact pathname?                                  → found
  basename matches exactly one registered binary?  → found
  basename matches several                         → fix_input, listing their pathnames
  else                                             → fix_input "Binary '<n>' not found. Available: [<pathnames>]"
```

**The analysis gate** (`get_program_info`) resolves the binary, applies the instant-ready check above, waits if the binary is pending (see Program Status), refuses unless it is `ready`, and opens it. The "Available" list shows full pathnames, while `list_project_binaries` shows names. Both forms resolve.

## Import

**Naming** (`_unique_name`): `<filename>-<first 6 hex chars of SHA-1 of the file contents>`, hashed in 64 KiB chunks, so the same filename from different paths can coexist.

**Deduplication** (`_new_import_entry`): a file whose unique name is already registered at the project root is not imported again, and that binary keeps its stored analysis options. A previous import of the same file that failed before reaching the project is replaced by the new attempt.

**Background import** (`import_binary_backgrounded(path, options)`, used by the MCP `import_binary` tool): raises `FileNotFoundError` at once if the path doesn't exist. Otherwise, for the file (or every file beneath a directory, recursively and unfiltered), it registers an `importing` entry carrying the options and queues an import job on the background worker. It returns the names it queued and, separately, the names already in the project, so the caller can be told which binaries were not re-imported. The job imports the file (`importProgram`, set the name, store the options with the program, `saveAs` at the root), opens its decompiler, and continues straight into the binary's analysis pass. If the import raises, the entry becomes `failed` with "Import failed: <reason>".

**Command-line import** (`import_binaries(paths, options=None)`): the server's positional inputs are imported synchronously, in order, before serving, with default options. A failure is recorded as a `failed` entry and the batch continues. These binaries are analyzed by the project analysis pass.

| Caller | Path | Analysis |
|---|---|---|
| CLI positional inputs | `import_binaries`, synchronous, before the server starts | queued by `analyze_project` |
| MCP `import_binary` tool | `import_binary_backgrounded` | the import job runs the analysis pass itself |

## Analysis Scheduling

**`analyze_project(wait=False)`** queues one analysis job per binary that is `analyzing` and not already queued, on the background worker. When serving, it returns at once. With `wait=True` (used only by `--analyze-only`), it blocks until those jobs finish.

**The analysis pass for one binary** (`_analyze_job`), under the binary's lock:

```
if the context is closing                 → stop
if the binary is ready and no forced pass is pending → stop   (became ready on first use)
open the program if needed
options ← options supplied in this process, else the options stored with the program
if a forced pass is pending or Ghidra says the program should be analyzed:
    clear configuration warnings
    apply the binary's configuration and run auto-analysis   (analysis-config; FlatProgramAPI.analyzeAll)
    markProgramAnalyzed(program)
    save the program                       ← only after a pass that didn't raise
status ← ready
on any exception: status ← failed, failure ← "Analysis failed: <reason>"; nothing is saved
finally: clear the forced-pass flag and leave the queue
```

Auto-analysis runs with a cancellable task monitor (a console monitor under `--verbose-analysis`), so shutdown can stop it.

## Program Status

Each binary the context knows about carries a status, a failure reason when it has failed, and any configuration warnings recorded during its analysis (analysis-config). All three are exposed to the server's project listing.

| Status | Meaning | Gate response to a tool call |
|---|---|---|
| `importing` | A background import has been accepted and is queued or running | wait, then `retry_later` |
| `analyzing` | In the project; queued for or undergoing its analysis pass | wait, then `retry_later` |
| `ready` | The analysis pass finished without error | allowed |
| `failed` | Import or analysis raised; the reason is recorded | `stop`, carrying the reason and the next step |

```
   import_binary ──► importing ──(import ok)──► analyzing ──(pass ok)──► ready
                         │                         │
                         └──(raises)──► failed ◄───┘ (raises)
   startup registration ──────────────► analyzing
   reanalyze_binary:  ready | failed (analysis) ──► analyzing
   delete:            ready | failed ──► (absent)
```

- **Waiting for readiness (on by default).** When a tool requests an `importing` or `analyzing` binary, the gate waits up to 45 s for it to become `ready` or `failed`, then answers accordingly. If it is still pending, the gate answers `retry_later` with a message saying how long the binary's import or analysis has been running, or that it is queued and behind how many binaries. The wait holds no lock: it waits on the binary's `settled` event, so background work and other calls proceed. `--no-wait-for-analysis` makes the gate answer `retry_later` at once.
- **Refusing a failed binary.** The `stop` message carries the recorded reason and the next step: `import_binary` again for a binary whose import failed, `reanalyze_binary` for one whose analysis failed.
- **Failure lifetime.** A failure is held for the life of the process. `reanalyze_binary` retries a binary whose analysis failed, with new options if needed, without a restart. On the next startup, a program Ghidra does not mark as analyzed is analyzed again.
- **Metadata of a pending binary.** `get_metadata` (behind `list_project_binary_metadata`) returns a binary's metadata whatever its analysis state, and answers `retry_later` only while the binary is still importing.

## Per-binary Analysis Options and Re-analysis

Each binary carries its own analysis options (`AnalysisOptions`): `pdb_path`, `gdts` (an ordered list of archive paths), `analyzer_options` (a mapping from Ghidra analysis option name to value), and `no_symbols`. analysis-config receives them when the binary is analyzed.

- **Setting them.** `import_binary` supplies options for a new binary. Binaries given on the command line, and binaries found in the project, use default options: none of the above set.
- **Validation** (`AnalysisOptions.create`). `pdb_path` and every GDT path must name an existing file when the tool is called, else `fix_input` naming the path, before anything is queued.
- **Persistence.** Options are stored as JSON with the program, under the program-options category `ghidra-mcp`, key `analysis-options`: during import, and saved immediately on re-analysis. A restart before analysis completes therefore re-runs with the same options.
- **`reanalyze_binary(binary_name, options)`.** Replaces the binary's stored options (omitted arguments revert to defaults), clears any recorded failure and configuration warnings, sets status `analyzing`, and queues a forced analysis pass on the background worker. It returns immediately. While the binary is `importing` or `analyzing`, the request is refused with `retry_later`. A binary whose import failed has no program to re-analyze, so the request is refused with `stop`, directing the caller to `import_binary`.

## Deletion

`delete_program(name)` resolves the binary as above (`fix_input` if it is unknown). While the binary is `importing` or `analyzing`, the request is refused with `retry_later`. Otherwise, under the program's lock, it disposes the decompiler, closes the program, deletes the project file, and removes the registry entry.

If deleting the project file fails, the binary stays registered with its program closed — the unopened state — so the next tool call reopens it lazily, and the call fails with `stop` carrying the reason.

## Shutdown

`close()` marks the context closing, cancels in-flight analysis through its task monitor, and waits for the background worker to stop, dropping queued jobs. It then disposes each decompiler and closes each opened program without saving, logging and continuing past failures, and closes the project. Nothing needs saving: every successful edit and analysis has already been saved, and `GhidraProject.close` discards unsaved changes by design (verified against Ghidra's `GhidraProject`).

## Concurrency Model

Under SDK 2.x, tool calls run on parallel worker threads, so serialization covers the request path as well as background work:

| Mechanism | Guards | Held |
|---|---|---|
| **One background worker** (`ThreadPoolExecutor(max_workers=1)`) | Ordering of background project work | Import and analysis jobs share one queue, so no two background jobs overlap. An MCP import queued behind a long analysis shows as `importing`. |
| **Per-program lock** (re-entrant) | Every Ghidra operation on one program: opening, its analysis pass, every query and write tool call (taken by `tools.handle_exceptions`), saves, deletion | For the whole operation. Analysis holds it for that program only, so calls on other programs proceed. |
| **Project-operations lock** | Ghidra project calls that add, open, or remove project files: `importProgram`/`saveAs`, `openProgram`, `DomainFile.delete` | Only around those calls |
| **Registry lock** | The `programs` dict and the background queue | Briefly; nothing else is acquired while holding it |

**Lock order.** A program's lock, then the project-operations lock, then the registry lock; never in another order. Long operations hold a program lock and occasionally need a project call or a registry update, so the program lock comes first and the others are short-lived leaves. **No lock is held while waiting** for readiness. The instant-ready check takes a program's lock only if it is free, so a tool call never blocks behind that program's analysis. `DecompInterface.decompileFunction` is itself `synchronized` (verified), but the per-program lock also covers write transactions and listing iteration, which it does not.

## Decisions & Alternatives

| Decision | Chosen | Alternatives Considered | Rationale |
|----------|--------|------------------------|-----------|
| Program naming | `<filename>-<sha1[:6]>` | Filename only; full hash | The same filename from different paths can coexist. |
| Hash prefix length | 6 hex chars (24 bits) | Longer prefix | *[inferred]* Readability. A collision needs the same filename *and* a 1-in-16M prefix match. |
| Dedupe key | Unique name at project root | Content hash regardless of filename | *[inferred]* The name already embeds the hash prefix. |
| Re-importing a binary already in the project | Skip it, keep its stored options, and tell the caller | Re-import; apply the new options silently | HLD tenet *Explicit over silent*: options passed with a skipped import would otherwise vanish unnoticed. `reanalyze_binary` is the way to change them. |
| Startup analysis | Background by default; blocking only for `--analyze-only` | Always block until analyzed | The server must accept connections immediately; stdio clients time out on a blocked handshake. |
| Re-analysis policy | Only if `shouldAskToAnalyze`, or re-analysis was requested for that binary with `reanalyze_binary` | Always re-analyze; a server-wide force flag | No re-analysis unless asked. Asking per binary avoids re-analyzing everything and needs no restart. |
| Analysis gate | Tools are refused until the binary is `ready` | Serve partially analyzed results | Results from a half-analyzed program are silently incomplete (HLD tenet *Explicit over silent*). |
| Worker model | One single-worker queue for import and analysis, plus per-program, project-operations, and registry locks | Two independent single-worker pools; a global lock | Background project work never overlaps. Per-program locks keep calls on ready programs flowing while another program is analyzed; a global lock would stall them for minutes. |
| Lock order | Program → project-operations → registry | Project lock first | Long operations already hold a program lock when they need a project call; taking the short-lived locks last means none is ever held across a long operation. |
| Program opening | Lazy: register at construction, open on first need, keep open | Eager: open everything at construction; close programs the analysis pass opened only to check them | HLD tenet *Reliability over footprint*: both are correct, since metadata is readable without opening (verified), so footprint breaks the tie. It makes startup and one-shot commands light and already-analyzed programs instantly ready. Keeping programs open avoids re-opening costs once a session is under way. |
| Waiting for readiness | By default, wait up to 45 s inside the call, holding no lock; then `retry_later` with elapsed time or queue position | Block startup; poll only; a longer cap | Startup blocking breaks stdio clients. A default in-call wait spares agents most polling — small binaries finish within it — and 45 s stays under typical client tool-call timeouts. |
| Per-binary analysis options | Stored in the binary's record, persisted with the program, set by `import_binary` and `reanalyze_binary` | Server-wide flags; memory only | Options differ per binary (a PDB matches one). Persisting them means a restart before analysis finishes re-runs it with the same options, instead of silently using defaults. |
| Re-analysis while pending | Refuse with `retry_later` | Queue a second pass | One pass per binary at a time keeps options and status unambiguous. |
| Deletion while pending | Refuse with `retry_later` | Cancel the work and delete | Cancelling a pass mid-flight risks a half-written program; waiting for the pass is cheap to retry. |
| Failed analysis | Mark `failed`; don't save | Save the partial state | The project on disk stays consistent: either fully analyzed or untouched. |
| Failed delete | Return the binary to the unopened state and report the reason | Drop it from the registry; mark it `failed` | The listing stays truthful (the file still exists), and lazy opening makes the binary usable again on its next call. |
| Shutdown | Cancel in-flight analysis, close without saving, dispose decompilers | Save on close; wait for analysis to finish | Edits and completed analyses are already saved. Cancelling avoids minute-long shutdowns; close discards unsaved changes by design (verified). |
| Decompiler lifetime | One `DecompInterface` per program, created at open, 100 MB payload, disposed on delete and close | Per-request decompiler; shared pool; leave disposal to garbage collection | *[inferred]* Amortize decompiler startup; allow large functions. A decompiler holds a native process, so disposing it is correct and lighter. |
| Analyzed-flag API | `GhidraProgramUtilities.markProgramAnalyzed` | Feature-detect older APIs | Ghidra 12.1 is the minimum (HLD Goals), and it has only `markProgramAnalyzed` (verified). |
| Binary lookup | Exact pathname, then a basename that matches exactly one program | Pathname only; last-wins basename | Clients can use the display name from `list_project_binaries`. An ambiguous basename fails per the HLD tenet *Never guess for the caller*. |
| Program status | `importing` / `analyzing` / `ready` / `failed`, with a recorded reason and warnings | A single completion flag | HLD tenet *Explicit over silent*. A completion flag can't distinguish "wait" from "this will never work". |
| Gate refusals | `retry_later` while pending; `stop` with the reason and next step once failed | One error for every not-ready case | HLD tenet *Actionable failures*. |
| Failure lifetime | Held in memory for the process; re-attempted on next startup | Persist failures in the project | Re-analysis on restart is how an operator recovers after fixing configuration. |
| Directory import | Recurse into all files | Top level only; filter by file type | *[inferred]* Convenience; files Ghidra can't load show up as `failed` imports. |
| Batch import errors | Record and continue | Abort the batch | *[inferred]* One bad file shouldn't block the rest. |

## Open Questions & Future Decisions

### Resolved
1. ✅ **Failed state.** Analysis or import failure is a visible `failed` status with a recorded reason; the gate answers `stop` with that reason. (2026-10-03)
2. ✅ **Partial delete.** A binary whose delete fails after closing returns to the unopened state, to be reopened lazily on next use, and the reason reaches the caller. (2026-10-03)
3. ✅ **Background import visibility.** In-progress imports show as `importing`; failed ones show as `failed` with the reason. (2026-10-03)
4. ✅ **Decompiler disposal.** Decompilers are disposed on delete and close. (2026-10-03)
5. ✅ **Basename collisions.** An ambiguous basename fails with `fix_input`, listing the pathnames. (2026-10-03)
6. ✅ **Partial analysis.** Not saved after a failed pass. (2026-10-03)
7. ✅ **Program opening.** Lazy; metadata comes from the `DomainFile` without opening (verified). (2026-10-03)
8. ✅ **Shutdown.** Cancel in-flight analysis, close without saving, dispose decompilers. (2026-10-03)
9. ✅ **Directory import.** No filter; per-file failures are visible as `failed` imports. (2026-10-03)
10. ✅ **Code hygiene.** The runtime record is `LoadedProgram`, distinct from the response model `models.ProgramInfo`; configuration is assigned before any program work. (2026-10-03)
11. ✅ **Concurrency.** One background worker and per-program, project-operations, and registry locks; the readiness wait holds no lock. (2026-10-03)
12. ✅ **Re-analysis tool.** `reanalyze_binary`, with per-binary options; refused with `retry_later` while pending. (2026-10-03)
13. ✅ **Per-binary analysis options.** Stored in the binary's record and persisted with the program; set by `import_binary`/`reanalyze_binary`. (2026-10-03)

### Deferred
*(none)*

### Open (observed behavior, intent unstated)
*(none)*

### Known gaps against stated intent
*(none)*

## References

- Code: `src/ghidra_mcp/context.py` (`AnalysisOptions`, `LoadedProgram`, `GhidraContext` lifecycle, import, scheduling, gate, deletion, shutdown)
- Calls out to: analysis-config (`_apply_gdts`, `_configure_analysis`, in `_run_analysis`)
- Called by: server, for CLI construction, startup import, `analyze_project`, and one-shots (`server.py` `main`), and for the project-management tools and every program tool (`server.py`)
- External: Ghidra `GhidraProject`, `ProjectLocator`, `DomainFile`, `FlatProgramAPI`, `GhidraProgramUtilities`, `GhidraScriptUtil`, `DecompInterface`, `DecompileOptions`, `TaskMonitorAdapter`, `ConsoleTaskMonitor`
- Arrow: `docs/arrows/program-lifecycle.md`
