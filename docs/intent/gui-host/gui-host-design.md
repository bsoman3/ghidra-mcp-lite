---
parent: high-level-design
prefix: GUI
---

# GUI Host

*Code references name Ghidra 12.1 APIs; behavior marked "observed" was seen in a spike against Ghidra 12.1.4 on macOS.*

## Context and Design Philosophy

GUI mode (`ghidra-mcp --gui`) hosts the Ghidra GUI inside the server's own process, so the analyst and the agent work on the same in-memory programs: an edit made by a tool appears in CodeBrowser immediately, and the agent can ask what the analyst is looking at. The choice of in-process hosting over a Java plugin or a shared Ghidra Server is recorded in [the GUI integration decision](../../decisions/gui-integration.md).

This component owns everything that exists only in GUI mode: launching the GUI, binding to its project, opening programs in CodeBrowser, delegating analysis to Ghidra's analysis manager, running writes on the Swing thread, the GUI save policy, and the GUI-only tools. It plugs into program-lifecycle (as the GUI implementation of its project-and-program host) and write-back (as the GUI implementation of its mutation runner). Headless mode never loads it.

Principles:

- **The analyst stays in control** (HLD tenet). The server never changes the analyst's current program, cursor, or selection except through `go_to`, never saves, and never starts analysis the analyst didn't ask for through a server request or the startup inputs. Edits land in Ghidra's undo history, where the analyst can reverse them.
- **One process, one project, one analyst.** The server serves the project the GUI opened at launch, over HTTP, for as long as the GUI runs.
- **Same tools, same contracts.** Every headless tool works in GUI mode with the same results and failure categories. Differences are limited to what this document states: who runs analysis, when edits are saved, and which extra failures the GUI can cause.
- **GUI state is touched only on the Swing thread** — and nothing else is, so the GUI stays responsive.

## Launch

`ghidra-mcp --gui [--project-path P] [--project-name N] [INPUT_PATHS…]`:

1. **Validate the command line.** GUI mode serves over streamable HTTP: when no transport is chosen, it uses `streamable-http`; an explicit `stdio` is a usage error. `--analyze-only`, `--list-project-binaries`, and `--delete-project-binary` are headless one-shots and are usage errors with `--gui`. The HTTP port is checked for availability before anything starts, so a busy port fails at once rather than after the GUI appears.
2. **Ensure the project exists.** Ghidra can open a project named on its command line but not create one (observed: `GhidraRun` opens an existing project argument). A missing project is created first in a short headless child process, using the same project creation as headless mode.
3. **Launch the GUI in-process.** A pyghidra GUI launcher starts the JVM and runs `GhidraRun` with the project as its argument. On macOS the main thread then runs the GUI event loop, so the MCP server runs on a background thread. The launcher gives Python's wrapped standard streams an `isatty()` method, because pyghidra's GUI launcher replaces them with wrappers that lack one and the HTTP server's logging setup requires it (observed: startup fails without it).
4. **Bind to the project.** Once the GUI reports an active project (`AppInfo.getActiveProject()`), the server binds to it and builds its registry from it.
5. **Import inputs and start the startup analysis pass** (see Analysis), then serve.

Ghidra's normal user settings are used, so the GUI looks and behaves as the analyst's own Ghidra. A separate settings directory can be supplied through the JVM's standard `JAVA_TOOL_OPTIONS` (`-Dapplication.settingsdir=…`), which the GUI smoke suite uses.

**Stopping.** Closing the Ghidra GUI ends the process, and Ghidra's own "save changes?" prompts handle unsaved work. The server has no separate shutdown path in GUI mode.

**Server failure after launch.** If the MCP server fails after the GUI has launched (for example, the port is taken in the meantime), the error is logged and the GUI stays open: the analyst may be mid-work, and closing their window would be the server acting against them.

## Project and Programs (the GUI host)

program-lifecycle reaches projects and programs through a host; this component is the GUI host.

| Operation | GUI host behavior |
|---|---|
| Project | The GUI's active project at launch. If the active project later changes or closes, every tool call fails with `stop` ("the Ghidra GUI closed project P; restart `ghidra-mcp --gui`"). The server does not follow the switch. |
| Registry | Program files in the bound project, as in headless mode. Because the analyst can import, rename, or delete programs through the GUI, the registry is refreshed from the project when the project listing is requested and when a binary name fails to resolve. A registered binary whose file has disappeared is dropped. A program added through the GUI is `ready` on first use if Ghidra marks it analyzed; otherwise, unless it is queued for analysis, it becomes `failed` with "not analyzed yet", and the gate's `stop` directs the caller to `reanalyze_binary` — the server does not start analysis the analyst skipped. |
| Opening a program | `DomainFile.getDomainObject` with the server's consumer. If the GUI already has the program open, Ghidra returns that same in-memory program (observed), which is what makes edits live. Opening a program for a tool call does not open it in CodeBrowser. |
| Import | `ProgramLoader` into the bound project, from the background worker (observed working off the Swing thread). Creating the project file is the only save GUI mode performs. |
| Opening in CodeBrowser | Only when the server starts analysis of a program (see Analysis), as a visible tab that does not become current (`ProgramManager.OPEN_VISIBLE`), so the analyst's view does not change. |
| Deletion | Refused with `stop` while the program has unsaved changes ("save or discard them in Ghidra first"), so deletion never prompts the analyst or discards their work. Otherwise close the program in every CodeBrowser that has it open, release the server's consumer, then delete the project file. If Ghidra refuses (for example, another tool still holds it), the call fails with `stop` and the reason. |
| Saving | Never, except creating an imported program's file (see Writes). |

**Which CodeBrowser.** The server uses the CodeBrowser whose window most recently had focus (`DockingWindowManager.getActiveInstance()`, among running CodeBrowser tools). If no CodeBrowser is running when one is needed, the server launches the default tool on the program it needs (Ghidra launches tools only with at least one file). Results that depend on it name the binary involved.

## Analysis

In GUI mode, analysis is Ghidra's own: it runs through the program's `AutoAnalysisManager`, in CodeBrowser's background task, with Ghidra's progress display and cancel control. program-lifecycle's statuses and gate behave as in headless mode; this section defines how they map onto Ghidra's manager.

**Running an analysis** (imports, `reanalyze_binary`, and the startup pass), one binary at a time on program-lifecycle's background worker:

1. Mark the program not to prompt for analysis (`GhidraProgramUtilities.markProgramNotToAskToAnalyze`), so opening it in CodeBrowser does not show Ghidra's "Analyze now?" dialog (observed).
2. Apply the binary's analysis options (analysis-config), on the worker, in their own transaction.
3. Open the program in the chosen CodeBrowser as a visible, non-current tab.
4. Register an `AutoAnalysisManagerListener`, then `reAnalyzeAll(null)` and `startBackgroundAnalysis()`.
5. Wait for analysis to end: the `analysisEnded` callback, or analysis no longer running after it has been seen running (covering an analyst who closes the tab mid-analysis). If analysis has not started within 30 seconds, the binary becomes `failed` ("Ghidra did not start analysis"). Then wait until the program has no open transaction: the listener fires while Ghidra's "Auto Analysis" transaction is still open (observed), and work done before it closes merges into it.
6. Not cancelled → mark the program analyzed (`markProgramAnalyzed`, which Ghidra does not do on this path — observed) in the server's own transaction, and set status `ready`. Cancelled → status `failed` with "analysis was cancelled in the Ghidra GUI", recoverable with `reanalyze_binary`.

**Startup pass.** Programs given on the command line, and programs in the project that Ghidra says need analysis, are analyzed as in headless mode, through the steps above. Programs Ghidra already marks as analyzed are `ready` on first use.

**Analysis the analyst starts.** When the analyst runs analysis from the GUI on a `ready` binary, its manager reports `isAnalyzing()`; for as long as that lasts the binary is listed as `analyzing`, re-analysis and deletion are refused with `retry_later`, and tool calls wait as usual and then answer `retry_later` ("Ghidra is analyzing 'x' (started in the GUI)"), since the server does not know how long it has been running.

**Blind spot.** Ghidra's analysis manager reports only that analysis ended or was cancelled. Analyzer errors are shown by Ghidra itself and are not reported to the server, so a binary whose analysis partly failed reads `ready`. This is documented to clients (HLD tenet *Explicit over silent*).

## Writes (the GUI mutation runner)

write-back prepares each edit (resolving the target, decompiling, parsing) on the request thread, then hands the mutation to a runner; this component is the GUI runner.

- **On the Swing thread, as its own transaction.** The mutation runs on the Swing thread in a transaction of its own. The analyst's own edits also run on the Swing thread, so the two never overlap.
- **Only when the program is idle.** Ghidra merges overlapping transactions on one program into one, and an abort in any of them aborts them all (Ghidra's transaction status `NOT_DONE_BUT_ABORTED`). So, immediately before starting, the runner checks the program's open transaction on the Swing thread; if one is open (analysis, a background command), the call fails with `retry_later` naming what Ghidra is doing ("Ghidra is busy with 'Auto Analysis' on hello-1a2b3c; retry shortly"). A background task that starts a transaction during the write's few milliseconds can still merge with it; this residual risk is documented.
- **Applied, not saved.** The edit stays unsaved; the analyst saves it with the rest of their work. The confirmation states that the edit is applied but not saved. The transaction's description — the same text that names the edit in headless mode — becomes its entry in Ghidra's undo history (observed), so the analyst can undo one agent edit.

A Ghidra analysis worker (`AutoAnalysisManager.scheduleWorker`) is not used for writes: it runs its callback inside analysis's own "Auto Analysis" transaction (observed), merging the write into analysis rather than isolating it.

## GUI-only Tools

Registered only in GUI mode:

| Tool | Parameters | Result | Failures |
|---|---|---|---|
| `get_current_address` | none | The binary open in the chosen CodeBrowser's current program, the cursor's address, and the name of the function containing it (or none) | `stop` if no CodeBrowser is running or it has no program open |
| `get_current_function` | none | The binary and the function containing the cursor (qualified name, entry address, signature) | `stop` if the cursor is not inside a function (stating the address), or as above |
| `go_to` | `binary_name`, `name_or_address` | Confirmation naming the location; a `resolution` note when the target came from a loose match | Resolution's read-mode failures (`fix_input`); program-lifecycle's gate |

`go_to` resolves its target in resolution's read mode, opens the binary in the chosen CodeBrowser if needed and makes it the current program, and moves the cursor there (`GoToService.goTo`). It is the one tool that changes the analyst's view, because changing it is the request.

## Threading

| Runs on the Swing thread | Runs elsewhere |
|---|---|
| Launching CodeBrowser; opening, closing, and selecting programs in it; navigation; reading the current location; each write's mutation transaction | Reads (queries), decompilation, imports, applying analysis options, waiting for analysis, registry refreshes, everything in headless code paths |

Rules:
- Calls are marshalled with `Swing.runNow` and a 30-second timeout; a Swing thread that does not respond within it fails the call with `stop` ("the Ghidra GUI is not responding").
- Code holding an open transaction never waits on the Swing thread, so a GUI repaint that needs the program cannot deadlock with it.
- program-lifecycle's per-program lock is still taken by every tool call; the Swing thread never takes it.
- Reads run concurrently with the analyst's edits. Ghidra's database lock keeps individual reads consistent; a listing iteration interrupted by a concurrent change surfaces as queries' partial-result markers or an internal error, like any other read failure.

## Testing

All Ghidra GUI calls go through one adapter (`GuiServices`), so the GUI-mode context can be exercised without a GUI.

- **Unit tests** cover this component's logic against a fake of that adapter: project binding and refresh, status mapping, the busy check, waiting for analysis and its transaction, marking analyzed, cancellation, deletion, current-location rules, `go_to`, and command-line validation.
- **GUI smoke suite** (marked `gui`, run on demand when `GHIDRA_MCP_GUI_TESTS=1`, needing a display). It starts `ghidra-mcp --gui` in a child process with isolated settings (`JAVA_TOOL_OPTIONS=-Dapplication.settingsdir=…`, with the license agreement accepted and startup tips disabled so no dialog blocks), and drives it over HTTP: import → `ready`, a write visible to a following read and reported as unsaved, `go_to` then `get_current_address` and `get_current_function`.
- **Manual checklist** for what automation cannot judge: no analysis prompt, the progress display, the undo entry, the listing refreshing.

## Decisions & Alternatives

| Decision | Chosen | Alternatives Considered | Rationale |
|----------|--------|------------------------|-----------|
| Hosting | The GUI in the server's process | A Java plugin with a bridge; a shared Ghidra Server repository; a documented hand-off | See [the GUI integration decision](../../decisions/gui-integration.md). |
| Transport in GUI mode | Streamable HTTP only | stdio | pyghidra's GUI launcher takes over standard output, and an MCP client launching a GUI over stdio is not a workflow. |
| Project | The GUI's active project at launch; `stop` if it changes | Follow the analyst to another project | One project per run keeps the registry, statuses, and options coherent; following would silently retarget the agent. |
| Missing project | Create it in a headless child process before launch | Create it through the GUI's project manager after launch | The child-process path reuses headless project creation and was exercised; the in-GUI path is unexercised. |
| Analysis | Ghidra's `AutoAnalysisManager`, in CodeBrowser's background task | The headless `analyzeAll` path on the server's worker | HLD tenet *The analyst stays in control*: the analyst sees and can cancel analysis, and two analysis engines never run on one program. |
| Readiness after analysis | Wait for Ghidra's analysis transaction to close, then mark analyzed | Trust `analysisEnded` alone | The listener fires while the transaction is still open, and Ghidra does not mark the program analyzed on this path (both observed). |
| Opening programs in CodeBrowser | Only to run analysis, as a visible, non-current tab | Open every program a tool touches; open hidden | Tool calls work without CodeBrowser; analysis needs a tool to run in; a visible tab shows its progress without changing the analyst's current program. |
| Write isolation | Swing thread, own transaction, `retry_later` if another transaction is open | Run writes in an analysis worker; write from the request thread | An analysis worker runs inside analysis's transaction (observed); request-thread writes can overlap the analyst's edits. |
| Saving | Never (apart from creating imported files); the reply says the edit is unsaved | Save after every write, as headless mode does | Saving would also save the analyst's unsaved work; leaving it unsaved keeps each edit undoable (HLD tenet *The analyst stays in control*). |
| GUI-only tools | `get_current_address`, `get_current_function`, `go_to`, registered only with `--gui` | Register everywhere and fail headless | Agents see only tools that can work. |
| "Current" with several CodeBrowsers | The most recently focused one, naming the binary in results | Fail when more than one is open | Matches the analyst's sense of "where I am"; naming the binary discloses the choice (HLD tenet *Never guess for the caller*). |
| Cursor outside a function | `get_current_function` fails with `stop`, stating the address | Return an empty function | The agent should report it rather than act on nothing; `get_current_address` already covers the general case. |
| Settings | The analyst's own Ghidra settings; overridable through `JAVA_TOOL_OPTIONS` | Always isolated settings | GUI mode is the analyst's Ghidra; isolation is a testing need, met by a standard JVM mechanism. |

## Open Questions & Future Decisions

### Resolved
1. ✅ **Programs added through the GUI without analysis.** `failed` with "not analyzed yet" on first use, directing the caller to `reanalyze_binary`; the server does not start analysis the analyst skipped. (2026-10-04)
2. ✅ **Deleting a program with unsaved changes.** Refused with `stop`; the analyst saves or discards first. (2026-10-04)
3. ✅ **The analyst closes the analysis tab.** Analysis no longer running after it started counts as ended; analysis that never starts within 30 s is a failure. (2026-10-04)
4. ✅ **Server failure after launch.** Logged; the GUI stays open. (2026-10-04)

### Deferred
1. **Analyzer failure detection.** Ghidra's manager does not report analyzer errors; reading them from Ghidra's message log could close the blind spot later.
2. **Hidden programs for analysis.** Opening programs with `OPEN_HIDDEN` would avoid new tabs during the startup pass, if analysis runs for hidden programs; unverified.

### Open (observed behavior, intent unstated)
*(none)*

### Known gaps against stated intent
*(none)*

## References

- Decision: [GUI integration](../../decisions/gui-integration.md)
- Plugs into: program-lifecycle (project-and-program host), write-back (mutation runner), server (`--gui`, transport rule, GUI-only tool registration), analysis-config (options applied before Ghidra's analysis starts), resolution (`go_to` in read mode)
- External: pyghidra GUI launcher; Ghidra `GhidraRun`, `AppInfo`, `ProgramLoader`, `DomainFile`, `ProgramManager`, `CodeViewerService`, `GoToService`, `AutoAnalysisManager`, `AutoAnalysisManagerListener`, `GhidraProgramUtilities`, `DockingWindowManager`, `Swing`
- Arrow: `docs/arrows/gui-host.md`
