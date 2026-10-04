# GUI Host Specs

**LLD**: docs/intent/gui-host/gui-host-design.md
**Implementing artifacts**:
- src/ghidra_mcp/gui.py (`GuiServices`, `GuiGhidraContext`, launcher and GUI-mode serving)
- src/ghidra_mcp/server.py (`--gui` handling, GUI-only tool registration)

Status markers: `[x]` implemented · `[ ]` active gap · `[D]` deferred

*Tests: `tests/test_gui_host.py`, `tests/test_server.py` (command line, registration), `tests/test_packaging.py` (README), and the on-demand GUI smoke suite `tests/gui/test_gui_smoke.py`.*

*"GUI mode" means the server was started with `--gui`. "The chosen CodeBrowser" is the running CodeBrowser whose window most recently had focus, or else the first running CodeBrowser.*

---

## Launch

- [x] **GUI-001**: When `--gui` is given without a transport option, the system shall serve over streamable HTTP.
- [x] **GUI-002**: If `--gui` is given with the `stdio` transport, or together with `--analyze-only`, `--list-project-binaries`, or `--delete-project-binary`, then the system shall reject the command line before starting Ghidra.
- [x] **GUI-003**: If the HTTP host and port cannot be bound when `--gui` is given, then the system shall exit with an error before launching the GUI.
- [x] **GUI-004**: When `--gui` is given and the project does not exist, the system shall create it in a separate headless process before launching the GUI.
- [x] **GUI-005**: When `--gui` is given, the system shall launch the Ghidra GUI in its own process with the project open, and, once the GUI reports the project active, build its GUI-mode context, import the input paths, start the analysis pass, register the GUI-only tools, and serve MCP from a background thread.
- [x] **GUI-006**: When the Ghidra GUI exits in GUI mode, the system shall exit.
- [x] **GUI-007**: When serving in GUI mode, the system shall give the standard streams wrapped by pyghidra's GUI launcher an `isatty()` method, so that the HTTP server can start.
- [x] **GUI-008**: If the MCP server fails after the GUI has launched, then the system shall log the error and leave the GUI open.

## Project and Programs

- [x] **GUI-009**: In GUI mode, the system shall bind to the GUI's active project at launch and serve only that project.
- [x] **GUI-010**: If the GUI's active project changes or closes after launch, then the system shall fail every tool call with a `stop` failure stating that the project changed and that the server must be restarted.
- [x] **GUI-011**: In GUI mode, when the project listing is requested, or a binary name fails to resolve, the system shall refresh its registry from the project, registering Program files it does not know and dropping registered binaries whose files no longer exist.
- [x] **GUI-012**: When a tool first uses a program in GUI mode that Ghidra does not mark as analyzed and that is not queued for analysis, the system shall mark it `failed` with the reason that it has not been analyzed, without starting analysis.
- [x] **GUI-013**: When opening a program for a tool call in GUI mode, the system shall obtain it from its project file with the server's own consumer, sharing the in-memory program the GUI has open, and shall not open it in CodeBrowser.
- [x] **GUI-014**: When importing a binary in GUI mode, the system shall load it into the bound project with Ghidra's program loader, saving only to create the program's project file.
- [x] **GUI-015**: If deletion is requested in GUI mode for a program with unsaved changes, then the system shall refuse with a `stop` failure asking for the changes to be saved or discarded in Ghidra first. Otherwise it shall close the program in every CodeBrowser, release the server's consumer, and delete the project file.
- [x] **GUI-016**: In GUI mode, the system shall not save any program, except to create an imported program's project file.

## Analysis

- [x] **GUI-017**: When running analysis of a binary in GUI mode, the system shall mark the program not to prompt for analysis, apply the binary's analysis options, open the program in the chosen CodeBrowser as a visible tab that does not become current (launching CodeBrowser if none is running), and start Ghidra's analysis manager with a full re-analysis in the background.
- [x] **GUI-018**: When running analysis in GUI mode, the system shall treat analysis as ended when Ghidra's analysis manager reports its end, or when analysis is no longer running after it has been seen running. If analysis has not started within 30 seconds, then the system shall fail the analysis, stating that Ghidra did not start it.
- [x] **GUI-019**: When analysis ends without cancellation in GUI mode, the system shall wait until the program has no open transaction, then mark the program analyzed in its own transaction and set the binary `ready`.
- [x] **GUI-020**: If analysis is cancelled in the GUI, then the system shall mark the binary `failed`, stating that analysis was cancelled in the Ghidra GUI.
- [x] **GUI-021**: While Ghidra is analyzing a `ready` binary on the analyst's request in GUI mode, the system shall list the binary as `analyzing`, refuse re-analysis and deletion with `retry_later`, and answer tool calls for it with `retry_later` (after the usual wait), stating that Ghidra is analyzing it from the GUI.
- [x] **GUI-022**: The README shall state that, in GUI mode, analyzer failures are not reported and a binary whose analysis partly failed is listed as `ready`.

## Writes

- [x] **GUI-023**: When a write tool applies its change in GUI mode, the system shall run the mutation on the Swing thread as its own transaction, without saving the program.
- [x] **GUI-024**: If a transaction is already open on the program when a write is about to start in GUI mode, then the system shall not start the write, and shall fail the call with `retry_later` naming the open transaction.
- [x] **GUI-025**: When a write succeeds in GUI mode, the system shall state in its confirmation that the change is applied but not saved.

## GUI-only Tools

- [x] **GUI-026**: The system shall register `get_current_address`, `get_current_function`, and `go_to` only in GUI mode.
- [x] **GUI-027**: When `get_current_address` is called, the system shall return the binary of the chosen CodeBrowser's current program, the cursor's address, and the name of the function containing it, or none.
- [x] **GUI-028**: When `get_current_function` is called and the cursor is inside a function, the system shall return the binary and that function's qualified name, entry address, and signature. If the cursor is not inside a function, then the system shall fail with `stop`, stating the cursor's address.
- [x] **GUI-029**: If `get_current_address` or `get_current_function` is called while no CodeBrowser is running or the chosen CodeBrowser has no program open, then the system shall fail with `stop`.
- [x] **GUI-030**: When `go_to` is called, the system shall resolve its target as a cross-reference target is resolved (RES-012, RES-019, RES-022), open the binary in the chosen CodeBrowser as its current program (launching CodeBrowser if none is running), move the cursor to the target address, and confirm the location, including resolution's disclosure note for a loose match.

## Threading

- [x] **GUI-031**: If the Swing thread does not run a GUI-mode call within 30 seconds, then the system shall fail the call with `stop`, stating that the Ghidra GUI is not responding.
