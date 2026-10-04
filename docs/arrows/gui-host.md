# Arrow: gui-host

GUI mode (`--gui`): hosting the Ghidra GUI in the server's process, binding to its project, delegating analysis to Ghidra's analysis manager, running writes on the Swing thread without saving, and the GUI-only tools.

## Status

**OK** — all 31 active specs implemented and covered by tests (2026-10-04), including an on-demand GUI smoke suite run against Ghidra 12.1.4 on macOS; audited at `5cc28ab`.

## References

### HLD
- docs/high-level-design.md § Approach (GUI mode); § Tenets (*The analyst stays in control*); § System Design; § Key Design Decisions
- docs/decisions/gui-integration.md

### LLD
- docs/intent/gui-host/gui-host-design.md

### EARS
- docs/intent/gui-host/gui-host-specs.md (31 specs, prefix `GUI-*`)

### Tests
- `tests/test_gui_host.py` — the GUI-mode context, write runner, GUI-only tools, and serving, against a fake `GuiServices`
- `tests/test_server.py` — `--gui` command-line rules and GUI-only tool registration
- `tests/test_packaging.py` — README GUI Mode section
- `tests/gui/test_gui_smoke.py` — real GUI, driven over HTTP (`GHIDRA_MCP_GUI_TESTS=1`, needs a display)

### Code
- `src/ghidra_mcp/gui.py` — `GuiServices` (the only code touching Ghidra GUI APIs), `GuiGhidraContext` (the GUI host), `serve_when_ready`, `launch`, `check_port`, `ensure_project`, `ensure_isatty`
- `src/ghidra_mcp/server.py` — `--gui` handling in `main`; `get_current_address`, `get_current_function`, `go_to`, `register_gui_tools`
- Seams it plugs into, owned elsewhere: program-lifecycle (`GhidraContext`'s project and program operations), write-back (`LoadedProgram.mutation_runner`, used by `_with_transaction`)

## Architecture

**Purpose:** Let the analyst watch and steer the agent in Ghidra's GUI by serving MCP from inside the GUI's process, on the same in-memory programs, without overriding the analyst's work.

**Key Components:**
1. Launch — command-line rules, a port check, project creation in a headless child process, pyghidra's GUI launcher with the server on a background thread.
2. GUI host — `GuiGhidraContext` binds to the GUI's project, follows programs added or removed in the GUI, opens programs through their project files (sharing the GUI's instances), and never saves.
3. Analysis — Ghidra's analysis manager in CodeBrowser's background task; readiness after its transaction closes; cancellation and analyst-started analysis mapped onto statuses.
4. Writes — Swing-thread transactions, refused with `retry_later` while another transaction is open; replies say the edit is unsaved.
5. GUI-only tools — current address, current function, and `go_to`, against the most recently focused CodeBrowser.

## Spec Coverage

| Category | Spec IDs | Implemented | Deferred | Gaps |
|----------|----------|-------------|----------|------|
| Launch | GUI-001 to GUI-008 | 8 | 0 | 0 |
| Project and programs | GUI-009 to GUI-016 | 8 | 0 | 0 |
| Analysis | GUI-017 to GUI-022 | 6 | 0 | 0 |
| Writes | GUI-023 to GUI-025 | 3 | 0 | 0 |
| GUI-only tools | GUI-026 to GUI-030 | 5 | 0 | 0 |
| Threading | GUI-031 | 1 | 0 | 0 |

**Summary:** 31 of 31 active specs implemented, all with tests; 0 gaps. No open questions; 2 items are deferred.

## Key Findings

1. **Live sharing works** — the GUI and the server hold the same in-memory program, so edits appear immediately (observed in the spike and the smoke suite).
2. **Analysis transactions outlive the end signal** — Ghidra reports analysis ended while its "Auto Analysis" transaction is still open, and does not mark the program analyzed on this path; the host waits and marks it.
3. **Analysis workers merge, not isolate** — a write run inside `AutoAnalysisManager.scheduleWorker` joins analysis's transaction, so writes use their own Swing-thread transaction instead.
4. **Ghidra launches tools only with a file** — CodeBrowser is launched on the program it needs.

## Work Required

### Must Fix
*(none)*

### Should Fix
*(none)*

### Nice to Have
*(none)*

### Deferred
- Analyzer failure detection from Ghidra's message log; analysis of hidden programs (LLD Deferred 1–2).

### Open Questions
*Mirrors the LLD's Open Questions with the same numbering.*
*(none)*
