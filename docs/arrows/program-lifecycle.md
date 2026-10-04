# Arrow: program-lifecycle

Tracks which binaries are in the Ghidra project and what state each is in: project open/create, registration with lazy opening, import (including in-progress tracking), analysis scheduling on a single background worker, program status and the analysis gate (including the default 45 s wait), per-binary analysis options and re-analysis, locking, deletion, and shutdown.

## Status

**OK** — all 47 active specs implemented and covered by tests (2026-10-03). Mapped 2026-10-03 from git SHA `1acf6ba`; implemented and audited at `7f8909c`.

## References

### HLD
- docs/high-level-design.md § Tenets (*Explicit over silent*, *Actionable failures*, *Reliability over footprint*); § System Design (segment table, cross-cutting concerns); § Key Design Decisions

### LLD
- docs/intent/program-lifecycle/program-lifecycle-design.md

### EARS
- docs/intent/program-lifecycle/program-lifecycle-specs.md (47 specs, prefix `LIFE-*`; `LIFE-003` retired)

### Tests
- `tests/test_lifecycle.py` — Ghidra-free tests against `HarnessContext` (`tests/fakes.py`), which replaces the Ghidra seams
- `tests/integration/test_ghidra_smoke.py` — real Ghidra: `--analyze-only`, waiting for an MCP import, persisted options, re-analysis

### Code
- `src/ghidra_mcp/context.py` — `AnalysisOptions`, `LoadedProgram`, `Status`; `GhidraContext`: construction and `close`, registration and `_resolve`, the gate (`get_program_info`, `_ready_if_already_analyzed`, `_pending_message`, `_failed_message`), `get_metadata`, `_ensure_open`, `delete_program`, import (`import_binary_backgrounded`, `import_binaries`, `_import_job`), scheduling (`analyze_project`, `reanalyze_binary`, `_analyze_job`), and the Ghidra seams
- `src/ghidra_mcp/tools.py` — `handle_exceptions` runs each tool method under its program's lock
- Outbound, owned elsewhere: `_apply_gdts` and `_configure_analysis` (analysis-config), which record configuration warnings on the binary
- Inbound, owned elsewhere: construction, startup import, analysis start, and one-shots in `server.py` `main`; the project-management tools and every program tool in `server.py` (server)

## Architecture

**Purpose:** Own the Ghidra project and the set of binaries. Open programs only when needed, make every binary's status visible, serialize all Ghidra access per program, and let tools run only against ready programs: waiting a bounded time for readiness, otherwise refusing with a recovery category.

**Key Components:**
1. Runtime record (`LoadedProgram`) — per-binary state: status, failure reason, warnings, analysis options, the program and decompiler once opened, metadata, source path, load time, its lock and readiness event.
2. Project and registry — opens or creates the project, registers Program files without opening them, and resolves binaries by pathname or an unambiguous basename.
3. Import — names programs `<filename>-<sha1[:6]>`, skips (and reports) files already in the project, recurses into directories, and runs synchronously (CLI inputs) or on the background worker (MCP `import_binary`).
4. Analysis scheduling — one single-worker queue for import and analysis, with a cancellable monitor. A program is analyzed only if Ghidra says it needs it or `reanalyze_binary` requested it, with its own persisted analysis options.
5. Gate and locks — the gate answers ready, `retry_later` (after the default 45 s wait, with elapsed time or queue position), or `stop` (with the reason and next step). Locks are taken in the order program → project-operations → registry; none is held while waiting.

**Program status:** `importing` → `analyzing` → `ready`, with `failed` reachable from import or analysis. Programs Ghidra already marks as analyzed are `ready` on first use.

## Spec Coverage

| Category | Spec IDs | Implemented | Deferred | Gaps |
|----------|----------|-------------|----------|------|
| Project and startup | LIFE-001, LIFE-002, LIFE-004, LIFE-005 | 4 | 0 | 0 |
| Lazy opening and listing | LIFE-038, LIFE-042 | 2 | 0 | 0 |
| Binary resolution and analysis gate | LIFE-006 to LIFE-008, LIFE-030, LIFE-032, LIFE-039 | 6 | 0 | 0 |
| Import | LIFE-009 to LIFE-015, LIFE-033, LIFE-034 | 9 | 0 | 0 |
| Analysis scheduling and status | LIFE-016 to LIFE-023, LIFE-031, LIFE-037, LIFE-040 | 11 | 0 | 0 |
| Concurrency | LIFE-024, LIFE-025, LIFE-041 | 3 | 0 | 0 |
| Per-binary options and re-analysis | LIFE-043 to LIFE-046, LIFE-048 | 5 | 0 | 0 |
| Deletion | LIFE-026 to LIFE-028, LIFE-036, LIFE-047 | 5 | 0 | 0 |
| Shutdown and resources | LIFE-029, LIFE-035 | 2 | 0 | 0 |

**Summary:** 47 of 47 active specs implemented, all with tests; 0 gaps. No open questions.

## Key Findings

1. **Locking and the parallel request path** — SDK 2.x runs tool calls on worker threads. Each tool method runs under its program's lock (`handle_exceptions`), background work is a single queue, and the registry is read through snapshots, so tool calls, imports, and analysis never touch one program or the registry concurrently.
2. **Waiting without blocking** — the gate waits on the binary's readiness event holding no lock, and the instant-ready check takes a program's lock only if it is free, so a call never queues behind another program's analysis.
3. **Options travel with the binary** — analysis options are stored as JSON in the program's `ghidra-mcp` options category, so a restart mid-analysis re-runs with the same options.

## Work Required

### Must Fix
*(none)*

### Should Fix
*(none)*

### Nice to Have
*(none)*

### Deferred
- *(none)*

### Open Questions
*Mirrors the LLD's Open Questions with the same numbering.*
*(none)*
