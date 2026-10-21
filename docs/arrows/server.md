# Arrow: server

Starts the server and presents the tools to MCP clients: the `ghidra-mcp` CLI (options, `.gpr` handling, one-shot project commands including `--analyze-only`, transport selection), MCP SDK 2.x registration of the 35 tools (plus 3 in GUI mode) and their agent-facing descriptions, the lifespan hook that shares the Ghidra context, the failure-category taxonomy every segment uses, the project listing, logging setup, and packaging.

## Status

**OK** — all 52 active specs implemented and covered by tests (2026-10-11); one item deferred. Mapped 2026-10-03 from git SHA `1acf6ba`; extended for GUI mode and the analysis tools, then for the mise setup environment, project-path handling, and Ctrl+C shutdown; audited at `5c6bcb3` (2026-10-20).

## References

### HLD
- docs/high-level-design.md § Tenets; § Goals (current platform); § System Design (segment table, cross-cutting concerns); § Key Design Decisions

### LLD
- docs/intent/server/server-design.md (includes the full 29-tool registry, startup sequence, Transports, MCP Server and Lifespan, Project Listing, and Failure Reporting)

### EARS
- docs/intent/server/server-specs.md (52 specs, prefix `SRV-*`; `SRV-006` and `SRV-026` retired)

### Tests
- `tests/test_server.py` — failure reporting, tool surface, CLI (unit, with fakes)
- `tests/test_errors.py` — recovery categories and classification
- `tests/test_packaging.py` — package metadata, README prerequisites and CLI reference
- `tests/conftest.py` — gates the suites behind the `test:integration` and `test:gui` tasks (SRV-047): skips `integration` tests without `GHIDRA_INSTALL_DIR` and `gui` tests without `GHIDRA_MCP_GUI_TESTS=1`; provides the `anyio` backend
- `tests/integration/test_ghidra_smoke.py` — `--analyze-only`, tool calls on SDK worker threads, end-to-end `fix_input`, `import_binary` with analysis options, `reanalyze_binary` (needs `GHIDRA_INSTALL_DIR`)

### Code
- `src/ghidra_mcp/server.py` — logging setup; `_lifespan`; `_err`, `_tag_sdk_message`, and the `_categorize_sdk_failures` middleware; `mcp = MCPServer(...)`; `_tools` (per-call `GhidraTools`); the 35 tool wrappers, the 3 GUI-only tools and `register_gui_tools`; CLI `main` (including `--gui`)
- `src/ghidra_mcp/errors.py` — `FixInput`, `RetryLater`, `Stop`, `classify`, `describe`
- `src/ghidra_mcp/tools.py` — `handle_exceptions` (program lock, logging by category)
- `src/ghidra_mcp/models.py` — `ProgramInfo`, `ProgramInfos` (project-management responses)
- `src/ghidra_mcp/__main__.py`, `src/ghidra_mcp/__init__.py`, `pyproject.toml`, `README.md` — entry points, version, dependencies, prerequisites, installation, CLI and tool reference
- `mise.toml`, `mise.local.toml.example`, `.gitignore` — the project-only setup environment (Python 3.13, `.venv`, required Ghidra and JDK paths, tasks)
- Outbound, owned elsewhere: program-lifecycle (`GhidraContext` construction, import, analysis, re-analysis, delete, the gate and its wait, program status, locks); analysis-config (per-binary options passed through `GhidraContext`); queries and write-back (via `GhidraTools`)

## Architecture

**Purpose:** Be the process boundary. Turn a command line into a running Ghidra-backed MCP server that answers its handshake immediately, and turn MCP tool calls into `GhidraContext`/`GhidraTools` calls whose failures name their recovery.

**Key Components:**
1. CLI (`main`) — click options with env-var fallbacks for transport (`stdio`/`streamable-http`), port, and host; resolves `.gpr` paths; starts the JVM via `pyghidra.start`; constructs `GhidraContext`; runs one-shots (list, delete, `--analyze-only`) or imports inputs, starts background analysis, and serves. Per-binary analysis options are tool arguments, not flags.
2. MCP server — `MCPServer("ghidra-mcp", lifespan=_lifespan, middleware=[_categorize_sdk_failures])` from SDK 2.x. Sync tools run on worker threads, and response models become output schemas.
3. Tool wrappers — 35 `@mcp.tool()` functions, plus 3 GUI-only tools registered by `register_gui_tools` with `--gui`. Their docstrings are the tool descriptions agents read. Binary-scoped tools get a `GhidraTools` via `_tools(ctx, binary_name)`, which goes through program-lifecycle's analysis gate.
4. Failure reporting — every failure is raised as a `ToolError` whose message begins with `[fix_input]`, `[retry_later]`, or `[stop]`. Unexpected exceptions are reported as `[stop] Internal error…`, with details only in the log.
5. Packaging — the `ghidra-mcp` console script, `python -m ghidra_mcp`, dependencies, and README prerequisites.

## Spec Coverage

| Category | Spec IDs | Implemented | Deferred | Gaps |
|----------|----------|-------------|----------|------|
| Command line | SRV-001 to SRV-005, SRV-007, SRV-008, SRV-043, SRV-045, SRV-050, SRV-051 | 11 | 0 | 0 |
| One-shot project commands | SRV-009 to SRV-012, SRV-033, SRV-035 | 6 | 0 | 0 |
| Startup and serving | SRV-013 to SRV-017, SRV-038, SRV-052 to SRV-054 | 9 | 0 | 0 |
| Tool surface | SRV-018 to SRV-024, SRV-037, SRV-039, SRV-044 | 10 | 0 | 0 |
| Failure reporting | SRV-025, SRV-027, SRV-028, SRV-031, SRV-032, SRV-036, SRV-042 | 7 | 0 | 0 |
| Packaging and platform | SRV-029, SRV-030, SRV-034, SRV-040, SRV-041, SRV-046 to SRV-049 | 9 | 0 | 0 |

**Summary:** 52 of 52 active specs implemented and covered by tests in `tests/`; 0 gaps. No open questions; 1 item is deferred.

## Key Findings

1. **No access control on HTTP** — authentication is out of scope, so any client that can reach the port can import files readable by the server, delete binaries, and rewrite annotations. The bind address defaults to `127.0.0.1`, and unexpected-exception text is withheld from clients.
2. **Only a `ToolError` message reaches the model** under SDK 2.x (verified, `mcp` 2.3.0), so every failure is a `ToolError` tagged with its recovery category, and a middleware tags the SDK's own rejections.
3. **Sync tools run on SDK worker threads** (`anyio.to_thread.run_sync`, verified), which keeps one slow call from stalling the server; program-lifecycle's locks serialize the resulting parallel Ghidra access (LIFE-041).
4. **The handshake never waits for analysis** — waiting happens inside tool calls (45 s by default), and `--analyze-only` pre-analyzes large binaries ahead of serving.
5. **`search_strings` has no `offset` parameter.** Deferred under the HLD's bounded, stable responses goal.

## Work Required

### Must Fix
- *(none)*

### Should Fix
- *(none)*

### Nice to Have
- *(none)*

### Deferred
- `search_strings` offset (finding 5). Part of the HLD's bounded, stable responses goal.

### Open Questions
*Mirrors the LLD's Open Questions with the same numbering.*
*(none)*
