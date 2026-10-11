---
parent: high-level-design
prefix: SRV
---

# Server

*Code references name symbols in `src/ghidra_mcp/server.py` unless another file is given; README references name sections.*

## Context and Design Philosophy

The server segment is the process boundary. On one side is an operator's command line or an MCP client's configuration. On the other are `GhidraContext` (program-lifecycle) and `GhidraTools` (queries, write-back). It owns the `ghidra-mcp` CLI, the MCP server application, all 29 tool registrations and their descriptions, the conversion of exceptions into MCP errors, logging, and packaging.

Principles stated in the code and README:

- **Two deployment patterns.** Local, where the client launches the server over `stdio`, and remote, where the server runs on a VM and clients connect over `streamable-http` (README § MCP Client Configuration).
- **Thin wrappers.** Each tool function delegates to `GhidraContext` or a per-call `GhidraTools`, and adds only response shaping and error mapping. *[inferred]* This keeps behavior in testable classes.
- **Tool descriptions are the agent's contract.** Each wrapper's docstring is what MCP clients present to the model, so wording accuracy matters. See the resolved `list_functions` wording in queries.
- **Safe default bind.** The host defaults to `127.0.0.1`; remote use requires an explicit `--host 0.0.0.0` (README § CLI Reference).
- **No authentication.** Authentication is out of scope (resolved 2026-10-03).
- **Every failure names its recovery.** Each tool failure carries one category (`fix_input`, `retry_later`, or `stop`), per the HLD tenet *Actionable failures*. This segment defines the taxonomy and every other segment adopts it (see Failure Reporting).

## CLI

`ghidra-mcp [OPTIONS] [INPUT_PATHS]...` (`main`; README § CLI Reference):

| Option | Default | Env | Effect consumed by |
|---|---|---|---|
| `-t, --transport` `stdio`\|`streamable-http` (`sse` removed; see Transports) | `stdio` (`streamable-http` with `--gui`) | `MCP_TRANSPORT` | server |
| `-p, --port` | `8000` | `MCP_PORT` | server (HTTP transports) |
| `-o, --host` | `127.0.0.1` | `MCP_HOST` | server (HTTP transports) |
| `--project-path` | `ghidra_projects` | n/a | program-lifecycle (server turns a `.gpr` into a directory and name). `~` is expanded and the path made absolute with `..` resolved, because Ghidra rejects path elements that start with a dot. A project's data folder (`<name>.rep`) is rejected with a usage error naming its `.gpr`. |
| `--project-name` | `my_project` | n/a | program-lifecycle (ignored for `.gpr`) |
| `--wait-for-analysis / --no-wait-for-analysis` | **on** | n/a | program-lifecycle: a tool call for a pending binary waits up to 45 s before `retry_later`. Startup never blocks on it. |
| `--analyze-only` | flag | n/a | server one-shot: import inputs, analyze everything to completion, report each binary's status, exit |
| `--verbose-analysis / --no-verbose-analysis` | off | n/a | `pyghidra.start` and program-lifecycle |
| `--symbols-path` | none (→ `<project>/symbols`) | n/a | analysis-config |
| `--list-project-binaries` | flag | n/a | server one-shot |
| `--delete-project-binary NAME` | none | n/a | server one-shot |
| `--gui` | flag | n/a | gui-host: host the Ghidra GUI in this process and serve over streamable HTTP (GUI mode) |
| `INPUT_PATHS` (each must exist) | none | n/a | program-lifecycle import |
| `-v, --version` / `-h, --help` | n/a | n/a | click |

Click validates that input paths exist before the JVM starts. With `--gui`, the `stdio` transport and the one-shots (`--analyze-only`, `--list-project-binaries`, `--delete-project-binary`) are usage errors, and an unavailable HTTP port is reported before the GUI launches (gui-host).

Per-binary analysis options (PDB path, GDT archives, analyzer options, symbol use, forced re-analysis) are **not** CLI flags. They are arguments of the `import_binary` and `reanalyze_binary` tools. Binaries given on the command line, including under `--analyze-only`, are analyzed with default options: symbols on (via the symbol server when `ghidrecomp` is installed), no GDTs, and no analyzer overrides.

## Startup Sequence

`main` (`server.py`):

```
1. project_path ← expand ~, make absolute, resolve ..
   if it ends with .rep → usage error: pass <name>.gpr instead
   if it ends with .gpr → project_dir = parent, project_name = stem
2. pyghidra.start(verbose_analysis)                      # JVM up; pyghidra reports a missing Ghidra
3. ctx ← GhidraContext(project, verbose_analysis, wait_for_analysis, symbols_path)
4. --list-project-binaries → print "- <pathname>" per binary (or "No binaries in project."); exit 1 on error
   --delete-project-binary → "Deleted: <name>", or the reason on stderr and exit 1
5. import INPUT_PATHS with default analysis options       # synchronous; failures recorded as failed binaries
6. --analyze-only → analysis pass to completion; print "<name>: ready" or "<name>: failed (<reason>)";
                    exit 1 if any binary failed
7. start the analysis pass in the background             # never blocks the handshake
8. mcp.run("stdio") | mcp.run("streamable-http", host=…, port=…); finally ctx.close()
```

With `--gui`, steps 2–8 are replaced by gui-host's launch: the server validates the command line, ensures the project exists, and launches the Ghidra GUI in-process; once the GUI reports the project active, gui-host builds the GUI-mode context, imports the inputs, starts the analysis pass, registers the GUI-only tools, and serves over streamable HTTP on a background thread. The process exits when the GUI exits.

Waiting for analysis happens inside tool calls (program-lifecycle LIFE-039), never before the handshake. A stdio client therefore always gets its `initialize` reply promptly, however long analysis takes.

## Transports

`stdio` (local) and `streamable-http` (remote, and always in GUI mode) only. `sse` is removed: the MCP specification deprecates it in favor of streamable HTTP, and SDK 2.x caps SSE events at 1 MiB by default, which large results would exceed.

## MCP Server and Lifespan (SDK 2.x)

The server is built on MCP Python SDK 2.x: `MCPServer` from `mcp.server.mcpserver`. Relevant 2.x behavior (verified against `mcp` 2.3.0):
- `MCPServer("ghidra-mcp", lifespan=_lifespan, middleware=[_categorize_sdk_failures])`. Tools read the context as `ctx.request_context.lifespan_context`.
- Host and port go to `run(transport, host=…, port=…)`. There are no `settings` assignments.
- **Synchronous tool functions run on worker threads** (`anyio.to_thread.run_sync`), so concurrent calls execute in parallel. All tools are synchronous, including `decompile_function`. Ghidra access is serialized by program-lifecycle's locks (LIFE-041): every `GhidraTools` method runs under its program's lock.
- A tool returning a pydantic model advertises an output schema and returns structured content derived from it.
- A raised `ToolError` reaches the model as an error result; any other exception is reported only as `Error executing tool <name>` (see Failure Reporting).

## Tool Registry

35 tools in every mode, plus 3 GUI-only tools registered only in GUI mode (see the end of the table). Order follows `server.py`. Every binary-scoped tool resolves its binary through `get_program_info`, which applies the analysis gate (program-lifecycle LIFE-006–008, LIFE-032, LIFE-039). Every tool converts exceptions with `_err`. All tools are synchronous.

| # | Tool | Owning segment | Delegates to | Parameters (defaults) | Behavior in the wrapper itself |
|---|---|---|---|---|---|
| 1 | `list_project_binaries` | program-lifecycle | `list_entries` | n/a | Builds `ProgramInfo(name, file_path, load_time, analysis_complete, status, failure, warnings, metadata)` for every binary, including in-progress imports. Not gated. |
| 2 | `list_project_binary_metadata` | program-lifecycle | `get_metadata` | `binary_name` | Not gated; `retry_later` only while the binary is importing. Returns the raw metadata dict. |
| 3 | `import_binary` | program-lifecycle | `AnalysisOptions.create`, `import_binary_backgrounded` | `binary_path, pdb_path=None, gdts=None, analyzer_options=None, no_symbols=False` | Validates the PDB and GDT paths (`fix_input`). Returns `"Importing '<p>' in the background as <names>."`, plus, for files already in the project, `"Already in the project, not re-imported: <names>. Its stored analysis options are unchanged; use reanalyze_binary to change them."`, then a pointer to `list_project_binaries`. |
| 4 | `delete_project_binary` | program-lifecycle | `delete_program` | `binary_name` | `"Deleted: <n>"`. A failed delete is `stop` with the reason; a pending binary is `retry_later`. Not gated. |
| 5 | `list_functions` | queries | `list_functions` | `binary_name, query=None, offset=0, limit=100` | Wraps `(functions, total)` in `FunctionList`. |
| 6 | `list_segments` | queries | `list_segments` | `binary_name` | Wraps in `MemorySegments`. |
| 7 | `list_data_items` | queries | `list_data_items` | `binary_name, offset=0, limit=100` | Wraps in `DataItems`. |
| 8 | `list_classes` | queries | `list_classes` | `binary_name, offset=0, limit=100` | Wraps in `NamespaceList`. |
| 9 | `list_namespaces` | queries | `list_namespaces` | `binary_name, offset=0, limit=100` | Wraps in `NamespaceList`. |
| 10 | `get_function_by_address` | queries | `get_function_by_address` | `binary_name, address` | Pass-through. |
| 11 | `disassemble_function` | queries | `disassemble_function` | `binary_name, name_or_address` | Pass-through. |
| 12 | `decompile_function` | queries | `decompile_function_by_name_or_addr` | `binary_name, name_or_address` | Pass-through. |
| 13 | `search_symbols` | queries | `search_symbols_by_name` | `binary_name, query, offset=0, limit=100` | Wraps in `SymbolSearchResults`. |
| 14 | `list_imports` | queries | `list_imports` | `binary_name, query=None, offset=0, limit=25` | Wraps in `ImportInfos`. |
| 15 | `list_exports` | queries | `list_exports` | `binary_name, query=None, offset=0, limit=25` | Wraps in `ExportInfos`. |
| 16 | `list_cross_references` | queries | `list_cross_references` | `binary_name, name_or_address` | Wraps in `CrossReferenceInfos`. |
| 17 | `get_xrefs_from` | queries | `get_xrefs_from` | `binary_name, address` | Wraps in `CrossReferenceInfos`. |
| 18 | `search_strings` | queries | `search_strings` | `binary_name, query, limit=100` | **No `offset`.** Wraps in `StringSearchResults`. |
| 19 | `read_bytes` | queries | `read_bytes` | `binary_name, address, size=32` | Pass-through. |
| 20 | `set_disassembly_comment` | write-back | `set_disassembly_comment` | `binary_name, address, comment` | Pass-through. |
| 21 | `set_decompiler_comment` | write-back | `set_decompiler_comment` | `binary_name, address, comment` | Pass-through. |
| 22 | `rename_function` | write-back | `rename_function` | `binary_name, name_or_address, new_name` | Pass-through. |
| 23 | `rename_function_by_address` | write-back | `rename_function_by_address` | `binary_name, address, new_name` | Pass-through. |
| 24 | `rename_data` | write-back | `rename_data` | `binary_name, address, new_name` | Pass-through. |
| 25 | `rename_variable` | write-back | `rename_variable` | `binary_name, function_name_or_address, old_var_name, new_var_name` | Pass-through. |
| 26 | `set_function_prototype` | write-back | `set_function_prototype` | `binary_name, name_or_address, prototype` | Pass-through. |
| 27 | `set_local_variable_type` | write-back | `set_local_variable_type` | `binary_name, function_name_or_address, var_name, new_type` | Pass-through. |
| 28 | `gen_callgraph` | queries | `gen_callgraph` | `binary_name, function_name, direction=calling, display_type=flow, include_refs=True, max_depth=None, condense_threshold=50, top_layers=5, bottom_layers=5, max_run_time=60` | Defaults equal the implementation's. `function_name` accepts a name or an address. |
| 29 | `reanalyze_binary` | program-lifecycle | `AnalysisOptions.create`, `reanalyze_binary` | `binary_name, pdb_path=None, gdts=None, analyzer_options=None, no_symbols=False` | Validates the PDB and GDT paths (`fix_input`). Returns `"Re-analyzing '<n>' in the background…"`. `retry_later` while that binary is importing or analyzing; `stop` for a binary whose import failed. Not gated. |
| 30 | `get_function_callers` | queries | `get_function_callers` | `binary_name, name_or_address` | Pass-through. |
| 31 | `get_function_callees` | queries | `get_function_callees` | `binary_name, name_or_address` | Pass-through. |
| 32 | `diff_functions` | queries | `diff_functions` | `binary_name, function_a, function_b, other_binary_name=None, view=decompiled, normalize=True, context_lines=3` | Gates both binaries and takes both programs' locks in pathname order. |
| 33 | `find_similar_functions_fuzzy` | queries | `find_similar_functions_fuzzy` | `binary_name, name_or_address, target_binary_name=None, limit=10, min_similarity=0.5` | Gates both binaries and takes both programs' locks in pathname order. |
| 34 | `get_function_pcode` | queries | `get_function_pcode` | `binary_name, name_or_address, form=raw, max_ops=2000` | Pass-through. |
| 35 | `analyze_dataflow` | queries | `analyze_dataflow` | `binary_name, function_name_or_address, variable, direction=backward, max_ops=500` | Pass-through. |
| 36 | `get_current_address` | gui-host | `GuiGhidraContext.current_location` | n/a | GUI mode only. The binary, address, and containing function of CodeBrowser's cursor. |
| 37 | `get_current_function` | gui-host | `GuiGhidraContext.current_location` | n/a | GUI mode only. The binary and the function containing CodeBrowser's cursor. |
| 38 | `go_to` | gui-host | `GuiGhidraContext.go_to` | `binary_name, name_or_address` | GUI mode only. Moves CodeBrowser to the target; gated like other binary-scoped tools. |

README § Tool Reference groups these tools by category.

## Project Listing

`list_project_binaries` reports every registered binary **and every in-progress background import**. Each entry carries the name, source file path, load time, status, the failure reason when the status is `failed`, any configuration warnings recorded during analysis (analysis-config), and Ghidra metadata. The status is one of:
- `importing`
- `analyzing` (queued for or undergoing analysis)
- `ready`
- `failed`

`list_project_binary_metadata` returns a registered binary's metadata whatever its analysis state.

## Failure Reporting

### Recovery categories

Every tool failure carries exactly one recovery category, telling the caller what to do next:

| Category | The caller should | Raised for |
|---|---|---|
| `fix_input` | Change the request and call again | Unknown binary; unparseable address; target not found, ambiguous, or (for a write) not an exact match, with candidates; invalid regex; unresolvable type; unparseable prototype; missing import path; out-of-range size; address outside program memory; a name Ghidra rejects |
| `retry_later` | Repeat the same request later | The binary is still importing, or is queued for or undergoing analysis |
| `stop` | Not retry; report or escalate | The binary's analysis failed (with the recorded reason); decompiler failure; a Ghidra command reporting failure; a save failure; any unclassified exception |

**How the category reaches the client.** Every failure is raised to the SDK as a `ToolError` whose message begins with the category tag. Under SDK 2.x (verified against `mcp` 2.3.0), a `ToolError` becomes an error result the model reads, `Error executing tool <name>: [fix_input] Function 'foo' not found. Did you mean: …`, and the SDK logs it at INFO without a traceback. Any other exception would surface only as `Error executing tool <name>`, with no category, which is why `_err` converts everything. An `MCPError` would become a protocol-level error, so tools never raise one.

**How implementations raise it.** Tool implementations signal the category with a small exception family in a shared module: `FixInput` (a `ValueError` subclass), `RetryLater`, and `Stop`. `_err` formats the tag. An unclassified `ValueError`, `re.error`, or `FileNotFoundError` maps to `fix_input`. Every other exception is unexpected and maps to `stop` with the message `Internal error; details are in the server log`: its text and traceback are logged at ERROR, and none of it reaches the client.

**Failures the SDK produces itself.** The SDK can reject a call before our code runs: an unknown tool name, or arguments that fail the tool's input schema. It reports these as error results with its own text (`Unknown tool: <name>`, or `Error executing tool <name>: <validation error>`). A server middleware adds `[fix_input]` to such results, and `[stop]` with an internal-error notice to a bare SDK crash message. Results that already carry a category are left alone (verified against `mcp` 2.3.0, whose middleware receives the `tools/call` result as a wire dict).

**Logging.** `fix_input` and `retry_later` failures log below ERROR, since they are routine caller conditions. Anticipated `stop` failures log at WARNING. Unexpected exceptions log at ERROR with a traceback.

### Mapping

`_err(e)` converts every failure into a `ToolError`. `classify` and `describe` live in `errors.py`.

| Exception | Category | Typical sources |
|---|---|---|
| `FixInput`, `ValueError` | `fix_input` | Resolution failures, unknown binary, invalid sizes, parse failures, unknown variable |
| `re.error` | `fix_input` | Invalid import/export regex |
| `FileNotFoundError` | `fix_input` | `import_binary` with a missing path |
| Ghidra `InvalidInputException` / `DuplicateNameException` | `fix_input`, carrying Ghidra's message | A rejected name |
| `RetryLater` | `retry_later` | The analysis gate, for a binary still importing or analyzing; re-analysis or deletion of a pending binary |
| `Stop` | `stop` | The analysis gate, for a failed binary; failed delete; re-analysis of a failed import; decompile failure in the variable tools; `ghidrecomp` missing |
| anything else | `stop`: "Internal error; details are in the server log." (traceback logged at ERROR) | Unexpected crashes, other Java exceptions |

`handle_exceptions` (`tools.py`) decorates most `GhidraTools` methods. It runs the method under its program's lock (program-lifecycle LIFE-041) and logs each failure once, with the method name: `fix_input`/`retry_later` at DEBUG, `stop` at WARNING, unexpected exceptions at ERROR with a traceback.

## Logging

`logging.basicConfig(level=INFO, stream=sys.stderr, format="%(asctime)s [%(levelname)s] %(message)s")` runs when `server.py` is imported. *[inferred]* It writes to stderr because the stdio transport owns stdout.

## Packaging and Entry Points

- `pyproject.toml`: hatchling build. Package `src/ghidra_mcp`. Console script `ghidra-mcp = ghidra_mcp.server:main`. `requires-python = ">=3.11"`; ruff targets py311 with line length 100.
- Dependencies: `click>=8.2.1`, `mcp[cli]>=2.3,<3`, `pydantic>=2`, `jpype1>=1.5.2`, `pyghidra>=3.1`. `pydantic` and `jpype1` are imported directly, so they are declared directly. Extras: `ghidrecomp` (call graphs and symbol configuration) and `dev` (pytest).
- The version is defined once, as `__version__` in `__init__.py` (used by `--version`), and read dynamically by hatch.
- `python -m ghidra_mcp` → `__main__.py` → `server.main`.
- **Target platform** (HLD Goals): Ghidra 12.1 or later (12.1.4 current) with JDK 21+, and Python 3.11–3.14.

## Setup Environment (mise)

Users install and run the project through mise, configured for this project only (`mise.toml` at the project root; nothing at workspace or user level):

- **Python from mise.** `[tools] python = "3.13"`. pyghidra pins JPype 1.5.2, which ships prebuilt wheels up to Python 3.13; on 3.14 it builds from source and needs a C compiler. 3.11–3.14 remain supported for anyone setting up Python another way.
- **A project virtual environment.** mise creates and activates `.venv` in the project (`_.python.venv`), so `pip install` and the `ghidra-mcp` command stay inside the project.
- **Ghidra and the JDK are paths, not mise tools.** `GHIDRA_INSTALL_DIR` and `JAVA_HOME` are required environment variables: mise refuses to run, with a message saying where to set them, until both are defined. Each user sets them in a git-ignored `mise.local.toml` (a committed `mise.local.toml.example` shows the form), or exports them in the shell.
- **Tasks.** `install` (`pip install -e ".[ghidrecomp,dev]"`); `test` (the unit tests only: mise always sets `GHIDRA_INSTALL_DIR`, which would otherwise switch the integration suite on), `test:integration`, and `test:gui` (which sets `GHIDRA_MCP_GUI_TESTS=1`); `serve` and `gui` (`ghidra-mcp` and `ghidra-mcp --gui`), which pass their arguments through to the command.
- **MCP clients.** A client launches the server outside the user's shell, so client configurations run it as `mise exec -C <project> -- ghidra-mcp …`, which applies the project's Python environment and paths.

## Decisions & Alternatives

| Decision | Chosen | Alternatives Considered | Rationale |
|----------|--------|------------------------|-----------|
| Transports | `stdio` locally; `streamable-http` remotely | Keep `sse` as well | Two deployment patterns are stated (README § MCP Client Configuration). `sse` is deprecated by the MCP specification, and SDK 2.x caps SSE events at 1 MiB. |
| MCP SDK | 2.x (`MCPServer`), minimum 2.3 | Stay on the 1.x maintenance line (1.30) | Latest stable. Its `ToolError` semantics carry failure categories to the model, and running sync tools on worker threads keeps one slow call from stalling the server. The parallelism this introduces is handled by program-lifecycle's locks. |
| Waiting for analysis | Answer the handshake immediately. By default, a tool call for a pending binary waits up to 45 s, then returns `retry_later` saying how long analysis has been running or that it is queued. `--no-wait-for-analysis` disables the wait. | Block startup until analysis completes; opt-in waiting; a longer cap; progress notifications | Blocking startup makes stdio clients time out on large binaries (a 7.6 MB Go binary took 7 min 43 s to analyze). A default wait works without client configuration. 45 s stays under typical client tool-call timeouts. Progress notifications depend on client support. |
| Per-binary analysis options | `import_binary` / `reanalyze_binary` arguments; the corresponding CLI flags are removed | Server-wide CLI flags | A PDB belongs to one binary, so a global flag forced a guessing rule. GDTs and analyzer tuning differ per binary. Re-analysis no longer needs a restart. |
| Pre-analysis | An `--analyze-only` one-shot | Only analysis at serve time | Lets operators analyze large binaries ahead of time, so serving starts instantly. |
| Unexpected-exception text | Withheld from clients (`[stop] Internal error; details are in the server log`) and logged with a traceback | Include the exception text | With authentication out of scope, internal paths and Java messages shouldn't reach whoever can connect. This also matches SDK 2.x's own crash handling. |
| Wrapper defaults | Equal to the implementation's defaults; `gen_callgraph` exposes `include_refs` and `max_depth` | Keep separate wrapper defaults | One source of truth; agents can reach every implemented option. |
| Default bind address | `127.0.0.1` | `0.0.0.0` | *[inferred]* Safe default; README asks for `0.0.0.0` explicitly when remote. |
| Authentication | None | Token or mTLS | Out of scope for this project. |
| Context sharing | Construct before the server runs; attach to the server instance; yield it from the lifespan hook | Construct inside the lifespan hook | *[inferred]* One-shots, startup import, and `--analyze-only` all need the context before serving. |
| Wrapper style | Thin wrappers; a fresh `GhidraTools` per call | Methods on a long-lived tools object | *[inferred]* Per-call binding to the resolved program is simple and stateless. |
| Failure categories | `fix_input` / `retry_later` / `stop`, carried as a leading message tag | JSON-RPC error codes; a structured error object in the tool result | HLD tenet *Actionable failures*. SDK 2.x shows the model only a `ToolError`'s message, and earlier SDKs dropped error codes set by tools (both verified). A tag survives the SDK's wrapping and reads well for agents and people. |
| Category signalling | `FixInput`, `RetryLater`, and `Stop` exceptions, formatted by `_err` | Return error values instead of raising | Implementations raise, which keeps the happy path uncluttered. `FixInput` subclasses `ValueError`, so `ValueError` handling stays valid. |
| Project listing content | Status, failure reason, warnings, and metadata for every binary and every in-progress import | Name, path, load time, and a completion flag only | HLD tenet *Explicit over silent*. Metadata is already held in memory, so including it costs nothing new. |
| Metadata availability | Return metadata whatever the analysis state | Put it behind the analysis gate | Metadata doesn't depend on analysis; a `retry_later` would misinform the caller. |
| One-shot exit status | Non-zero exit when the command fails | Always exit 0 | HLD tenet *Explicit over silent*; lets scripts detect failure. |
| Logging | stderr at INFO | stdout | *[inferred]* The stdio transport owns stdout. |
| Setup environment | A project-only `mise.toml`: Python 3.13 and a project venv from mise; Ghidra and the JDK supplied as paths (`GHIDRA_INSTALL_DIR`, `JAVA_HOME`, required) | mise also installing Ghidra and a JDK; a workspace- or user-level mise configuration; manual venv and pip; Docker | Ghidra and a JDK are large, usually already installed, and shared with other tools, so users point at their own copies. A project-only configuration keeps neighboring projects independent. Python 3.13 avoids compiling JPype. Docker cannot host GUI mode on a desktop. |
| GUI-only tools | Registered only when `--gui` is given | Register in every mode and fail headless | Agents see only tools that can work (gui-host). |
| CLI framework | click, with env-var fallbacks for transport, port, and host | argparse | *[inferred]* |
| Project management on the CLI | Flags on the main command that exit after running | Subcommands | *[inferred]* |
| `.gpr` support | Accept a `.gpr` path and derive the directory and name | Require directory plus name | Stated in README § CLI Reference. |
| `.rep` paths | Reject with a usage error naming the project's `.gpr` | Treat a `.rep` like its `.gpr`; accept it as a project directory | One way to name a project keeps commands unambiguous. Accepting the data folder as a directory would create a new project inside another project's data. |

## Open Questions & Future Decisions

### Resolved
1. ✅ **Authentication** for the HTTP transports is out of scope. (2026-10-03)
2. ✅ **One-shot exit status.** One-shot commands exit non-zero on failure. (2026-10-03)
3. ✅ **Failure classification.** Recovery categories `fix_input`, `retry_later`, and `stop`, carried as a message tag (see Failure Reporting). (2026-10-03)
4. ✅ **Listing metadata.** `list_project_binaries` includes metadata, together with status, failure reason, and warnings (see Project Listing). (2026-10-03)
5. ✅ **Metadata gate.** `list_project_binary_metadata` does not wait for analysis. (2026-10-03)

6. ✅ **Remote hardening.** No path allowlist or read-only mode. Unexpected-exception text is withheld from clients and logged. (2026-10-03)
7. ✅ **`--wait-for-analysis`.** The handshake is answered immediately. Calls wait up to 45 s by default (`--no-wait-for-analysis` disables it). `--analyze-only` is added for pre-analysis. (2026-10-03)
8. ✅ **Blocking calls.** SDK 2.x runs sync tools on worker threads; `decompile_function` becomes sync; Ghidra access is serialized by program-lifecycle's locks. (2026-10-03)
9. ✅ **Wrapper defaults.** They equal the implementation's defaults; `include_refs` and `max_depth` are exposed. (2026-10-03)
10. ✅ **Dependencies.** Python ≥ 3.11; `mcp` 2.x; `pydantic` and `jpype1` declared directly; the version single-sourced. (2026-10-03)
11. ✅ **Heavy one-shots.** Resolved by lazy opening (program-lifecycle). (2026-10-03)
12. ✅ **The `http` alias and `sse`.** Both removed; transports are `stdio` and `streamable-http`. (2026-10-03)
13. ✅ **Log levels.** `fix_input`/`retry_later` below ERROR, anticipated `stop` at WARNING, unexpected exceptions at ERROR with a traceback. (2026-10-03)
14. ✅ **Analysis flags become tool arguments.** `--force-analysis`, `--no-symbols`, `--sym-file-path`, `--gdt`, and `--program-options` are removed. Their roles are `reanalyze_binary` and `import_binary`/`reanalyze_binary` arguments. (2026-10-03)

### Deferred
1. **`search_strings` offset** (`search_strings`). Part of the HLD's deferred goal of bounded, stable responses.

### Open (observed behavior, intent unstated)
*(none)*

### Known gaps against stated intent
*(none)*

## References

- Code: `src/ghidra_mcp/server.py` (all); `src/ghidra_mcp/tools.py` (`handle_exceptions`); `src/ghidra_mcp/models.py` (`ProgramInfo`, `ProgramInfos`); `src/ghidra_mcp/errors.py`; `src/ghidra_mcp/__main__.py`; `src/ghidra_mcp/__init__.py`; `pyproject.toml`
- Depends on: program-lifecycle (`GhidraContext`); queries and write-back (`GhidraTools`); analysis-config (per-binary options passed through `GhidraContext`)
- External: `mcp` 2.x (`MCPServer`, `Context`, `ToolError`), `click`, `pyghidra`
- User docs: `README.md`
- Arrow: `docs/arrows/server.md`
