# Server Specs

**LLD**: docs/intent/server/server-design.md
**Implementing artifacts**:
- src/ghidra_mcp/server.py (CLI, MCP server app, lifespan, `_err`, `_tools`, 29 tool wrappers)
- src/ghidra_mcp/tools.py (`handle_exceptions`)
- src/ghidra_mcp/errors.py (failure categories, `classify`, `describe`)
- src/ghidra_mcp/models.py (`ProgramInfo`, `ProgramInfos`)
- src/ghidra_mcp/__main__.py, src/ghidra_mcp/__init__.py, pyproject.toml, README.md (prerequisites and CLI reference)

Status markers: `[x]` implemented · `[ ]` active gap · `[D]` deferred

*Tests: `tests/test_server.py`, `tests/test_errors.py`, `tests/test_packaging.py`, with end-to-end checks in `tests/integration/test_ghidra_smoke.py`. `SRV-006` and `SRV-026` are retired.*

*"Tool message" means the text a tool supplies when it fails. The SDK delivers it to the client after its own `Error executing tool <name>: ` prefix.*

---

## Command Line

- [x] **SRV-001**: The system shall provide a `ghidra-mcp` console command, and `python -m ghidra_mcp`, that starts the MCP server.
- [x] **SRV-002**: The system shall accept a transport option limited to `stdio` (default) and `streamable-http`, a port option (default 8000), and a host option (default `127.0.0.1`), each overridable by the `MCP_TRANSPORT`, `MCP_PORT`, and `MCP_HOST` environment variables respectively.
- [x] **SRV-003**: When `--project-path` names a `.gpr` file, the system shall use the file's directory as the project directory and the file's stem as the project name, ignoring `--project-name`.
- [x] **SRV-004**: Where `--project-path` and `--project-name` are not given, the system shall use `ghidra_projects` (relative to the working directory) as the project directory and `my_project` as the project name.
- [x] **SRV-005**: If an input path given on the command line does not exist, then the system shall reject the command line before starting Ghidra.
- [x] **SRV-007**: When starting, the system shall start the Ghidra JVM through pyghidra before constructing the Ghidra context.
- [x] **SRV-008**: The system shall pass `--wait-for-analysis` (on by default), `--verbose-analysis`, and `--symbols-path` through to the Ghidra context unchanged.

## One-shot Project Commands

- [x] **SRV-009**: When `--list-project-binaries` is given, the system shall print each binary's project pathname (or `No binaries in project.` if there are none), close the project, and exit without serving.
- [x] **SRV-010**: When `--delete-project-binary NAME` is given, the system shall attempt to delete that binary, close the project, and exit without serving.
- [x] **SRV-011**: If deleting the binary named by `--delete-project-binary` raises an error, then the system shall print the error to stderr.
- [x] **SRV-012**: If deleting the binary named by `--delete-project-binary` reports failure without raising, then the system shall report the failure instead of printing `Deleted`.
- [x] **SRV-033**: If a one-shot project command (`--list-project-binaries`, `--delete-project-binary`, or `--analyze-only`) fails, then the system shall exit with a non-zero status.
- [x] **SRV-035**: When `--analyze-only` is given, the system shall import any input paths, run the project analysis pass to completion, print each binary's final status (with the failure reason for failed binaries), close the project, and exit without serving, with a non-zero status if any binary failed.

## Startup and Serving

- [x] **SRV-013**: When input paths are given and no one-shot command is requested, the system shall import them into the project before starting project analysis and serving.
- [x] **SRV-014**: When serving, the system shall start project analysis in the background and answer the MCP handshake immediately, whether or not `--wait-for-analysis` is set.
- [x] **SRV-015**: When serving, the system shall run the selected transport, binding the HTTP transport to the configured host and port.
- [x] **SRV-016**: When the server stops, the system shall close the Ghidra context.
- [x] **SRV-017**: The system shall write log output to stderr.
- [x] **SRV-038**: The system shall execute Ghidra-backed tool calls off the server's event loop, so that one long-running call does not stall other requests.

## Tool Surface

- [x] **SRV-018**: The system shall register the 29 MCP tools listed in the server LLD's Tool Registry, each with a description and documented parameters.
- [x] **SRV-019**: The system shall make the single Ghidra context available to every tool call through the MCP lifespan context.
- [x] **SRV-020**: When any query or write-back tool is called, the system shall resolve its binary through the program-lifecycle analysis gate (LIFE-006 to LIFE-008) before delegating to the tool implementation.
- [x] **SRV-021**: When `list_project_binaries` is called, the system shall return every registered binary and every in-progress background import, each with its name, source file path, load time, status (`importing`, `analyzing`, `ready`, or `failed`), failure reason when failed, configuration warnings recorded during analysis, and Ghidra metadata, regardless of analysis state.
- [x] **SRV-022**: When `list_project_binary_metadata` is called for a registered binary, the system shall return its Ghidra metadata regardless of analysis state.
- [x] **SRV-023**: When `import_binary` is called, the system shall validate any `pdb_path` and `gdts` paths, start a background import and analysis of the given path with the supplied analysis options (`pdb_path`, `gdts`, `analyzer_options`, `no_symbols`), and return immediately with a message that names each binary being imported, names any binary already in the project as not re-imported with its stored analysis options unchanged (pointing to `reanalyze_binary`), and directs the caller to `list_project_binaries` for status.
- [x] **SRV-044**: The system shall register a `reanalyze_binary` tool taking `binary_name` and the analysis options `pdb_path`, `gdts`, `analyzer_options`, and `no_symbols`, delegating to program-lifecycle (LIFE-044) and returning immediately with a confirmation.
- [x] **SRV-024**: When `delete_project_binary` is called, the system shall return a confirmation if the delete succeeds, and a `stop` failure carrying the reason if it does not.
- [x] **SRV-037**: Where a tool returns a response model, the system shall advertise an output schema for the tool and return structured content derived from that model.
- [x] **SRV-039**: The `gen_callgraph` tool shall expose `include_refs` and `max_depth`, and every tool's parameter defaults shall equal those of its implementation.

## Failure Reporting

- [x] **SRV-025**: If a tool fails because the caller must change the request, then the system shall return an error result whose tool message begins with `[fix_input]` and states what was wrong, including the candidates when the failure is an unresolved or ambiguous target.
- [x] **SRV-027**: If a tool fails for a reason that is neither `fix_input` nor `retry_later`, then the system shall return an error result whose tool message begins with `[stop]`. The message shall carry the reason for an anticipated failure, and for an unexpected exception shall state only that an internal error occurred, while the exception and its traceback are logged.
- [x] **SRV-028**: When a tool fails, the system shall log the failure with the method's name: `fix_input` and `retry_later` failures below ERROR, anticipated `stop` failures at WARNING, and unexpected exceptions at ERROR with a traceback.
- [x] **SRV-031**: If a tool targets a binary that is still importing, or is queued for or undergoing analysis, then the system shall return an error result whose tool message begins with `[retry_later]`.
- [x] **SRV-032**: The system shall classify an unclassified `ValueError`, an invalid regular expression, or a missing file path raised by a tool implementation as `fix_input`.
- [x] **SRV-036**: The system shall report every tool failure as a tool error result rather than a protocol-level error, so that the message reaches the model.
- [x] **SRV-042**: If the SDK rejects a tool call before the tool runs (an unknown tool, or arguments that fail the tool's input schema), then the system shall add `[fix_input]` to the error result. If the SDK reports a tool crash without a message, then the system shall add `[stop]` with an internal-error notice.

## Packaging and Platform

- [x] **SRV-029**: The system shall declare `ghidrecomp` as an optional dependency, needed only for call-graph generation and PDB/symbol-server setup.
- [x] **SRV-030**: The system shall report its version via `-v` / `--version`.
- [x] **SRV-043**: The CLI shall not accept `--force-analysis`, `--no-symbols`, `--sym-file-path`, `--gdt`, or `--program-options`; per-binary analysis options are tool arguments.
- [x] **SRV-034**: The README prerequisites shall state Ghidra 12.1 or later with JDK 21 or later and Python 3.11 through 3.14, and the package metadata shall require Python ≥ 3.11 and MCP Python SDK 2.x at version 2.3 or later.
- [x] **SRV-040**: The package metadata shall declare `pydantic` and `jpype1` as direct dependencies, and the package version shall be defined in exactly one place.
- [x] **SRV-041**: The README CLI reference shall list only the `stdio` and `streamable-http` transports, shall describe `--wait-for-analysis` (on by default; tool calls wait up to 45 seconds) and `--analyze-only` as implemented, and shall not list the removed per-binary analysis flags.
