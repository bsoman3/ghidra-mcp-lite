# ghidra-mcp-lite

A lightweight MCP server for Ghidra headless analysis. Exposes 35 native Ghidra tools (38 in [GUI mode](#gui-mode)) — decompilation, disassembly, cross-references, callers and callees, function diffs, fuzzy similarity search, p-code, data-flow slices, renaming, type setting, callgraphs, and more — with no ChromaDB, no ML model, and no vector indexing.

Designed to run comfortably on a small VM (e.g. a t3.small) where embedding-based servers saturate the CPU on startup.

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| **[mise](https://mise.jdx.dev)** | Sets up the project's Python environment and runs it. Install with `brew install mise` or see the mise docs |
| **Ghidra 12.1+** | Tested on 12.1.4. Download from [ghidra-sre.org](https://ghidra-sre.org); you point the project at it |
| **JDK 21+** | Required by Ghidra 12.1; you point the project at it |

mise provides Python 3.13 in a project-local virtual environment (`.venv`). The package itself supports Python 3.11–3.14; 3.13 is pinned because pyghidra's JPype dependency ships prebuilt wheels up to 3.13. Nothing is installed or configured outside the project directory.

---

## Installation

1. Point the project at your Ghidra and JDK by creating `mise.local.toml` (git-ignored) from the example:

   ```bash
   cd ghidra-mcp-lite
   cp mise.local.toml.example mise.local.toml
   ```

   ```toml
   [env]
   GHIDRA_INSTALL_DIR = "/path/to/ghidra_12.1.4_PUBLIC"   # contains ghidraRun and Ghidra/
   JAVA_HOME = "/path/to/jdk-21"                          # on macOS: /usr/libexec/java_home -v 21
   ```

2. Trust the project's mise configuration, install Python, and install the server:

   ```bash
   mise trust
   mise install
   mise run install
   ```

This creates `.venv` with the `ghidra-mcp` command, `ghidrecomp` (for `gen_callgraph` and PDB/symbol setup), and the test tools. mise refuses to run until `GHIDRA_INSTALL_DIR` and `JAVA_HOME` are set, and says where to set them. With `mise activate` in your shell, `ghidra-mcp` is on your PATH inside the project; otherwise use `mise run` or `mise exec`, as below.

---

## How It Works

### Finding Ghidra

pyghidra locates Ghidra through `GHIDRA_INSTALL_DIR` and the JDK through `JAVA_HOME`, both set by mise from `mise.local.toml`. The server fails to start with a clear error if either path is wrong.

### Loading a Binary and Running Analysis

Pass one or more binary paths as positional arguments on startup:

```bash
ghidra-mcp /path/to/binary [/path/to/another ...]
```

What happens internally:

1. `pyghidra.start()` initialises the Ghidra JVM (loads Ghidra's JAR files into the Python process via JPype).
2. A Ghidra project is created or opened at `--project-path` / `--project-name` (defaults: `./ghidra_projects/my_project`).
3. Each binary is imported into the project via `GhidraProject.importProgram()` and saved. Binaries are named `<filename>-<sha1[:6]>` to allow the same filename from different paths.
4. Ghidra auto-analysis (`analyzeAll`) runs in a background thread. The server answers the MCP handshake immediately; a tool call for a binary that is still being analyzed fails with `[retry_later]`.
5. The Ghidra project is persisted to disk. On the next startup with the same `--project-path`, already-analyzed binaries are re-opened instantly — no re-analysis unless you ask for it with the `reanalyze_binary` tool.

By default, a tool call for a binary that is still being analyzed waits up to 45 s for it, then fails with `[retry_later]`, saying how long analysis has been running or where the binary is in the queue. To fail straight away instead:

```bash
ghidra-mcp --no-wait-for-analysis /path/to/binary
```

Large binaries (Go binaries in particular) can take many minutes to analyze. Pre-analyze them once, then every later start serves them instantly:

```bash
ghidra-mcp --analyze-only /path/to/binary   # exits non-zero if any binary failed
```

---

## Quick Start

Run these from the project directory (`mise run serve` and `mise run gui` pass their arguments to `ghidra-mcp`):

```bash
# Import, analyze, and serve a binary over stdio
mise run serve /path/to/target_binary

# Serve over HTTP (useful for remote VMs)
mise run serve --transport streamable-http --host 0.0.0.0 --port 8000 /path/to/target_binary

# Open an existing Ghidra project without importing anything
mise run serve --project-path /path/to/existing_project.gpr

# List what's already in the project
mise run serve --project-path ~/ghidra_projects --list-project-binaries

# Analyze ahead of time without serving
mise run serve --analyze-only /path/to/target_binary

# GUI mode: open the Ghidra GUI and serve alongside it (see GUI Mode)
mise run gui --project-path ~/ghidra_projects /path/to/target_binary
```

---

## MCP Client Configuration

There are two deployment patterns:

- **Local** — the MCP client launches the server as a subprocess on the same machine (`stdio` transport). Use this for desktop RE work.
- **Remote** — the server runs on a VM or container (`streamable-http` transport). The MCP client connects over HTTP. Use this for cloud-based headless analysis (e.g. a t3.small).

A client launches the server outside your shell, so local configurations run it through mise: `mise exec -C /path/to/ghidra-mcp-lite -- ghidra-mcp …` applies the project's Python environment and the paths in `mise.local.toml`. Use absolute paths. If the client cannot find `mise` (for example, an editor started from the Dock), give its full path instead, such as `/opt/homebrew/bin/mise` (see `which mise`).

---

### Claude Code

Config file: `~/.claude/settings.json`

**Local (stdio):**

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "mise",
      "args": [
        "exec", "-C", "/path/to/ghidra-mcp-lite", "--",
        "ghidra-mcp", "--project-path", "/path/to/ghidra_projects", "/path/to/target_binary"
      ]
    }
  }
}
```

**Remote VM (streamable-http):**

Start the server on the VM, from the project directory:
```bash
mise run serve --transport streamable-http --host 0.0.0.0 --port 8000 /path/to/binary
```

Configure Claude Code to connect:
```json
{
  "mcpServers": {
    "ghidra": {
      "type": "http",
      "url": "http://<vm-ip>:8000/mcp"
    }
  }
}
```

Add via CLI:
```bash
# stdio
claude mcp add ghidra -- mise exec -C /path/to/ghidra-mcp-lite -- ghidra-mcp --project-path /path/to/ghidra_projects /path/to/binary

# remote HTTP
claude mcp add --transport http ghidra http://<vm-ip>:8000/mcp
```

---

### GitHub Copilot (VS Code)

Create or edit `.vscode/mcp.json` in your workspace:

**Local (stdio):**

```json
{
  "servers": {
    "ghidra": {
      "type": "stdio",
      "command": "mise",
      "args": [
        "exec", "-C", "/path/to/ghidra-mcp-lite", "--",
        "ghidra-mcp", "--project-path", "/path/to/ghidra_projects", "/path/to/target_binary"
      ]
    }
  }
}
```

**Remote VM (HTTP):**

```json
{
  "servers": {
    "ghidra": {
      "type": "http",
      "url": "http://<vm-ip>:8000/mcp"
    }
  }
}
```

For a user-level (not workspace) config, add the same block under `"mcp"` in VS Code's `settings.json`:

```json
{
  "mcp": {
    "servers": {
      "ghidra": {
        "type": "stdio",
        "command": "mise",
        "args": [
          "exec", "-C", "/path/to/ghidra-mcp-lite", "--",
          "ghidra-mcp", "--project-path", "/path/to/ghidra_projects", "/path/to/target_binary"
        ]
      }
    }
  }
}
```

---

### Cline

Config file locations:
- **macOS:** `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
- **Linux:** `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
- **Windows:** `%APPDATA%\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json`

Or configure from the Cline panel: **MCP Servers → Edit MCP Settings**.

**Local (stdio):**

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "mise",
      "args": [
        "exec", "-C", "/path/to/ghidra-mcp-lite", "--",
        "ghidra-mcp", "--project-path", "/path/to/ghidra_projects", "/path/to/target_binary"
      ],
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

**Remote VM (HTTP):**

```json
{
  "mcpServers": {
    "ghidra": {
      "url": "http://<vm-ip>:8000/mcp",
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

---

## GUI Mode

Run the server inside the Ghidra GUI to watch and steer the agent's work:

```bash
mise run gui --project-path ~/ghidra_projects /path/to/binary
claude mcp add --transport http ghidra http://127.0.0.1:8000/mcp   # in another terminal
```

`--gui` opens the Ghidra GUI in the server's own process with the project open, and serves MCP over streamable HTTP (`--host`/`--port` as usual). The tools work on the same in-memory programs CodeBrowser shows, so renames, comments, and types appear as the agent makes them.

- **You own saving.** Edits are applied but not saved; each tool's reply says so. Every agent edit is its own entry in Ghidra's undo history (Edit → Undo), and you save with the rest of your work. Deleting a binary with unsaved changes is refused until you save or discard them.
- **Analysis is Ghidra's own.** Imports and `reanalyze_binary` open the program in CodeBrowser as a new, non-current tab and run Ghidra's auto-analysis there, with its progress bar and cancel button. Cancelling marks the binary `failed` (retry with `reanalyze_binary`). Ghidra does not report analyzer failures to the server, so a binary whose analysis partly failed is listed as `ready`. Analysis you start yourself from the Analysis menu shows as `analyzing`. A program you import without analyzing is `failed` ("not analyzed yet") until `reanalyze_binary` analyzes it.
- **Busy means retry.** A write is refused with `[retry_later]` while Ghidra has another change in progress on that program (such as auto-analysis), so the agent never mixes its edit into yours or into analysis.
- **Three extra tools.** `get_current_address` and `get_current_function` report where your cursor is in the most recently focused CodeBrowser; `go_to` moves CodeBrowser to a binary, address, or symbol. They exist only in GUI mode.
- **One project, one session.** GUI mode serves the project it opened; if you close or switch projects in the GUI, tool calls fail until you restart `ghidra-mcp --gui`. Closing the Ghidra GUI stops the server. stdio is not available in GUI mode.

A Ghidra project can be open in only one process at a time, so a headless `ghidra-mcp` and a separately started Ghidra GUI cannot share a project; GUI mode is how to use both at once.

---

## CLI Reference

```
ghidra-mcp [OPTIONS] [INPUT_PATHS]...
```

| Option | Default | Description |
|--------|---------|-------------|
| `-t, --transport` | `stdio` | Transport: `stdio` or `streamable-http` |
| `-p, --port` | `8000` | Port (HTTP transports only) |
| `-o, --host` | `127.0.0.1` | Host (HTTP transports only). Use `0.0.0.0` for remote access |
| `--project-path` | `./ghidra_projects` | Project directory, or path to an existing `.gpr` file |
| `--project-name` | `my_project` | Project name (ignored when `--project-path` is a `.gpr` file) |
| `--wait-for-analysis` / `--no-wait-for-analysis` | on | Let tool calls for a binary still being analyzed wait up to 45 s before returning `retry_later`. Startup never blocks |
| `--verbose-analysis` | off | Print verbose Ghidra analysis output to stderr |
| `--symbols-path` | auto | Local symbol store directory |
| `--list-project-binaries` | — | Print all binaries in the project and exit |
| `--delete-project-binary NAME` | — | Delete a binary from the project and exit |
| `--gui` | off | GUI mode: open the Ghidra GUI in this process and serve over streamable HTTP alongside it (see [GUI Mode](#gui-mode)) |
| `--analyze-only` | — | Import inputs, analyze every binary to completion, print each binary's status, and exit (non-zero if any failed) |

Environment variables: `MCP_TRANSPORT`, `MCP_PORT`, `MCP_HOST`, `GHIDRA_INSTALL_DIR`.

---

## Tool Reference

### Project Management

| Tool | Description |
|------|-------------|
| `list_project_binaries` | List all binaries, including ones still importing, with status (`importing`, `analyzing`, `ready`, `failed`), failure reason, configuration warnings, and metadata |
| `list_project_binary_metadata` | Architecture, compiler, hashes, function/symbol counts |
| `import_binary` | Import a binary (or directory) from disk and analyze it in the background. Optional per-binary analysis options: `pdb_path`, `gdts`, `analyzer_options` (`{option name: value}`), `no_symbols` |
| `reanalyze_binary` | Re-run analysis of one binary with new analysis options (same arguments as `import_binary`); also recovers a binary whose analysis failed |
| `delete_project_binary` | Remove a binary from the project |

### Navigation / Discovery

| Tool | Description |
|------|-------------|
| `list_functions` | Functions defined in the binary (excludes external/imported functions and thunks) with addresses and signatures; filterable by name |
| `list_segments` | Memory segments: name, range, size, r/w/x, type |
| `list_data_items` | Defined data labels, globals, structs, arrays |
| `list_classes` | Class namespaces (C++, ObjC) |
| `list_namespaces` | All non-global namespaces |
| `list_imports` | External symbols imported by the binary; regex-filterable |
| `list_exports` | The binary's entry points: exported symbols and the program entry; regex-filterable |
| `search_strings` | Case-insensitive substring search over all defined strings (an empty query lists them all) |
| `search_symbols` | Substring search over the full symbol table, including externals and default `DAT_…`/`LAB_…` labels |

### Function Lookup

| Tool | Description |
|------|-------------|
| `get_function_by_address` | Function name and signature at an address (no decompilation) |

### Disassembly / Decompilation

| Tool | Description |
|------|-------------|
| `disassemble_function` | Assembly listing: address, bytes, mnemonic, operands, EOL comments (unreadable fields are listed per instruction) |
| `decompile_function` | Pseudo-C output via the Ghidra decompiler (up to 120 s; a decompiler failure is an error) |

### Cross-References

| Tool | Description |
|------|-------------|
| `list_cross_references` | All references *to* a function, symbol, or address |
| `get_xrefs_from` | All references *from* an address (calls, jumps, data refs) |

### Annotation / Renaming

| Tool | Description |
|------|-------------|
| `set_disassembly_comment` | Set EOL comment in the disassembly listing (empty text removes it) |
| `set_decompiler_comment` | Set `//` comment in the decompiler view (empty text removes it) |
| `rename_function` | Rename a function by name or address |
| `rename_function_by_address` | Rename by exact entry-point address (unambiguous) |
| `rename_data` | Rename the defined data at an address (renames its symbol, or creates a label if it has none or only a default `DAT_…` one) |
| `rename_variable` | Rename a local variable using the decompiler's high-level model |

### Type / Prototype

| Tool | Description |
|------|-------------|
| `set_function_prototype` | Set return type and parameter names/types from a C declaration |
| `set_local_variable_type` | Set the data type of a local variable |

### Callgraph

| Tool | Description |
|------|-------------|
| `gen_callgraph` | MermaidJS call graph (calling or called direction; requires ghidrecomp) |

### Analysis

| Tool | Description |
|------|-------------|
| `get_function_callers` | Functions that call a function (including through its thunks), each with its call sites |
| `get_function_callees` | Functions a function calls, with call sites; thunks name their real target; unresolved indirect calls listed separately |
| `diff_functions` | Unified diff of two functions (same or different binaries) as decompiled C or disassembly, with a similarity ratio; address-derived names masked by default |
| `find_similar_functions_fuzzy` | Rank a binary's functions by similarity to a given one (multiset Jaccard of instruction-mnemonic 3-grams; works across binaries) |
| `get_function_pcode` | A function's p-code: per instruction (`raw`) or from the decompiler (`high`); bounded by `max_ops` |
| `analyze_dataflow` | Backward or forward data-flow slice of a decompiler variable (e.g. `param_1`): the p-code operations and variables involved |

### Memory

| Tool | Description |
|------|-------------|
| `read_bytes` | Read raw bytes from memory as hex (up to 8192) |

All write-back tools (rename, comment, prototype, type) run inside a Ghidra transaction and save the project to disk before returning. If Ghidra rejects the edit, it is rolled back. If the save itself fails, the error says the edit is applied in memory but not saved. Write tools act only on exact targets: a function must be named exactly or given by its entry-point address, and thunks and external functions are refused.

### Errors

Every failed tool call returns an error result whose message starts with a recovery category:

| Category | Meaning |
|----------|---------|
| `[fix_input]` | Change the request (unknown binary, bad address, ambiguous name — candidates are listed) |
| `[retry_later]` | The binary is still being imported or analyzed; call again later |
| `[stop]` | Retrying won't help (for example, analysis failed). Unexpected errors say "Internal error"; details are in the server log |

---

## Notes

**Analysis time.** Ghidra analysis of a 5 MB binary typically takes 1–5 minutes on a t3.small, and Go binaries can take much longer. Run `--analyze-only` once to analyze ahead of time; on later startups the project is reloaded from disk instantly.

**Analysis options are per binary.** Pass a PDB, GDT archives, analyzer options, or `no_symbols` as arguments of `import_binary` or `reanalyze_binary`; they apply to that binary only and are saved with it in the project. Binaries given on the command line are analyzed with default options. If a configuration step fails (a bad option value, an archive that can't be applied), analysis continues and the problem appears in that binary's `warnings`.

**Names and addresses.** Tools that take a function or symbol accept a name (case-insensitive, namespace-qualified like `Foo::bar`) or a hex address. Read tools also accept a unique partial name, or an address inside a function, and say what they resolved to in the result's `resolution` field. Write tools need an exact name or a function's entry-point address, and don't act on thunks or external functions. When a string could mean two different targets, or matches several, the error lists the candidates.

**Partial results.** When some items can't be read, read tools return the rest and mark the result `partial`: `list_data_items` and `search_strings` list the unreadable items in `failures`, `disassemble_function` names unreadable fields in each instruction's `errors`, and `read_bytes` reports `requested_size` when the range runs past memory.

**Project reuse.** Point `--project-path` at the same directory on every run and Ghidra will reuse existing analysis. Import and analysis only run for new binaries.

**Write-back tools require a writable project.** The project directory must be writable by the server process. If you open an existing `.gpr` file from a read-only location the rename/comment/type tools will fail.

**ghidrecomp.** `gen_callgraph` requires the `ghidrecomp` package, and PDB/symbol-server setup uses it; `mise run install` includes it. Without it, `gen_callgraph` fails and symbol configuration is skipped and noted in the binary's `warnings`; all other tools work.

**Development.** `mise run test` runs the unit tests. `mise run test:integration` runs the tools against your Ghidra (it also needs a C compiler), and `mise run test:gui` runs the GUI smoke suite, which opens a Ghidra window. `mise tasks` lists every task.

**`get_current_function` / `get_current_address` are not implemented.** These tools from GUI-based Ghidra MCP servers require an interactive Ghidra UI session and cannot be supported in headless mode.
