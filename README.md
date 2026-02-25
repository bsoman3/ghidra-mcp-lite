# ghidra-mcp-lite

A lightweight MCP server for Ghidra headless analysis. Exposes 28 native Ghidra tools — decompilation, disassembly, cross-references, renaming, type setting, callgraphs, and more — with no ChromaDB, no ML model, and no vector indexing.

Designed to run comfortably on a small VM (e.g. a t3.small) where embedding-based servers saturate the CPU on startup.

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| **Ghidra 11.1+** | Tested on 11.1–11.3.x. Download from [ghidra-sre.org](https://ghidra-sre.org) |
| **JDK 17+** | Required by Ghidra. Must be in `PATH` or `JAVA_HOME` |
| **Python 3.10+** | The server is pure Python |
| **pyghidra 2.2+** | Installed automatically as a dependency |

---

## Installation

```bash
git clone <this-repo>
cd ghidra-mcp-lite
pip install -e .
```

Or without cloning:

```bash
pip install git+<this-repo-url>
```

This installs the `ghidra-mcp` CLI entry point.

---

## How It Works

### Finding Ghidra

pyghidra locates Ghidra via the `GHIDRA_INSTALL_DIR` environment variable. Set it to the root of your Ghidra installation — the directory that contains `ghidraRun` and the `Ghidra/` subdirectory:

```bash
export GHIDRA_INSTALL_DIR=/opt/ghidra_11.3.2_PUBLIC
```

You can set this in your shell profile, in the MCP server config's `env` block, or on the command line. The server will fail to start with a clear error if it cannot locate Ghidra.

If you have multiple JDKs installed and pyghidra picks the wrong one, set `JAVA_HOME` explicitly:

```bash
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
```

### Loading a Binary and Running Analysis

Pass one or more binary paths as positional arguments on startup:

```bash
ghidra-mcp /path/to/binary [/path/to/another ...]
```

What happens internally:

1. `pyghidra.start()` initialises the Ghidra JVM (loads Ghidra's JAR files into the Python process via JPype).
2. A Ghidra project is created or opened at `--project-path` / `--project-name` (defaults: `./ghidra_projects/my_project`).
3. Each binary is imported into the project via `GhidraProject.importProgram()` and saved. Binaries are named `<filename>-<sha1[:6]>` to allow the same filename from different paths.
4. Ghidra auto-analysis (`analyzeAll`) runs in a background thread. The server accepts MCP connections immediately; tools that require a fully-analyzed binary return a clear error until analysis finishes.
5. The Ghidra project is persisted to disk. On the next startup with the same `--project-path`, already-analyzed binaries are re-opened instantly — no re-analysis unless you pass `--force-analysis`.

To block MCP connections until analysis is fully complete:

```bash
ghidra-mcp --wait-for-analysis /path/to/binary
```

---

## Quick Start

```bash
# Set Ghidra location
export GHIDRA_INSTALL_DIR=/opt/ghidra_11.3.2_PUBLIC

# Import, analyze, and serve a binary over stdio
ghidra-mcp /path/to/target_binary

# Serve over HTTP (useful for remote VMs)
ghidra-mcp --transport streamable-http --host 0.0.0.0 --port 8000 \
    --wait-for-analysis /path/to/target_binary

# Open an existing Ghidra project without importing anything
ghidra-mcp --project-path /path/to/existing_project.gpr

# List what's already in the project
ghidra-mcp --project-path ./ghidra_projects --list-project-binaries
```

---

## MCP Client Configuration

There are two deployment patterns:

- **Local** — the MCP client launches the server as a subprocess on the same machine (`stdio` transport). Use this for desktop RE work.
- **Remote** — the server runs on a VM or container (`streamable-http` transport). The MCP client connects over HTTP. Use this for cloud-based headless analysis (e.g. a t3.small).

---

### Claude Code

Config file: `~/.claude/settings.json`

**Local (stdio):**

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "ghidra-mcp",
      "args": [
        "--wait-for-analysis",
        "/path/to/target_binary"
      ],
      "env": {
        "GHIDRA_INSTALL_DIR": "/opt/ghidra_11.3.2_PUBLIC"
      }
    }
  }
}
```

**Remote VM (streamable-http):**

Start the server on the VM:
```bash
GHIDRA_INSTALL_DIR=/opt/ghidra_11.3.2_PUBLIC \
ghidra-mcp --transport streamable-http \
           --host 0.0.0.0 \
           --port 8000 \
           --wait-for-analysis /path/to/binary
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
claude mcp add ghidra -- ghidra-mcp --wait-for-analysis /path/to/binary

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
      "command": "ghidra-mcp",
      "args": [
        "--wait-for-analysis",
        "/path/to/target_binary"
      ],
      "env": {
        "GHIDRA_INSTALL_DIR": "/opt/ghidra_11.3.2_PUBLIC"
      }
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
        "command": "ghidra-mcp",
        "args": ["--wait-for-analysis", "/path/to/target_binary"],
        "env": {
          "GHIDRA_INSTALL_DIR": "/opt/ghidra_11.3.2_PUBLIC"
        }
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
      "command": "ghidra-mcp",
      "args": [
        "--wait-for-analysis",
        "/path/to/target_binary"
      ],
      "env": {
        "GHIDRA_INSTALL_DIR": "/opt/ghidra_11.3.2_PUBLIC"
      },
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

## CLI Reference

```
ghidra-mcp [OPTIONS] [INPUT_PATHS]...
```

| Option | Default | Description |
|--------|---------|-------------|
| `-t, --transport` | `stdio` | Transport: `stdio`, `streamable-http`, `sse` |
| `-p, --port` | `8000` | Port (HTTP transports only) |
| `-o, --host` | `127.0.0.1` | Host (HTTP transports only). Use `0.0.0.0` for remote access |
| `--project-path` | `./ghidra_projects` | Project directory, or path to an existing `.gpr` file |
| `--project-name` | `my_project` | Project name (ignored when `--project-path` is a `.gpr` file) |
| `--wait-for-analysis` | off | Block startup until analysis of all binaries completes |
| `--force-analysis` | off | Re-analyze even if Ghidra already marked the binary as analyzed |
| `--no-symbols` | off | Disable PDB/symbol server lookup during analysis |
| `--verbose-analysis` | off | Print verbose Ghidra analysis output to stderr |
| `--symbols-path` | auto | Local symbol store directory |
| `--sym-file-path` | none | Path to a specific PDB file for the binary |
| `--gdt PATH` | none | Apply a GDT type archive (repeatable) |
| `--program-options PATH` | none | JSON file with per-analyzer options |
| `--list-project-binaries` | — | Print all binaries in the project and exit |
| `--delete-project-binary NAME` | — | Delete a binary from the project and exit |

Environment variables: `MCP_TRANSPORT`, `MCP_PORT`, `MCP_HOST`, `GHIDRA_INSTALL_DIR`.

---

## Tool Reference

### Project Management

| Tool | Description |
|------|-------------|
| `list_project_binaries` | List all binaries in the project with analysis status |
| `list_project_binary_metadata` | Architecture, compiler, hashes, function/symbol counts |
| `import_binary` | Import a binary from disk (analyzed in background) |
| `delete_project_binary` | Remove a binary from the project |

### Navigation / Discovery

| Tool | Description |
|------|-------------|
| `list_functions` | All functions with addresses and signatures; filterable by name |
| `list_segments` | Memory segments: name, range, size, r/w/x, type |
| `list_data_items` | Defined data labels, globals, structs, arrays |
| `list_classes` | Class namespaces (C++, ObjC) |
| `list_namespaces` | All non-global namespaces |
| `list_imports` | External symbols imported by the binary; regex-filterable |
| `list_exports` | Symbols exported by the binary; regex-filterable |
| `search_strings` | Case-insensitive substring search over all defined strings |
| `search_symbols` | Substring search over the full symbol table |

### Function Lookup

| Tool | Description |
|------|-------------|
| `get_function_by_address` | Function name and signature at an address (no decompilation) |

### Disassembly / Decompilation

| Tool | Description |
|------|-------------|
| `disassemble_function` | Assembly listing: address, bytes, mnemonic, operands, EOL comments |
| `decompile_function` | Pseudo-C output via the Ghidra decompiler |

### Cross-References

| Tool | Description |
|------|-------------|
| `list_cross_references` | All references *to* a function, symbol, or address |
| `get_xrefs_from` | All references *from* an address (calls, jumps, data refs) |

### Annotation / Renaming

| Tool | Description |
|------|-------------|
| `set_disassembly_comment` | Set EOL comment in the disassembly listing |
| `set_decompiler_comment` | Set `//` comment in the decompiler view |
| `rename_function` | Rename a function by name or address |
| `rename_function_by_address` | Rename by exact entry-point address (unambiguous) |
| `rename_data` | Rename or create a label at a data address |
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
| `read_bytes` | Read raw bytes from memory as hex |

All write-back tools (rename, comment, prototype, type) run inside a Ghidra transaction and save the project to disk before returning.

---

## Notes

**Analysis time.** Ghidra analysis of a 5 MB binary typically takes 1–5 minutes on a t3.small. Use `--wait-for-analysis` so the MCP client doesn't receive "analysis incomplete" errors. On second startup the project is reloaded from disk instantly.

**Project reuse.** Point `--project-path` at the same directory on every run and Ghidra will reuse existing analysis. Import and analysis only run for new binaries.

**Write-back tools require a writable project.** The project directory must be writable by the server process. If you open an existing `.gpr` file from a read-only location the rename/comment/type tools will fail.

**ghidrecomp is optional.** `gen_callgraph` requires the `ghidrecomp` package. All other tools work without it.

**`get_current_function` / `get_current_address` are not implemented.** These tools from GUI-based Ghidra MCP servers require an interactive Ghidra UI session and cannot be supported in headless mode.
