"""
Lightweight Ghidra MCP server.

Native Ghidra tools only — no ChromaDB, no ML/embedding.
Compatible with: stdio, streamable-http, sse transports.
"""

import json
import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import click
import pyghidra
from mcp.server import Server
from mcp.server.fastmcp import Context, FastMCP
from mcp.shared.exceptions import McpError
from mcp.types import INTERNAL_ERROR, INVALID_PARAMS, ErrorData

from ghidra_mcp import __version__
from ghidra_mcp.context import GhidraContext
from ghidra_mcp.models import (
    BytesReadResult,
    CallGraphDirection,
    CallGraphDisplayType,
    CallGraphResult,
    CrossReferenceInfos,
    DataItems,
    DecompiledFunction,
    DisassemblyResult,
    ExportInfos,
    FunctionInfo,
    FunctionList,
    ImportInfos,
    MemorySegments,
    NamespaceList,
    ProgramInfo,
    ProgramInfos,
    StringSearchResults,
    SymbolSearchResults,
)
from ghidra_mcp.tools import GhidraTools

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Server setup
# ─────────────────────────────────────────────────────────────────────────────


@asynccontextmanager
async def _lifespan(server: Server) -> AsyncIterator[GhidraContext]:
    try:
        yield server._ghidra_context  # type: ignore[attr-defined]
    finally:
        pass


mcp = FastMCP("ghidra-mcp", lifespan=_lifespan)  # type: ignore[arg-type]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _err(e: Exception) -> McpError:
    if isinstance(e, ValueError):
        return McpError(ErrorData(code=INVALID_PARAMS, message=str(e)))
    if isinstance(e, McpError):
        return e
    return McpError(ErrorData(code=INTERNAL_ERROR, message=str(e)))


def _tools(ctx: Context, binary_name: str) -> GhidraTools:
    ghidra_ctx: GhidraContext = ctx.request_context.lifespan_context
    return GhidraTools(ghidra_ctx.get_program_info(binary_name))


# ─────────────────────────────────────────────────────────────────────────────
# Project management
# ─────────────────────────────────────────────────────────────────────────────


@mcp.tool()
def list_project_binaries(ctx: Context) -> ProgramInfos:
    """List every binary loaded in the active Ghidra project along with its analysis status.

    Returns name, file path, load time, and whether Ghidra analysis has completed.
    Use this first to discover binary names required by other tools.
    """
    ghidra_ctx: GhidraContext = ctx.request_context.lifespan_context
    programs = [
        ProgramInfo(
            name=pi.name,
            file_path=str(pi.file_path) if pi.file_path else None,
            load_time=pi.load_time,
            analysis_complete=pi.analysis_complete,
            metadata={},
        )
        for pi in ghidra_ctx.programs.values()
    ]
    return ProgramInfos(programs=programs)


@mcp.tool()
def list_project_binary_metadata(binary_name: str, ctx: Context) -> dict:
    """Retrieve detailed Ghidra metadata for a binary.

    Returns architecture, compiler, endianness, file hashes, function/symbol counts, etc.

    Args:
        binary_name: Name of the binary (from list_project_binaries).
    """
    try:
        ghidra_ctx: GhidraContext = ctx.request_context.lifespan_context
        return ghidra_ctx.get_program_info(binary_name).metadata
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
def import_binary(binary_path: str, ctx: Context) -> str:
    """Import a binary from disk into the Ghidra project and analyze it in the background.

    When complete, the binary will appear in list_project_binaries with analysis_complete=true.

    Args:
        binary_path: Absolute path to the binary file to import.
    """
    try:
        ghidra_ctx: GhidraContext = ctx.request_context.lifespan_context
        ghidra_ctx.import_binary_backgrounded(binary_path)
        return (
            f"Importing '{binary_path}' in the background. "
            "Use list_project_binaries to check analysis status."
        )
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
def delete_project_binary(binary_name: str, ctx: Context) -> str:
    """Permanently delete a binary from the Ghidra project.

    Args:
        binary_name: Name of the binary to delete (from list_project_binaries).
    """
    try:
        ghidra_ctx: GhidraContext = ctx.request_context.lifespan_context
        if ghidra_ctx.delete_program(binary_name):
            return f"Deleted: {binary_name}"
        raise McpError(
            ErrorData(code=INVALID_PARAMS, message=f"Could not delete '{binary_name}'")
        )
    except McpError:
        raise
    except Exception as e:
        raise _err(e) from e


# ─────────────────────────────────────────────────────────────────────────────
# Navigation / discovery
# ─────────────────────────────────────────────────────────────────────────────


@mcp.tool()
def list_functions(
    binary_name: str,
    ctx: Context,
    query: str | None = None,
    offset: int = 0,
    limit: int = 100,
) -> FunctionList:
    """List all functions in a binary with their addresses and signatures.

    Args:
        binary_name: Name of the binary.
        query: Optional case-insensitive substring to filter function names.
        offset: Number of results to skip (pagination).
        limit: Maximum number of results to return.
    """
    try:
        funcs, total = _tools(ctx, binary_name).list_functions(
            query=query, offset=offset, limit=limit
        )
        return FunctionList(functions=funcs, total=total)
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
def list_segments(binary_name: str, ctx: Context) -> MemorySegments:
    """List all memory segments (sections) of a binary.

    Returns name, address range, size, r/w/x permissions, type, and initialization status.
    Useful for understanding the binary's memory layout before diving into code.

    Args:
        binary_name: Name of the binary.
    """
    try:
        return MemorySegments(segments=_tools(ctx, binary_name).list_segments())
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
def list_data_items(
    binary_name: str,
    ctx: Context,
    offset: int = 0,
    limit: int = 100,
) -> DataItems:
    """List defined data items (globals, structs, arrays, string data labels).

    Args:
        binary_name: Name of the binary.
        offset: Number of results to skip (pagination).
        limit: Maximum number of results to return.
    """
    try:
        items, total = _tools(ctx, binary_name).list_data_items(offset=offset, limit=limit)
        return DataItems(items=items, total=total)
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
def list_classes(
    binary_name: str,
    ctx: Context,
    offset: int = 0,
    limit: int = 100,
) -> NamespaceList:
    """List all class namespaces defined in the binary (C++ classes, ObjC classes, etc.).

    Args:
        binary_name: Name of the binary.
        offset: Number of results to skip (pagination).
        limit: Maximum number of results to return.
    """
    try:
        namespaces, total = _tools(ctx, binary_name).list_classes(offset=offset, limit=limit)
        return NamespaceList(namespaces=namespaces, total=total)
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
def list_namespaces(
    binary_name: str,
    ctx: Context,
    offset: int = 0,
    limit: int = 100,
) -> NamespaceList:
    """List all non-global namespaces (classes, libraries, user-defined namespaces).

    Args:
        binary_name: Name of the binary.
        offset: Number of results to skip (pagination).
        limit: Maximum number of results to return.
    """
    try:
        namespaces, total = _tools(ctx, binary_name).list_namespaces(offset=offset, limit=limit)
        return NamespaceList(namespaces=namespaces, total=total)
    except Exception as e:
        raise _err(e) from e


# ─────────────────────────────────────────────────────────────────────────────
# Function lookup
# ─────────────────────────────────────────────────────────────────────────────


@mcp.tool()
def get_function_by_address(binary_name: str, address: str, ctx: Context) -> FunctionInfo:
    """Get function metadata (name, signature) for the function at or containing an address.

    Lighter than decompile_function — returns metadata only, no pseudo-C output.

    Args:
        binary_name: Name of the binary.
        address: Hex address (with or without 0x prefix).
    """
    try:
        return _tools(ctx, binary_name).get_function_by_address(address)
    except Exception as e:
        raise _err(e) from e


# ─────────────────────────────────────────────────────────────────────────────
# Disassembly / decompilation
# ─────────────────────────────────────────────────────────────────────────────


@mcp.tool()
def disassemble_function(
    binary_name: str, name_or_address: str, ctx: Context
) -> DisassemblyResult:
    """Get the assembly listing for a function.

    Returns every instruction in the function body with address, raw bytes, mnemonic,
    operands, and any EOL comments.

    Args:
        binary_name: Name of the binary.
        name_or_address: Function name (case-insensitive) or hex address.
    """
    try:
        return _tools(ctx, binary_name).disassemble_function(name_or_address)
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
async def decompile_function(
    binary_name: str, name_or_address: str, ctx: Context
) -> DecompiledFunction:
    """Decompile a function and return its pseudo-C source code.

    Args:
        binary_name: Name of the binary containing the function.
        name_or_address: Function name (case-insensitive) or hex address (e.g. '0x401000').
    """
    try:
        return _tools(ctx, binary_name).decompile_function_by_name_or_addr(name_or_address)
    except Exception as e:
        raise _err(e) from e


# ─────────────────────────────────────────────────────────────────────────────
# Symbol / import / export
# ─────────────────────────────────────────────────────────────────────────────


@mcp.tool()
def search_symbols(
    binary_name: str,
    query: str,
    ctx: Context,
    offset: int = 0,
    limit: int = 25,
) -> SymbolSearchResults:
    """Search for symbols (functions, labels, globals, imports) by name substring.

    Performs a case-insensitive substring match across the full symbol table.

    Args:
        binary_name: Name of the binary to search.
        query: Substring to match against symbol names.
        offset: Pagination offset.
        limit: Maximum results to return.
    """
    try:
        return SymbolSearchResults(
            symbols=_tools(ctx, binary_name).search_symbols_by_name(
                query, offset=offset, limit=limit
            )
        )
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
def list_imports(
    binary_name: str,
    ctx: Context,
    query: str = ".*",
    offset: int = 0,
    limit: int = 25,
) -> ImportInfos:
    """List external functions and symbols imported by a binary.

    Args:
        binary_name: Name of the binary.
        query: Regex pattern to filter import names (e.g. 'socket' or 'mem.*').
        offset: Pagination offset.
        limit: Maximum results to return.
    """
    try:
        return ImportInfos(
            imports=_tools(ctx, binary_name).list_imports(query=query, offset=offset, limit=limit)
        )
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
def list_exports(
    binary_name: str,
    ctx: Context,
    query: str = ".*",
    offset: int = 0,
    limit: int = 25,
) -> ExportInfos:
    """List functions and symbols exported by a binary.

    Args:
        binary_name: Name of the binary.
        query: Regex pattern to filter export names.
        offset: Pagination offset.
        limit: Maximum results to return.
    """
    try:
        return ExportInfos(
            exports=_tools(ctx, binary_name).list_exports(query=query, offset=offset, limit=limit)
        )
    except Exception as e:
        raise _err(e) from e


# ─────────────────────────────────────────────────────────────────────────────
# Cross-references
# ─────────────────────────────────────────────────────────────────────────────


@mcp.tool()
def list_cross_references(
    binary_name: str, name_or_address: str, ctx: Context
) -> CrossReferenceInfos:
    """Find all cross-references (xrefs) TO a function, symbol, or address.

    Useful for finding callers, data consumers, and jump targets.
    If an exact match is not found the error message will suggest close matches.

    Args:
        binary_name: Name of the binary.
        name_or_address: Function/symbol name or hex address to find references to.
    """
    try:
        return CrossReferenceInfos(
            cross_references=_tools(ctx, binary_name).list_cross_references(name_or_address)
        )
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
def get_xrefs_from(
    binary_name: str, address: str, ctx: Context
) -> CrossReferenceInfos:
    """Find all references FROM a given address (calls/jumps/data refs originating here).

    Complements list_cross_references which finds refs TO an address.

    Args:
        binary_name: Name of the binary.
        address: Hex address to find outgoing references from.
    """
    try:
        return CrossReferenceInfos(
            cross_references=_tools(ctx, binary_name).get_xrefs_from(address)
        )
    except Exception as e:
        raise _err(e) from e


# ─────────────────────────────────────────────────────────────────────────────
# String / bytes
# ─────────────────────────────────────────────────────────────────────────────


@mcp.tool()
def search_strings(
    binary_name: str,
    query: str,
    ctx: Context,
    limit: int = 100,
) -> StringSearchResults:
    """Search for strings defined in a binary using a case-insensitive substring match.

    Uses Ghidra's native DefinedStringIterator — no ML model, no ChromaDB.
    The 'total' field shows how many matches exist even if limit was reached.

    Args:
        binary_name: Name of the binary.
        query: Case-insensitive substring to search for.
        limit: Maximum number of results to return (default: 100).
    """
    try:
        strings, total = _tools(ctx, binary_name).search_strings(query=query, limit=limit)
        return StringSearchResults(strings=strings, total=total)
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
def read_bytes(
    binary_name: str, address: str, ctx: Context, size: int = 32
) -> BytesReadResult:
    """Read raw bytes from the binary's memory image at a given address.

    Args:
        binary_name: Name of the binary.
        address: Memory address in hex (with or without 0x prefix).
        size: Number of bytes to read (default: 32, max: 8192).
    """
    try:
        return _tools(ctx, binary_name).read_bytes(address=address, size=size)
    except Exception as e:
        raise _err(e) from e


# ─────────────────────────────────────────────────────────────────────────────
# Annotation / renaming (write-back)
# ─────────────────────────────────────────────────────────────────────────────


@mcp.tool()
def set_disassembly_comment(
    binary_name: str, address: str, comment: str, ctx: Context
) -> str:
    """Set an EOL comment at an address, visible in the disassembly listing.

    Changes are saved to the Ghidra project immediately.

    Args:
        binary_name: Name of the binary.
        address: Hex address where the comment should appear.
        comment: Comment text.
    """
    try:
        return _tools(ctx, binary_name).set_disassembly_comment(address, comment)
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
def set_decompiler_comment(
    binary_name: str, address: str, comment: str, ctx: Context
) -> str:
    """Set a PRE comment at an address, visible in the decompiler view as // comment.

    Changes are saved to the Ghidra project immediately.

    Args:
        binary_name: Name of the binary.
        address: Hex address where the comment should appear.
        comment: Comment text.
    """
    try:
        return _tools(ctx, binary_name).set_decompiler_comment(address, comment)
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
def rename_function(
    binary_name: str, name_or_address: str, new_name: str, ctx: Context
) -> str:
    """Rename a function. Accepts current name or hex address as identifier.

    Changes are saved to the Ghidra project immediately.

    Args:
        binary_name: Name of the binary.
        name_or_address: Current function name or hex entry point address.
        new_name: New name to assign.
    """
    try:
        return _tools(ctx, binary_name).rename_function(name_or_address, new_name)
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
def rename_function_by_address(
    binary_name: str, address: str, new_name: str, ctx: Context
) -> str:
    """Rename a function by its exact entry point address.

    Useful when multiple functions share the same name (ambiguous rename).
    Changes are saved to the Ghidra project immediately.

    Args:
        binary_name: Name of the binary.
        address: Exact hex entry point address of the function.
        new_name: New name to assign.
    """
    try:
        return _tools(ctx, binary_name).rename_function_by_address(address, new_name)
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
def rename_data(
    binary_name: str, address: str, new_name: str, ctx: Context
) -> str:
    """Rename a data label at a given address.

    Creates a new label if none exists. Changes are saved immediately.

    Args:
        binary_name: Name of the binary.
        address: Hex address of the data item.
        new_name: New label name to assign.
    """
    try:
        return _tools(ctx, binary_name).rename_data(address, new_name)
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
def rename_variable(
    binary_name: str,
    function_name_or_address: str,
    old_var_name: str,
    new_var_name: str,
    ctx: Context,
) -> str:
    """Rename a local variable within a function using the decompiler's high-level model.

    Changes are saved to the Ghidra project immediately.

    Args:
        binary_name: Name of the binary.
        function_name_or_address: Function name or hex address containing the variable.
        old_var_name: Current variable name (as shown in decompiler output).
        new_var_name: New variable name.
    """
    try:
        return _tools(ctx, binary_name).rename_variable(
            function_name_or_address, old_var_name, new_var_name
        )
    except Exception as e:
        raise _err(e) from e


# ─────────────────────────────────────────────────────────────────────────────
# Type / prototype (write-back)
# ─────────────────────────────────────────────────────────────────────────────


@mcp.tool()
def set_function_prototype(
    binary_name: str, name_or_address: str, prototype: str, ctx: Context
) -> str:
    """Set a function's full prototype (return type, parameter names and types).

    The prototype is parsed as a C declaration.
    Example: 'int process_data(char *buf, int len)'
    Changes are saved to the Ghidra project immediately.

    Args:
        binary_name: Name of the binary.
        name_or_address: Function name or hex address.
        prototype: C function signature string (without trailing semicolon).
    """
    try:
        return _tools(ctx, binary_name).set_function_prototype(name_or_address, prototype)
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
def set_local_variable_type(
    binary_name: str,
    function_name_or_address: str,
    var_name: str,
    new_type: str,
    ctx: Context,
) -> str:
    """Set the data type of a local variable within a function.

    Type string examples: 'int', 'char *', 'unsigned int', 'uint32_t', 'struct Foo *'
    Changes are saved to the Ghidra project immediately.

    Args:
        binary_name: Name of the binary.
        function_name_or_address: Function name or hex address containing the variable.
        var_name: Variable name (as shown in decompiler output).
        new_type: C type string to assign.
    """
    try:
        return _tools(ctx, binary_name).set_local_variable_type(
            function_name_or_address, var_name, new_type
        )
    except Exception as e:
        raise _err(e) from e


# ─────────────────────────────────────────────────────────────────────────────
# Callgraph
# ─────────────────────────────────────────────────────────────────────────────


@mcp.tool()
def gen_callgraph(
    binary_name: str,
    function_name: str,
    ctx: Context,
    direction: CallGraphDirection = CallGraphDirection.CALLING,
    display_type: CallGraphDisplayType = CallGraphDisplayType.FLOW,
    condense_threshold: int = 50,
    top_layers: int = 3,
    bottom_layers: int = 3,
    max_run_time: int = 120,
) -> CallGraphResult:
    """Generate a MermaidJS call graph for a function.

    Args:
        binary_name: Name of the binary.
        function_name: Name or hex address of the target function.
        direction: 'calling' = functions this one calls; 'called' = callers of this function.
        display_type: Graph layout: 'flow', 'flow_ends', or 'mind'.
        condense_threshold: Number of edges before the graph is condensed.
        top_layers: Layers preserved at the top of a condensed graph.
        bottom_layers: Layers preserved at the bottom of a condensed graph.
        max_run_time: Timeout in seconds before the generator gives up.
    """
    try:
        return _tools(ctx, binary_name).gen_callgraph(
            function_name_or_address=function_name,
            cg_direction=direction,
            cg_display_type=display_type,
            max_run_time=max_run_time,
            condense_threshold=condense_threshold,
            top_layers=top_layers,
            bottom_layers=bottom_layers,
        )
    except Exception as e:
        raise _err(e) from e


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-v", "--version")
# Transport
@click.option(
    "-t", "--transport",
    type=click.Choice(["stdio", "streamable-http", "sse"], case_sensitive=False),
    default="stdio", envvar="MCP_TRANSPORT", show_default=True,
    help="MCP transport protocol.",
)
@click.option("-p", "--port", type=int, default=8000, envvar="MCP_PORT", show_default=True)
@click.option("-o", "--host", default="127.0.0.1", envvar="MCP_HOST", show_default=True)
# Project
@click.option(
    "--project-path",
    type=click.Path(path_type=Path),
    default=Path("ghidra_projects"),
    show_default=True,
    help="Directory for the Ghidra project, or path to an existing .gpr file.",
)
@click.option("--project-name", default="my_project", show_default=True)
# Analysis
@click.option("--force-analysis/--no-force-analysis", default=False, show_default=True,
              help="Re-analyze binaries even if already analyzed.")
@click.option("--no-symbols/--with-symbols", default=False, show_default=True,
              help="Disable PDB/symbol loading during analysis.")
@click.option(
    "--wait-for-analysis/--no-wait-for-analysis", default=False, show_default=True,
    help="Block server startup until all binaries are fully analyzed.",
)
@click.option("--verbose-analysis/--no-verbose-analysis", default=False, show_default=True,
              help="Verbose Ghidra analysis logging.")
@click.option("--symbols-path", type=click.Path(), default=None,
              help="Path to local symbol store directory.")
@click.option("--sym-file-path", type=click.Path(exists=True), default=None,
              help="Path to a single PDB file for the binary.")
@click.option("--gdt", type=click.Path(exists=True), multiple=True,
              help="Path to a GDT file (can be repeated).")
@click.option("--program-options", type=click.Path(exists=True), default=None,
              help="JSON file with analyzer options.")
# Project management (exits after running)
@click.option("--list-project-binaries", is_flag=True,
              help="Print all binaries in the project and exit.")
@click.option("--delete-project-binary", type=str, default=None,
              help="Delete a binary from the project by name and exit.")
@click.argument("input_paths", type=click.Path(exists=True), nargs=-1)
def main(
    transport: str,
    port: int,
    host: str,
    project_path: Path,
    project_name: str,
    force_analysis: bool,
    no_symbols: bool,
    wait_for_analysis: bool,
    verbose_analysis: bool,
    symbols_path: str | None,
    sym_file_path: str | None,
    gdt: tuple[str, ...],
    program_options: str | None,
    list_project_binaries: bool,
    delete_project_binary: str | None,
    input_paths: tuple[str, ...],
) -> None:
    """Lightweight Ghidra MCP server — native Ghidra tools, no ML/embedding.

    \b
    input_paths  Binaries to import and analyze on startup (optional).

    \b
    Examples:
      # Import and serve a binary over stdio:
      ghidra-mcp /path/to/binary

      # HTTP transport, wait for analysis before accepting requests:
      ghidra-mcp --transport streamable-http --wait-for-analysis /path/to/binary

      # List binaries in an existing project:
      ghidra-mcp --project-path ./myproject --list-project-binaries
    """
    # Handle .gpr file paths
    if project_path.suffix.lower() == ".gpr":
        project_dir = str(project_path.parent)
        project_name = project_path.stem
    else:
        project_dir = str(project_path)

    prog_opts = None
    if program_options:
        with open(program_options) as f:
            prog_opts = json.load(f)

    pyghidra.start(verbose_analysis)

    ctx = GhidraContext(
        project_name=project_name,
        project_path=project_dir,
        force_analysis=force_analysis,
        verbose_analysis=verbose_analysis,
        no_symbols=no_symbols,
        gdts=list(gdt),
        program_options=prog_opts,
        wait_for_analysis=wait_for_analysis,
        symbols_path=symbols_path,
        sym_file_path=sym_file_path,
    )

    # One-shot management commands
    if list_project_binaries:
        bins = ctx.list_binaries()
        if bins:
            for name in bins:
                click.echo(f"- {name}")
        else:
            click.echo("No binaries in project.")
        ctx.close()
        return

    if delete_project_binary:
        try:
            ctx.delete_program(delete_project_binary)
            click.echo(f"Deleted: {delete_project_binary}")
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
        ctx.close()
        return

    # Import any binaries provided on the command line
    if input_paths:
        logger.info(f"Importing {len(input_paths)} binary/binaries...")
        ctx.import_binaries([Path(p) for p in input_paths])

    # Kick off analysis (background unless --wait-for-analysis)
    ctx.analyze_project()

    # Attach context to the FastMCP instance (read by _lifespan)
    mcp._ghidra_context = ctx  # type: ignore[attr-defined]
    mcp.settings.port = port
    mcp.settings.host = host

    logger.info(f"Starting server (transport={transport}, host={host}, port={port})")

    try:
        if transport == "stdio":
            mcp.run(transport="stdio")
        elif transport in ("streamable-http", "http"):
            mcp.run(transport="streamable-http")
        elif transport == "sse":
            mcp.run(transport="sse")
        else:
            raise ValueError(f"Unknown transport: {transport}")
    finally:
        ctx.close()


if __name__ == "__main__":
    main()
