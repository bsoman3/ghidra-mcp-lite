"""
Lightweight Ghidra MCP server.

Native Ghidra tools only — no ChromaDB, no ML/embedding.
Transports: stdio and streamable-http (MCP Python SDK 2.x).
"""

import logging
import sys
from collections.abc import AsyncIterator, Iterator
from contextlib import ExitStack, asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any, Literal

import click
import pyghidra
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from ghidra_mcp import __version__, gui
from ghidra_mcp.context import AnalysisOptions, GhidraContext
from ghidra_mcp.errors import STOP, Stop, classify, describe
from ghidra_mcp.models import (
    BytesReadResult,
    CallGraphDirection,
    CallGraphDisplayType,
    CallGraphResult,
    CrossReferenceInfos,
    CurrentAddress,
    CurrentFunction,
    DataflowResult,
    DataItems,
    DecompiledFunction,
    DisassemblyResult,
    ExportInfos,
    FunctionCallees,
    FunctionCallers,
    FunctionDiff,
    FunctionInfo,
    FunctionList,
    FunctionPcode,
    ImportInfos,
    MemorySegments,
    NamespaceList,
    ProgramInfo,
    ProgramInfos,
    SimilarFunctions,
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
async def _lifespan(server: MCPServer) -> AsyncIterator[GhidraContext]:
    try:
        yield server._ghidra_context  # type: ignore[attr-defined]
    finally:
        pass


_CATEGORY_TAGS = ("[fix_input]", "[retry_later]", "[stop]")
_SDK_PREFIX = "Error executing tool "


def _tag_sdk_message(text: str) -> str:
    """Add a recovery category to an error the SDK produced before or around a tool."""
    if any(tag in text for tag in _CATEGORY_TAGS):
        return text
    if text.startswith(_SDK_PREFIX):
        name, sep, detail = text[len(_SDK_PREFIX):].partition(": ")
        if sep:  # argument rejected against the tool's input schema
            return f"{_SDK_PREFIX}{name}: [fix_input] {detail}"
        return f"{text}: [{STOP}] Internal error; details are in the server log."
    return f"[fix_input] {text}"  # e.g. "Unknown tool: <name>"


# @spec SRV-042
async def _categorize_sdk_failures(ctx, call_next):
    """Middleware: give SDK-generated tool errors (unknown tool, bad arguments) a category too."""
    result = await call_next(ctx)
    if ctx.method == "tools/call" and isinstance(result, dict) and result.get("isError"):
        for block in result.get("content", []):
            if isinstance(block, dict) and block.get("type") == "text":
                block["text"] = _tag_sdk_message(block.get("text", ""))
                break
    return result


mcp = MCPServer("ghidra-mcp", lifespan=_lifespan, middleware=[_categorize_sdk_failures])


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


# @spec SRV-025, SRV-027, SRV-031, SRV-032, SRV-036
def _err(e: Exception) -> ToolError:
    """Convert a tool failure into a ToolError whose message starts with its recovery category.

    The SDK shows a ToolError's message to the model; an unexpected exception's text is
    withheld from the client and logged with its traceback instead.
    """
    if isinstance(e, ToolError):
        return e
    category = classify(e)
    if category is None:
        if not getattr(e, "_ghidra_mcp_logged", False):
            logger.error(f"Unexpected tool failure: {e!s}", exc_info=e)
        return ToolError(f"[{STOP}] Internal error; details are in the server log.")
    return ToolError(f"[{category}] {describe(e)}")


def _tools(ctx: Context, binary_name: str) -> GhidraTools:
    ghidra_ctx: GhidraContext = ctx.request_context.lifespan_context
    return GhidraTools(ghidra_ctx.get_program_info(binary_name))


# ─────────────────────────────────────────────────────────────────────────────
# Project management
# ─────────────────────────────────────────────────────────────────────────────


@mcp.tool()
def list_project_binaries(ctx: Context) -> ProgramInfos:
    """List every binary loaded in the active Ghidra project along with its analysis status.

    Includes binaries still being imported. Each entry has a status (importing, analyzing,
    ready, failed), the failure reason when failed, configuration warnings recorded during
    analysis, and Ghidra metadata. Use this first to discover binary names required by other
    tools.
    """
    # @spec SRV-021
    try:
        ghidra_ctx: GhidraContext = ctx.request_context.lifespan_context
        programs = [
            ProgramInfo(
                name=pi.name,
                file_path=str(pi.file_path) if pi.file_path else None,
                load_time=pi.load_time,
                analysis_complete=pi.analysis_complete,
                status=pi.status.value,
                failure=pi.failure,
                warnings=list(pi.warnings),
                metadata=dict(pi.metadata),
            )
            for pi in ghidra_ctx.list_entries()
        ]
        return ProgramInfos(programs=programs)
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
def list_project_binary_metadata(binary_name: str, ctx: Context) -> dict:
    """Retrieve detailed Ghidra metadata for a binary.

    Returns architecture, compiler, endianness, file hashes, function/symbol counts, etc.
    Available whether or not analysis has finished.

    Args:
        binary_name: Name of the binary (from list_project_binaries).
    """
    # @spec SRV-022
    try:
        ghidra_ctx: GhidraContext = ctx.request_context.lifespan_context
        return ghidra_ctx.get_metadata(binary_name)
    except Exception as e:
        raise _err(e) from e


# @spec SRV-023
@mcp.tool()
def import_binary(
    binary_path: str,
    ctx: Context,
    pdb_path: str | None = None,
    gdts: list[str] | None = None,
    analyzer_options: dict[str, Any] | None = None,
    no_symbols: bool = False,
) -> str:
    """Import a binary (or every file under a directory) and analyze it in the background.

    The analysis options apply to this binary only. list_project_binaries shows its status
    (importing, analyzing, ready, failed) and any configuration warnings.

    Args:
        binary_path: Absolute path to the binary file (or directory) to import.
        pdb_path: Path to a PDB file for this binary.
        gdts: Paths of GDT type archives to apply, in order.
        analyzer_options: Ghidra analysis options to set, as {option name: value},
            e.g. {"Decompiler Parameter ID": false}.
        no_symbols: Disable PDB symbol loading for this binary.
    """
    try:
        ghidra_ctx: GhidraContext = ctx.request_context.lifespan_context
        options = AnalysisOptions.create(
            no_symbols=no_symbols, pdb_path=pdb_path, gdts=gdts, analyzer_options=analyzer_options
        )
        queued, existing = ghidra_ctx.import_binary_backgrounded(binary_path, options)
        parts = []
        if queued:
            parts.append(f"Importing '{binary_path}' in the background as {', '.join(queued)}.")
        if existing:
            parts.append(
                f"Already in the project, not re-imported: {', '.join(existing)}. Its stored "
                "analysis options are unchanged; use reanalyze_binary to change them."
            )
        parts.append("Use list_project_binaries to check analysis status.")
        return " ".join(parts)
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
        raise Stop(f"Could not delete '{binary_name}'; see the server log for details.")
    except Exception as e:
        raise _err(e) from e


# @spec SRV-044
@mcp.tool()
def reanalyze_binary(
    binary_name: str,
    ctx: Context,
    pdb_path: str | None = None,
    gdts: list[str] | None = None,
    analyzer_options: dict[str, Any] | None = None,
    no_symbols: bool = False,
) -> str:
    """Re-run Ghidra analysis of one binary in the background, with new analysis options.

    The options replace the binary's previous ones (omitted options revert to defaults).
    Also recovers a binary whose analysis failed. Refused while the binary is still being
    imported or analyzed.

    Args:
        binary_name: Name of the binary (from list_project_binaries).
        pdb_path: Path to a PDB file for this binary.
        gdts: Paths of GDT type archives to apply, in order.
        analyzer_options: Ghidra analysis options to set, as {option name: value}.
        no_symbols: Disable PDB symbol loading for this binary.
    """
    try:
        ghidra_ctx: GhidraContext = ctx.request_context.lifespan_context
        options = AnalysisOptions.create(
            no_symbols=no_symbols, pdb_path=pdb_path, gdts=gdts, analyzer_options=analyzer_options
        )
        ghidra_ctx.reanalyze_binary(binary_name, options)
        return (
            f"Re-analyzing '{binary_name}' in the background. "
            "Use list_project_binaries to check its status."
        )
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
    """List the binary's own functions (no externals or thunks) with addresses and signatures.

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

    An item that can't be read is listed in 'failures', and the result is marked 'partial'.

    Args:
        binary_name: Name of the binary.
        offset: Number of results to skip (pagination).
        limit: Maximum number of results to return.
    """
    try:
        return _tools(ctx, binary_name).list_data_items(offset=offset, limit=limit)
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
    operands, and any EOL comments. A field that can't be read is left empty and named in
    that instruction's 'errors', and the result is marked 'partial'.
    If no function's name matches exactly, a unique partial name match (or an address
    inside a function) is used, and the result's 'resolution' field says so. Otherwise the
    error lists the candidates.

    Args:
        binary_name: Name of the binary.
        name_or_address: Function name (case-insensitive) or hex address.
    """
    try:
        return _tools(ctx, binary_name).disassemble_function(name_or_address)
    except Exception as e:
        raise _err(e) from e


# @spec SRV-038
@mcp.tool()
def decompile_function(
    binary_name: str, name_or_address: str, ctx: Context
) -> DecompiledFunction:
    """Decompile a function and return its pseudo-C source code.

    Decompilation is limited to 120 seconds; a decompiler failure or timeout is an error.
    If no function's name matches exactly, a unique partial name match (or an address
    inside a function) is used, and the result's 'resolution' field says so. Otherwise the
    error lists the candidates.

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
    limit: int = 100,
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
    query: str | None = None,
    offset: int = 0,
    limit: int = 25,
) -> ImportInfos:
    """List external functions and symbols imported by a binary.

    Args:
        binary_name: Name of the binary.
        query: Optional case-insensitive regex to filter import names (e.g. 'socket' or 'mem.*').
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
    query: str | None = None,
    offset: int = 0,
    limit: int = 25,
) -> ExportInfos:
    """List a binary's entry points: its exported functions and symbols and the program entry
    (Ghidra's external entry points).

    Args:
        binary_name: Name of the binary.
        query: Optional case-insensitive regex to filter export names.
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

    Useful for finding callers, data consumers, and jump targets. A hex address is used as
    is. Otherwise the target is the symbol whose name matches exactly, or the one symbol whose
    name contains the query (reported in the 'resolution' field); if several match, the error
    lists them. Each result's function_name is the function containing the reference's source.

    Args:
        binary_name: Name of the binary.
        name_or_address: Function/symbol name or hex address to find references to.
    """
    try:
        return _tools(ctx, binary_name).list_cross_references(name_or_address)
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
def get_xrefs_from(
    binary_name: str, address: str, ctx: Context
) -> CrossReferenceInfos:
    """Find all references FROM a given address (calls/jumps/data refs originating here).

    Complements list_cross_references which finds refs TO an address. Each result's
    function_name is the function containing the reference's target address (the source
    function is the same for every result).

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

    An empty query lists every defined string (up to limit).

    Uses Ghidra's native DefinedStringIterator — no ML model, no ChromaDB.
    The 'total' field shows how many matches exist even if limit was reached. A string that
    can't be read is listed in 'failures', and the result is marked 'partial'.

    Args:
        binary_name: Name of the binary.
        query: Case-insensitive substring to search for.
        limit: Maximum number of results to return (default: 100).
    """
    try:
        return _tools(ctx, binary_name).search_strings(query=query, limit=limit)
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
def read_bytes(
    binary_name: str, address: str, ctx: Context, size: int = 32
) -> BytesReadResult:
    """Read raw bytes from the binary's memory image at a given address.

    If the range runs past the end of memory, the bytes that exist are returned and the result
    is marked 'partial' (compare 'size' with 'requested_size'). Uninitialized memory is an error.

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

    Replaces any existing EOL comment there; empty text removes it. Changes are saved to the
    Ghidra project immediately.

    Args:
        binary_name: Name of the binary.
        address: Hex address (in the program's memory) where the comment should appear.
        comment: Comment text, or an empty string to remove the comment.
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

    Replaces any existing PRE comment there; empty text removes it. Changes are saved to the
    Ghidra project immediately.

    Args:
        binary_name: Name of the binary.
        address: Hex address (in the program's memory) where the comment should appear.
        comment: Comment text, or an empty string to remove the comment.
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
    """Rename the defined data at an address.

    The address must hold defined data. Its primary symbol is renamed, unless the data has
    no symbol or only a default one (e.g. DAT_00404010), in which case a label with the new
    name is created. Changes are saved immediately.

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


# @spec SRV-039
@mcp.tool()
def gen_callgraph(
    binary_name: str,
    function_name: str,
    ctx: Context,
    direction: CallGraphDirection = CallGraphDirection.CALLING,
    display_type: CallGraphDisplayType = CallGraphDisplayType.FLOW,
    include_refs: bool = True,
    max_depth: int | None = None,
    condense_threshold: int = 50,
    top_layers: int = 5,
    bottom_layers: int = 5,
    max_run_time: int = 60,
) -> CallGraphResult:
    """Generate a MermaidJS call graph for a function.

    If no function's name matches exactly, a unique partial name match (or an address
    inside a function) is used, and the result's 'resolution' field says so. Otherwise the
    error lists the candidates.

    Args:
        binary_name: Name of the binary.
        function_name: Name or hex address of the target function.
        direction: 'calling' = functions this one calls; 'called' = callers of this function.
        display_type: Graph layout: 'flow', 'flow_ends', or 'mind'.
        include_refs: Include non-call references as edges.
        max_depth: Maximum depth to display (unlimited when omitted).
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
            include_refs=include_refs,
            max_depth=max_depth,
            max_run_time=max_run_time,
            condense_threshold=condense_threshold,
            top_layers=top_layers,
            bottom_layers=bottom_layers,
        )
    except Exception as e:
        raise _err(e) from e


# ─────────────────────────────────────────────────────────────────────────────
# Call relations, comparison, p-code, and data flow
# ─────────────────────────────────────────────────────────────────────────────


# @spec QRY-052
@contextmanager
def _locked(*entries) -> Iterator[None]:
    """Hold the programs' locks, taken in pathname order so that two-binary calls can't deadlock."""
    unique = {entry.pathname: entry for entry in entries}
    with ExitStack() as stack:
        for pathname in sorted(unique):
            stack.enter_context(unique[pathname].lock)
        yield


@mcp.tool()
def get_function_callers(binary_name: str, name_or_address: str, ctx: Context) -> FunctionCallers:
    """List the functions that call a function, including calls through its thunks.

    Each caller appears once with its call-site addresses; call sites outside any function
    are grouped without a name.

    Args:
        binary_name: Name of the binary.
        name_or_address: Function name or hex address (a unique partial name is used and reported).
    """
    try:
        return _tools(ctx, binary_name).get_function_callers(name_or_address)
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
def get_function_callees(binary_name: str, name_or_address: str, ctx: Context) -> FunctionCallees:
    """List the functions a function calls, with call sites; thunks name the function they
    forward to, and unresolved indirect calls are listed separately.

    Args:
        binary_name: Name of the binary.
        name_or_address: Function name or hex address (a unique partial name is used and reported).
    """
    try:
        return _tools(ctx, binary_name).get_function_callees(name_or_address)
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
def diff_functions(
    binary_name: str,
    function_a: str,
    function_b: str,
    ctx: Context,
    other_binary_name: str | None = None,
    view: Literal["decompiled", "disassembly"] = "decompiled",
    normalize: bool = True,
    context_lines: int = 3,
) -> FunctionDiff:
    """Compare two functions as a unified diff, in one binary or across two.

    With normalize (the default), Ghidra's address-derived names (FUN_…, DAT_…, LAB_…),
    long hex literals, and the functions' own names are masked, so copies of the same code
    at other addresses compare as identical.

    Args:
        binary_name: Binary containing function_a (and function_b unless other_binary_name is given).
        function_a: First function, by name or hex address.
        function_b: Second function, by name or hex address.
        other_binary_name: Binary containing function_b, if different.
        view: 'decompiled' (C, the default) or 'disassembly'.
        normalize: Mask address-derived names and literals before comparing.
        context_lines: Lines of context in the diff.
    """
    try:
        ghidra_ctx: GhidraContext = ctx.request_context.lifespan_context
        first = ghidra_ctx.get_program_info(binary_name)
        second = ghidra_ctx.get_program_info(other_binary_name) if other_binary_name else first
        with _locked(first, second):
            other = GhidraTools(second) if second is not first else None
            return GhidraTools(first).diff_functions(function_a, function_b, other=other, view=view,
                                                     normalize=normalize, context_lines=context_lines)
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
def find_similar_functions_fuzzy(
    binary_name: str,
    name_or_address: str,
    ctx: Context,
    target_binary_name: str | None = None,
    limit: int = 10,
    min_similarity: float = 0.5,
) -> SimilarFunctions:
    """Find functions similar to a given one, in the same binary or another.

    Similarity is the multiset Jaccard index of instruction-mnemonic 3-grams (operands
    ignored), so it tolerates different addresses, registers, and small edits. Candidates
    are limited to functions within half to double the query's size.

    Args:
        binary_name: Binary containing the query function.
        name_or_address: Query function, by name or hex address.
        target_binary_name: Binary to search (default: the same binary).
        limit: Maximum number of matches.
        min_similarity: Minimum similarity, 0 to 1.
    """
    try:
        ghidra_ctx: GhidraContext = ctx.request_context.lifespan_context
        source = ghidra_ctx.get_program_info(binary_name)
        target = ghidra_ctx.get_program_info(target_binary_name) if target_binary_name else source
        with _locked(source, target):
            other = GhidraTools(target) if target is not source else None
            return GhidraTools(source).find_similar_functions_fuzzy(
                name_or_address, target=other, limit=limit, min_similarity=min_similarity)
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
def get_function_pcode(
    binary_name: str,
    name_or_address: str,
    ctx: Context,
    form: Literal["raw", "high"] = "raw",
    max_ops: int = 2000,
) -> FunctionPcode:
    """Get a function's p-code: per-instruction ('raw') or the decompiler's ('high').

    At most max_ops operations are returned (1–20000); 'truncated' and 'total_ops' show
    whether more exist.

    Args:
        binary_name: Name of the binary.
        name_or_address: Function name or hex address.
        form: 'raw' (the default) or 'high'.
        max_ops: Maximum operations to return.
    """
    try:
        return _tools(ctx, binary_name).get_function_pcode(name_or_address, form=form, max_ops=max_ops)
    except Exception as e:
        raise _err(e) from e


@mcp.tool()
def analyze_dataflow(
    binary_name: str,
    function_name_or_address: str,
    variable: str,
    ctx: Context,
    direction: Literal["backward", "forward"] = "backward",
    max_ops: int = 500,
) -> DataflowResult:
    """Trace data flow for a decompiler variable: what contributes to it ('backward') or
    what it influences ('forward').

    Returns the high p-code operations in the slice, by address, and the variables they
    touch. The variable name must match the decompiler output exactly (e.g. param_1,
    local_10, iVar2); an unknown name lists the available ones.

    Args:
        binary_name: Name of the binary.
        function_name_or_address: Function name or hex address.
        variable: Decompiler variable name.
        direction: 'backward' (the default) or 'forward'.
        max_ops: Maximum operations to return (1–5000).
    """
    try:
        return _tools(ctx, binary_name).analyze_dataflow(function_name_or_address, variable,
                                                         direction=direction, max_ops=max_ops)
    except Exception as e:
        raise _err(e) from e


# ─────────────────────────────────────────────────────────────────────────────
# GUI-only tools (registered by register_gui_tools in GUI mode)
# ─────────────────────────────────────────────────────────────────────────────


def get_current_address(ctx: Context) -> CurrentAddress:
    """GUI mode only. Where the analyst's cursor is in Ghidra's CodeBrowser.

    Returns the binary open in the most recently focused CodeBrowser, the cursor's address,
    and the name of the function containing it (if any).
    """
    try:
        ghidra_ctx: gui.GuiGhidraContext = ctx.request_context.lifespan_context
        return CurrentAddress(**ghidra_ctx.current_location())
    except Exception as e:
        raise _err(e) from e


def get_current_function(ctx: Context) -> CurrentFunction:
    """GUI mode only. The function containing the analyst's cursor in Ghidra's CodeBrowser.

    Fails if the cursor is not inside a function.
    """
    try:
        ghidra_ctx: gui.GuiGhidraContext = ctx.request_context.lifespan_context
        binary, func = ghidra_ctx.current_function()
        return CurrentFunction(
            binary_name=binary,
            function=FunctionInfo(
                name=str(func.getName(True)),
                address=str(func.getEntryPoint()),
                signature=str(func.getSignature()),
                external=bool(func.isExternal()),
            ),
        )
    except Exception as e:
        raise _err(e) from e


def go_to(binary_name: str, name_or_address: str, ctx: Context) -> str:
    """GUI mode only. Show a location in Ghidra's CodeBrowser: makes the binary the current
    program and moves the cursor there.

    Args:
        binary_name: Name of the binary.
        name_or_address: Hex address, or a symbol or function name (a unique partial name is
            used and reported).
    """
    try:
        ghidra_ctx: gui.GuiGhidraContext = ctx.request_context.lifespan_context
        return ghidra_ctx.go_to(binary_name, name_or_address)
    except Exception as e:
        raise _err(e) from e


GUI_TOOLS = (get_current_address, get_current_function, go_to)


# @spec GUI-026
def register_gui_tools() -> None:
    """Register the GUI-only tools; called only in GUI mode."""
    for fn in GUI_TOOLS:
        mcp.add_tool(fn)


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-v", "--version")
# Transport
# @spec SRV-002
@click.option(
    "-t", "--transport",
    type=click.Choice(["stdio", "streamable-http"], case_sensitive=False),
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
# Analysis (per-binary options are import_binary / reanalyze_binary arguments)
# @spec SRV-008, SRV-043
@click.option(
    "--wait-for-analysis/--no-wait-for-analysis", default=True, show_default=True,
    help="Let tool calls for a binary still being analyzed wait up to 45 s before "
         "returning retry_later. Startup never blocks.",
)
@click.option("--verbose-analysis/--no-verbose-analysis", default=False, show_default=True,
              help="Verbose Ghidra analysis logging.")
@click.option("--symbols-path", type=click.Path(), default=None,
              help="Path to local symbol store directory.")
# Project management (exits after running)
@click.option("--list-project-binaries", is_flag=True,
              help="Print all binaries in the project and exit.")
@click.option("--delete-project-binary", type=str, default=None,
              help="Delete a binary from the project by name and exit.")
@click.option("--analyze-only", is_flag=True,
              help="Import inputs, analyze every binary to completion, report each status, "
                   "and exit (non-zero if any binary failed).")
@click.option("--gui", "gui_mode", is_flag=True,
              help="GUI mode: open the Ghidra GUI in this process and serve over streamable HTTP "
                   "alongside it; tool edits appear live and are left for you to save.")
@click.argument("input_paths", type=click.Path(exists=True), nargs=-1)
def main(
    transport: str,
    port: int,
    host: str,
    project_path: Path,
    project_name: str,
    wait_for_analysis: bool,
    verbose_analysis: bool,
    symbols_path: str | None,
    list_project_binaries: bool,
    delete_project_binary: str | None,
    analyze_only: bool,
    gui_mode: bool,
    input_paths: tuple[str, ...],
) -> None:
    """Lightweight Ghidra MCP server — native Ghidra tools, no ML/embedding.

    \b
    input_paths  Binaries to import and analyze on startup (optional).

    \b
    Examples:
      # Import and serve a binary over stdio:
      ghidra-mcp /path/to/binary

      # Serve over HTTP for remote clients (tool calls wait up to 45 s for analysis):
      ghidra-mcp --transport streamable-http --host 0.0.0.0 /path/to/binary

      # Pre-analyze a large binary once, then serve instantly on later starts:
      ghidra-mcp --analyze-only /path/to/binary

      # List binaries in an existing project:
      ghidra-mcp --project-path ./myproject --list-project-binaries

      # GUI mode: watch and steer the agent in Ghidra's GUI (serves on http://127.0.0.1:8000/mcp):
      ghidra-mcp --gui --project-path ~/ghidra_projects /path/to/binary
    """
    # @spec SRV-050: Ghidra rejects path elements starting with "." (such as ".."), and MCP
    # client configs pass "~" unexpanded.
    project_path = project_path.expanduser().resolve()
    # @spec SRV-051
    if project_path.suffix.lower() == ".rep":
        raise click.UsageError(
            f"{project_path} is a Ghidra project's data folder; pass the project file instead: "
            f"--project-path {project_path.with_suffix('.gpr')}"
        )

    # Handle .gpr file paths
    if project_path.suffix.lower() == ".gpr":
        project_dir = str(project_path.parent)
        project_name = project_path.stem
    else:
        project_dir = str(project_path)

    # @spec SRV-045, GUI-001, GUI-002, GUI-003
    if gui_mode:
        click_ctx = click.get_current_context()
        explicit_transport = click_ctx.get_parameter_source("transport") != click.core.ParameterSource.DEFAULT
        if transport == "stdio" and explicit_transport:
            raise click.UsageError("--gui serves over streamable-http; the stdio transport is not available.")
        for flag, given in (("--analyze-only", analyze_only), ("--list-project-binaries", list_project_binaries),
                            ("--delete-project-binary", delete_project_binary)):
            if given:
                raise click.UsageError(f"{flag} cannot be combined with --gui.")
        try:
            gui.check_port(host, port)
        except OSError as e:
            click.echo(f"Error: cannot serve on {host}:{port}: {e}", err=True)
            sys.exit(1)
        gui.ensure_project(project_dir, project_name)
        gui.launch(
            project_dir=project_dir, project_name=project_name, input_paths=input_paths, host=host,
            port=port, wait_for_analysis=wait_for_analysis, verbose_analysis=verbose_analysis,
            symbols_path=symbols_path,
        )
        return

    pyghidra.start(verbose_analysis)

    ctx = GhidraContext(
        project_name=project_name,
        project_path=project_dir,
        verbose_analysis=verbose_analysis,
        wait_for_analysis=wait_for_analysis,
        symbols_path=symbols_path,
    )

    # One-shot management commands
    # @spec SRV-009, SRV-033
    if list_project_binaries:
        try:
            bins = ctx.list_binaries()
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            ctx.close()
            sys.exit(1)
        if bins:
            for name in bins:
                click.echo(f"- {name}")
        else:
            click.echo("No binaries in project.")
        ctx.close()
        return

    # @spec SRV-010, SRV-011, SRV-012, SRV-033
    if delete_project_binary:
        try:
            deleted = ctx.delete_program(delete_project_binary)
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            ctx.close()
            sys.exit(1)
        ctx.close()
        if not deleted:
            click.echo(
                f"Error: could not delete '{delete_project_binary}'; see the log for details.",
                err=True,
            )
            sys.exit(1)
        click.echo(f"Deleted: {delete_project_binary}")
        return

    # Import any binaries provided on the command line
    if input_paths:
        logger.info(f"Importing {len(input_paths)} binary/binaries...")
        ctx.import_binaries([Path(p) for p in input_paths])

    # @spec SRV-035, SRV-033
    if analyze_only:
        ctx.analyze_project(wait=True)
        any_failed = False
        for pi in ctx.list_entries():
            if pi.analysis_complete:
                click.echo(f"{pi.name}: ready")
            else:
                any_failed = True
                click.echo(f"{pi.name}: failed ({pi.failure or pi.status.value})")
        ctx.close()
        if any_failed:
            sys.exit(1)
        return

    # @spec SRV-014: analysis runs in the background; the handshake is never delayed.
    ctx.analyze_project()

    # Attach context to the server instance (read by _lifespan)
    mcp._ghidra_context = ctx  # type: ignore[attr-defined]

    logger.info(f"Starting server (transport={transport}, host={host}, port={port})")

    # @spec SRV-015
    try:
        if transport == "stdio":
            mcp.run(transport="stdio")
        else:
            mcp.run(transport="streamable-http", host=host, port=port)
    finally:
        ctx.close()


if __name__ == "__main__":
    main()
