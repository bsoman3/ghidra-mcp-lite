"""
Native Ghidra tool implementations.
No ChromaDB, no ML/embedding — all search uses Ghidra's own iterators and APIs.
"""

import contextlib
import difflib
import functools
import logging
import re
import typing
from collections import Counter
from dataclasses import dataclass
from enum import Enum

from jpype import JByte

from ghidra_mcp.errors import STOP, Stop, classify
from ghidra_mcp.models import (
    BytesReadResult,
    CallGraphDirection,
    CallRelation,
    DataflowResult,
    FunctionCallees,
    FunctionCallers,
    FunctionDiff,
    FunctionPcode,
    PcodeOpInfo,
    SimilarFunction,
    SimilarFunctions,
    CallGraphDisplayType,
    CallGraphResult,
    CrossReferenceInfo,
    CrossReferenceInfos,
    DataItem,
    DataItems,
    DecompiledFunction,
    DisassemblyLine,
    DisassemblyResult,
    ExportInfo,
    FunctionInfo,
    ImportInfo,
    ItemFailure,
    MemorySegment,
    MemorySegments,
    NamespaceInfo,
    NamespaceList,
    StringInfo,
    StringSearchResults,
    SymbolInfo,
)

if typing.TYPE_CHECKING:
    from ghidra.app.decompiler import DecompileResults
    from ghidra.program.model.listing import Function
    from ghidra.program.model.symbol import Symbol

    from ghidra_mcp.context import LoadedProgram

logger = logging.getLogger(__name__)

T = typing.TypeVar("T")

# Upper bound on one decompile_function call; a timeout is reported as a decompiler failure.
DECOMPILE_TIMEOUT_SECONDS = 120
# Largest page list_functions returns; callers page through more with offset.
MAX_FUNCTION_PAGE = 500
MAX_PCODE_OPS = 20000
MAX_DATAFLOW_OPS = 5000
SIMILARITY_METHOD = "multiset Jaccard of instruction-mnemonic 3-grams (operands ignored), size-prefiltered"

_AUTO_NAME = re.compile(r"\b(FUN|DAT|LAB|PTR|switchD)_[0-9a-fA-F]+\b")
_AUTO_STRING = re.compile(r"\b([su])_\w*?[0-9a-fA-F]{4,}\b")
_HEX_LITERAL = re.compile(r"\b0x[0-9a-fA-F]{4,}\b")


# @spec QRY-043
def normalize_listing(text: str, own_names: typing.Iterable[str] = ()) -> str:
    """Mask what differs between copies of the same code at other addresses or in other
    binaries: the function's own names, Ghidra's address-derived default names, and long
    hexadecimal literals."""
    for name in sorted({n for n in own_names if n}, key=len, reverse=True):
        text = re.sub(rf"(?<![\w:]){re.escape(name)}(?!\w)", "<self>", text)
    text = _AUTO_NAME.sub(lambda m: f"{m.group(1)}_*", text)
    text = _AUTO_STRING.sub(lambda m: f"{m.group(1)}_*", text)
    return _HEX_LITERAL.sub("0x*", text)


# @spec QRY-044
def diff_texts(a: str, b: str, label_a: str, label_b: str, context_lines: int) -> tuple[str, float, bool]:
    """Unified diff, line-level similarity ratio, and identity of two texts."""
    a_lines, b_lines = a.splitlines(), b.splitlines()
    diff = "\n".join(difflib.unified_diff(a_lines, b_lines, fromfile=label_a, tofile=label_b,
                                          n=context_lines, lineterm=""))
    ratio = round(difflib.SequenceMatcher(None, a_lines, b_lines, autojunk=False).ratio(), 3)
    return diff, ratio, a_lines == b_lines


# @spec QRY-045
def mnemonic_grams(mnemonics: typing.Sequence[str]) -> Counter:
    """The multiset of 3-grams of a mnemonic sequence (a shorter sequence is one gram)."""
    seq = [str(m) for m in mnemonics]
    if len(seq) < 3:
        return Counter({tuple(seq): 1}) if seq else Counter()
    return Counter(tuple(seq[i:i + 3]) for i in range(len(seq) - 2))


def multiset_jaccard(a: Counter, b: Counter) -> float:
    keys = a.keys() | b.keys()
    largest = sum(max(a[k], b[k]) for k in keys)
    return round(sum(min(a[k], b[k]) for k in keys) / largest, 4) if largest else 0.0


# @spec QRY-046
def rank_similar(query_count: int, query_grams: Counter, candidates, *, limit: int, min_similarity: float,
                 order: typing.Callable[[typing.Any], typing.Any] | None = None) -> list[tuple]:
    """(key, instruction count, score) for candidates within half to double the query's size
    and scoring at least min_similarity, highest first, ties by order(key)."""
    scored = []
    for key, count, grams in candidates:
        if not (query_count / 2 <= count <= query_count * 2):
            continue
        score = multiset_jaccard(query_grams, grams)
        if score >= min_similarity:
            scored.append((key, count, score))
    scored.sort(key=lambda t: (-t[2], order(t[0]) if order else t[0]))
    return scored[:limit]


def _check_max_ops(max_ops: int, ceiling: int) -> None:
    if not 1 <= max_ops <= ceiling:
        raise ValueError(f"max_ops must be between 1 and {ceiling}, not {max_ops}.")


class ResolutionMode(str, Enum):
    """Read tools may accept a unique loose match and disclose it; write tools need an exact one."""

    READ = "read"
    WRITE = "write"


@dataclass(frozen=True)
class Resolved(typing.Generic[T]):
    """A resolved target, with a disclosure note when read mode accepted a loose match."""

    target: T
    note: str | None = None


# @spec SRV-028, LIFE-041
def handle_exceptions(func):
    """Run a GhidraTools method under its program's lock; log a failure once, at a level
    matching its recovery category, and re-raise."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        program_info = getattr(args[0], "program_info", None) if args else None
        lock = getattr(program_info, "lock", None)
        try:
            with lock if lock is not None else contextlib.nullcontext():
                return func(*args, **kwargs)
        except Exception as e:
            if getattr(e, "_ghidra_mcp_logged", False):
                raise
            category = classify(e)
            if category is None:
                logger.error(f"Error in {func.__name__}: {e!s}", exc_info=e)
            elif category == STOP:
                logger.warning(f"Error in {func.__name__}: {e!s}")
            else:
                logger.debug(f"Error in {func.__name__}: {e!s}")
            try:
                e._ghidra_mcp_logged = True  # type: ignore[attr-defined]
            except Exception:
                pass  # some exception types (e.g. Java proxies) reject new attributes
            raise

    return wrapper


class GhidraTools:
    """All native Ghidra tool implementations."""

    def __init__(self, program_info: "LoadedProgram"):
        self.program_info = program_info
        self.program = program_info.program
        self.project = program_info.project
        self.decompiler = program_info.decompiler

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _func_label(self, func: "Function") -> str:
        return f"{func.getSymbol().getName(True)}-{func.entryPoint}"

    @staticmethod
    def _error_text(e: Exception) -> str:
        message = e.getMessage() if hasattr(e, "getMessage") else None
        return str(message or e) or type(e).__name__

    def _parse_address(self, address: str):
        """Parse a hex address string (with or without 0x prefix) into a Ghidra Address."""
        af = self.program.getAddressFactory()
        addr_str = address[2:] if address.lower().startswith("0x") else address
        try:
            addr = af.getAddress(addr_str)
        except Exception as e:
            raise ValueError(f"Invalid address '{address}': {e}") from e
        if addr is None:
            raise ValueError(f"Invalid address: {address}")
        return addr

    # @spec WB-001, WB-002, WB-003, WB-022
    def _with_transaction(self, description: str, body: typing.Callable) -> typing.Any:
        """
        Run body() inside a Ghidra transaction.
        On success: commit and save to the project. A save failure raises Stop, saying the
        edit is applied in memory but not saved.
        On failure (body raises): roll back.
        In GUI mode the program's mutation runner applies the change instead (gui-host).
        """
        runner = getattr(self.program_info, "mutation_runner", None)
        if runner is not None:  # @spec WB-028
            return runner(self.program, description, body)
        tx = self.program.startTransaction(description)
        ok = False
        try:
            result = body()
            ok = True
        finally:
            self.program.endTransaction(tx, ok)
        try:
            self.project.save(self.program)
        except Exception as e:
            raise Stop(
                f"{description}: the edit is applied in memory but not saved to the project: "
                f"{self._error_text(e)}"
            ) from e
        return result

    # @spec RES-014, RES-015, RES-023, RES-024
    def _resolve_data_type(self, type_str: str):
        """
        Resolve a C type string to a Ghidra DataType.
        Tries a data-type-manager lookup, then CParser for declarations such as pointers,
        then a scan by name that must match exactly one type.
        """
        from ghidra.app.util.cparser.C import CParser

        dtm = self.program.getDataTypeManager()

        # Direct lookup by path (e.g. "/int", "/winnt.h/HANDLE")
        dt = dtm.getDataType(type_str)
        if dt is not None:
            return dt

        # CParser handles "char *", "unsigned int", "struct Foo *", etc.
        parser = CParser(dtm)
        try:
            parsed = parser.parse(type_str + " __x;")
        except Exception:
            parsed = False  # not a declaration CParser understands; try the name scan
        if parsed is None:
            raise ValueError(f"Cannot resolve data type: '{type_str}' (the declaration names no type)")
        if parsed is not False:
            return parsed

        # Last resort: the one data type with this name, in any category
        matches = [dt for dt in dtm.getAllDataTypes() if dt.getName() == type_str]
        if len(matches) == 1:
            return matches[0]
        if matches:
            paths = ", ".join(dt.getPathName() for dt in matches)
            raise ValueError(f"Ambiguous data type '{type_str}'. Did you mean: {paths}")
        raise ValueError(f"Cannot resolve data type: '{type_str}'")

    # -------------------------------------------------------------------------
    # Function resolution
    # -------------------------------------------------------------------------

    def _try_address(self, text: str):
        """The address a string parses as, or None. Ghidra accepts an optional 0x prefix."""
        try:
            return self.program.getAddressFactory().getAddress(text)
        except Exception:
            return None

    @staticmethod
    def _function_label(func: "Function") -> str:
        return f"{func.getSymbol().getName(True)} @ {func.getEntryPoint()}"

    @staticmethod
    def _same_function(a: "Function", b: "Function") -> bool:
        return str(a.getEntryPoint()) == str(b.getEntryPoint())

    # @spec RES-003, RES-004, RES-005, RES-006, RES-007, RES-018, RES-020, RES-021, RES-022, RES-025
    @handle_exceptions
    def resolve_function(self, name_or_address: str, mode: ResolutionMode) -> Resolved["Function"]:
        """
        Resolve a function from an address or a name (namespace-qualified, case-insensitive).

        Both interpretations are considered; if they lead to different functions, the call
        fails listing both. Read mode also accepts a unique partial name match or an address
        inside a function, and discloses it in the note. Write mode accepts only an exact name
        or an entry-point address, and refuses thunks and external functions.
        """
        fm = self.program.getFunctionManager()
        query = name_or_address
        query_lc = query.lower()

        addr = self._try_address(query)
        at = fm.getFunctionAt(addr) if addr is not None else None
        containing = None
        if addr is not None and at is None:
            containing = fm.getFunctionContaining(addr)
        by_address = at or containing

        functions = self.get_all_functions(include_externals=True)
        exact = [f for f in functions if f.getSymbol().getName(True).lower() == query_lc]
        partial = [] if exact else [
            f for f in functions if query_lc in f.getSymbol().getName(True).lower()
        ]
        by_name, partial_match = None, False
        if len(exact) == 1:
            by_name = exact[0]
        elif not exact and len(partial) == 1 and mode is ResolutionMode.READ:
            by_name, partial_match = partial[0], True

        if by_address is not None and by_name is not None and not self._same_function(by_address, by_name):
            where = "is the entry of" if at is not None else "lies inside"
            raise ValueError(
                f"'{query}' is both an address and a name: address {addr} {where} "
                f"{self._function_label(by_address)}, and the name matches "
                f"{self._function_label(by_name)}. Pass the entry address of the one you mean."
            )

        if at is not None:
            resolved = Resolved(at)
        elif containing is not None:
            if mode is ResolutionMode.READ:
                resolved = Resolved(
                    containing,
                    f"'{query}' resolved to {self._function_label(containing)} "
                    "(address inside the function)",
                )
            elif by_name is not None:  # the exact name names the same function
                resolved = Resolved(by_name)
            else:
                raise ValueError(
                    f"Write tools need a function's entry-point address; {addr} lies inside "
                    f"{self._function_label(containing)}."
                )
        elif by_name is not None:
            note = None
            if partial_match:
                note = f"'{query}' resolved to {self._function_label(by_name)} (partial name match)"
            resolved = Resolved(by_name, note)
        elif len(exact) > 1:
            hints = ", ".join(self._function_label(f) for f in exact)
            raise ValueError(f"Ambiguous match for '{query}'. Did you mean: {hints}")
        elif partial:
            hints = ", ".join(self._function_label(f) for f in partial)
            raise ValueError(f"Function '{query}' not found. Did you mean: {hints}")
        elif addr is not None and mode is ResolutionMode.WRITE:
            raise ValueError(
                f"Function '{query}' not found: no function's name matches, and write tools need "
                f"a function's entry-point address, but no function starts at {addr}."
            )
        else:
            raise ValueError(f"Function '{query}' not found.")

        if mode is ResolutionMode.WRITE:
            self._refuse_thunk_or_external(query, resolved.target)
        return resolved

    def _refuse_thunk_or_external(self, query: str, func: "Function") -> None:
        if func.isThunk():
            target = func.getThunkedFunction(True)
            target_label = self._function_label(target) if target is not None else "an unknown function"
            raise ValueError(
                f"'{query}' is a thunk for {target_label}; write tools don't act on thunks. "
                "Target the thunked function instead."
            )
        if func.isExternal():
            raise ValueError(
                f"'{query}' is an external function ({self._function_label(func)}) with no body "
                "in this program; write tools don't act on external functions."
            )

    @handle_exceptions
    def find_function(self, name_or_address: str) -> "Function":
        """Resolve a function for a write tool: exact matches only (resolution's write mode)."""
        return self.resolve_function(name_or_address, ResolutionMode.WRITE).target

    # -------------------------------------------------------------------------
    # Symbol resolution
    # -------------------------------------------------------------------------

    def _symbols_by_name(self) -> list["Symbol"]:
        return self.get_all_symbols(include_externals=True, include_dynamic=True)

    @staticmethod
    def _symbol_label(sym: "Symbol") -> str:
        return f"{sym.getName(True)} @ {sym.getAddress()}"

    @staticmethod
    def _by_address(symbols: list["Symbol"]) -> dict[str, "Symbol"]:
        """One representative symbol per address, in order."""
        grouped: dict[str, "Symbol"] = {}
        for sym in symbols:
            grouped.setdefault(str(sym.getAddress()), sym)
        return grouped

    # @spec RES-008, RES-009, RES-010, RES-011, RES-012, RES-019, RES-022, RES-026
    @handle_exceptions
    def resolve_reference_target(self, name_or_address: str) -> Resolved[typing.Any]:
        """
        Resolve the target address of a cross-reference lookup.

        A string that parses as an address in the program (in memory, or with symbols defined
        there) is its own target, however many symbols are defined there. Otherwise the target
        is the address of the one symbol (dynamic and external ones included) whose qualified
        name equals the query case-insensitively, or, disclosed, the one whose name contains it.
        If the address and a name lead to different targets, the call fails listing both.
        """
        query = name_or_address
        query_lc = query.lower()
        st = self.program.getSymbolTable()

        addr = self._try_address(query)
        if addr is not None and not (
            self.program.getMemory().contains(addr) or list(st.getSymbols(addr))
        ):
            addr = None

        symbols = self._symbols_by_name()
        exact = self._by_address([s for s in symbols if s.getName(True).lower() == query_lc])
        partial = {} if exact else self._by_address(
            [s for s in symbols if query_lc in s.getName(True).lower()]
        )
        by_name, partial_match = None, False
        if len(exact) == 1:
            by_name = next(iter(exact.values()))
        elif not exact and len(partial) == 1:
            by_name, partial_match = next(iter(partial.values())), True

        if addr is not None and by_name is not None and str(by_name.getAddress()) != str(addr):
            raise ValueError(
                f"'{query}' is both an address and a name: address {addr}, and the name matches "
                f"{self._symbol_label(by_name)}. Pass the address you mean."
            )
        if addr is not None:
            return Resolved(addr)
        if by_name is not None:
            note = None
            if partial_match:
                note = f"'{query}' resolved to {self._symbol_label(by_name)} (partial name match)"
            return Resolved(by_name.getAddress(), note)
        if len(exact) > 1:
            hints = ", ".join(self._symbol_label(s) for s in exact.values())
            raise ValueError(f"Ambiguous match for '{query}'. Did you mean: {hints}")
        if partial:
            hints = ", ".join(self._symbol_label(s) for s in partial.values())
            raise ValueError(f"Symbol '{query}' not found. Did you mean: {hints}")
        raise ValueError(f"Symbol '{query}' not found.")

    # @spec RES-013
    def _lookup_symbols(self, query: str) -> list["Symbol"]:
        """Symbols for a search: those whose qualified name equals or contains the query
        (case-insensitively), external and dynamic ones included, plus every symbol defined
        at the query's address when it parses as one."""
        query_lc = query.lower()
        found: list["Symbol"] = []
        addr = self._try_address(query)
        if addr is not None:
            found.extend(self.program.getSymbolTable().getSymbols(addr))
        found.extend(s for s in self._symbols_by_name() if query_lc in s.getName(True).lower())

        unique: dict[tuple[str, str], "Symbol"] = {}
        for sym in found:
            unique.setdefault((sym.getName(True), str(sym.getAddress())), sym)
        return list(unique.values())

    # -------------------------------------------------------------------------
    # Core listing helpers (return raw Ghidra objects)
    # -------------------------------------------------------------------------

    # @spec RES-016
    @handle_exceptions
    def get_all_functions(self, include_externals: bool = False) -> list["Function"]:
        """Every function. Without externals, both external and thunk functions are left out."""
        fm = self.program.getFunctionManager()
        functions = list(fm.getFunctions(True))  # every non-external function, thunks included
        if include_externals:
            return functions + list(fm.getExternalFunctions())
        return [f for f in functions if not f.isExternal() and not f.thunk]

    @handle_exceptions
    def get_all_symbols(
        self, include_externals: bool = False, include_dynamic: bool = False
    ) -> list["Symbol"]:
        st = self.program.getSymbolTable()
        return [
            s
            for s in st.getAllSymbols(include_dynamic)
            if include_externals or not s.isExternal()
        ]

    # -------------------------------------------------------------------------
    # Navigation / discovery tools
    # -------------------------------------------------------------------------

    # @spec QRY-001, QRY-002, QRY-003, QRY-053
    @handle_exceptions
    def list_functions(
        self, query: str | None = None, offset: int = 0, limit: int = 100
    ) -> tuple[list[FunctionInfo], int]:
        """List all non-external functions, with optional case-insensitive name filter."""
        if not 1 <= limit <= MAX_FUNCTION_PAGE:
            raise ValueError(
                f"limit must be between 1 and {MAX_FUNCTION_PAGE}, not {limit}; "
                "use offset to page through more results."
            )
        funcs = self.get_all_functions(include_externals=False)
        results: list[FunctionInfo] = []
        for func in funcs:
            name = func.getSymbol().getName(True)
            if query and query.lower() not in name.lower():
                continue
            results.append(
                FunctionInfo(
                    name=name,
                    address=str(func.getEntryPoint()),
                    signature=str(func.getSignature()),
                    external=func.isExternal(),
                )
            )
        total = len(results)
        return results[offset : offset + limit], total

    @handle_exceptions
    def list_segments(self) -> list[MemorySegment]:
        """List all memory segments (blocks) in the binary."""
        mem = self.program.getMemory()
        segments: list[MemorySegment] = []
        for block in mem.getBlocks():
            perms = ""
            if block.isRead():
                perms += "r"
            if block.isWrite():
                perms += "w"
            if block.isExecute():
                perms += "x"
            segments.append(
                MemorySegment(
                    name=block.getName(),
                    start=str(block.getStart()),
                    end=str(block.getEnd()),
                    size=block.getSize(),
                    permissions=perms or "-",
                    type=str(block.getType()),
                    initialized=block.isInitialized(),
                )
            )
        return segments

    # @spec QRY-005, QRY-031
    @handle_exceptions
    def list_data_items(self, offset: int = 0, limit: int = 100) -> DataItems:
        """List defined data items (labels, globals, structs, strings-as-data).

        An item that can't be read is reported in failures, and the result is marked partial.
        """
        listing = self.program.getListing()
        results: list[DataItem] = []
        failures: list[ItemFailure] = []
        total = 0
        for data in listing.getDefinedData(True):
            try:
                label = str(data.getLabel()) if data.getLabel() else str(data.getAddress())
                val = data.getValue()
                item = DataItem(
                    label=label,
                    address=str(data.getAddress()),
                    type=str(data.getDataType().getName()),
                    value=str(val) if val is not None else "",
                )
            except Exception as e:
                failures.append(ItemFailure(address=str(data.getAddress()), error=self._error_text(e)))
                continue
            total += 1
            if total > offset and len(results) < limit:
                results.append(item)
        return DataItems(items=results, total=total, partial=bool(failures), failures=failures)

    @handle_exceptions
    def list_classes(
        self, offset: int = 0, limit: int = 100
    ) -> tuple[list[NamespaceInfo], int]:
        """List all class namespaces defined in the binary."""
        st = self.program.getSymbolTable()
        results: list[NamespaceInfo] = []

        for sym in st.getAllSymbols(False):
            if str(sym.getSymbolType()) == "Class":
                results.append(
                    NamespaceInfo(
                        name=sym.getName(True),
                        type="Class",
                        parent=str(sym.getParentNamespace()),
                    )
                )

        total = len(results)
        return results[offset : offset + limit], total

    @handle_exceptions
    def list_namespaces(
        self, offset: int = 0, limit: int = 100
    ) -> tuple[list[NamespaceInfo], int]:
        """List all non-global namespaces (classes, libraries, user-defined)."""
        st = self.program.getSymbolTable()
        results: list[NamespaceInfo] = []
        ns_types = {"Namespace", "Class", "Library"}

        for sym in st.getAllSymbols(False):
            sym_type = str(sym.getSymbolType())
            if sym_type in ns_types:
                results.append(
                    NamespaceInfo(
                        name=sym.getName(True),
                        type=sym_type,
                        parent=str(sym.getParentNamespace()),
                    )
                )

        total = len(results)
        return results[offset : offset + limit], total

    # -------------------------------------------------------------------------
    # Function lookup tools
    # -------------------------------------------------------------------------

    @handle_exceptions
    def get_function_by_address(self, address: str) -> FunctionInfo:
        """Return function metadata for the function at or containing the given address."""
        addr = self._parse_address(address)
        fm = self.program.getFunctionManager()

        func = fm.getFunctionAt(addr)
        if func is None:
            func = fm.getFunctionContaining(addr)
        if func is None:
            raise ValueError(f"No function at or containing address {address}")

        return FunctionInfo(
            name=func.getSymbol().getName(True),
            address=str(func.getEntryPoint()),
            signature=str(func.getSignature()),
            external=func.isExternal(),
        )

    # -------------------------------------------------------------------------
    # Decompilation tools
    # -------------------------------------------------------------------------

    # @spec QRY-016, QRY-029
    @handle_exceptions
    def decompile_function_by_name_or_addr(self, name_or_address: str) -> DecompiledFunction:
        resolved = self.resolve_function(name_or_address, ResolutionMode.READ)
        result = self.decompile_function(resolved.target, DECOMPILE_TIMEOUT_SECONDS)
        return result.model_copy(update={"resolution": resolved.note})

    # @spec QRY-017, QRY-035, QRY-038
    def decompile_function(self, func: "Function", timeout: int = DECOMPILE_TIMEOUT_SECONDS) -> DecompiledFunction:
        """Decompile a function; a decompiler failure (including a timeout) raises Stop."""
        from ghidra.util.task import ConsoleTaskMonitor

        result: "DecompileResults" = self.decompiler.decompileFunction(
            func, timeout, ConsoleTaskMonitor()
        )
        error = result.getErrorMessage()
        if error:
            raise Stop(f"Decompilation of {self._func_label(func)} failed: {error}")
        decompiled = result.decompiledFunction
        if decompiled is None:
            raise Stop(f"Decompilation of {self._func_label(func)} produced no result.")
        return DecompiledFunction(
            name=self._func_label(func), code=decompiled.getC(), signature=decompiled.getSignature()
        )

    # @spec QRY-018, QRY-029, QRY-030, QRY-037
    @handle_exceptions
    def disassemble_function(self, name_or_address: str) -> DisassemblyResult:
        """Return the assembly listing for a function.

        A field that can't be read is left empty and named in that line's errors, and the
        result is marked partial.
        """
        from ghidra.program.model.listing import CommentType

        resolved = self.resolve_function(name_or_address, ResolutionMode.READ)
        func = resolved.target
        listing = self.program.getListing()
        instructions: list[DisassemblyLine] = []

        for instr in listing.getInstructions(func.getBody(), True):
            errors: list[str] = []
            try:
                instr_bytes = bytes([b & 0xFF for b in instr.getBytes()]).hex()
            except Exception as e:
                instr_bytes = ""
                errors.append(f"bytes: {self._error_text(e)}")

            operand_parts = []
            try:
                for i in range(instr.getNumOperands()):
                    operand_parts.append(instr.getDefaultOperandRepresentation(i))
            except Exception as e:
                errors.append(f"operands: {self._error_text(e)}")

            comment = None
            try:
                comment = listing.getComment(CommentType.EOL, instr.getAddress())
            except Exception as e:
                errors.append(f"comment: {self._error_text(e)}")

            instructions.append(
                DisassemblyLine(
                    address=str(instr.getAddress()),
                    bytes=instr_bytes,
                    mnemonic=instr.getMnemonicString(),
                    operands=", ".join(operand_parts),
                    comment=comment,
                    errors=errors,
                )
            )

        return DisassemblyResult(
            function_name=func.getSymbol().getName(True),
            address=str(func.getEntryPoint()),
            instructions=instructions,
            partial=any(line.errors for line in instructions),
            resolution=resolved.note,
        )

    # -------------------------------------------------------------------------
    # Symbol / import / export tools
    # -------------------------------------------------------------------------

    @handle_exceptions
    def search_symbols_by_name(
        self, query: str, offset: int = 0, limit: int = 100
    ) -> list[SymbolInfo]:
        if not query:
            raise ValueError("query is required")

        symbols = self._lookup_symbols(query)
        rm = self.program.getReferenceManager()
        results: list[SymbolInfo] = []

        for sym in symbols:
            ref_count = len(list(rm.getReferencesTo(sym.getAddress())))
            results.append(
                SymbolInfo(
                    name=sym.name,
                    address=str(sym.getAddress()),
                    type=str(sym.getSymbolType()),
                    namespace=str(sym.getParentNamespace()),
                    source=str(sym.getSource()),
                    refcount=ref_count,
                    external=sym.isExternal(),
                )
            )

        return results[offset : offset + limit]

    @handle_exceptions
    def list_exports(
        self, query: str | None = None, offset: int = 0, limit: int = 25
    ) -> list[ExportInfo]:
        exports: list[ExportInfo] = []
        for sym in self.program.getSymbolTable().getAllSymbols(True):
            if not sym.isExternalEntryPoint():
                continue
            if query and not re.search(query, sym.getName(), re.IGNORECASE):
                continue
            exports.append(ExportInfo(name=sym.getName(), address=str(sym.getAddress())))
        return exports[offset : offset + limit]

    @handle_exceptions
    def list_imports(
        self, query: str | None = None, offset: int = 0, limit: int = 25
    ) -> list[ImportInfo]:
        imports: list[ImportInfo] = []
        for sym in self.program.getSymbolTable().getExternalSymbols():
            if query and not re.search(query, sym.getName(), re.IGNORECASE):
                continue
            imports.append(
                ImportInfo(name=sym.getName(), library=str(sym.getParentNamespace()))
            )
        return imports[offset : offset + limit]

    # -------------------------------------------------------------------------
    # Cross-reference tools
    # -------------------------------------------------------------------------

    # @spec QRY-021, QRY-029
    @handle_exceptions
    def list_cross_references(self, name_or_address: str) -> CrossReferenceInfos:
        """All references TO a symbol or address."""
        resolved = self.resolve_reference_target(name_or_address)
        rm = self.program.getReferenceManager()
        fm = self.program.getFunctionManager()
        refs: list[CrossReferenceInfo] = []

        for ref in rm.getReferencesTo(resolved.target):
            from_func = fm.getFunctionContaining(ref.getFromAddress())
            refs.append(
                CrossReferenceInfo(
                    function_name=from_func.getName() if from_func else None,
                    from_address=str(ref.getFromAddress()),
                    to_address=str(ref.getToAddress()),
                    type=str(ref.getReferenceType()),
                )
            )
        return CrossReferenceInfos(cross_references=refs, resolution=resolved.note)

    @handle_exceptions
    def get_xrefs_from(self, address: str) -> list[CrossReferenceInfo]:
        """All references FROM a given address (calls, jumps, data refs made at this point)."""
        addr = self._parse_address(address)
        rm = self.program.getReferenceManager()
        fm = self.program.getFunctionManager()
        refs: list[CrossReferenceInfo] = []

        for ref in rm.getReferencesFrom(addr):
            to_func = fm.getFunctionContaining(ref.getToAddress())
            refs.append(
                CrossReferenceInfo(
                    function_name=to_func.getName() if to_func else None,
                    from_address=str(ref.getFromAddress()),
                    to_address=str(ref.getToAddress()),
                    type=str(ref.getReferenceType()),
                )
            )
        return refs

    # -------------------------------------------------------------------------
    # String / bytes tools
    # -------------------------------------------------------------------------

    # @spec QRY-010, QRY-011, QRY-032
    @handle_exceptions
    def search_strings(self, query: str, limit: int = 100) -> StringSearchResults:
        """
        Search defined strings using Ghidra's DefinedStringIterator.
        Simple case-insensitive substring match — no ChromaDB, no ML model.
        A string whose value can't be read is reported in failures, and the result is marked partial.
        """
        from ghidra.program.util import DefinedStringIterator

        query_lc = query.lower()
        results: list[StringInfo] = []
        failures: list[ItemFailure] = []
        total = 0

        for data in DefinedStringIterator.forProgram(self.program):
            try:
                val = str(data.getValue())
            except Exception as e:
                failures.append(ItemFailure(address=str(data.getAddress()), error=self._error_text(e)))
                continue
            if query_lc in val.lower():
                total += 1
                if len(results) < limit:
                    results.append(StringInfo(value=val, address=str(data.getAddress())))

        return StringSearchResults(
            strings=results, total=total, partial=bool(failures), failures=failures
        )

    # @spec QRY-019, QRY-020, QRY-033, QRY-034
    @handle_exceptions
    def read_bytes(self, address: str, size: int = 32) -> BytesReadResult:
        """Read raw bytes from the program's memory image."""
        MAX_SIZE = 8192
        if size <= 0:
            raise ValueError("size must be > 0")
        if size > MAX_SIZE:
            raise ValueError(f"size {size} exceeds maximum {MAX_SIZE}")

        addr = self._parse_address(address)
        mem = self.program.getMemory()
        block = mem.getBlock(addr)
        if block is None:
            raise ValueError(f"Address {address} is not in mapped memory")
        if not block.isInitialized():
            raise ValueError(
                f"Address {address} is in uninitialized memory (block '{block.getName()}'); "
                "it has no bytes to read."
            )

        buf = JByte[size]  # type: ignore[reportInvalidTypeArguments]
        n = mem.getBytes(addr, buf)
        data = bytes([b & 0xFF for b in buf[:n]]) if n > 0 else b""  # type: ignore
        return BytesReadResult(
            address=str(addr),
            size=len(data),
            data=data.hex(),
            requested_size=size,
            partial=len(data) < size,
        )

    # -------------------------------------------------------------------------
    # Annotation / write-back tools
    # -------------------------------------------------------------------------

    def _set_comment(self, address: str, kind: str, comment: str, label: str) -> str:
        """Set (or, for empty text, remove) one kind of comment at an address in memory."""
        from ghidra.program.model.listing import CommentType

        addr = self._parse_address(address)
        if not self.program.getMemory().contains(addr):
            raise ValueError(f"Address {address} is not in the program's memory")
        listing = self.program.getListing()
        comment_type = getattr(CommentType, kind)
        text = comment if comment else None  # None removes the comment

        def _do():
            listing.setComment(addr, comment_type, text)
            action = "Set" if text is not None else "Removed"
            return f"{action} {label} comment at {address}"

        return self._with_transaction(f"Set {kind} comment at {address}", _do)

    # @spec WB-006, WB-025, WB-026, WB-027
    @handle_exceptions
    def set_disassembly_comment(self, address: str, comment: str) -> str:
        """Set an EOL comment at an address (visible in the disassembly listing).
        Empty text removes it."""
        return self._set_comment(address, "EOL", comment, "disassembly")

    # @spec WB-007, WB-025, WB-026, WB-027
    @handle_exceptions
    def set_decompiler_comment(self, address: str, comment: str) -> str:
        """Set a PRE comment at an address (visible in the decompiler view as // comment).
        Empty text removes it."""
        return self._set_comment(address, "PRE", comment, "decompiler")

    # @spec WB-008
    @handle_exceptions
    def rename_function(self, name_or_address: str, new_name: str) -> str:
        """Rename a function by its current name or address."""
        from ghidra.program.model.symbol import SourceType

        func = self.find_function(name_or_address)
        old_name = func.getName()

        def _do():
            func.setName(new_name, SourceType.USER_DEFINED)
            return f"Renamed '{old_name}' → '{new_name}'"

        return self._with_transaction(f"Rename function {old_name} → {new_name}", _do)

    # @spec WB-009, WB-010
    @handle_exceptions
    def rename_function_by_address(self, address: str, new_name: str) -> str:
        """Rename a function by its entry point address."""
        from ghidra.program.model.symbol import SourceType

        addr = self._parse_address(address)
        fm = self.program.getFunctionManager()
        func = fm.getFunctionAt(addr)
        if func is None:
            raise ValueError(f"No function at address {address}")

        old_name = func.getName()

        def _do():
            func.setName(new_name, SourceType.USER_DEFINED)
            return f"Renamed function at {address}: '{old_name}' → '{new_name}'"

        return self._with_transaction(f"Rename function at {address}", _do)

    # @spec WB-011
    @handle_exceptions
    def rename_data(self, address: str, new_name: str) -> str:
        """Rename the defined data at an address: its primary symbol if that is a named
        (non-dynamic) symbol, otherwise by creating a label."""
        from ghidra.program.model.symbol import SourceType

        addr = self._parse_address(address)
        listing = self.program.getListing()
        st = self.program.getSymbolTable()

        data = listing.getDataAt(addr)
        if data is None:
            raise ValueError(f"No defined data at address {address}")

        def _do():
            sym = data.getPrimarySymbol()
            if sym is not None and not sym.isDynamic():
                sym.setName(new_name, SourceType.USER_DEFINED)
            else:  # no symbol, or a default DAT_… label: name the location with a new label
                st.createLabel(addr, new_name, SourceType.USER_DEFINED)
            return f"Renamed data at {address} → '{new_name}'"

        return self._with_transaction(f"Rename data at {address}", _do)

    # @spec WB-013, WB-014, WB-015
    def _find_local_variable(self, func: "Function", var_name: str):
        """Decompile a function (30 s) and return the local symbol named exactly var_name."""
        from ghidra.util.task import ConsoleTaskMonitor

        result = self.decompiler.decompileFunction(func, 30, ConsoleTaskMonitor())
        if result.getErrorMessage() != "":
            raise Stop(
                f"Decompilation failed for '{func.getName()}': {result.getErrorMessage()}"
            )

        symbols = list(result.getHighFunction().getLocalSymbolMap().getSymbols())
        for sym in symbols:
            if sym.getName() == var_name:
                return sym
        available = [s.getName() for s in symbols]
        raise ValueError(
            f"Variable '{var_name}' not found in '{func.getName()}'. Available: {available}"
        )

    # @spec WB-016
    @handle_exceptions
    def rename_variable(
        self, function_name_or_address: str, old_var_name: str, new_var_name: str
    ) -> str:
        """Rename a local variable within a function (uses the decompiler's high-level model)."""
        from ghidra.program.model.pcode import HighFunctionDBUtil
        from ghidra.program.model.symbol import SourceType

        func = self.find_function(function_name_or_address)
        target_sym = self._find_local_variable(func, old_var_name)

        def _do():
            HighFunctionDBUtil.updateDBVariable(
                target_sym, new_var_name, None, SourceType.USER_DEFINED
            )
            return (
                f"Renamed variable '{old_var_name}' → '{new_var_name}' "
                f"in function '{func.getName()}'"
            )

        return self._with_transaction(
            f"Rename variable {old_var_name} in {func.getName()}", _do
        )

    # @spec WB-018, WB-019, WB-020, WB-024
    @handle_exceptions
    def set_function_prototype(self, name_or_address: str, prototype: str) -> str:
        """
        Set a function's prototype (signature) from a C declaration string.
        Example prototype: 'int process_data(char *buf, int len)'
        """
        from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
        from ghidra.app.util.cparser.C import CParser
        from ghidra.program.model.data import FunctionDefinitionDataType
        from ghidra.program.model.symbol import SourceType
        from ghidra.util.task import ConsoleTaskMonitor

        func = self.find_function(name_or_address)
        dtm = self.program.getDataTypeManager()
        parser = CParser(dtm)

        try:
            parsed = parser.parse(prototype + ";")
        except Exception as e:
            raise ValueError(f"Failed to parse prototype '{prototype}': {e}") from e

        if not isinstance(parsed, FunctionDefinitionDataType):
            raise ValueError(
                f"Parsed result is not a function definition (got {type(parsed).__name__}). "
                "Ensure the prototype is a valid C function signature, e.g. 'int foo(int a)'"
            )

        old_name = func.getName()

        def _do():
            cmd = ApplyFunctionSignatureCmd(
                func.getEntryPoint(), parsed, SourceType.USER_DEFINED
            )
            if not cmd.applyTo(self.program, ConsoleTaskMonitor()):
                reason = cmd.getStatusMsg() or "no reason given"
                raise Stop(f"Ghidra could not apply the prototype to '{old_name}': {reason}")
            message = f"Set prototype for '{old_name}': {prototype}"
            new_name = func.getName()
            if new_name != old_name:  # Ghidra renames a function that still has a default name
                message += f". The function was renamed to '{new_name}'"
            return message

        return self._with_transaction(f"Set prototype for {old_name}", _do)

    # @spec WB-017
    @handle_exceptions
    def set_local_variable_type(
        self, function_name_or_address: str, var_name: str, new_type: str
    ) -> str:
        """
        Set the data type of a local variable within a function.
        Type string examples: 'int', 'char *', 'unsigned int', 'struct Foo *'
        """
        from ghidra.program.model.pcode import HighFunctionDBUtil
        from ghidra.program.model.symbol import SourceType

        func = self.find_function(function_name_or_address)
        data_type = self._resolve_data_type(new_type)
        target_sym = self._find_local_variable(func, var_name)

        def _do():
            HighFunctionDBUtil.updateDBVariable(
                target_sym, None, data_type, SourceType.USER_DEFINED
            )
            return (
                f"Set type of '{var_name}' to '{new_type}' "
                f"in function '{func.getName()}'"
            )

        return self._with_transaction(
            f"Set variable type {var_name} in {func.getName()}", _do
        )

    # -------------------------------------------------------------------------
    # Call relations, comparison, p-code, and data flow
    # -------------------------------------------------------------------------

    @staticmethod
    def _label(func: "Function") -> tuple[str, str]:
        return str(func.getName(True)), str(func.getEntryPoint())

    @staticmethod
    def _relations(groups: dict) -> list[CallRelation]:
        named = sorted((g for k, g in groups.items() if k is not None), key=lambda g: g["order"])
        unnamed = [groups[None]] if None in groups else []
        return [
            CallRelation(
                name=g["name"], address=g["address"], thunk_of=g.get("thunk_of"),
                call_sites=[site for _, site in sorted(g["sites"])],
            )
            for g in named + unnamed
        ]

    # @spec QRY-039
    @handle_exceptions
    def get_function_callers(self, name_or_address: str) -> FunctionCallers:
        """Functions that call this one, directly or through its thunks."""
        resolved = self.resolve_function(name_or_address, ResolutionMode.READ)
        func = resolved.target
        rm = self.program.getReferenceManager()
        fm = self.program.getFunctionManager()
        targets = [func.getEntryPoint(), *(func.getFunctionThunkAddresses(True) or [])]
        groups: dict = {}
        for target in targets:
            for ref in rm.getReferencesTo(target):
                if not ref.getReferenceType().isCall():
                    continue
                site = ref.getFromAddress()
                caller = fm.getFunctionContaining(site)
                key = str(caller.getEntryPoint()) if caller is not None else None
                group = groups.setdefault(key, {
                    "name": str(caller.getName(True)) if caller is not None else None,
                    "address": key,
                    "order": caller.getEntryPoint().getOffset() if caller is not None else -1,
                    "sites": set(),
                })
                group["sites"].add((site.getOffset(), str(site)))
        name, entry = self._label(func)
        return FunctionCallers(function=name, address=entry, callers=self._relations(groups),
                               resolution=resolved.note)

    # @spec QRY-040, QRY-041
    @handle_exceptions
    def get_function_callees(self, name_or_address: str) -> FunctionCallees:
        """Call targets of this function's instructions, and its unresolved indirect calls."""
        resolved = self.resolve_function(name_or_address, ResolutionMode.READ)
        func = resolved.target
        listing = self.program.getListing()
        rm = self.program.getReferenceManager()
        fm = self.program.getFunctionManager()
        groups: dict = {}
        indirect: list[tuple[int, str]] = []
        for instr in listing.getInstructions(func.getBody(), True):
            site = instr.getAddress()
            calls = [r for r in rm.getReferencesFrom(site) if r.getReferenceType().isCall()]
            if not calls:
                flow = instr.getFlowType()
                if flow.isCall() and flow.isComputed():
                    indirect.append((site.getOffset(), str(site)))
                continue
            for ref in calls:
                target = ref.getToAddress()
                callee = fm.getFunctionAt(target)
                thunk_of = None
                if callee is not None and callee.isThunk():
                    thunked = callee.getThunkedFunction(True)
                    thunk_of = str(thunked.getName(True)) if thunked is not None else None
                group = groups.setdefault(str(target), {
                    "name": str(callee.getName(True)) if callee is not None else None,
                    "address": str(target),
                    "order": target.getOffset(),
                    "thunk_of": thunk_of,
                    "sites": set(),
                })
                group["sites"].add((site.getOffset(), str(site)))
        name, entry = self._label(func)
        return FunctionCallees(function=name, address=entry, callees=self._relations(groups),
                               indirect_call_sites=[s for _, s in sorted(indirect)], resolution=resolved.note)

    def _function_text(self, func: "Function", view: str) -> str:
        if view == "decompiled":
            return self.decompile_function(func, DECOMPILE_TIMEOUT_SECONDS).code
        lines = []
        for instr in self.program.getListing().getInstructions(func.getBody(), True):
            operands = ", ".join(instr.getDefaultOperandRepresentation(i) for i in range(instr.getNumOperands()))
            lines.append(f"{instr.getMnemonicString()} {operands}".rstrip())
        return "\n".join(lines)

    # @spec QRY-042, QRY-043, QRY-044
    @handle_exceptions
    def diff_functions(self, function_a: str, function_b: str, other: "GhidraTools | None" = None,
                       view: str = "decompiled", normalize: bool = True, context_lines: int = 3) -> FunctionDiff:
        """Compare two functions, the second in another binary when other is given."""
        if view not in ("decompiled", "disassembly"):
            raise ValueError(f"view must be 'decompiled' or 'disassembly', not '{view}'.")
        if context_lines < 0:
            raise ValueError("context_lines must not be negative.")
        other = other or self
        resolved_a = self.resolve_function(function_a, ResolutionMode.READ)
        resolved_b = other.resolve_function(function_b, ResolutionMode.READ)
        func_a, func_b = resolved_a.target, resolved_b.target
        text_a, text_b = self._function_text(func_a, view), other._function_text(func_b, view)
        if normalize:
            text_a = normalize_listing(text_a, [str(func_a.getName()), str(func_a.getName(True))])
            text_b = normalize_listing(text_b, [str(func_b.getName()), str(func_b.getName(True))])
        label_a = "{} @ {}".format(*self._label(func_a))
        label_b = "{} @ {}".format(*other._label(func_b))
        diff, ratio, identical = diff_texts(
            text_a, text_b, f"{self.program_info.name}:{label_a}", f"{other.program_info.name}:{label_b}",
            context_lines,
        )
        return FunctionDiff(
            binary_a=self.program_info.name, function_a=label_a, binary_b=other.program_info.name,
            function_b=label_b, view=view, normalized=normalize, identical=identical, similarity=ratio,
            diff=diff, resolution_a=resolved_a.note, resolution_b=resolved_b.note,
        )

    # @spec QRY-047
    def _similarity_index(self) -> dict:
        """entry → (instruction count, mnemonic grams, qualified name, entry offset), computed
        once per program and kept until the binary is next analyzed."""
        index = self.program_info.similarity_index
        if index is None:
            index = {}
            listing = self.program.getListing()
            for func in self.get_all_functions(include_externals=False):
                mnemonics = [str(i.getMnemonicString()) for i in listing.getInstructions(func.getBody(), True)]
                entry = func.getEntryPoint()
                index[str(entry)] = (len(mnemonics), mnemonic_grams(mnemonics), str(func.getName(True)),
                                     entry.getOffset())
            self.program_info.similarity_index = index
        return index

    # @spec QRY-045, QRY-046
    @handle_exceptions
    def find_similar_functions_fuzzy(self, name_or_address: str, target: "GhidraTools | None" = None,
                                     limit: int = 10, min_similarity: float = 0.5) -> SimilarFunctions:
        """Rank target's functions by similarity to this function."""
        if limit < 1:
            raise ValueError("limit must be at least 1.")
        if not 0 <= min_similarity <= 1:
            raise ValueError("min_similarity must be between 0 and 1.")
        target = target or self
        resolved = self.resolve_function(name_or_address, ResolutionMode.READ)
        func = resolved.target
        key = str(func.getEntryPoint())
        query = self._similarity_index().get(key)
        if query is None:  # a thunk or external query is not in the index
            mnemonics = [str(i.getMnemonicString())
                         for i in self.program.getListing().getInstructions(func.getBody(), True)]
            query = (len(mnemonics), mnemonic_grams(mnemonics))
        count, grams = query[0], query[1]
        index = target._similarity_index()
        same_program = target.program_info is self.program_info
        candidates = [(k, v[0], v[1]) for k, v in index.items() if not (same_program and k == key)]
        ranked = rank_similar(count, grams, candidates, limit=limit, min_similarity=min_similarity,
                              order=lambda k: index[k][3])
        name, entry = self._label(func)
        return SimilarFunctions(
            binary=self.program_info.name, function=name, address=entry, instruction_count=count,
            target_binary=target.program_info.name, method=SIMILARITY_METHOD,
            candidates=[SimilarFunction(name=index[k][2], address=k, similarity=score, instruction_count=n)
                        for k, n, score in ranked],
            scanned=len(candidates), resolution=resolved.note,
        )

    def _decompile_high(self, func: "Function"):
        from ghidra.util.task import ConsoleTaskMonitor

        result = self.decompiler.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, ConsoleTaskMonitor())
        error = result.getErrorMessage()
        if error:
            raise Stop(f"Decompilation of {self._func_label(func)} failed: {error}")
        high = result.getHighFunction()
        if high is None:
            raise Stop(f"Decompilation of {self._func_label(func)} produced no result.")
        return high

    @staticmethod
    def _op_info(op, address: str | None = None) -> PcodeOpInfo:
        seq = op.getSeqnum()
        return PcodeOpInfo(address=address or str(seq.getTarget()), seq=int(seq.getTime()),
                           mnemonic=str(op.getMnemonic()), text=str(op))

    # @spec QRY-048, QRY-049
    @handle_exceptions
    def get_function_pcode(self, name_or_address: str, form: str = "raw", max_ops: int = 2000) -> FunctionPcode:
        """The function's raw (per-instruction) or high (decompiler) p-code."""
        _check_max_ops(max_ops, MAX_PCODE_OPS)
        if form not in ("raw", "high"):
            raise ValueError(f"form must be 'raw' or 'high', not '{form}'.")
        resolved = self.resolve_function(name_or_address, ResolutionMode.READ)
        func = resolved.target
        ops: list[PcodeOpInfo] = []
        if form == "raw":
            for instr in self.program.getListing().getInstructions(func.getBody(), True):
                address = str(instr.getAddress())
                ops.extend(self._op_info(op, address) for op in instr.getPcode())
        else:
            ops.extend(self._op_info(op) for op in self._decompile_high(func).getPcodeOps())
        name, entry = self._label(func)
        return FunctionPcode(function=name, address=entry, form=form, ops=ops[:max_ops], total_ops=len(ops),
                             truncated=len(ops) > max_ops, resolution=resolved.note)

    # @spec QRY-049, QRY-050, QRY-051
    @handle_exceptions
    def analyze_dataflow(self, function_name_or_address: str, variable: str, direction: str = "backward",
                         max_ops: int = 500) -> DataflowResult:
        """The backward or forward data-flow slice of a decompiler variable."""
        _check_max_ops(max_ops, MAX_DATAFLOW_OPS)
        if direction not in ("backward", "forward"):
            raise ValueError(f"direction must be 'backward' or 'forward', not '{direction}'.")
        resolved = self.resolve_function(function_name_or_address, ResolutionMode.READ)
        func = resolved.target
        high = self._decompile_high(func)
        symbols = list(high.getLocalSymbolMap().getSymbols())
        symbol = next((s for s in symbols if s.getName() == variable), None)
        if symbol is None:
            available = sorted(str(s.getName()) for s in symbols)
            raise ValueError(f"Variable '{variable}' not found in '{func.getName()}'. Available: {available}")
        high_variable = symbol.getHighVariable()
        if high_variable is None:
            raise ValueError(f"Variable '{variable}' has no data flow in the decompiled '{func.getName()}'.")

        from ghidra.app.decompiler.component import DecompilerUtils

        slice_ops = (DecompilerUtils.getBackwardSliceToPCodeOps if direction == "backward"
                     else DecompilerUtils.getForwardSliceToPCodeOps)
        unique: dict = {}
        for varnode in high_variable.getInstances():
            for op in slice_ops(varnode):
                seq = op.getSeqnum()
                target = seq.getTarget()
                unique.setdefault((target.getOffset() if target is not None else -1, int(seq.getTime())), op)
        ordered = [unique[k] for k in sorted(unique)]
        names: set[str] = set()
        for op in ordered:
            for varnode in [*op.getInputs(), op.getOutput()]:
                high_var = varnode.getHigh() if varnode is not None else None
                if high_var is not None and high_var.getName():
                    names.add(str(high_var.getName()))
        ops = [self._op_info(op) for op in ordered]
        name, entry = self._label(func)
        return DataflowResult(function=name, address=entry, variable=variable, direction=direction,
                              ops=ops[:max_ops], variables=sorted(names), total_ops=len(ops),
                              truncated=len(ops) > max_ops, resolution=resolved.note)

    # -------------------------------------------------------------------------
    # Callgraph
    # -------------------------------------------------------------------------

    @handle_exceptions
    def gen_callgraph(
        self,
        function_name_or_address: str,
        cg_direction: CallGraphDirection = CallGraphDirection.CALLING,
        cg_display_type: CallGraphDisplayType = CallGraphDisplayType.FLOW,
        include_refs: bool = True,
        max_depth: int | None = None,
        max_run_time: int = 60,
        condense_threshold: int = 50,
        top_layers: int = 5,
        bottom_layers: int = 5,
    ) -> CallGraphResult:
        try:
            from ghidrecomp.callgraph import gen_callgraph
        except ImportError as e:
            raise Stop(
                "ghidrecomp is required for callgraph generation. "
                "Install it with: pip install 'ghidra-mcp-lite[ghidrecomp]'"
            ) from e

        resolved = self.resolve_function(function_name_or_address, ResolutionMode.READ)
        func = resolved.target
        name, direction, _, graphs_data = gen_callgraph(
            func=func,
            max_display_depth=max_depth,
            direction=cg_direction.value,
            max_run_time=max_run_time,
            name=func.getSymbol().getName(True),
            include_refs=include_refs,
            condense_threshold=condense_threshold,
            top_layers=top_layers,
            bottom_layers=bottom_layers,
            wrap_mermaid=False,
        )

        graph_content = ""
        for graph_type, content in graphs_data:
            if graph_type == cg_display_type.value:  # other entries (URLs, images) are skipped
                graph_content = content
                break

        if not graph_content:
            raise ValueError(
                f"Display type '{cg_display_type.value}' not found in callgraph output for {func}."
            )

        mermaid_url = ""
        for graph_type, content in graphs_data:
            if graph_type == "mermaid_url":
                mermaid_url = content.split("\n")[0]
                break

        return CallGraphResult(
            function_name=name,
            direction=CallGraphDirection(direction),
            display_type=cg_display_type,
            graph=graph_content,
            mermaid_url=mermaid_url,
            resolution=resolved.note,
        )
