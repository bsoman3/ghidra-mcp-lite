"""
Native Ghidra tool implementations.
No ChromaDB, no ML/embedding — all search uses Ghidra's own iterators and APIs.
"""

import functools
import logging
import re
import typing

from jpype import JByte

from ghidra_mcp.models import (
    BytesReadResult,
    CallGraphDirection,
    CallGraphDisplayType,
    CallGraphResult,
    CrossReferenceInfo,
    DataItem,
    DataItems,
    DecompiledFunction,
    DisassemblyLine,
    DisassemblyResult,
    ExportInfo,
    FunctionInfo,
    ImportInfo,
    MemorySegment,
    MemorySegments,
    NamespaceInfo,
    NamespaceList,
    StringInfo,
    SymbolInfo,
)

if typing.TYPE_CHECKING:
    from ghidra.app.decompiler import DecompileResults
    from ghidra.program.model.listing import Function
    from ghidra.program.model.symbol import Symbol

    from ghidra_mcp.context import ProgramInfo

logger = logging.getLogger(__name__)


def handle_exceptions(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {e!s}")
            raise

    return wrapper


class GhidraTools:
    """All native Ghidra tool implementations."""

    def __init__(self, program_info: "ProgramInfo"):
        self.program_info = program_info
        self.program = program_info.program
        self.project = program_info.project
        self.decompiler = program_info.decompiler

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _func_label(self, func: "Function") -> str:
        return f"{func.getSymbol().getName(True)[:50]}-{func.entryPoint}"

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

    def _with_transaction(self, description: str, body: typing.Callable) -> typing.Any:
        """
        Run body() inside a Ghidra transaction.
        On success: commit and save to the project.
        On failure: roll back.
        """
        tx = self.program.startTransaction(description)
        ok = False
        try:
            result = body()
            ok = True
            return result
        finally:
            self.program.endTransaction(tx, ok)
            if ok:
                self.project.save(self.program)

    def _resolve_data_type(self, type_str: str):
        """
        Resolve a C type string to a Ghidra DataType.
        Tries direct lookup first, then CParser for complex/pointer types.
        """
        from ghidra.app.util.cparser.C import CParser

        dtm = self.program.getDataTypeManager()

        # Direct name lookup (handles built-ins: uint, char, int, void, etc.)
        dt = dtm.getDataType(type_str)
        if dt is not None:
            return dt

        # CParser handles "char *", "unsigned int", "struct Foo *", etc.
        parser = CParser(dtm)
        try:
            return parser.parse(type_str + " __x;")
        except Exception:
            pass

        # Last resort: scan all data types for name match
        for dt in dtm.getAllDataTypes():
            if dt.getName() == type_str:
                return dt

        raise ValueError(f"Cannot resolve data type: '{type_str}'")

    # -------------------------------------------------------------------------
    # Function resolution
    # -------------------------------------------------------------------------

    @handle_exceptions
    def find_function(
        self, name_or_address: str, include_externals: bool = True
    ) -> "Function":
        """
        Resolve a function by hex address or name.
        On ambiguity or near-miss, raises with suggestions.
        """
        af = self.program.getAddressFactory()
        fm = self.program.getFunctionManager()

        # Try as address first
        try:
            addr = af.getAddress(name_or_address)
            if addr:
                func = fm.getFunctionAt(addr)
                if func:
                    return func
        except Exception:
            pass

        functions = self.get_all_functions(include_externals=include_externals)
        query_lc = name_or_address.lower()

        exact = [f for f in functions if query_lc == f.getSymbol().getName(True).lower()]
        if len(exact) == 1:
            return exact[0]
        if len(exact) > 1:
            hints = [f"{f.getSymbol().getName(True)} @ {f.getEntryPoint()}" for f in exact]
            raise ValueError(
                f"Ambiguous match for '{name_or_address}'. Did you mean: {', '.join(hints)}"
            )

        partials = [f for f in functions if query_lc in f.getSymbol().getName(True).lower()]
        if partials:
            hints = [f"{f.getSymbol().getName(True)} @ {f.getEntryPoint()}" for f in partials]
            raise ValueError(
                f"Function '{name_or_address}' not found. Did you mean: {', '.join(hints)}"
            )

        raise ValueError(f"Function '{name_or_address}' not found.")

    def _lookup_symbols(
        self,
        name_or_address: str,
        *,
        exact: bool = True,
        partial: bool = False,
    ) -> list["Symbol"]:
        st = self.program.getSymbolTable()
        af = self.program.getAddressFactory()

        # Try as address
        try:
            addr = af.getAddress(name_or_address)
            if addr:
                syms = list(st.getSymbols(addr))
                if syms:
                    return syms
        except Exception:
            pass

        query_lc = name_or_address.lower()
        base = self.get_all_symbols(include_externals=True)
        matches: set = set()

        if exact:
            matches.update(s for s in base if query_lc == s.getName(True).lower())
        if partial:
            matches.update(s for s in base if query_lc in s.getName(True).lower())

        return list(matches)

    @handle_exceptions
    def find_symbol(self, name_or_address: str) -> "Symbol":
        """Resolve a single symbol, raising on ambiguity."""
        matches = self._lookup_symbols(name_or_address, exact=True, partial=True)
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            hints = [f"{s.getName(True)} @ {s.getAddress()}" for s in matches]
            raise ValueError(
                f"Ambiguous match for '{name_or_address}'. Did you mean: {', '.join(hints)}"
            )
        raise ValueError(f"Symbol '{name_or_address}' not found.")

    # -------------------------------------------------------------------------
    # Core listing helpers (return raw Ghidra objects)
    # -------------------------------------------------------------------------

    @handle_exceptions
    def get_all_functions(self, include_externals: bool = False) -> list["Function"]:
        fm = self.program.getFunctionManager()
        return [
            f
            for f in fm.getFunctions(True)
            if include_externals or (not f.isExternal() and not f.thunk)
        ]

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

    @handle_exceptions
    def list_functions(
        self, query: str | None = None, offset: int = 0, limit: int = 100
    ) -> tuple[list[FunctionInfo], int]:
        """List all non-external functions, with optional case-insensitive name filter."""
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

    @handle_exceptions
    def list_data_items(
        self, offset: int = 0, limit: int = 100
    ) -> tuple[list[DataItem], int]:
        """List defined data items (labels, globals, structs, strings-as-data)."""
        listing = self.program.getListing()
        results: list[DataItem] = []
        total = 0

        for data in listing.getDefinedData(True):
            try:
                label = str(data.getLabel()) if data.getLabel() else str(data.getAddress())
                val = data.getValue()
                total += 1
                if total > offset and len(results) < limit:
                    results.append(
                        DataItem(
                            label=label,
                            address=str(data.getAddress()),
                            type=str(data.getDataType().getName()),
                            value=str(val) if val is not None else "",
                        )
                    )
            except Exception as e:
                logger.debug(f"Skipping data item: {e}")

        return results, total

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

    @handle_exceptions
    def decompile_function_by_name_or_addr(self, name_or_address: str) -> DecompiledFunction:
        func = self.find_function(name_or_address)
        return self.decompile_function(func)

    def decompile_function(self, func: "Function", timeout: int = 0) -> DecompiledFunction:
        from ghidra.util.task import ConsoleTaskMonitor

        result: "DecompileResults" = self.decompiler.decompileFunction(
            func, timeout, ConsoleTaskMonitor()
        )
        if result.getErrorMessage() == "":
            code = result.decompiledFunction.getC()
            sig = result.decompiledFunction.getSignature()
        else:
            code = result.getErrorMessage()
            sig = None
        return DecompiledFunction(name=self._func_label(func), code=code, signature=sig)

    @handle_exceptions
    def disassemble_function(self, name_or_address: str) -> DisassemblyResult:
        """Return the assembly listing for a function."""
        from ghidra.program.model.listing import CodeUnit

        func = self.find_function(name_or_address)
        listing = self.program.getListing()
        body = func.getBody()
        instructions: list[DisassemblyLine] = []

        for instr in listing.getInstructions(body, True):
            try:
                raw = bytes([b & 0xFF for b in instr.getBytes()])
                instr_bytes = raw.hex()
            except Exception:
                instr_bytes = ""

            mnemonic = instr.getMnemonicString()
            operand_parts = []
            try:
                for i in range(instr.getNumOperands()):
                    operand_parts.append(instr.getDefaultOperandRepresentation(i))
            except Exception:
                pass
            operands = ", ".join(operand_parts)

            comment = None
            try:
                comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress())
            except Exception:
                pass

            instructions.append(
                DisassemblyLine(
                    address=str(instr.getAddress()),
                    bytes=instr_bytes,
                    mnemonic=mnemonic,
                    operands=operands,
                    comment=comment,
                )
            )

        return DisassemblyResult(
            function_name=func.getSymbol().getName(True),
            address=str(func.getEntryPoint()),
            instructions=instructions,
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

        symbols = self._lookup_symbols(query, exact=True, partial=True)
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

    @handle_exceptions
    def list_cross_references(self, name_or_address: str) -> list[CrossReferenceInfo]:
        """All references TO a symbol or address."""
        sym = self.find_symbol(name_or_address)
        rm = self.program.getReferenceManager()
        fm = self.program.getFunctionManager()
        refs: list[CrossReferenceInfo] = []

        for ref in rm.getReferencesTo(sym.getAddress()):
            from_func = fm.getFunctionContaining(ref.getFromAddress())
            refs.append(
                CrossReferenceInfo(
                    function_name=from_func.getName() if from_func else None,
                    from_address=str(ref.getFromAddress()),
                    to_address=str(ref.getToAddress()),
                    type=str(ref.getReferenceType()),
                )
            )
        return refs

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

    @handle_exceptions
    def search_strings(
        self, query: str, limit: int = 100
    ) -> tuple[list[StringInfo], int]:
        """
        Search defined strings using Ghidra's DefinedStringIterator.
        Simple case-insensitive substring match — no ChromaDB, no ML model.
        """
        try:
            from ghidra.program.util import DefinedStringIterator  # Ghidra >= 11.3.3

            iterator = DefinedStringIterator.forProgram(self.program)
        except ImportError:
            from ghidra.program.util import DefinedDataIterator  # Ghidra <= 11.3.2

            iterator = DefinedDataIterator.definedStrings(self.program)

        query_lc = query.lower()
        results: list[StringInfo] = []
        total = 0

        for data in iterator:
            try:
                val = str(data.getValue())
                if query_lc in val.lower():
                    total += 1
                    if len(results) < limit:
                        results.append(StringInfo(value=val, address=str(data.getAddress())))
            except Exception as e:
                logger.debug(f"Skipping string at {data.getAddress()}: {e}")

        return results, total

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
        if not mem.contains(addr):
            raise ValueError(f"Address {address} is not in mapped memory")

        buf = JByte[size]  # type: ignore[reportInvalidTypeArguments]
        n = mem.getBytes(addr, buf)
        data = bytes([b & 0xFF for b in buf[:n]]) if n > 0 else b""  # type: ignore

        return BytesReadResult(address=str(addr), size=len(data), data=data.hex())

    # -------------------------------------------------------------------------
    # Annotation / write-back tools
    # -------------------------------------------------------------------------

    @handle_exceptions
    def set_disassembly_comment(self, address: str, comment: str) -> str:
        """Set an EOL comment at an address (visible in the disassembly listing)."""
        from ghidra.program.model.listing import CodeUnit

        addr = self._parse_address(address)
        listing = self.program.getListing()

        def _do():
            listing.setComment(addr, CodeUnit.EOL_COMMENT, comment)
            return f"Set disassembly comment at {address}"

        return self._with_transaction(f"Set EOL comment at {address}", _do)

    @handle_exceptions
    def set_decompiler_comment(self, address: str, comment: str) -> str:
        """Set a PRE comment at an address (visible in the decompiler view as // comment)."""
        from ghidra.program.model.listing import CodeUnit

        addr = self._parse_address(address)
        listing = self.program.getListing()

        def _do():
            listing.setComment(addr, CodeUnit.PRE_COMMENT, comment)
            return f"Set decompiler comment at {address}"

        return self._with_transaction(f"Set PRE comment at {address}", _do)

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

    @handle_exceptions
    def rename_data(self, address: str, new_name: str) -> str:
        """Rename a data label at a given address."""
        from ghidra.program.model.symbol import SourceType

        addr = self._parse_address(address)
        listing = self.program.getListing()
        st = self.program.getSymbolTable()

        data = listing.getDataAt(addr)
        if data is None:
            raise ValueError(f"No defined data at address {address}")

        def _do():
            sym = data.getPrimarySymbol()
            if sym is not None:
                sym.setName(new_name, SourceType.USER_DEFINED)
            else:
                st.createLabel(addr, new_name, SourceType.USER_DEFINED)
            return f"Renamed data at {address} → '{new_name}'"

        return self._with_transaction(f"Rename data at {address}", _do)

    @handle_exceptions
    def rename_variable(
        self, function_name_or_address: str, old_var_name: str, new_var_name: str
    ) -> str:
        """Rename a local variable within a function (uses the decompiler's high-level model)."""
        from ghidra.program.model.pcode import HighFunctionDBUtil
        from ghidra.program.model.symbol import SourceType
        from ghidra.util.task import ConsoleTaskMonitor

        func = self.find_function(function_name_or_address)

        # Decompile to get the HighFunction with local variable info
        result = self.decompiler.decompileFunction(func, 30, ConsoleTaskMonitor())
        if result.getErrorMessage() != "":
            raise RuntimeError(
                f"Decompilation failed for '{func.getName()}': {result.getErrorMessage()}"
            )

        high_func = result.getHighFunction()
        local_map = high_func.getLocalSymbolMap()
        target_sym = None

        for sym in local_map.getSymbols():
            if sym.getName() == old_var_name:
                target_sym = sym
                break

        if target_sym is None:
            available = [s.getName() for s in local_map.getSymbols()]
            raise ValueError(
                f"Variable '{old_var_name}' not found in '{func.getName()}'. "
                f"Available: {available}"
            )

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

        def _do():
            cmd = ApplyFunctionSignatureCmd(
                func.getEntryPoint(), parsed, SourceType.USER_DEFINED
            )
            cmd.applyTo(self.program, ConsoleTaskMonitor())
            return f"Set prototype for '{func.getName()}': {prototype}"

        return self._with_transaction(f"Set prototype for {func.getName()}", _do)

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
        from ghidra.util.task import ConsoleTaskMonitor

        func = self.find_function(function_name_or_address)
        data_type = self._resolve_data_type(new_type)

        # Decompile to get HighFunction
        result = self.decompiler.decompileFunction(func, 30, ConsoleTaskMonitor())
        if result.getErrorMessage() != "":
            raise RuntimeError(
                f"Decompilation failed for '{func.getName()}': {result.getErrorMessage()}"
            )

        high_func = result.getHighFunction()
        local_map = high_func.getLocalSymbolMap()
        target_sym = None

        for sym in local_map.getSymbols():
            if sym.getName() == var_name:
                target_sym = sym
                break

        if target_sym is None:
            available = [s.getName() for s in local_map.getSymbols()]
            raise ValueError(
                f"Variable '{var_name}' not found in '{func.getName()}'. "
                f"Available: {available}"
            )

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
            raise RuntimeError(
                "ghidrecomp is required for callgraph generation. "
                "Install it with: pip install ghidrecomp"
            ) from e

        func = self.find_function(function_name_or_address)
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
            if CallGraphDisplayType(graph_type) == cg_display_type:
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
        )
