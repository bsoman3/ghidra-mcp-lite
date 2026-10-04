"""A small in-memory stand-in for a Ghidra Program, for tests of GhidraTools without a JVM.

Only the API surface the tools use is modelled. Addresses print like Ghidra's (8 hex digits).
"""

from __future__ import annotations

import sys
import types
from dataclasses import dataclass, field

from ghidra_mcp.context import LoadedProgram


class Addr:
    def __init__(self, offset: int, space: str = "ram"):
        self.offset = offset
        self.space = space

    def __str__(self):
        prefix = "" if self.space == "ram" else f"{self.space}:"
        return f"{prefix}{self.offset:08x}"

    __repr__ = __str__

    def __eq__(self, other):
        return isinstance(other, Addr) and (other.offset, other.space) == (self.offset, self.space)

    def __hash__(self):
        return hash((self.offset, self.space))

    def getOffset(self):  # noqa: N802
        return self.offset

    def add(self, n):
        return Addr(self.offset + n, self.space)


class AddressFactory:
    """Mirrors AddressFactory.getAddress(String): hex with optional 0x; None if unparseable."""

    def getAddress(self, text):  # noqa: N802
        digits = text[2:] if text.lower().startswith("0x") else text
        try:
            return Addr(int(digits, 16))
        except ValueError:
            return None


class Namespace:
    def __init__(self, name: str | None):
        self.name = name or "Global"

    def getName(self, qualified=False):  # noqa: N802
        return self.name

    def __str__(self):
        return self.name


class Symbol:
    def __init__(self, name, address, *, namespace=None, dynamic=False, external=False,
                 symbol_type="Label", source="ANALYSIS", entry_point=False):
        self.name = name
        self.address = address if isinstance(address, Addr) else Addr(address)
        self.namespace = namespace
        self.dynamic = dynamic
        self.external = external
        self.symbol_type = symbol_type
        self.source = source
        self.entry_point = entry_point

    def getName(self, qualified=False):  # noqa: N802
        return f"{self.namespace}::{self.name}" if qualified and self.namespace else self.name

    def getAddress(self):  # noqa: N802
        return self.address

    def isDynamic(self):  # noqa: N802
        return self.dynamic

    def isExternal(self):  # noqa: N802
        return self.external

    def getSymbolType(self):  # noqa: N802
        return self.symbol_type

    def getParentNamespace(self):  # noqa: N802
        return Namespace(self.namespace)

    def getSource(self):  # noqa: N802
        return self.source

    def isExternalEntryPoint(self):  # noqa: N802
        return self.entry_point

    def setName(self, name, source):  # noqa: N802
        if getattr(self, "reject", None) is not None:
            raise self.reject
        self.name, self.source = name, source


class Body:
    def __init__(self, start: Addr, size: int):
        self.start, self.size = start, size

    def contains(self, addr):
        return (addr.space == self.start.space
                and self.start.offset <= addr.offset < self.start.offset + self.size)

    def getMinAddress(self):  # noqa: N802
        return self.start

    def getMaxAddress(self):  # noqa: N802
        return self.start.add(self.size - 1)


class Function:
    def __init__(self, name, entry, size=0x40, *, namespace=None, thunk_of=None, external=False):
        space = "EXTERNAL" if external else "ram"
        self.entry = entry if isinstance(entry, Addr) else Addr(entry, space)
        self.symbol = Symbol(name, self.entry, namespace=namespace, symbol_type="Function",
                             external=external)
        self.size = size
        self.thunk_of = thunk_of
        self.external = external

    def __str__(self):
        return self.symbol.getName(True)

    def getName(self, qualified=False):  # noqa: N802
        return self.symbol.getName(qualified)

    def getSymbol(self):  # noqa: N802
        return self.symbol

    def getEntryPoint(self):  # noqa: N802
        return self.entry

    @property
    def entryPoint(self):  # noqa: N802 - JPype bean property
        return self.entry

    def getBody(self):  # noqa: N802
        return Body(self.entry, 0 if self.external else self.size)

    def isThunk(self):  # noqa: N802
        return self.thunk_of is not None

    @property
    def thunk(self):  # JPype bean property for isThunk()
        return self.isThunk()

    def isExternal(self):  # noqa: N802
        return self.external

    def getThunkedFunction(self, recursive):  # noqa: N802
        return self.thunk_of

    def getSignature(self):  # noqa: N802
        return f"undefined {self.symbol.getName(True)}(void)"

    def setName(self, name, source):  # noqa: N802
        self.symbol.setName(name, source)


class FunctionManager:
    def __init__(self, functions):
        self.functions = functions

    def getFunctions(self, forward):  # noqa: N802 - non-external functions, like Ghidra
        return iter(sorted((f for f in self.functions if not f.external),
                           key=lambda f: f.entry.offset))

    def getExternalFunctions(self):  # noqa: N802
        return iter([f for f in self.functions if f.external])

    def getFunctionAt(self, addr):  # noqa: N802
        return next((f for f in self.functions if f.entry == addr), None)

    def getFunctionContaining(self, addr):  # noqa: N802
        return next((f for f in self.functions if not f.external and f.getBody().contains(addr)),
                    None)


class SymbolTable:
    def __init__(self, symbols):
        self.symbols = symbols

    def getExternalSymbols(self):  # noqa: N802
        return iter([s for s in self.symbols if s.external])

    def getSymbols(self, addr):  # noqa: N802
        return [s for s in self.symbols if s.address == addr]

    def getAllSymbols(self, include_dynamic):  # noqa: N802
        return iter([s for s in self.symbols if include_dynamic or not s.dynamic])

    def getPrimarySymbol(self, addr):  # noqa: N802
        return next(iter(self.getSymbols(addr)), None)

    def createLabel(self, addr, name, source):  # noqa: N802
        label = Symbol(name, addr, source=source)
        self.symbols.append(label)
        return label


class MemoryBlock:
    def __init__(self, name, start, size, *, perms="r", initialized=True, data=None,
                 block_type="DEFAULT"):
        self.name, self.start, self.size = name, start if isinstance(start, Addr) else Addr(start), size
        self.perms, self.initialized, self.block_type = perms, initialized, block_type
        self.data = data if data is not None else bytes(range(256)) * (size // 256 + 1)

    def contains(self, addr):
        return addr.space == "ram" and self.start.offset <= addr.offset < self.start.offset + self.size

    def getName(self):  # noqa: N802
        return self.name

    def getStart(self):  # noqa: N802
        return self.start

    def getEnd(self):  # noqa: N802
        return self.start.add(self.size - 1)

    def getSize(self):  # noqa: N802
        return self.size

    def isRead(self):  # noqa: N802
        return "r" in self.perms

    def isWrite(self):  # noqa: N802
        return "w" in self.perms

    def isExecute(self):  # noqa: N802
        return "x" in self.perms

    def getType(self):  # noqa: N802
        return self.block_type

    def isInitialized(self):  # noqa: N802
        return self.initialized


class Memory:
    def __init__(self, blocks):
        self.blocks = [b if isinstance(b, MemoryBlock) else MemoryBlock(f"blk{i}", b[0], b[1])
                       for i, b in enumerate(blocks)]

    def contains(self, addr):
        return self.getBlock(addr) is not None

    def getBlock(self, addr):  # noqa: N802
        return next((b for b in self.blocks if b.contains(addr)), None)

    def getBlocks(self):  # noqa: N802
        return list(self.blocks)

    def getBytes(self, addr, buf):  # noqa: N802 - reads up to the end of the block
        block = self.getBlock(addr)
        if block is None:
            raise RuntimeError(f"Address {addr} not in memory")
        start = addr.offset - block.start.offset
        n = min(len(buf), block.size - start)
        for i in range(n):
            byte = block.data[start + i]
            buf[i] = byte - 256 if byte > 127 else byte  # Java bytes are signed
        return n


class DataType:
    def __init__(self, name, category="/"):
        self.name, self.category = name, category

    def getName(self):  # noqa: N802
        return self.name

    def getPathName(self):  # noqa: N802
        return f"{self.category.rstrip('/')}/{self.name}"

    def __repr__(self):
        return f"DataType({self.getPathName()})"


class DataTypeManager:
    def __init__(self, types_=()):
        self.types = list(types_)

    def getDataType(self, path):  # noqa: N802 - a lookup by full path
        return next((t for t in self.types if t.getPathName() == path), None)

    def getAllDataTypes(self):  # noqa: N802
        return iter(self.types)


class Data:
    """A defined data item; any attribute set to an Exception raises when read."""

    def __init__(self, address, *, label=None, value=None, type_name="undefined4", primary=None):
        self.address = address if isinstance(address, Addr) else Addr(address)
        self.label, self.value, self.type_name = label, value, type_name
        self.primary = primary

    def getPrimarySymbol(self):  # noqa: N802
        return self.primary

    def _get(self, value):
        if isinstance(value, Exception):
            raise value
        return value

    def getAddress(self):  # noqa: N802
        return self.address

    def getLabel(self):  # noqa: N802
        return self._get(self.label)

    def getValue(self):  # noqa: N802
        return self._get(self.value)

    def getDataType(self):  # noqa: N802
        return DataType(self._get(self.type_name))


class Instruction:
    """An instruction; bytes or operands set to an Exception raise when read."""

    def __init__(self, address, raw=b"\x90", mnemonic="NOP", operands=()):
        self.address = address if isinstance(address, Addr) else Addr(address)
        self.raw, self.mnemonic, self.operands = raw, mnemonic, operands

    def getAddress(self):  # noqa: N802
        return self.address

    def getBytes(self):  # noqa: N802
        if isinstance(self.raw, Exception):
            raise self.raw
        return [b - 256 if b > 127 else b for b in self.raw]

    def getMnemonicString(self):  # noqa: N802
        return self.mnemonic

    def getNumOperands(self):  # noqa: N802
        if isinstance(self.operands, Exception):
            raise self.operands
        return len(self.operands)

    def getDefaultOperandRepresentation(self, i):  # noqa: N802
        return self.operands[i]


class Listing:
    def __init__(self, program):
        self.program = program

    def getDefinedData(self, forward):  # noqa: N802
        return iter(self.program.defined_data)

    def getInstructions(self, body, forward):  # noqa: N802
        return iter(sorted((i for i in self.program.instructions if body.contains(i.address)),
                           key=lambda i: i.address.offset))

    def getComment(self, comment_type, addr):  # noqa: N802
        value = self.program.comments.get((comment_type, addr))
        if isinstance(value, Exception):
            raise value
        return value

    def setComment(self, addr, comment_type, text):  # noqa: N802
        if text is None:
            self.program.comments.pop((comment_type, addr), None)
        else:
            self.program.comments[(comment_type, addr)] = text

    def getDataAt(self, addr):  # noqa: N802
        return next((d for d in self.program.defined_data if d.address == addr), None)


class Reference:
    def __init__(self, from_addr, to_addr, ref_type="UNCONDITIONAL_CALL"):
        self.from_addr, self.to_addr, self.ref_type = Addr(from_addr), Addr(to_addr), ref_type

    def getFromAddress(self):  # noqa: N802
        return self.from_addr

    def getToAddress(self):  # noqa: N802
        return self.to_addr

    def getReferenceType(self):  # noqa: N802
        return self.ref_type


class ReferenceManager:
    def __init__(self, references):
        self.references = references

    def getReferencesTo(self, addr):  # noqa: N802
        return iter([r for r in self.references if r.to_addr == addr])

    def getReferencesFrom(self, addr):  # noqa: N802
        return [r for r in self.references if r.from_addr == addr]


class HighSymbol:
    def __init__(self, name):
        self.name = name

    def getName(self):  # noqa: N802
        return self.name


class DecompileResult:
    def __init__(self, code=None, signature=None, error="", locals_=()):
        self.error = error
        self.locals = [HighSymbol(n) for n in locals_]
        self.decompiledFunction = (  # noqa: N815 - JPype bean property
            None if code is None else types.SimpleNamespace(getC=lambda: code, getSignature=lambda: signature)
        )

    def getErrorMessage(self):  # noqa: N802
        return self.error

    def getDecompiledFunction(self):  # noqa: N802
        return self.decompiledFunction

    def getHighFunction(self):  # noqa: N802
        symbols = self.locals
        return types.SimpleNamespace(
            getLocalSymbolMap=lambda: types.SimpleNamespace(getSymbols=lambda: iter(symbols))
        )


class FakeDecompiler:
    def __init__(self, result=None):
        self.result = result or DecompileResult("int main(void) { return 0; }", "int main(void)")
        self.calls = []

    def decompileFunction(self, func, timeout, monitor):  # noqa: N802
        self.calls.append((str(func), timeout))
        return self.result


@dataclass
class FakeProgram:
    functions: list = field(default_factory=list)
    symbols: list = field(default_factory=list)
    memory: list = field(default_factory=lambda: [(0x400000, 0x10000)])
    data_types: list = field(default_factory=list)
    defined_data: list = field(default_factory=list)
    instructions: list = field(default_factory=list)
    comments: dict = field(default_factory=dict)  # (comment type, Addr) -> text
    references: list = field(default_factory=list)
    strings: list = field(default_factory=list)  # Data items for DefinedStringIterator
    transactions: list = field(default_factory=list)
    commits: list = field(default_factory=list)  # one entry per ended transaction: committed?

    def __post_init__(self):
        # Every function has a symbol at its entry, as in Ghidra.
        self.symbols = [f.symbol for f in self.functions] + list(self.symbols)

    def getAddressFactory(self):  # noqa: N802
        return AddressFactory()

    def getFunctionManager(self):  # noqa: N802
        return FunctionManager(self.functions)

    def getSymbolTable(self):  # noqa: N802
        return SymbolTable(self.symbols)

    def getMemory(self):  # noqa: N802
        return Memory(self.memory)

    def getDataTypeManager(self):  # noqa: N802
        return DataTypeManager(self.data_types)

    def getListing(self):  # noqa: N802
        return Listing(self)

    def getReferenceManager(self):  # noqa: N802
        return ReferenceManager(self.references)

    def startTransaction(self, description):  # noqa: N802
        self.transactions.append(description)
        return len(self.transactions)

    def endTransaction(self, tx, commit):  # noqa: N802
        self.commits.append(commit)


class FakeProjectHandle:
    def __init__(self):
        self.saved = 0
        self.save_error = None

    def save(self, program):
        if self.save_error is not None:
            raise self.save_error
        self.saved += 1


class FakeJavaException(Exception):
    """Looks like a Java exception to errors.classify (getClass().getName(), getMessage())."""

    def __init__(self, java_class, message):
        super().__init__(message)
        self.java_class, self.message = java_class, message

    def getClass(self):  # noqa: N802
        return types.SimpleNamespace(getName=lambda: self.java_class)

    def getMessage(self):  # noqa: N802
        return self.message


def tools_for(program, decompiler=None):
    """A GhidraTools bound to a fake program, as the server builds one per call."""
    from ghidra_mcp.tools import GhidraTools

    entry = LoadedProgram(name="prog", pathname="/prog", project=FakeProjectHandle())
    entry.program = program
    entry.decompiler = decompiler
    return GhidraTools(entry)


def install_modules(monkeypatch, modules):
    """Install stub modules: {dotted name: {attribute: value}}; parents are created empty."""
    for name, attrs in modules.items():
        parts = name.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[:i])
            if parent not in sys.modules or not isinstance(sys.modules[parent], types.SimpleNamespace):
                monkeypatch.setitem(sys.modules, parent, types.SimpleNamespace())
        monkeypatch.setitem(sys.modules, name, types.SimpleNamespace(**attrs))


def install_cparser(monkeypatch, parse):
    """Stub ghidra.app.util.cparser.C.CParser with parse(text) -> DataType | None (or raise)."""

    class CParser:
        def __init__(self, dtm):
            self.dtm = dtm

        def parse(self, text):
            return parse(text)

    for name, attrs in {
        "ghidra": {}, "ghidra.app": {}, "ghidra.app.util": {}, "ghidra.app.util.cparser": {},
        "ghidra.app.util.cparser.C": {"CParser": CParser},
    }.items():
        monkeypatch.setitem(sys.modules, name, types.SimpleNamespace(**attrs))
