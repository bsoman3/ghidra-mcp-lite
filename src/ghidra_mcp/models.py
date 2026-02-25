from enum import Enum

from pydantic import BaseModel, Field


class DecompiledFunction(BaseModel):
    name: str = Field(..., description="The name and entry point of the function.")
    code: str = Field(..., description="Pseudo-C decompilation output.")
    signature: str | None = Field(None, description="Function signature.")


class FunctionInfo(BaseModel):
    name: str = Field(..., description="Fully-qualified function name.")
    address: str = Field(..., description="Entry point address.")
    signature: str | None = Field(None, description="Function signature.")
    external: bool = Field(False, description="Whether this is an external/thunk function.")


class FunctionList(BaseModel):
    functions: list[FunctionInfo] = Field(..., description="List of functions.")
    total: int = Field(..., description="Total matching functions (before pagination).")


class ProgramInfo(BaseModel):
    name: str = Field(..., description="Program name in the Ghidra project.")
    file_path: str | None = Field(None, description="Path to the binary on disk.")
    load_time: float | None = Field(None, description="Unix timestamp when the program was loaded.")
    analysis_complete: bool = Field(..., description="True if Ghidra analysis has finished.")
    metadata: dict = Field(..., description="Program metadata from Ghidra.")


class ProgramInfos(BaseModel):
    programs: list[ProgramInfo] = Field(..., description="All programs in the project.")


class ExportInfo(BaseModel):
    name: str = Field(..., description="Export name.")
    address: str = Field(..., description="Export address.")


class ExportInfos(BaseModel):
    exports: list[ExportInfo]


class ImportInfo(BaseModel):
    name: str = Field(..., description="Import name.")
    library: str = Field(..., description="Source library.")


class ImportInfos(BaseModel):
    imports: list[ImportInfo]


class CrossReferenceInfo(BaseModel):
    function_name: str | None = Field(None, description="Function containing the reference.")
    from_address: str = Field(..., description="Address the reference originates from.")
    to_address: str = Field(..., description="Address being referenced.")
    type: str = Field(..., description="Reference type (e.g. UNCONDITIONAL_CALL).")


class CrossReferenceInfos(BaseModel):
    cross_references: list[CrossReferenceInfo]


class SymbolInfo(BaseModel):
    name: str = Field(..., description="Symbol name.")
    address: str = Field(..., description="Symbol address.")
    type: str = Field(..., description="Symbol type (Function, Label, etc.).")
    namespace: str = Field(..., description="Parent namespace.")
    source: str = Field(..., description="Symbol source (USER_DEFINED, ANALYSIS, etc.).")
    refcount: int = Field(..., description="Number of references to this symbol.")
    external: bool = Field(..., description="Whether this is an external symbol.")


class SymbolSearchResults(BaseModel):
    symbols: list[SymbolInfo]


class StringInfo(BaseModel):
    value: str = Field(..., description="String value.")
    address: str = Field(..., description="Address of the string in the binary.")


class StringSearchResults(BaseModel):
    strings: list[StringInfo] = Field(..., description="Matching strings (up to limit).")
    total: int = Field(..., description="Total matches found (may exceed returned count).")


class BytesReadResult(BaseModel):
    address: str = Field(..., description="Normalized address bytes were read from.")
    size: int = Field(..., description="Number of bytes actually read.")
    data: str = Field(..., description="Raw bytes as a hex string.")


class CallGraphDirection(str, Enum):
    CALLING = "calling"
    CALLED = "called"


class CallGraphDisplayType(str, Enum):
    FLOW = "flow"
    FLOW_ENDS = "flow_ends"
    MIND = "mind"


class CallGraphResult(BaseModel):
    function_name: str = Field(..., description="Function the graph was generated for.")
    direction: CallGraphDirection
    display_type: CallGraphDisplayType
    graph: str = Field(..., description="MermaidJS graph string.")
    mermaid_url: str = Field(..., description="MermaidJS live preview URL.")


# ─── New models ───────────────────────────────────────────────────────────────


class MemorySegment(BaseModel):
    name: str = Field(..., description="Segment name (e.g. '.text', '.data').")
    start: str = Field(..., description="Start address.")
    end: str = Field(..., description="End address (inclusive).")
    size: int = Field(..., description="Size in bytes.")
    permissions: str = Field(..., description="Permission flags: r/w/x combination.")
    type: str = Field(..., description="Block type (DEFAULT, BIT_MAPPED, BYTE_MAPPED, etc.).")
    initialized: bool = Field(..., description="Whether the segment has initialized data.")


class MemorySegments(BaseModel):
    segments: list[MemorySegment]


class DataItem(BaseModel):
    label: str = Field(..., description="Label name (or address if unnamed).")
    address: str = Field(..., description="Address of the data item.")
    type: str = Field(..., description="Data type name (e.g. 'char *', 'dword', 'struct Foo').")
    value: str = Field(..., description="String representation of the value.")


class DataItems(BaseModel):
    items: list[DataItem] = Field(..., description="Defined data items (up to limit).")
    total: int = Field(..., description="Total defined data items (before pagination).")


class NamespaceInfo(BaseModel):
    name: str = Field(..., description="Fully-qualified namespace name.")
    type: str = Field(..., description="Namespace kind (Namespace, Class, Library, etc.).")
    parent: str = Field(..., description="Parent namespace name.")


class NamespaceList(BaseModel):
    namespaces: list[NamespaceInfo] = Field(..., description="Namespaces (up to limit).")
    total: int = Field(..., description="Total namespaces (before pagination).")


class DisassemblyLine(BaseModel):
    address: str = Field(..., description="Instruction address.")
    bytes: str = Field(..., description="Raw instruction bytes as hex string.")
    mnemonic: str = Field(..., description="Instruction mnemonic (e.g. MOV, CALL, JMP).")
    operands: str = Field(..., description="Operand string.")
    comment: str | None = Field(None, description="EOL comment if set.")


class DisassemblyResult(BaseModel):
    function_name: str = Field(..., description="Function name.")
    address: str = Field(..., description="Function entry point address.")
    instructions: list[DisassemblyLine] = Field(..., description="All instructions in the function body.")
