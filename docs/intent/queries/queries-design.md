---
parent: high-level-design
prefix: QRY
---

# Queries

*Code references name symbols in `src/ghidra_mcp/tools.py` (tool methods) and `src/ghidra_mcp/models.py` (response models) unless another file is given.*

## Context and Design Philosophy

Queries are the read side of the server: 16 MCP tools that let a client explore an analyzed binary (its functions, memory layout, data, symbols, strings, code, references, and call graphs) without changing it. Each tool runs against one `Program` that program-lifecycle has already let through its analysis gate. Each turns caller strings into Ghidra objects through resolution, and returns a pydantic model from `models.py`.

Principles:

- **Native Ghidra only.** All search uses Ghidra's own iterators and APIs, with no embeddings or vector index (README). This is what keeps the server light enough for a small VM.
- **Typed, self-describing results.** Every tool returns a model whose field descriptions double as the agent-facing contract. *[inferred]* This gives MCP clients structured output instead of free text.
- **Bounded where it's cheap to bound.** Most listings and searches take `limit` (and usually `offset`), and `read_bytes` is capped at 8192 bytes. Standardized bounding and ordering is deferred (HLD goal: bounded, stable responses).
- **Say what was resolved; mark what failed** (HLD tenets *Never guess for the caller*, *Explicit over silent*). A read whose target was resolved from a loose match states the resolution. A read that partly fails returns what succeeded, with each failed item marked (see Disclosure and Partial Results).

The MCP wrappers (parameter defaults, error mapping, tool descriptions) belong to server. Name and address resolution belongs to resolution. The per-program decompiler instance belongs to program-lifecycle.

## Tool Catalogue

This catalogue covers the 16 read-only binary tools owned by queries. The full 29-tool registry lives in the server LLD (`docs/intent/server/server-design.md`). That includes the 5 project-management tools (`list_project_binaries`, `list_project_binary_metadata`, `import_binary`, `delete_project_binary`, `reanalyze_binary`) and the 8 write-back tools.

| MCP tool | Implementation | Target resolution | Result model | Paging |
|---|---|---|---|---|
| `list_functions` | `list_functions` | n/a | `FunctionList` | offset/limit, total |
| `list_segments` | `list_segments` | n/a | `MemorySegments` | none |
| `list_data_items` | `list_data_items` | n/a | `DataItems` | offset/limit, total |
| `list_classes` | `list_classes` | n/a | `NamespaceList` | offset/limit, total |
| `list_namespaces` | `list_namespaces` | n/a | `NamespaceList` | offset/limit, total |
| `get_function_by_address` | `get_function_by_address` | `_parse_address` | `FunctionInfo` | n/a |
| `decompile_function` | `decompile_function_by_name_or_addr` | `resolve_function` (read) | `DecompiledFunction` | n/a |
| `disassemble_function` | `disassemble_function` | `resolve_function` (read) | `DisassemblyResult` | none |
| `search_symbols` | `search_symbols_by_name` | `_lookup_symbols` | `SymbolSearchResults` | offset/limit, no total |
| `list_imports` | `list_imports` | n/a (regex filter) | `ImportInfos` | offset/limit, no total |
| `list_exports` | `list_exports` | n/a (regex filter) | `ExportInfos` | offset/limit, no total |
| `list_cross_references` | `list_cross_references` | `resolve_reference_target` (read) | `CrossReferenceInfos` | none |
| `get_xrefs_from` | `get_xrefs_from` | `_parse_address` | `CrossReferenceInfos` | none |
| `search_strings` | `search_strings` | n/a (substring) | `StringSearchResults` | limit only, total |
| `read_bytes` | `read_bytes` | `_parse_address` | `BytesReadResult` | size 1–8192 |
| `gen_callgraph` | `gen_callgraph` | `resolve_function` (read) | `CallGraphResult` | n/a |

## Listings

- **Functions** — `get_all_functions(include_externals=False)`, which excludes external and thunk functions. An optional case-insensitive substring filter applies to the namespace-qualified name. Each entry carries the qualified name, entry address, `str(signature)`, and `external` (always false here). The list is fully materialized, then `total` is taken and the slice applied.
- **Segments** — one entry per memory block: name, start, inclusive end, size, permissions (`r`, `w`, `x` concatenated in that order, or `-` if none), block type, initialized flag.
- **Data items** — `listing.getDefinedData(True)`. The label falls back to the address string, the value to `str(getValue())` or `""`, and the type to the data type's name. The loop streams, collecting items after `offset` until `limit`. `total` counts every item read successfully; an item that raises is reported in `failures` (see Partial Results).
- **Classes** — non-dynamic symbols whose symbol type is `Class`: qualified name and parent namespace.
- **Namespaces** — non-dynamic symbols of type `Namespace`, `Class`, or `Library`.
- **Imports** — `symbolTable.getExternalSymbols()`. An optional case-insensitive `re.search` applies to the simple name. The library is the parent namespace.
- **Exports** — `getAllSymbols(True)` (includes dynamic symbols), filtered to external entry points, with the same optional regex filter: name and address.

## Searches

- **Strings** — `DefinedStringIterator.forProgram`, a case-insensitive substring match on `str(getValue())`. `total` counts every match, and the first `limit` matches are returned. A string whose value can't be read is reported in `failures`.
- **Symbols** — an empty query raises `ValueError("query is required")`. Matches come from resolution (`_lookup_symbols`: name matches, plus the symbols at the query's address when it parses as one). For every match, the reference count is the number of references to the symbol's address. Each entry carries the simple name, address, symbol type, parent namespace, source, and external flag. The `offset`/`limit` slice is applied afterwards, and no `total` is returned.

## Code Views

- **Function by address** — `_parse_address`, then `getFunctionAt`, falling back to `getFunctionContaining`. If neither finds one: `ValueError("No function at or containing address <a>")`.
- **Decompile** — `resolve_function` in read mode, then `decompiler.decompileFunction(func, 120, ConsoleTaskMonitor())` on the program's shared `DecompInterface`. On success, `code` is `getC()`, `signature` is the decompiled signature, and `name` is the full qualified name, `-`, then the entry address.
- **Disassemble** — `resolve_function` in read mode, then every instruction in the function body, in address order: address, hex bytes, mnemonic, operands (default representations joined by `", "`), and the EOL comment read through `listing.getComment(CommentType.EOL, addr)`.
- **Read bytes** — `size` must be 1–8192, else `ValueError`. Then `_parse_address`. The start address must lie in a memory block, else `ValueError("Address <a> is not in mapped memory")`, and that block must be initialized, else `ValueError` stating the memory is uninitialized. Reads into a Java byte buffer and returns the normalized address, the count actually read, the requested size, and hex data. `Memory.getBytes` returns fewer bytes than requested when the range runs past available memory, and throws only when the start address is in no memory block (verified against Ghidra's `Memory` javadoc).

## References

- **To** — `resolve_reference_target` (read mode; an address is its own target), then every reference to that address: the simple name of the function containing the *from* address (or `None`), from address, to address, and reference type.
- **From** — `_parse_address`, then every reference from that address: the simple name of the function containing the *to* address (or `None`), from, to, and type. The source function is the same for every reference from one address, so the target's function is the informative value; the field and tool descriptions say which function each tool reports.
- **Call graph** — a missing `ghidrecomp` raises `Stop("ghidrecomp is required…")`. Otherwise: `resolve_function` in read mode, then `ghidrecomp.callgraph.gen_callgraph(func, max_display_depth, direction, max_run_time, name=<qualified>, include_refs, condense_threshold, top_layers, bottom_layers, wrap_mermaid=False)`. The graph returned is the first entry whose type equals the requested display type; entries that are not display types (URLs, images) are skipped, and if none matches, `ValueError`. The Mermaid URL is the first line of the `mermaid_url` entry, or `""`. Defaults: `include_refs=True`, `max_depth=None`, `max_run_time=60`, `condense_threshold=50`, `top_layers=5`, `bottom_layers=5`.

## Disclosure and Partial Results

**Resolution disclosure.** `decompile_function`, `disassemble_function`, `gen_callgraph`, and `list_cross_references` resolve their target through resolution's read mode. Their results carry an optional `resolution` field. It holds resolution's note when the target came from a loose match (for example `'bar' resolved to Foo::bar @ 00401000 (partial name match)`), and is empty for an exact match.

**Partial results.** These tools return what succeeded and mark the rest:

| Tool | What can fail per item | Marker |
|---|---|---|
| `disassemble_function` | An instruction's bytes, operands, or comment | Per-line `errors` list (`"bytes: …"`, `"operands: …"`, `"comment: …"`); result-level `partial` flag |
| `list_data_items` | Reading one data item's label, value, or type | A `failures` list of address and error (`ItemFailure`); `partial` flag |
| `search_strings` | Reading one string's value | A `failures` list of address and error; `partial` flag |
| `read_bytes` | The range runs past available memory, so fewer bytes are read | `partial` flag plus `requested_size` and `size` |

**Whole-call failures.**
- A decompiler failure, or a decompiler result with neither a function nor an error message, fails the call as `stop`, carrying the decompiler's message.
- Decompilation is bounded at 120 s. A timeout is reported by the decompiler as an error, so it fails as `stop` like any decompiler failure.
- A `read_bytes` start address in uninitialized memory fails as `fix_input`, checked through the containing memory block's initialized flag before reading.
- An invalid import or export regex fails as `fix_input` (server, SRV-032).

## Pagination Contract

| Tool | `offset` | `limit` default (tool layer / server) | `total` | Where the slice happens |
|---|---|---|---|---|
| `list_functions` | yes | 100 / 100 | yes | after the full list is built |
| `list_data_items` | yes | 100 / 100 | yes | while streaming |
| `list_classes`, `list_namespaces` | yes | 100 / 100 | yes | after the full list is built |
| `search_symbols` | yes | 100 / 100 | no | after reference counts for all matches |
| `list_imports`, `list_exports` | yes | 25 / 25 | no | after the full list is built |
| `search_strings` | **no** | 100 / 100 | yes (all matches) | while streaming |
| `list_segments`, `list_cross_references`, `get_xrefs_from`, `disassemble_function` | no | n/a | n/a | not paginated |

No tool validates negative `offset` or `limit`.

## Response Models

Defined in `models.py` (except `ProgramInfo`/`ProgramInfos`, owned by server). Field contracts worth noting:

- `DecompiledFunction.code`: "Pseudo-C decompilation output." `name`: the function's qualified name and entry point.
- `DecompiledFunction`, `DisassemblyResult`, `CallGraphResult`, `CrossReferenceInfos`: optional `resolution` (loose-match disclosure).
- `DisassemblyLine.errors`, `DisassemblyResult.partial`; `DataItems.failures`/`partial`; `StringSearchResults.failures`/`partial`; `BytesReadResult.requested_size`/`partial` (partial results).
- `FunctionInfo.external`: "Whether this is an external/thunk function."
- `FunctionList.total`, `DataItems.total`, `NamespaceList.total`: totals before pagination. `StringSearchResults.total`: "may exceed returned count".
- `CrossReferenceInfo.function_name`: the source address's function for `list_cross_references`, the target address's function for `get_xrefs_from`.
- `BytesReadResult.size`: "Number of bytes actually read."
- `CallGraphDirection` ∈ {`calling`, `called`}; `CallGraphDisplayType` ∈ {`flow`, `flow_ends`, `mind`}.

## Decisions & Alternatives

| Decision | Chosen | Alternatives Considered | Rationale |
|----------|--------|------------------------|-----------|
| Search engine | Native Ghidra iterators and APIs | Embedding or vector search | Native Ghidra only, so it runs on small VMs. |
| String search | Case-insensitive substring over defined strings, with total match count | Regex; fuzzy matching | Simple and predictable for agents. |
| Import/export filtering | Case-insensitive regex | Substring, like the other tools | *[inferred]* Patterns like `mem.*`. |
| `list_functions` scope | Exclude externals and thunks, and document it | Include them | A listing of the binary's own code; imports have their own tool. |
| Decompiler | The program's shared `DecompInterface`, under the per-program lock; timeout 120 s | A decompiler per call; no timeout | Amortizes decompiler startup. A bound turns a hang into an explicit `stop`; 120 s allows large functions. |
| `get_xrefs_from` `function_name` | Report the function containing each reference's **target**, and document that meaning | Report the source function | The source function is the same for every reference from one address, so the target's function is the informative value. |
| Regex filters | Accept the risk of pathological patterns | Guard with a timeout or length limit | Authentication is out of scope, so callers are trusted. Python's `re` has no timeout, and a guard adds complexity for little gain. |
| Decompile failure | Fail the call as `stop` with the decompiler's message | Return the error text in `code` | HLD tenets *Explicit over silent* and *Actionable failures*: error text presented as pseudo-C misleads the caller. |
| Output label | Full qualified name, then `-<entry>` | Truncate to 50 characters | Accurate information; truncation can make distinct names look identical. |
| Partial failures | Return what succeeded with each failed item marked and a `partial` flag | Fail the whole call; skip silently | HLD tenet *Explicit over silent*, in the partial-result form chosen for the project. |
| Loose-match disclosure | An optional `resolution` field on target-taking read results | Disclose in a log or not at all | HLD tenet *Never guess for the caller*: a read may accept a loose match only if the response states it. |
| Result assembly | Tool methods return their response models, so markers and disclosure travel with the results | Return tuples for the server to wrap | Partial-result markers and notes are produced where the work happens. |
| `read_bytes` cap | 8192 bytes | Uncapped; configurable | *[inferred]* It bounds response size. |
| Call graphs | Delegate to `ghidrecomp`, as an optional dependency | Native implementation | `ghidrecomp` is an optional extra. |
| String iterator | `DefinedStringIterator` only | Feature-detect older APIs | Ghidra 12.1 is the minimum (HLD Goals). |

## Open Questions & Future Decisions

### Resolved
1. ✅ **`list_functions` scope** — keep excluding externals and thunks, and keep the `external` field as is. The tool description and README state the exclusion. (2026-10-03)
2. ✅ **Decompiler result with neither function nor error.** It fails as `stop` with an explanatory message. (2026-10-03)
3. ✅ **Disassembly degradation.** Per-line `errors` and a `partial` flag mark failed fields. (2026-10-03)
4. ✅ **Invalid regexes.** Classified as `fix_input` by the server (SRV-032). (2026-10-03)
5. ✅ **`read_bytes` partial reads.** `Memory.getBytes` returns fewer bytes rather than throwing when the range runs past memory (verified). The result marks this with a `partial` flag and both sizes; a start in uninitialized memory fails as `fix_input`. (2026-10-03)
6. ✅ **Call-graph entry coercion.** Non-display `ghidrecomp` entries are ignored. (2026-10-03)
7. ✅ **Label truncation.** The full qualified name is used. (2026-10-03)
8. ✅ **Decompile timeout.** 120 s. (2026-10-03)
9. ✅ **Pathological regexes.** The risk is accepted; no guard. (2026-10-03)
10. ✅ **Dynamic symbols in exports.** Kept; consistent with resolution including dynamic symbols in search. (2026-10-03)
11. ✅ **Older-Ghidra fallback.** Removed; Ghidra 12.1 is the minimum. (2026-10-03)
12. ✅ **`get_xrefs_from` `function_name`.** Behavior kept (the target's function); the field and tool descriptions say so. (2026-10-03)

### Deferred
1. **Pagination contract.** `total` is returned for some tools but not others, `search_strings` has no `offset`, and negative `offset`/`limit` values are not validated. Part of the HLD's bounded, stable responses goal.
2. **Unbounded outputs.** `list_cross_references`, `get_xrefs_from`, and `disassemble_function` return everything. Part of the same goal.
3. **`search_symbols` cost and shape.** Reference counts are computed for every match before pagination, there is no `total`, and the order is discovery order. Part of the same goal.
4. **Full scans per call.** Strings, data items, and symbols are scanned in full on every call. Part of the same goal.

### Open (observed behavior, intent unstated)
*(none)*

### Known gaps against stated intent
*(none)*

## References

- Code: `src/ghidra_mcp/tools.py` (the read-only tool methods, `_func_label`, `gen_callgraph`); `src/ghidra_mcp/models.py`
- Depends on: resolution (`resolve_function`, `resolve_reference_target`, `_lookup_symbols`, `_parse_address`, `get_all_functions`); program-lifecycle (the program's decompiler)
- Called by: server (MCP wrappers)
- External: Ghidra `Listing`, `CommentType`, `Memory`, `SymbolTable`, `ReferenceManager`, `FunctionManager`, `DecompInterface`, `DefinedStringIterator`; `ghidrecomp.callgraph`; `jpype.JByte`; `pydantic`
- Arrow: `docs/arrows/queries.md`
