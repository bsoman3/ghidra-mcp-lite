---
parent: high-level-design
prefix: QRY
---

# Queries

*Code references name symbols in `src/ghidra_mcp/tools.py` (tool methods) and `src/ghidra_mcp/models.py` (response models) unless another file is given.*

## Context and Design Philosophy

Queries are the read side of the server: 22 MCP tools that let a client explore an analyzed binary (its functions, memory layout, data, symbols, strings, code, references, call relations, call graphs, p-code, and data flow) and compare functions, without changing anything. Each tool runs against one `Program` that program-lifecycle has already let through its analysis gate. Each turns caller strings into Ghidra objects through resolution, and returns a pydantic model from `models.py`.

Principles:

- **Native Ghidra only.** All search uses Ghidra's own iterators and APIs, with no embeddings or vector index (README). This is what keeps the server light enough for a small VM.
- **Typed, self-describing results.** Every tool returns a model whose field descriptions double as the agent-facing contract. *[inferred]* This gives MCP clients structured output instead of free text.
- **Bounded where it's cheap to bound.** Most listings and searches take `limit` (and usually `offset`). `list_functions` returns at most 500 functions per page and `read_bytes` at most 8192 bytes; larger requests fail as `fix_input`. Standardized bounding and ordering is deferred (HLD goal: bounded, stable responses).
- **Say what was resolved; mark what failed** (HLD tenets *Never guess for the caller*, *Explicit over silent*). A read whose target was resolved from a loose match states the resolution. A read that partly fails returns what succeeded, with each failed item marked (see Disclosure and Partial Results).

The MCP wrappers (parameter defaults, error mapping, tool descriptions) belong to server. Name and address resolution belongs to resolution. The per-program decompiler instance belongs to program-lifecycle.

## Tool Catalogue

This catalogue covers the 22 read-only binary tools owned by queries. The full tool registry lives in the server LLD (`docs/intent/server/server-design.md`). That includes the 5 project-management tools (`list_project_binaries`, `list_project_binary_metadata`, `import_binary`, `delete_project_binary`, `reanalyze_binary`) and the 8 write-back tools.

| MCP tool | Implementation | Target resolution | Result model | Paging |
|---|---|---|---|---|
| `list_functions` | `list_functions` | n/a | `FunctionList` | offset/limit (1–500), total |
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
| `get_function_callers` | `get_function_callers` | `resolve_function` (read) | `FunctionCallers` | none |
| `get_function_callees` | `get_function_callees` | `resolve_function` (read) | `FunctionCallees` | none |
| `diff_functions` | `diff_functions` | `resolve_function` (read), each side in its own binary | `FunctionDiff` | n/a |
| `find_similar_functions_fuzzy` | `find_similar_functions_fuzzy` | `resolve_function` (read) | `SimilarFunctions` | `limit` |
| `get_function_pcode` | `get_function_pcode` | `resolve_function` (read) | `FunctionPcode` | `max_ops`, with `truncated` |
| `analyze_dataflow` | `analyze_dataflow` | `resolve_function` (read); variable by exact name | `DataflowResult` | `max_ops`, with `truncated` |

## Listings

- **Functions** — `get_all_functions(include_externals=False)`, which excludes external and thunk functions. An optional case-insensitive substring filter applies to the namespace-qualified name. Each entry carries the qualified name, entry address, `str(signature)`, and `external` (always false here). The list is fully materialized, then `total` is taken and the slice applied. A page holds 100 functions by default and at most 500: a `limit` outside 1–500 raises `ValueError` saying to page with `offset`, so it fails as `fix_input`. An `offset` at or past `total` returns an empty page with the real `total`, which tells the caller it has reached the end.
- **Segments** — one entry per memory block: name, start, inclusive end, size, permissions (`r`, `w`, `x` concatenated in that order, or `-` if none), block type, initialized flag.
- **Data items** — `listing.getDefinedData(True)`. The label falls back to the address string, the value to `str(getValue())` or `""`, and the type to the data type's name. The loop streams, collecting items after `offset` until `limit`. `total` counts every item read successfully; an item that raises is reported in `failures` (see Partial Results).
- **Classes** — non-dynamic symbols whose symbol type is `Class`: qualified name and parent namespace.
- **Namespaces** — non-dynamic symbols of type `Namespace`, `Class`, or `Library`.
- **Imports** — `symbolTable.getExternalSymbols()`. An optional case-insensitive `re.search` applies to the simple name. The library is the parent namespace.
- **Exports** — `getAllSymbols(True)` (includes dynamic symbols), filtered to external entry points, with the same optional regex filter: name and address. Ghidra's external entry points are the binary's entry points: its exports and the program entry (observed: `entry` and `_main` for a Mach-O executable).

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

## Call Relations, Comparison, P-code, and Data Flow

- **Callers** (`get_function_callers`) — the references *to* the function's entry, and to the entries of thunks that forward to it (`getFunctionThunkAddresses(true)`), whose reference type is a call. They are grouped by the function containing each call site: each caller is listed once with its name, entry address, and call-site addresses. Call sites outside any function form one group without a function.
- **Callees** (`get_function_callees`) — for every instruction in the function body, its call references, grouped by target: each callee is listed once with its name, entry address, call-site addresses, and, for a thunk, the qualified name of the function it forwards to. A call instruction whose flow is computed and that has no call reference is listed in `indirect_call_sites`, so unresolved indirect calls are visible rather than missing.
- **Diff** (`diff_functions`) — compares two functions, in the same binary or in two binaries (`other_binary_name`), as decompiled C (`view="decompiled"`, the default) or as disassembly (`view="disassembly"`: one `mnemonic operands` line per instruction, without addresses or bytes). With `normalize` (default on), Ghidra's address-derived default names (`FUN_…`, `DAT_…`, `LAB_…`, `PTR_…`, `switchD_…`, and string labels `s_…`/`u_…` that end in an address), hexadecimal literals of four or more digits, and each function's own name are replaced by placeholders, so functions compared across binaries or locations are not flooded with address noise. The result carries a unified diff (`context_lines`, default 3), a similarity ratio (`difflib.SequenceMatcher` over lines, 0–1), and whether the normalized texts are identical. Each side's resolution note is reported. A decompiler failure is `stop`, as for `decompile_function`.
- **Fuzzy similarity** (`find_similar_functions_fuzzy`) — ranks the functions of a binary (`target_binary_name`, default the query's own binary) by similarity to the query function. Each function's feature is the multiset of 3-grams of its instruction mnemonics, in address order, with operands ignored (a function shorter than three instructions contributes its whole mnemonic sequence as one gram). Similarity is the multiset Jaccard index, `Σ min / Σ max` of gram counts, 0–1. Candidates are non-external, non-thunk functions whose instruction count is within half to double the query's; the query itself is excluded. Matches at or above `min_similarity` (default 0.5) are returned, highest first (ties by address), up to `limit` (default 10), with each match's instruction count, the number of functions scanned, and the method used. Features are computed once per program and kept until the binary is next analyzed.
- **P-code** (`get_function_pcode`) — `form="raw"` (the default) lists each instruction's p-code operations (`Instruction.getPcode()`), in address order; `form="high"` lists the decompiler's high p-code (`HighFunction.getPcodeOps()`), decompiling with the 120-second limit. Each operation has its address, sequence number, mnemonic, and Ghidra's text form. At most `max_ops` operations (1–20000, default 2000) are returned; `total_ops` counts all, and `truncated` marks a cut list.
- **Data flow** (`analyze_dataflow`) — decompiles the function (120 seconds), finds the named variable among the decompiler's local symbols (parameters and locals) by exact, case-sensitive name, and returns the backward slice (`direction="backward"`, the default: the operations that contribute to the variable) or forward slice (the operations it influences), from Ghidra's `DecompilerUtils` slice functions over every instance of the variable. Operations are deduplicated and ordered by address and sequence number; the result also lists the names of the variables those operations read or write. `max_ops` (1–5000, default 500) bounds the list as for p-code. An unknown variable fails as `fix_input`, listing the available names; a variable with no data flow in the decompiler output (no high variable) also fails as `fix_input`.

**Two binaries in one call.** `diff_functions` and `find_similar_functions_fuzzy` may read two binaries. Both pass program-lifecycle's gate, and the server takes both programs' locks in pathname order before the call, so two such calls on the same pair can never deadlock.

## Disclosure and Partial Results

**Resolution disclosure.** `decompile_function`, `disassemble_function`, `gen_callgraph`, `list_cross_references`, `get_function_callers`, `get_function_callees`, `find_similar_functions_fuzzy`, `get_function_pcode`, and `analyze_dataflow` resolve their target through resolution's read mode, and `diff_functions` resolves two. Their results carry an optional `resolution` field (`resolution_a`/`resolution_b` for a diff). It holds resolution's note when the target came from a loose match (for example `'bar' resolved to Foo::bar @ 00401000 (partial name match)`), and is empty for an exact match.

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
| `list_functions` | yes | 100 / 100, at most 500 | yes | after the full list is built |
| `list_data_items` | yes | 100 / 100 | yes | while streaming |
| `list_classes`, `list_namespaces` | yes | 100 / 100 | yes | after the full list is built |
| `search_symbols` | yes | 100 / 100 | no | after reference counts for all matches |
| `list_imports`, `list_exports` | yes | 25 / 25 | no | after the full list is built |
| `search_strings` | **no** | 100 / 100 | yes (all matches) | while streaming |
| `list_segments`, `list_cross_references`, `get_xrefs_from`, `disassemble_function` | no | n/a | n/a | not paginated |

`list_functions` rejects a `limit` outside 1–500. No other tool validates `limit`, and no tool validates a negative `offset`.

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
- `FunctionCallers`/`FunctionCallees` list `CallRelation`s (name, address, call sites, and for callees `thunk_of`); `FunctionCallees.indirect_call_sites` marks unresolved indirect calls.
- `FunctionDiff`, `SimilarFunctions`, `FunctionPcode` (with `PcodeOpInfo`), and `DataflowResult` as described above; `truncated` and `total_ops` mark a bounded list.

## Decisions & Alternatives

| Decision | Chosen | Alternatives Considered | Rationale |
|----------|--------|------------------------|-----------|
| Search engine | Native Ghidra iterators and APIs | Embedding or vector search | Native Ghidra only, so it runs on small VMs. |
| String search | Case-insensitive substring over defined strings, with total match count | Regex; fuzzy matching | Simple and predictable for agents. |
| Import/export filtering | Case-insensitive regex | Substring, like the other tools | *[inferred]* Patterns like `mem.*`. |
| `list_functions` scope | Exclude externals and thunks, and document it | Include them | A listing of the binary's own code; imports have their own tool. |
| `list_functions` page size | At most 500 functions per page; a `limit` outside 1–500 fails as `fix_input`, saying to page with `offset` | No cap; clamp a larger `limit` to 500 | Programs hold thousands of functions (Go binaries over 5,000), and one uncapped call floods an agent's context. Failing explicitly follows *Explicit over silent*: a clamped page looks complete unless the caller checks `total`. 500 keeps a page within an agent's context while a full listing takes a handful of calls. |
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
| Callers through thunks | Include call sites that reach the function through its thunks | Only direct references to its entry | Calls to imported and forwarded functions go through thunks; omitting them would hide most callers of such functions. |
| Indirect calls | List computed calls without a resolved target as `indirect_call_sites` | Omit them | HLD tenet *Explicit over silent*: an unresolved call is a known gap, not an absence. |
| Diff text | Decompiled C by default, disassembly on request, both normalized for address-derived names | Raw text only; p-code | Decompiled C is what analysts compare; normalization keeps cross-binary diffs readable. Raw comparison remains available with `normalize=false`. |
| Fuzzy similarity | Multiset Jaccard of mnemonic 3-grams, size-prefiltered, cached per program | BSim; Function ID hashes; embeddings | BSim needs a database and Function ID matches only near-identical bodies; embeddings are a non-goal. The heuristic is transparent (the method is reported), cheap, and tolerant of small edits. |
| P-code size | `max_ops` with `total_ops` and `truncated` | Unbounded | P-code is several times the size of disassembly; a cheap explicit bound keeps responses usable (HLD tenet *Explicit over silent*). |
| Data-flow variable matching | Exact, case-sensitive decompiler names, listing candidates on a miss | Loose matching | Variable names like `local_10`/`local_100` collide under partial matching; exact names are what the decompiler shows. |
| Two-binary locking | Both programs' locks, in pathname order, taken by the server | Lock one program at a time | Reads of both programs must not interleave with writes or analysis; a fixed order prevents deadlock. |

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
1. **Pagination contract.** `total` is returned for some tools but not others, `search_strings` has no `offset`, `limit` is capped only for `list_functions`, and negative `offset` values are not validated. Part of the HLD's bounded, stable responses goal.
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
