# Queries Specs

**LLD**: docs/intent/queries/queries-design.md
**Implementing artifacts**:
- src/ghidra_mcp/tools.py (read-only tool methods, `_func_label`, `gen_callgraph`)
- src/ghidra_mcp/models.py (response models, except `ProgramInfo`/`ProgramInfos`)

Status markers: `[x]` implemented · `[ ]` active gap · `[D]` deferred

*Tests: `tests/test_queries.py` (and `tests/test_category_guards.py` for QRY-025), with end-to-end checks in `tests/integration/test_ghidra_smoke.py`.*

---

## Listings

- [x] **QRY-001**: When listing functions, the system shall return each function defined in the binary, excluding external and thunk functions, with its namespace-qualified name, entry address, and signature.
- [x] **QRY-002**: Where a name filter is supplied to the function listing, the system shall return only functions whose qualified name contains the filter case-insensitively.
- [x] **QRY-003**: When listing functions, the system shall report the total number of matching functions before pagination and return the page selected by offset and limit.
- [x] **QRY-004**: When listing memory segments, the system shall return every memory block with its name, start address, inclusive end address, size, permissions as an `r`/`w`/`x` string (or `-` if none), block type, and initialized flag.
- [x] **QRY-005**: When listing defined data items, the system shall return each item's label (or its address when it has no label), address, data type name, and string value (empty when it has none), paged by offset and limit, together with the total number of defined data items read successfully.
- [x] **QRY-006**: When listing classes, the system shall return every class namespace with its qualified name and parent namespace, paged by offset and limit, together with the total number of classes.
- [x] **QRY-007**: When listing namespaces, the system shall return every namespace, class, and library with its qualified name, kind, and parent namespace, paged by offset and limit, together with the total number found.
- [x] **QRY-008**: When listing imports, the system shall return each external symbol's name and source library, filtered by a case-insensitive regular expression when one is given, paged by offset and limit.
- [x] **QRY-009**: When listing exports, the system shall return each external entry point's name and address, filtered by a case-insensitive regular expression when one is given, paged by offset and limit.
- [x] **QRY-031**: If reading a defined data item fails while listing data items, then the system shall include that item in a `failures` list with its address and error, and mark the result `partial`.

## Searches

- [x] **QRY-010**: When searching strings, the system shall return defined strings whose value contains the query case-insensitively, up to the limit, and report the total number of matches, including those beyond the limit.
- [x] **QRY-011**: The system shall search strings with Ghidra's native `DefinedStringIterator`.
- [x] **QRY-012**: If a symbol search query is empty, then the system shall raise a `ValueError`.
- [x] **QRY-013**: When searching symbols, the system shall return, for each matching symbol (matching rules: RES-013), its name, address, symbol type, parent namespace, source, external flag, and the number of references to its address, paged by offset and limit.
- [x] **QRY-032**: If reading a defined string's value fails during a string search, then the system shall include it in a `failures` list with its address and error, and mark the result `partial`.

## Code Views

- [x] **QRY-014**: When looking up a function by address, the system shall return the function whose entry point is that address, or otherwise the function containing it, with its qualified name, entry address, signature, and external flag.
- [x] **QRY-015**: If no function starts at or contains the address given to a function-by-address lookup, then the system shall raise a `ValueError`.
- [x] **QRY-016**: When decompilation of a function succeeds, the system shall return its pseudo-C code, its decompiled signature, and a label combining the function's full qualified name and entry address.
- [x] **QRY-017**: If decompilation of a function fails, then the system shall fail the call as `stop`, carrying the decompiler's message, rather than returning the message as pseudo-C code.
- [x] **QRY-035**: If the decompiler returns neither a decompiled function nor an error message, then the system shall fail the call as `stop`, stating that decompilation produced no result.
- [x] **QRY-038**: When decompiling a function for `decompile_function`, the system shall limit decompilation to 120 seconds.
- [x] **QRY-018**: When disassembling a function, the system shall return every instruction in the function body in address order, each with its address, raw bytes as hex, mnemonic, operands, and end-of-line comment when present.
- [x] **QRY-030**: If reading an instruction's bytes, operands, or comment fails during disassembly, then the system shall record the failure in that line's `errors` list and mark the result `partial`.
- [x] **QRY-037**: When reading end-of-line comments during disassembly, the system shall use Ghidra's `CommentType` API rather than the int-constant overloads deprecated for removal since Ghidra 11.4.
- [x] **QRY-019**: When reading bytes, the system shall accept sizes from 1 to 8192 and return the normalized start address, the number of bytes read, and the bytes as hex.
- [x] **QRY-020**: If a byte-read size is outside 1–8192, or its start address is not in the program's memory, then the system shall raise a `ValueError`.
- [x] **QRY-033**: When a byte read returns fewer bytes than requested, the system shall mark the result `partial` and report both the requested and the actual size.
- [x] **QRY-034**: If a byte read's start address lies in a memory block that is not initialized, then the system shall raise a `ValueError` stating that the memory is uninitialized, before attempting the read.

## References

- [x] **QRY-021**: When listing cross-references to a target (`list_cross_references`), the system shall return every reference to the target's address with its source address, target address, reference type, and the name of the function containing the source address (or none).
- [x] **QRY-022**: When listing references from an address (`get_xrefs_from`), the system shall return every reference originating at that address with its source address, target address, and reference type.
- [x] **QRY-023**: The `get_xrefs_from` tool description and the `CrossReferenceInfo.function_name` field description shall state that, for `get_xrefs_from`, `function_name` is the function containing each reference's target address, and for `list_cross_references` the function containing its source address.
- [x] **QRY-024**: Where `ghidrecomp` is installed, when generating a call graph for a function, the system shall return a MermaidJS graph in the requested direction (`calling` or `called`) and display type (`flow`, `flow_ends`, or `mind`), together with a Mermaid live-preview URL when `ghidrecomp` provides one.
- [x] **QRY-025**: If `ghidrecomp` is not installed when a call graph is requested, then the system shall raise an error stating that `ghidrecomp` is required.
- [x] **QRY-026**: If `ghidrecomp`'s output contains no graph of the requested display type, then the system shall raise a `ValueError`.
- [x] **QRY-036**: When selecting the requested display type from `ghidrecomp`'s output, the system shall ignore entries that are not display types.

## Resolution Disclosure

- [x] **QRY-029**: When `decompile_function`, `disassemble_function`, `gen_callgraph`, `list_cross_references`, `get_function_callers`, `get_function_callees`, `find_similar_functions_fuzzy`, `get_function_pcode`, or `analyze_dataflow` resolves its target from a loose match (RES-018, RES-019, RES-020), the system shall include resolution's disclosure note in the result's `resolution` field; `diff_functions` shall report each side's note in `resolution_a` and `resolution_b`.

## Call Relations

- [x] **QRY-039**: When `get_function_callers` is called, the system shall return the functions whose call references reach the target function's entry or the entry of a thunk that forwards to it, each listed once with its qualified name, entry address, and call-site addresses, and shall group call sites outside any function into one entry without a function.
- [x] **QRY-040**: When `get_function_callees` is called, the system shall return the targets of the call references made from the function's instructions, each listed once with its qualified name, entry address, call-site addresses, and, for a thunk, the qualified name of the function it forwards to.
- [x] **QRY-041**: When `get_function_callees` finds a call instruction with computed flow and no call reference, the system shall list its address in `indirect_call_sites`.

## Function Comparison

- [x] **QRY-042**: When `diff_functions` is called, the system shall compare the two functions — the second in `other_binary_name` when given, else in the same binary — as decompiled C (`view="decompiled"`, the default) or as disassembly (`view="disassembly"`, one `mnemonic operands` line per instruction without addresses or bytes).
- [x] **QRY-043**: Where `diff_functions` is called with `normalize` set (the default), the system shall replace Ghidra's address-derived default names (`FUN_`, `DAT_`, `LAB_`, `PTR_`, or `switchD_` followed by hexadecimal digits, and string labels `s_…`/`u_…` ending in an address), hexadecimal literals of four or more digits, and each function's own name with placeholders before comparing.
- [x] **QRY-044**: When `diff_functions` compares two functions, the system shall return a unified diff with `context_lines` lines of context (default 3), the line-level similarity ratio from 0 to 1, and whether the compared texts are identical.
- [x] **QRY-045**: When `find_similar_functions_fuzzy` is called, the system shall score each candidate by the multiset Jaccard index of the instruction-mnemonic 3-grams of the candidate and the query function (a function of fewer than three instructions contributing its whole mnemonic sequence as one gram), and report the method used.
- [x] **QRY-046**: When `find_similar_functions_fuzzy` ranks candidates, the system shall consider the non-external, non-thunk functions of `target_binary_name` (default: the query's binary), excluding the query function and functions whose instruction count is outside half to double the query's, and return those scoring at least `min_similarity` (default 0.5), highest first and then by address, up to `limit` (default 10), with each one's instruction count and the number of functions scanned.
- [x] **QRY-047**: The system shall compute a program's similarity features at most once and keep them until the binary is next analyzed.

## P-code and Data Flow

- [x] **QRY-048**: When `get_function_pcode` is called, the system shall return the function's p-code operations — each instruction's p-code in address order (`form="raw"`, the default) or the decompiler's high p-code (`form="high"`, decompiled with a 120-second limit, a decompiler failure being `stop`) — each with its address, sequence number, mnemonic, and text.
- [x] **QRY-049**: When `get_function_pcode` or `analyze_dataflow` produces more operations than `max_ops`, the system shall return the first `max_ops`, report the total, and mark the result `truncated`. If `max_ops` is outside 1–20000 (p-code) or 1–5000 (data flow), then the system shall raise a `ValueError`.
- [x] **QRY-050**: When `analyze_dataflow` is called, the system shall decompile the function (120 seconds, a decompiler failure being `stop`), find the variable among the decompiler's local symbols by exact, case-sensitive name, and return the operations in its backward slice (`direction="backward"`, the default) or forward slice, over every instance of the variable, deduplicated and ordered by address and sequence number, together with the names of the variables those operations read or write.
- [x] **QRY-051**: If the variable given to `analyze_dataflow` is not among the decompiled function's local symbols, or has no data flow in the decompiler output, then the system shall raise a `ValueError`, listing the available variable names for an unknown variable.
- [x] **QRY-052**: When `diff_functions` or `find_similar_functions_fuzzy` reads two binaries, the system shall pass both through the analysis gate and hold both programs' locks, acquired in pathname order, for the duration of the call.

## Query Contract

- [x] **QRY-027**: The system shall not modify the program, its annotations, or the project while executing any query tool.
- [x] **QRY-028**: The system shall return every query tool's result as a typed response model defined in `models.py`.
