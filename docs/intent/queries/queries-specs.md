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

- [x] **QRY-029**: When `decompile_function`, `disassemble_function`, `gen_callgraph`, or `list_cross_references` resolves its target from a loose match (RES-018, RES-019, RES-020), the system shall include resolution's disclosure note in the result's `resolution` field.

## Query Contract

- [x] **QRY-027**: The system shall not modify the program, its annotations, or the project while executing any query tool.
- [x] **QRY-028**: The system shall return every query tool's result as a typed response model defined in `models.py`.
