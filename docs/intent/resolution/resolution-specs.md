# Resolution Specs

**LLD**: docs/intent/resolution/resolution-design.md
**Implementing artifacts**:
- src/ghidra_mcp/tools.py (`ResolutionMode`, `Resolved`, `_parse_address`, `_resolve_data_type`, `resolve_function`, `find_function`, `resolve_reference_target`, `_lookup_symbols`, `get_all_functions`, `get_all_symbols`)

Status markers: `[x]` implemented · `[ ]` active gap · `[D]` deferred

*Tests: `tests/test_resolution.py`, with end-to-end checks in `tests/integration/test_ghidra_smoke.py`.*

*Modes: "read mode" is function or symbol resolution for read tools (`decompile_function`, `disassemble_function`, `gen_callgraph`, `list_cross_references`); "write mode" is resolution for write tools (`rename_function`, `rename_variable`, `set_function_prototype`, `set_local_variable_type`). A string "resolves as an address" to a function when a function starts at or contains that address, and, for a cross-reference target, when the address is in the program's memory or has symbols defined at it.*

---

## Address Parsing

- [x] **RES-001**: When parsing a caller-supplied value for an address-only tool parameter, the system shall accept a hex address with or without a `0x`/`0X` prefix.
- [x] **RES-002**: If a caller-supplied value for an address-only tool parameter cannot be parsed as an address, then the system shall raise a `ValueError` naming the invalid value.

## Function Resolution

- [x] **RES-003**: When resolving a function, in either mode, from a string that parses as the entry-point address of a function, the system shall return that function.
- [x] **RES-004**: When resolving a function, in either mode, by name and exactly one function's namespace-qualified name equals the query case-insensitively, the system shall return that function.
- [x] **RES-005**: If more than one function's qualified name equals the query case-insensitively, then the system shall raise a `ValueError` reporting the ambiguity and listing each candidate's name and entry address.
- [x] **RES-006**: If, when resolving a function in write mode, no function's qualified name equals the query but one or more contain it (case-insensitively), then the system shall raise a `ValueError` stating the function was not found and listing those candidates with entry addresses.
- [x] **RES-007**: If no function's qualified name equals or contains the query, then the system shall raise a `ValueError` stating the function was not found.
- [x] **RES-018**: When resolving a function in read mode and no function's qualified name equals the query but exactly one contains it, the system shall resolve to that function and return a disclosure stating the input, the resolved qualified name and entry address, and that it was a partial name match.
- [x] **RES-020**: When resolving a function in read mode from a string that parses as an address inside exactly one function's body but not at its entry point, the system shall resolve to that function and return a disclosure stating that the address lies inside it.
- [x] **RES-021**: If, when resolving a function in write mode, the string parses as an address inside a function's body but not at its entry point, and no function's qualified name equals the string, then the system shall raise a `ValueError` stating that write tools require an entry-point address and naming the containing function. If no function starts at or contains the address and no function's name equals or contains the string, the `ValueError` shall state that no function starts at that address.
- [x] **RES-022**: If a string resolves both as an address (to a function starting at or containing it, or, for a cross-reference target, to the address itself) and as a name (to a different function, or a symbol at a different address), then the system shall raise a `ValueError` listing both candidates instead of choosing.
- [x] **RES-025**: If, when resolving a function in write mode, the match is a thunk or an external function, then the system shall raise a `ValueError` naming the thunk's target function (for a thunk) or stating that the function is external.

## Symbol Resolution (single target)

- [x] **RES-008**: When resolving a single symbol by name and exactly one symbol's name equals the query case-insensitively, the system shall return that symbol, even if other symbols' names contain the query.
- [x] **RES-009**: If, when resolving a single symbol by name, no symbol's name equals the query and symbols at more than one address contain it, then the system shall raise a `ValueError` listing those candidates.
- [x] **RES-010**: If symbols at more than one address have names equal to the query case-insensitively when resolving a single symbol, then the system shall raise a `ValueError` reporting the ambiguity and listing each candidate's name and address.
- [x] **RES-011**: If no symbol's name equals or contains the query when resolving a single symbol, then the system shall raise a `ValueError` stating the symbol was not found.
- [x] **RES-012**: When resolving the target of a cross-reference lookup (`list_cross_references`) from a string that parses as an address in the program's memory, or one with symbols defined at it, the system shall resolve to that address regardless of how many symbols are defined there.
- [x] **RES-019**: When resolving a single symbol in read mode and no symbol's name equals the query but exactly one contains it, the system shall resolve to that symbol and return a disclosure stating the input, the resolved name and address, and that it was a partial name match.
- [x] **RES-026**: When resolving a single symbol in read mode by name, the system shall include dynamic symbols (such as `DAT_…` and `LAB_…` default labels) among the candidates.

## Symbol Search Matching

- [x] **RES-013**: When matching symbols for a symbol search (`search_symbols`), the system shall select symbols, including external and dynamic symbols, whose names equal or contain the query case-insensitively, together with every symbol defined at the query's address when the query parses as an address. (Ordering: deferred.)

## Data Type Resolution

- [x] **RES-014**: When resolving a C type string, the system shall try, in order, a direct data-type-manager lookup, parsing the string as a C declaration, and a scan of all data types by name, and shall return the first result obtained.
- [x] **RES-015**: If a C type string cannot be resolved by any of those methods, then the system shall raise a `ValueError` naming the type string.
- [x] **RES-023**: If more than one data type's name equals the type string in the name scan, then the system shall raise a `ValueError` listing the candidates with their category paths.
- [x] **RES-024**: If parsing a type string as a C declaration yields no data type, then the system shall raise a `ValueError` naming the type string.

## Backing Listings

- [x] **RES-016**: When listing a program's functions with externals excluded, the system shall exclude both external functions and thunk functions.

## Error Contract

- [x] **RES-017**: The system shall report every resolution failure, whether of an address, function, symbol, or data type, as a `ValueError`, which the server classifies as `fix_input` (SRV-032).
