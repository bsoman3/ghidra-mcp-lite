---
parent: high-level-design
prefix: RES
---

# Resolution

*Code references name symbols in `src/ghidra_mcp/tools.py` unless another file is given.*

## Context and Design Philosophy

MCP clients, usually LLM agents, identify targets with loosely typed strings: a function name copied from decompiler output, a hex address with or without `0x`, a C type like `char *`. Almost every tool takes one such string (`name_or_address`, `address`, `function_name_or_address`, `new_type`). Resolution turns that string into exactly one Ghidra object, or fails with an error the caller can act on.

Principles:

- **One string, either form.** A single parameter accepts a name or an address.
- **Case-insensitive names.** Function and symbol names match case-insensitively.
- **Never guess for the caller** (HLD tenet). A target resolves only when the match is unambiguous. Read tools may accept a unique loose match and disclose it; write tools act only on an exact match. Anything else fails with the candidates (see Resolution Modes).

Every resolution failure raises `ValueError`, which the server classifies as `fix_input` (server, SRV-032).

Resolution works *inside one program*. Resolving a *binary* name belongs to program-lifecycle (`get_program_info`).

## Consumers

| Resolver | Used by queries | Used by write-back |
|---|---|---|
| `_parse_address` | `get_function_by_address`, `get_xrefs_from`, `read_bytes` | `set_disassembly_comment`, `set_decompiler_comment`, `rename_function_by_address`, `rename_data` |
| `resolve_function(…, READ)` | `decompile_function`, `disassemble_function`, `gen_callgraph` | n/a |
| `find_function` (= `resolve_function(…, WRITE)`) | n/a | `rename_function`, `rename_variable`, `set_function_prototype`, `set_local_variable_type` |
| `resolve_reference_target` (read mode) | `list_cross_references` | n/a |
| `_lookup_symbols` | `search_symbols` | n/a |
| `_resolve_data_type` | n/a | `set_local_variable_type` |
| `get_all_functions` | `list_functions` (externals and thunks excluded) | n/a |

## Resolution Modes

Function and single-symbol resolution run in one of two modes (`ResolutionMode`), chosen by the calling tool, and return a `Resolved` value: the target, plus a disclosure `note` when read mode accepted a loose match.

| Input outcome | Read mode | Write mode |
|---|---|---|
| Exactly one exact match: the qualified name equals the query case-insensitively, or the address is a function's entry point | resolve | resolve |
| Several exact matches | `fix_input` with candidates | `fix_input` with candidates |
| No exact match; the query is contained in exactly one qualified name (including a plain name inside a namespace) | resolve **and disclose** | `fix_input` with candidates |
| No exact match; the query is contained in several names | `fix_input` with candidates | `fix_input` with candidates |
| The address lies inside exactly one function's body but not at its entry | resolve **and disclose** | `fix_input` naming the containing function |
| The string resolves both as an address and as a name, to different targets | `fix_input` listing both | `fix_input` listing both |
| The match is a thunk or an external function | resolve | `fix_input`, naming the thunk's target function (for a thunk) or stating that the function is external |

**What counts as an address interpretation.** Ghidra's address parser accepts hex with or without `0x`, so hex-looking names such as `add` or `cafe` also parse as addresses (verified against `AbstractAddressSpace.parseString`). A parsed address only competes with the name interpretation when it leads somewhere: for functions, when a function starts at or contains it; for cross-reference targets, when it lies in program memory or has symbols defined at it. So `add` resolves by name when nothing is at `0x0add`, and fails listing both candidates when something is.

**Dynamic symbols.** Default labels such as `DAT_…` and `LAB_…` are dynamic symbols. They take part in read-mode name resolution and in symbol search, so names copied from decompiler output resolve.

**Disclosure.** When read mode resolves a loose match, the note states the input, the resolved qualified name and address, and the kind of loose match, for example `'bar' resolved to Foo::bar @ 00401000 (partial name match)` or `'0x401010' resolved to main @ 00401000 (address inside the function)`. Queries carries the note in the tool's `resolution` field.

## Address Parsing

`_parse_address(address)` (address-only parameters):

1. If the string starts with `0x` (case-insensitive), strip those two characters. Whitespace is not stripped.
2. `program.getAddressFactory().getAddress(rest)`.
3. Exception → `ValueError("Invalid address '<a>': <e>")`. `None` → `ValueError("Invalid address: <a>")`.

The name-or-address resolvers parse with `_try_address`, which returns `None` instead of raising, because a string that doesn't parse is simply a name.

## Function Resolution

`resolve_function(name_or_address, mode)`:

```
addr       ← _try_address(query)
at         ← function whose entry point is addr
containing ← function whose body contains addr (when none starts there)
functions  ← every function: non-external (thunks included) plus external functions
exact      ← functions whose qualified name equals the query (case-insensitive)
partial    ← functions whose qualified name contains the query (only when no exact match)
by_name    ← the single exact match; or, in read mode, the single partial match

if (at or containing) and by_name differ          → fix_input listing both
if at                                              → at
if containing:  read  → containing, disclosed
                write → by_name if it is the same function, else fix_input naming the containing function
if by_name                                         → by_name (disclosed if partial)
several exact                                      → fix_input "Ambiguous match", with candidates
any partial                                        → fix_input "not found", with candidates
write mode and addr parsed                         → fix_input "no function starts at <addr>"
else                                               → fix_input "not found"
write mode: a thunk or external target             → fix_input (RES-025)
```

Candidates are listed as `<qualified name> @ <entry>`. `find_function(name_or_address)` is the write-mode form, returning the function itself.

## Cross-reference Target Resolution

`resolve_reference_target(name_or_address)` returns an address, since references point at addresses:

```
addr     ← _try_address(query), kept only if in memory or with symbols at it
symbols  ← every symbol, external and dynamic included
exact    ← symbols whose qualified name equals the query, grouped by address
partial  ← symbols whose qualified name contains the query, grouped by address (only when no exact match)
by_name  ← the single exact address; or the single partial address (disclosed)

if addr and by_name's address differ → fix_input listing both
if addr                              → addr   (however many symbols are defined there)
if by_name                           → its address
exact at several addresses           → fix_input "Ambiguous match", with candidates
partial at several addresses         → fix_input "not found", with candidates
else                                 → fix_input "not found"
```

Grouping by address means several symbols at one address (aliases, a function and its label) are one target, since they share every incoming reference.

## Symbol Search Matching

`_lookup_symbols(query)` (for `search_symbols`) returns every symbol, external and dynamic included, whose qualified name contains the query case-insensitively (equality included), plus every symbol defined at the query's address when it parses as one. A search returns a list, so there is nothing to choose between: both interpretations are included, de-duplicated by name and address.

## Data Type Resolution

`_resolve_data_type(type_str)` tries three tiers:

1. `dtm.getDataType(type_str)`, a lookup by data-type path such as `/int` or `/winnt.h/HANDLE`.
2. `CParser(dtm).parse(type_str + " __x;")`, which handles declarations such as `char *`, `unsigned int`, or `struct Foo *`. A parse exception falls through to the next tier. A parse that yields no type fails with `fix_input`.
3. A scan of `dtm.getAllDataTypes()` for types whose name equals the string. Exactly one → that type. Several → `fix_input` listing their category paths. None → `ValueError("Cannot resolve data type: '<t>'")`.

Type resolution serves only a write tool (`set_local_variable_type`), so it follows write-mode strictness: same-named types in different categories are not guessed between.

## Backing Listings

| Helper | Includes | Default |
|---|---|---|
| `get_all_functions(include_externals)` | `True`: every non-external function (thunks included) plus external functions. `False`: excludes external **and** thunk functions. | `False` |
| `get_all_symbols(include_externals, include_dynamic)` | The symbol table, optionally excluding externals; dynamic symbols only if requested | both `False` (name resolution passes both `True`) |

Both materialize the full list on every call.

## Decisions & Alternatives

| Decision | Chosen | Alternatives Considered | Rationale |
|----------|--------|------------------------|-----------|
| Input shape | One string parameter that accepts a name or an address | Separate name and address parameters | *[inferred]* A smaller tool surface for LLM clients. |
| Address versus name | Evaluate both interpretations; if they lead to different targets, fail with both as candidates. An address only counts when it leads somewhere (a function there, or memory/symbols for a reference target). | Address always wins; names always win; require `0x` for addresses | HLD tenet *Never guess for the caller*. Ghidra parses hex-looking names such as `cafe` as addresses, so either fixed precedence silently guesses; ignoring addresses that lead nowhere keeps names like `add` usable. |
| Case handling | Case-insensitive name matching | Case-sensitive | Function names are documented to clients as case-insensitive. |
| Name form | An exact match means the namespace-qualified name (`getName(True)`); a plain name inside a namespace is a loose match | Treat a simple-name match as exact | *[inferred]* Disambiguates same-named functions in different namespaces. The HLD tenet lists a plain name inside a namespace as a loose match. |
| Loose matches | Read mode resolves a unique loose match and discloses it; write mode returns candidates | Always return candidates; always auto-resolve | HLD tenet *Never guess for the caller*: reads save the agent a round trip without hiding what happened, and writes never act on a guess. |
| Ambiguity | Fail and list candidates with addresses | Pick the first match | HLD tenet *Never guess for the caller*. |
| Function search scope | Read mode includes externals and thunks. Write mode refuses them, naming the thunk's target. | Include them for writes too; silently redirect writes to the thunk's target | Reads can usefully target imported functions by name. A write to a thunk or external is almost never what the caller meant, and redirecting it silently would be a guess. |
| Symbol search scope | Include externals and dynamic symbols | Exclude dynamic symbols | Agents copy `DAT_…`/`LAB_…` names from decompiler output and expect them to resolve. Including them costs larger scans, which the HLD tenet *Reliability over footprint* accepts. |
| Reference targets | An address, with symbols grouped by address | A single symbol | References point at addresses; several symbols at one address share every reference, so treating them as ambiguous would be a false failure. |
| Search with an address-like query | Include both the symbols at the address and the name matches | Fail listing both (as single-target resolution does) | A search returns a list, so including both interpretations hides nothing; failing would leave no way to search for a hex-looking name. |
| Disclosure shape | A `Resolved(target, note)` value from the resolver | Log the loose match; store it on the tools object | The note travels with the target to the response that must state it, without hidden state. |
| Type resolution | Manager lookup, then `CParser`, then a name scan that must match exactly one type | `CParser` only; first name match wins | The tiers cover paths, declarations, and bare names. The scan follows write-mode strictness. |
| Error type | `ValueError` for every resolution failure | Custom exception types | The server classifies `ValueError` as `fix_input` (SRV-032), so callers get one consistent "fix your input" category. |

## Open Questions & Future Decisions

### Resolved
1. ✅ **Containing addresses.** Read mode resolves an address inside a function and discloses it; write mode requires the entry point and names the containing function in its `fix_input` failure. (2026-10-03)
2. ✅ **Hex-looking names.** When a string resolves both as an address and as a name to different targets, resolution fails and lists both. (2026-10-03)
3. ✅ **Plain names inside namespaces.** These are loose matches: read mode discloses, write mode returns candidates. (2026-10-03)
4. ✅ **Type resolution edge cases.** Same-named types in different categories, and an empty declaration parse, fail with `fix_input`. (2026-10-03)
5. ✅ **`0x` on the raw-string paths.** Ghidra's address parser accepts the prefix (verified); no change needed. (2026-10-03)
6. ✅ **Thunks and externals.** Write mode refuses them with `fix_input`, naming the thunk's target; read mode includes them. (2026-10-03)
7. ✅ **Dynamic symbols.** Included in read-mode name resolution and symbol search. (2026-10-03)

### Deferred
1. **Unbounded suggestion lists.** Candidate lists in errors are not capped. Part of the HLD's bounded, stable responses goal.
2. **Symbol result order.** `_lookup_symbols` returns symbols in discovery order, not a documented sort. Part of the HLD's bounded, stable responses goal.
3. **Full scans.** Every name lookup materializes all functions or symbols; indexed lookups are deferred under the same goal.

### Open (observed behavior, intent unstated)
*(none)*

### Known gaps against stated intent
*(none)*

## References

- Code: `src/ghidra_mcp/tools.py` (`ResolutionMode`, `Resolved`, `_parse_address`, `_try_address`, `_resolve_data_type`, `resolve_function`, `find_function`, `resolve_reference_target`, `_lookup_symbols`, `get_all_functions`, `get_all_symbols`)
- Called by: queries and write-back (see Consumers)
- Error mapping: server (`_err`; `handle_exceptions`)
- External: Ghidra `AddressFactory`, `FunctionManager`, `SymbolTable`, `Memory`, `DataTypeManager`, `CParser`
- Arrow: `docs/arrows/resolution.md`
