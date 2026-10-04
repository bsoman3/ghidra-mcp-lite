---
parent: high-level-design
prefix: WB
---

# Write-back

*Code references name symbols in `src/ghidra_mcp/tools.py` unless another file is given.*

## Context and Design Philosophy

Reverse engineering accumulates knowledge as annotations: meaningful names, comments, corrected types and prototypes. Write-back is the set of 8 MCP tools that record those annotations in the Ghidra program, so they show up in later decompiler and disassembly output and survive server restarts.

Principles:

- **Atomic per call.** Every write-back tool runs its mutation inside one Ghidra transaction, which commits on success and rolls back on failure (README § Tool Reference).
- **Durable immediately.** Each tool saves the program to the project before returning.
- **Analyst-authored provenance.** Every edit uses `SourceType.USER_DEFINED`. *[inferred]* This marks edits as human-authored so Ghidra gives them the highest source priority.
- **Writes act only on exact targets** (HLD tenet *Never guess for the caller*). Function targets resolve in resolution's write mode; anything looser fails with candidates.
- **No silent outcomes** (HLD tenets *Explicit over silent*, *Actionable failures*). A write either succeeds and says exactly what changed, including side effects such as a rename, or fails with a category. A Ghidra command that reports failure rolls back as `stop`. A name Ghidra rejects is `fix_input`. An edit committed but not saved is reported as such.

All preparatory work runs **before** the transaction opens: resolving the target, checking the address, decompiling, finding the variable, parsing the type or prototype. Input errors therefore never open a transaction. Only the mutation itself runs inside `_with_transaction`.

## Transaction Contract

`_with_transaction(description, body)`:

```
tx ← program.startTransaction(description)
ok ← False
try:
    result ← body()
    ok ← True
finally:
    program.endTransaction(tx, ok)        # commit if ok, else roll back
save the program to the project
    on failure → Stop("<description>: the edit is applied in memory but not saved to the project: <reason>")
return result
```

A body that raises rolls back and the exception propagates with its own category. A body whose Ghidra command reports failure raises `Stop` itself, so that case rolls back too.

## Tool Catalogue

| MCP tool | Implementation | Target resolution | Mutation | Success message |
|---|---|---|---|---|
| `set_disassembly_comment` | `set_disassembly_comment` → `_set_comment` | `_parse_address`, must be in memory | `listing.setComment(addr, CommentType.EOL, text)` | `Set disassembly comment at <address>` (`Removed …` for empty text) |
| `set_decompiler_comment` | `set_decompiler_comment` → `_set_comment` | `_parse_address`, must be in memory | `listing.setComment(addr, CommentType.PRE, text)` | `Set decompiler comment at <address>` (`Removed …` for empty text) |
| `rename_function` | `rename_function` | `find_function` (write mode) | `func.setName(new, USER_DEFINED)` | `Renamed '<old>' → '<new>'` |
| `rename_function_by_address` | `rename_function_by_address` | `_parse_address` + `getFunctionAt` | `func.setName(new, USER_DEFINED)` | `Renamed function at <address>: '<old>' → '<new>'` |
| `rename_data` | `rename_data` | `_parse_address` + `getDataAt` | named primary symbol `setName`, else `createLabel` | `Renamed data at <address> → '<new>'` |
| `rename_variable` | `rename_variable` | `find_function` + `_find_local_variable` | `updateDBVariable(sym, new, None, USER_DEFINED)` | `Renamed variable '<old>' → '<new>' in function '<f>'` |
| `set_function_prototype` | `set_function_prototype` | `find_function` | `ApplyFunctionSignatureCmd(entry, parsed, USER_DEFINED).applyTo(…)` | `Set prototype for '<f>': <prototype>`, plus `. The function was renamed to '<new>'` when Ghidra renamed it |
| `set_local_variable_type` | `set_local_variable_type` | `find_function` + `_resolve_data_type` + `_find_local_variable` | `updateDBVariable(sym, None, type, USER_DEFINED)` | `Set type of '<v>' to '<type>' in function '<f>'` |

Messages echo the caller's `address` string as given, not the normalized address, and use simple (unqualified) function names.

## Comments

The EOL comment appears in the disassembly listing. The PRE comment appears as a `//` comment in the decompiler view. Each call replaces the existing comment of that kind at the address, and empty text removes it (passed to Ghidra as `null`); the tool descriptions say so. An address outside program memory fails as `fix_input` before any transaction opens. Comments are written through Ghidra's `CommentType` API, since the int-constant `setComment` overloads are deprecated for removal since Ghidra 11.4 (verified against Ghidra's source).

## Renames

- **By name or address** (`rename_function`): resolution's write mode, so only an exact qualified name or an entry-point address resolves, and thunks and external functions are refused (RES-025).
- **By exact entry point** (`rename_function_by_address`): for when several functions share a name. Uses `getFunctionAt` only; no function there → `ValueError("No function at address <a>")`.
- **Data label** (`rename_data`): requires defined data at the address, else `ValueError("No defined data at address <a>")`. Inside the transaction, it renames the data's primary symbol when that is a named (non-dynamic) symbol. When the data has no primary symbol, or only a dynamic default label (`DAT_…`), it creates a `USER_DEFINED` label with the new name. The tool description and README state the defined-data requirement.

## Decompiler-Driven Variable Edits

`rename_variable` and `set_local_variable_type` share one helper:

```
func ← find_function(function_name_or_address)
[set_local_variable_type only] type ← _resolve_data_type(new_type)
_find_local_variable(func, var_name):
    result ← decompiler.decompileFunction(func, 30, ConsoleTaskMonitor())   # outside the transaction
    result has an error → Stop("Decompilation failed for '<f>': <msg>")
    sym ← the symbol in result.getHighFunction().getLocalSymbolMap() whose getName() == var_name   (case-sensitive)
    none → ValueError("Variable '<v>' not found in '<f>'. Available: [<names>]")
in transaction: HighFunctionDBUtil.updateDBVariable(sym, new_name | None, None | type, USER_DEFINED)
```

Variable names are those shown in decompiler output, parameters included. `updateDBVariable` itself commits parameters and creates database locals for decompiler-synthesized variables when needed (verified against Ghidra's `HighFunctionDBUtil`), so no separate commit step is required.

## Prototype Application

`set_function_prototype`:

1. `find_function`.
2. `CParser(program DTM).parse(prototype + ";")`. A parse exception → `ValueError("Failed to parse prototype …")`. Types in the declaration must already exist in the program's data type manager.
3. The result must be a `FunctionDefinitionDataType`, else `ValueError` with an example of a valid signature.
4. In the transaction: `ApplyFunctionSignatureCmd(entry, parsed, USER_DEFINED).applyTo(program, ConsoleTaskMonitor())`. A `false` result raises `Stop` carrying the command's status message, which rolls the transaction back.

`ApplyFunctionSignatureCmd`'s 3-argument constructor uses `FunctionRenameOption.RENAME_IF_DEFAULT` and `preserveCallingConvention=false` (verified against Ghidra's source). So a function that still has a default name (such as `FUN_00401000`) is renamed to the declaration's name, and any other function keeps its name. The confirmation states the new name whenever this happens.

## Error Surface

| Condition | Raised | Category |
|---|---|---|
| Unparseable address | `ValueError` (`_parse_address`) | `fix_input` |
| Comment address outside program memory | `ValueError` | `fix_input` |
| Function not found, ambiguous, not exact, a thunk, or external (write mode) | `ValueError` (`find_function`) | `fix_input` |
| No function at the entry address | `ValueError` | `fix_input` |
| No defined data at the address | `ValueError` | `fix_input` |
| Decompile failed (variable tools) | `Stop`, with the decompiler's message | `stop` |
| Variable not found | `ValueError`, listing available names | `fix_input` |
| Type string unresolvable or ambiguous | `ValueError` (`_resolve_data_type`) | `fix_input` |
| Prototype unparseable or not a function definition | `ValueError` | `fix_input` |
| Ghidra rejects a new name as invalid or duplicate | Java `InvalidInputException` / `DuplicateNameException`; rolled back | `fix_input`, carrying Ghidra's reason |
| Ghidra rejects the mutation for another reason (e.g. read-only project) | Java exception; rolled back | `stop` (internal error) |
| `ApplyFunctionSignatureCmd` returns `false` | `Stop`, with the status message; rolled back | `stop` |
| Save fails after commit | `Stop`, stating the edit is applied but not saved | `stop` |

## Interactions with Other Segments

- **Resolution:** write mode refuses thunks and externals (RES-025) and acts only on exact matches. Symbol-level ambiguity rules come from there.
- **Analysis-config:** GDT archives are applied with `always_replace=False` (ACFG-016), so prototypes set here survive restarts and re-analysis.
- **Program-lifecycle:** every write runs under its program's lock (LIFE-041), so it never overlaps analysis or another call on the same program. The shared `DecompInterface` comes from the program's record.

## Decisions & Alternatives

| Decision | Chosen | Alternatives Considered | Rationale |
|----------|--------|------------------------|-----------|
| Atomicity | One transaction per tool call; roll back on exception | Batched edits across calls | One call, one edit: a failure never leaves half an annotation. |
| Durability | Save the program after every successful write | Save on shutdown or periodically | Edits survive a crash or restart; shutdown discards unsaved changes by design. |
| Source type | `USER_DEFINED` for every edit | `ANALYSIS` / `IMPORTED` | *[inferred]* Marks analyst authorship at the highest source priority. |
| Preparatory work | Resolve, check, decompile, and parse before opening the transaction | Do everything inside it | Input errors never open a transaction. |
| Variable edits | Decompiler `HighFunction` plus `HighFunctionDBUtil.updateDBVariable`, through one shared helper | Edit listing `Variable`s directly | Names are the ones shown in decompiler output, which is what agents see. |
| Variable-edit decompile timeout | 30 s | 120 s, as in `decompile_function` | *[inferred]* The lookup needs only the high-level model, and a write should fail fast. |
| Prototype input | One C declaration string parsed by `CParser` | Structured return and parameter fields | Matches how agents read signatures in decompiler output. |
| Data rename | Rename a named primary symbol, else create a label | Always create a new label | *[inferred]* Avoids stacking labels at one address. |
| By-address rename | A separate tool, exact entry point | Only the name-or-address form | For when several functions share a name. |
| Comment kinds | EOL for disassembly, PRE for the decompiler | PLATE or POST comments | The two views agents read. |
| `rename_data` scope | Only addresses holding defined data, as documented | Create labels at any address | A label on undefined bytes is a different operation from renaming data. |
| Dynamic primary symbol | Create a `USER_DEFINED` label | `setName` on the dynamic symbol | Creating a label is Ghidra's documented way to name a location. Renaming a dynamic symbol's behavior is unverified. |
| Empty comment text | Removes the comment | Store an empty comment; add a separate clear tool | No new tool surface, and matches Ghidra's `null`-removes convention. |
| Variable-name matching | Exact and case-sensitive | Case-insensitive | HLD tenet *Never guess for the caller*: write tools act only on exact matches. A miss lists the available names as candidates. |
| Prototype renames | Keep Ghidra's rename-if-default behavior, and state the resulting name in the confirmation | Never rename; always rename | The declaration names the function, so renaming a default-named function matches the caller's request. The HLD tenet *Explicit over silent* requires the side effect to be stated. |
| Failed command or save | Roll back on a failed command (`stop` with Ghidra's status message); report a post-commit save failure as `stop` | Report success; undo after a failed save | HLD tenets *Explicit over silent* and *Actionable failures*. |

## Open Questions & Future Decisions

### Resolved
1. ✅ **Save failure after commit.** Reported as `stop`, stating that the edit is applied in memory but not saved; no automatic undo. (2026-10-03)
2. ✅ **Error classification.** A failed decompile is `stop`; a name Ghidra rejects as invalid or duplicate is `fix_input` with Ghidra's reason; other Ghidra rejections are `stop`. (2026-10-03)
3. ✅ **Variable-name matching.** Stays exact and case-sensitive, per write-mode strictness. (2026-10-03)
4. ✅ **Prototype name handling.** Verified as rename-if-default; kept, with the resulting name stated in the confirmation. (2026-10-03)
5. ✅ **Comment address validation.** An address outside program memory fails as `fix_input`. (2026-10-03)
6. ✅ **Decompiler-synthesized symbols.** No change needed: `updateDBVariable` commits and creates them itself (verified). (2026-10-03)
7. ✅ **Dynamic primary symbol.** A `USER_DEFINED` label is created instead of renaming it. (2026-10-03)
8. ✅ **Duplicated variable-tool logic.** Consolidated into one helper. (2026-10-03)
9. ✅ **Clearing comments.** Empty text removes the comment, and this is documented. (2026-10-03)
10. ✅ **`rename_data` scope.** The defined-data requirement is kept, and the documentation says so. (2026-10-03)

### Deferred
*(none yet)*

### Open (observed behavior, intent unstated)
*(none)*

### Known gaps against stated intent
*(none)*

## References

- Code: `src/ghidra_mcp/tools.py` (`_with_transaction`, `_set_comment`, the comment, rename, variable, and prototype tool methods, `_find_local_variable`)
- Depends on: resolution (`find_function`, `_parse_address`, `_resolve_data_type`); program-lifecycle (the program's decompiler and project handle, the program lock)
- Called by: server (MCP wrappers)
- External: Ghidra `Listing`, `CommentType`, `SymbolTable`, `HighFunctionDBUtil`, `CParser`, `FunctionDefinitionDataType`, `ApplyFunctionSignatureCmd`, `SourceType`
- Arrow: `docs/arrows/write-back.md`
