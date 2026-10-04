# Arrow: write-back

The 8 tools that record an analyst's annotations in the program (comments, function and data renames, local variable names and types, function prototypes), each atomically in one transaction, saved immediately, acting only on exact targets, and reporting every outcome.

## Status

**OK** — all 28 active specs implemented and covered by tests (2026-10-04). Mapped 2026-10-03 from git SHA `1acf6ba`; extended for GUI mode and the analysis tools, and audited at `5cc28ab` (2026-10-04).

## References

### HLD
- docs/high-level-design.md § Tenets (*Never guess for the caller*, *Explicit over silent*, *Actionable failures*); § System Design; § Key Design Decisions

### LLD
- docs/intent/write-back/write-back-design.md

### EARS
- docs/intent/write-back/write-back-specs.md (28 specs, prefix `WB-*`)

### Tests
- `tests/test_write_back.py` — every write tool against an in-memory program (`tests/program_fakes.py`), with stubbed Ghidra classes
- `tests/test_category_guards.py` — decompile failure in the variable tools (WB-014)
- `tests/integration/test_ghidra_smoke.py` — real Ghidra: prototype, variable rename and retype, function rename, comment set and removal

### Code
- `src/ghidra_mcp/tools.py` — `_with_transaction`, `_set_comment`, `set_disassembly_comment`, `set_decompiler_comment`, `rename_function`, `rename_function_by_address`, `rename_data`, `_find_local_variable`, `rename_variable`, `set_function_prototype`, `set_local_variable_type`
- Inbound, owned elsewhere: the MCP wrappers in `server.py` (server)
- Outbound, owned elsewhere: resolution (`find_function`, `_parse_address`, `_resolve_data_type`); program-lifecycle (the program's decompiler, project handle, and lock); gui-host (the GUI-mode mutation runner, `GuiGhidraContext.run_mutation`)

## Architecture

**Purpose:** Turn an analyst's annotation into a durable, attributed change to the program, or fail without changing anything and say why.

**Key Components:**
1. Transaction contract — prepare outside, mutate inside one transaction, roll back on failure, save after commit, and report a failed save as `stop`.
2. Comments — EOL and PRE comments through `CommentType`; empty text removes; addresses must be in memory.
3. Renames — functions (write-mode resolution or exact entry point) and defined data (named primary symbol, else a new label).
4. Variable edits — one helper decompiles (30 s) and finds the variable by exact name; `updateDBVariable` applies the change.
5. Prototypes — `CParser` declaration, `ApplyFunctionSignatureCmd`; a failed apply rolls back as `stop`, and a rename-if-default is stated.

## Spec Coverage

| Category | Spec IDs | Implemented | Deferred | Gaps |
|----------|----------|-------------|----------|------|
| Transaction contract | WB-001 to WB-005, WB-022, WB-028 | 7 | 0 | 0 |
| Comments | WB-006, WB-007, WB-025 to WB-027 | 5 | 0 | 0 |
| Renames | WB-008 to WB-012, WB-023 | 6 | 0 | 0 |
| Local variable edits | WB-013 to WB-017 | 5 | 0 | 0 |
| Function prototypes | WB-018 to WB-020, WB-024 | 4 | 0 | 0 |
| Results | WB-021 | 1 | 0 | 0 |

**Summary:** 28 of 28 active specs implemented, all with tests; 0 gaps. No open questions.

## Key Findings

1. **Command results are checked** — `ApplyFunctionSignatureCmd.applyTo` signals failure by return value; a `false` now rolls back and fails as `stop` with Ghidra's status message.
2. **Every outcome is reported** — a post-commit save failure says the edit is applied but not saved, a prototype-driven rename is stated, and Ghidra's name rejections are `fix_input`.
3. **Writes on real Ghidra** — the integration suite applies a prototype, renames and retypes parameters through `HighFunctionDBUtil`, and sets and removes comments through `CommentType`.

## Work Required

### Must Fix
*(none)*

### Should Fix
*(none)*

### Nice to Have
*(none)*

### Open Questions
*Mirrors the LLD's Open Questions with the same numbering.*
*(none)*
