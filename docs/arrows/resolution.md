# Arrow: resolution

Works out which address, function, symbol, or data type a caller meant from a user-supplied string: hex-address parsing, read-mode versus write-mode matching, disclosure of loose matches, ambiguity failures with candidates, and C type-string resolution.

## Status

**OK** — all 26 active specs implemented and covered by tests (2026-10-03); three items deferred. Mapped 2026-10-03 from git SHA `1acf6ba`; implemented at `7f8909c`; audited at `5c6bcb3` (2026-10-20).

## References

### HLD
- docs/high-level-design.md § Tenets (*Never guess for the caller*); § System Design (segment table, cross-cutting concerns); § Key Design Decisions

### LLD
- docs/intent/resolution/resolution-design.md

### EARS
- docs/intent/resolution/resolution-specs.md (26 specs, prefix `RES-*`)

### Tests
- `tests/test_resolution.py` — against an in-memory program (`tests/program_fakes.py`)
- `tests/integration/test_ghidra_smoke.py` — real Ghidra: entry-point and containing-address resolution through the read tools

### Code
- `src/ghidra_mcp/tools.py` — `ResolutionMode`, `Resolved`, `_parse_address`, `_try_address`, `_resolve_data_type`, `resolve_function`, `find_function`, `resolve_reference_target`, `_lookup_symbols`, `get_all_functions`, `get_all_symbols`
- Inbound, owned elsewhere: queries in read mode (`decompile`, `disassemble`, `gen_callgraph` → `resolve_function`; `list_cross_references` → `resolve_reference_target`; `search_symbols` → `_lookup_symbols`; `get_function_by_address`, `get_xrefs_from`, `read_bytes` → `_parse_address`; `list_functions` → `get_all_functions`); write-back in write mode (renames, prototype, and variable tools → `find_function`; comments, `rename_function_by_address`, `rename_data` → `_parse_address`; `set_local_variable_type` → `_resolve_data_type`)
- Outbound obligation: queries carries the disclosure note in read-tool responses (QRY-029).

## Architecture

**Purpose:** Give every tool one consistent way to turn loosely typed caller input (`"main"`, `"0x401000"`, `"char *"`) into a specific Ghidra object without guessing: resolve when unambiguous, disclose loose matches in read mode, and fail with candidates otherwise.

**Key Components:**
1. `_parse_address` — strips an optional `0x` prefix and parses with the program's address factory; raises `ValueError` on failure.
2. `resolve_function(query, mode)` — weighs the address and name interpretations; read mode adds disclosed partial-name and containing-address matches; write mode stays exact and refuses thunks and externals. `find_function` is its write-mode form.
3. `resolve_reference_target` — the target address of a cross-reference lookup: an address as is, or the address of the one matching symbol (dynamic and external included), grouped by address.
4. `_lookup_symbols` — symbol search: name matches plus the symbols at an address-like query.
5. `_resolve_data_type` — data-type-path lookup, then `CParser` on `"<type> __x;"`, then a name scan that must match exactly one type.

## Spec Coverage

| Category | Spec IDs | Implemented | Deferred | Gaps |
|----------|----------|-------------|----------|------|
| Address parsing | RES-001 to RES-002 | 2 | 0 | 0 |
| Function resolution | RES-003 to RES-007, RES-018, RES-020 to RES-022, RES-025 | 10 | 0 | 0 |
| Symbol resolution (single target) | RES-008 to RES-012, RES-019, RES-026 | 7 | 0 | 0 |
| Symbol search matching | RES-013 | 1 | 0 | 0 |
| Data type resolution | RES-014, RES-015, RES-023, RES-024 | 4 | 0 | 0 |
| Backing listings | RES-016 | 1 | 0 | 0 |
| Error contract | RES-017 | 1 | 0 | 0 |

**Summary:** 26 of 26 active specs implemented, all with tests; 0 gaps. No open questions; 3 items are deferred.

## Key Findings

1. **Hex-looking names** — Ghidra parses `add` or `cafe` as addresses (verified), so an address interpretation only competes with a name when it leads to a function (or, for reference targets, to memory or symbols). When both lead somewhere different, the call fails listing both.
2. **Read tools disclose, write tools refuse** — a unique partial name or an address inside a function resolves in read mode with a note (`'bar' resolved to Foo::bar @ 00401000 (partial name match)`); write mode returns candidates instead.
3. **Reference targets are addresses** — several symbols at one address are one target, so aliases no longer make `list_cross_references` fail as ambiguous.

## Work Required

### Must Fix
*(none)*

### Should Fix
*(none)*

### Nice to Have
*(none)*

### Deferred
- Unbounded suggestion lists, symbol result order, and full scans. Part of the HLD's bounded, stable responses goal.

### Open Questions
*Mirrors the LLD's Open Questions with the same numbering.*
*(none)*
