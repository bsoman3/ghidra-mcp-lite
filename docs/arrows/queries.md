# Arrow: queries

The read side of the server: 22 tools that list, search, decompile, disassemble, cross-reference, relate callers and callees, diff, find similar functions, show p-code and data flow for, read bytes from, and graph an analyzed binary without changing it, disclosing loose target matches and marking partial results.

## Status

**OK** — all 53 active specs implemented and covered by tests (2026-10-20); four items deferred. Mapped 2026-10-03 from git SHA `1acf6ba`; extended for GUI mode and the analysis tools, and audited at `5cc28ab` (2026-10-04).

## References

### HLD
- docs/high-level-design.md § Tenets (*Never guess for the caller*, *Explicit over silent*); § Goals (deferred bounded, stable responses); § System Design; § Key Design Decisions

### LLD
- docs/intent/queries/queries-design.md

### EARS
- docs/intent/queries/queries-specs.md (53 specs, prefix `QRY-*`)

### Tests
- `tests/test_queries.py` — every read tool against an in-memory program (`tests/program_fakes.py`), with stubbed Ghidra classes and `ghidrecomp`
- `tests/test_analysis_tools.py` — call relations, comparison and similarity helpers, p-code bounds, data-flow errors, two-binary locking
- `tests/test_category_guards.py` — missing `ghidrecomp` (QRY-025)
- `tests/integration/test_ghidra_smoke.py` — real Ghidra: listing, decompile, disassembly (`CommentType`), disclosure, cross-references, bytes, strings, data items

### Code
- `src/ghidra_mcp/tools.py` — the read-only tool methods (`list_functions` … `read_bytes`, `gen_callgraph`), `_func_label`, `DECOMPILE_TIMEOUT_SECONDS`
- `src/ghidra_mcp/models.py` — response models, including `ItemFailure` and the `resolution`/`partial`/`failures` fields
- Inbound, owned elsewhere: the MCP wrappers in `server.py` (server)
- Outbound, owned elsewhere: resolution (`resolve_function`, `resolve_reference_target`, `_lookup_symbols`, `_parse_address`, `get_all_functions`); program-lifecycle (the program's decompiler)

## Architecture

**Purpose:** Let a client explore an analyzed binary with native Ghidra APIs, returning typed results that state how a loosely named target was resolved and mark anything that could not be read.

**Key Components:**
1. Listings and searches — functions, segments, data items, classes, namespaces, imports, exports, symbols, strings.
2. Code views — function by address, decompilation (120 s bound; failures are `stop`), disassembly (per-line errors), byte reads (partial and uninitialized handling).
3. References and call graphs — references to a target or from an address; `ghidrecomp` call graphs.
5. Call relations, comparison, p-code, data flow — callers/callees (through thunks, with indirect calls marked), normalized function diffs, mnemonic-3-gram fuzzy similarity (cached per program), raw and high p-code, decompiler data-flow slices.
4. Disclosure — an optional `resolution` field on the four target-taking read results.

## Spec Coverage

| Category | Spec IDs | Implemented | Deferred | Gaps |
|----------|----------|-------------|----------|------|
| Listings | QRY-001 to QRY-009, QRY-031, QRY-053 | 11 | 0 | 0 |
| Searches | QRY-010 to QRY-013, QRY-032 | 5 | 0 | 0 |
| Code views | QRY-014 to QRY-020, QRY-030, QRY-033 to QRY-035, QRY-037, QRY-038 | 13 | 0 | 0 |
| References | QRY-021 to QRY-026, QRY-036 | 7 | 0 | 0 |
| Resolution disclosure | QRY-029 | 1 | 0 | 0 |
| Call relations | QRY-039 to QRY-041 | 3 | 0 | 0 |
| Function comparison | QRY-042 to QRY-047, QRY-052 | 7 | 0 | 0 |
| P-code and data flow | QRY-048 to QRY-051 | 4 | 0 | 0 |
| Query contract | QRY-027 to QRY-028 | 2 | 0 | 0 |

**Summary:** 53 of 53 active specs implemented, all with tests; 0 gaps. No open questions; 4 items are deferred.

## Key Findings

1. **Partial results are marked, never silent** — unreadable data items and strings go to `failures`, unreadable instruction fields to per-line `errors`, and short byte reads report both sizes, each with a `partial` flag.
2. **Decompiler failures are errors** — a failure, timeout (120 s), or empty result is `stop` with the decompiler's message, never pseudo-C.
3. **Mach-O naming** — Ghidra names a Mach-O `main` `entry` and prefixes C symbols with `_`; tools report Ghidra's names as they are.

## Work Required

### Must Fix
*(none)*

### Should Fix
*(none)*

### Nice to Have
*(none)*

### Deferred
- Pagination contract, unbounded outputs, `search_symbols` cost/shape, and full scans per call. Part of the HLD's bounded, stable responses goal.

### Open Questions
*Mirrors the LLD's Open Questions with the same numbering.*
*(none)*
