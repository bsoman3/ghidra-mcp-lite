# Arrow: analysis-config

Decides *how* Ghidra analyzes a binary: PDB/symbol-server setup, GDT type-archive application, and typed analyzer options, all from the binary's own analysis options. A step that fails becomes a visible configuration warning on the program, and analysis continues; analyst-set signatures are never overwritten by GDTs.

## Status

**OK** — all 21 active specs implemented and covered by tests (2026-10-04). Mapped 2026-10-03 from git SHA `1acf6ba`; audited at `7f8909c`, extended for GUI mode and the analysis tools on 2026-10-04 (not yet committed).

## References

### HLD
- docs/high-level-design.md § Tenets (*Explicit over silent*, *Never guess for the caller*); § System Design (segment table, cross-cutting concerns); § Key Design Decisions

### LLD
- docs/intent/analysis-config/analysis-config-design.md

### EARS
- docs/intent/analysis-config/analysis-config-specs.md (21 specs, prefix `ACFG-*`; `ACFG-022` retired)

### Tests
- `tests/test_analysis_config.py` — option coercion, symbols, GDT application and warnings, with stubbed Ghidra and `ghidrecomp` modules
- `tests/integration/test_ghidra_smoke.py` — real Ghidra: a GDT archive and analyzer options applied at import; an unknown option reported as a warning on re-analysis

### Code
- `src/ghidra_mcp/context.py` — `_apply_gdts`, `_configure_analysis`, `_configure_symbols`, `_has_analysis_option`, `set_analysis_option`, `apply_gdt`
- Inbound, owned elsewhere: program-lifecycle's `_run_analysis`, which calls this component only when auto-analysis is about to run and supplies the binary's `AnalysisOptions` (LIFE-043)
- Outbound obligation: configuration warnings are exposed through program-lifecycle's program status (LIFE-037); the options themselves come from server's `import_binary`/`reanalyze_binary` (SRV-023, SRV-044)

## Architecture

**Purpose:** Translate a binary's analysis options into Ghidra program state immediately before its auto-analysis runs, without silently dropping any of it and without overwriting analyst work.

**Key Components:**
1. `_apply_gdts` / `apply_gdt` — applies each `.gdt` archive's function data types with `ApplyFunctionDataTypesCmd`, in its own transaction, with `always_replace=False`, then closes the archive.
2. `_configure_analysis` — one transaction for symbol configuration and analyzer options.
3. `_configure_symbols` — disables `PDB Universal` (where registered) for `no_symbols`, or loads the binary's own PDB (`pdb_path`), or configures a symbol server, via the optional `ghidrecomp`.
4. `set_analysis_option` — dispatches on Ghidra's reported option type (INT/LONG/STRING/DOUBLE/FLOAT/BOOLEAN/ENUM) to the matching typed setter, and returns a warning instead of raising when it can't.
5. Configuration warnings — per-step failures recorded on the binary and shown in the project listing.

## Spec Coverage

| Category | Spec IDs | Implemented | Deferred | Gaps |
|----------|----------|-------------|----------|------|
| Inputs and defaults | ACFG-001 to ACFG-002 | 2 | 0 | 0 |
| Application order | ACFG-003 to ACFG-004 | 2 | 0 | 0 |
| Symbols / PDB | ACFG-005 to ACFG-009, ACFG-018, ACFG-021 | 7 | 0 | 0 |
| Analyzer options | ACFG-010 to ACFG-015, ACFG-019 | 7 | 0 | 0 |
| GDT archives | ACFG-016, ACFG-017, ACFG-020 | 3 | 0 | 0 |

**Summary:** 21 of 21 active specs implemented, all with tests; 0 gaps. No open questions.

## Key Findings

1. **GDT application needs a caller-held transaction** — `ApplyFunctionDataTypesCmd` starts none of its own (verified), so `apply_gdt` opens one per archive; the integration suite applies `generic_clib_64.gdt` without warnings.
2. **`PDB Universal` exists only for PDB-capable formats** — for ELF and Mach-O its option reads `NO_TYPE` (observed against Ghidra 12.1.4), so `no_symbols` skips them silently instead of warning on every non-Windows binary.
3. **`ghidrecomp` is optional** — without it, symbol configuration is skipped with a visible warning, and analyzer options still apply.

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
