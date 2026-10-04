# Analysis Configuration Specs

**LLD**: docs/intent/analysis-config/analysis-config-design.md
**Implementing artifacts**:
- src/ghidra_mcp/context.py (`_apply_gdts`, `_configure_analysis`, `_configure_symbols`, `set_analysis_option`, `apply_gdt`)

Status markers: `[x]` implemented · `[ ]` active gap · `[D]` deferred

*Tests: `tests/test_analysis_config.py`, with end-to-end checks in `tests/integration/test_ghidra_smoke.py`. `ACFG-022` is retired.*

*A binary's "analysis options" are `no_symbols`, `pdb_path`, `gdts`, and `analyzer_options`, supplied to `import_binary` or `reanalyze_binary` and stored with the binary (LIFE-043); unset options take their defaults. A "configuration warning" is attached to the program it concerns, logged at WARNING level, and exposed through the program's status in the project listing (LIFE-037).*

---

## Inputs and Defaults

- [x] **ACFG-001**: Where `--symbols-path` is not given, the system shall use `<project path>/symbols` as the local symbol store directory.
- [x] **ACFG-002**: The system shall apply a binary's `gdts` analysis option (zero or more GDT archive paths) to that binary's program in the order given.

## Application Order

- [x] **ACFG-003**: When auto-analysis of a program is about to run (the program is not yet marked analyzed, or re-analysis was requested for it), the system shall apply every GDT archive in that binary's options to the program inside a transaction, before `analyzeAll`, and shall not apply GDT archives to a program whose auto-analysis is skipped.
- [x] **ACFG-004**: When auto-analysis of a program is about to run (the program is not yet marked analyzed, or re-analysis was requested for it), the system shall apply symbol configuration and analyzer-option configuration to that program immediately before `analyzeAll`.

## Symbols / PDB

- [x] **ACFG-005**: Where a binary's `no_symbols` option is set, the system shall disable the `PDB Universal` analyzer on that binary's program before its auto-analysis, if that analyzer is registered for the program, logging a warning. For a program without it (such as ELF or Mach-O), the system shall leave its analysis options unchanged and record no configuration warning.
- [x] **ACFG-006**: Where a binary's `no_symbols` option is not set, `ghidrecomp` is importable, and the binary has a `pdb_path` option, the system shall configure that PDB file for the binary's program before auto-analysis.
- [x] **ACFG-007**: Where a binary's `no_symbols` option is not set, `ghidrecomp` is importable, and the binary has no `pdb_path` option, the system shall configure a symbol server rooted at the local symbol store directory and enable remote PDB lookup for the program before auto-analysis.
- [x] **ACFG-008**: When PDB or symbol-server configuration completes for a program, the system shall log the loaded PDB location at INFO level, or log a warning if no PDB was found.
- [x] **ACFG-009**: Where `ghidrecomp` is not importable, the system shall skip PDB and symbol-server configuration and continue with analyzer-option configuration.
- [x] **ACFG-018**: Where `ghidrecomp` is not importable and a binary's `no_symbols` option is not set, the system shall record a configuration warning on that binary's program saying that symbol configuration was skipped.
- [x] **ACFG-021**: If PDB-file or symbol-server configuration raises for a program, then the system shall record a configuration warning with the reason and continue with the program's analysis.

## Analyzer Options

- [x] **ACFG-010**: Where a binary has an `analyzer_options` option (a mapping of Ghidra analysis option names to values), the system shall apply each entry as a named analysis option on the binary's program before auto-analysis, whether or not its `no_symbols` option is set.
- [x] **ACFG-011**: When setting an analysis option of Ghidra type INT or LONG, the system shall coerce the value with `int()`; of type DOUBLE or FLOAT, with `float()`; of type STRING, with `str()`.
- [x] **ACFG-012**: When setting a BOOLEAN analysis option, the system shall treat a string value as true only if it equals `"true"` case-insensitively, and shall convert a non-string value by Python truthiness.
- [x] **ACFG-013**: When setting an ENUM analysis option, the system shall resolve the value by enum constant name, falling back to the first constant whose string representation equals the value.
- [x] **ACFG-014**: If an ENUM analysis option has no current value, or no enum constant matches the supplied value, then the system shall record a configuration warning naming the option and value and leave the option unchanged.
- [x] **ACFG-015**: If an analysis option's Ghidra type is not INT, LONG, STRING, DOUBLE, FLOAT, BOOLEAN, or ENUM, then the system shall record a configuration warning naming the option and leave it unchanged.
- [x] **ACFG-019**: If an analysis option's value cannot be coerced to the option's type, then the system shall record a configuration warning naming the option and value, leave the option unchanged, and continue with the remaining options.

## GDT Archives

- [x] **ACFG-016**: When applying a GDT archive to a program, the system shall open the archive read-only and apply its function data types across the whole program with source type `USER_DEFINED`, creating bookmarks for applied types, and shall not replace a function signature whose existing source is `USER_DEFINED`.
- [x] **ACFG-017**: If applying a GDT archive to a program raises or reports failure, then the system shall record a configuration warning naming the archive and the reason (including Ghidra's status message), and continue.
- [x] **ACFG-020**: When a GDT archive has been applied to a program, the system shall close the archive.
