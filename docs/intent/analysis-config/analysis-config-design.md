---
parent: high-level-design
prefix: ACFG
---

# Analysis Configuration

*Code references name symbols in `src/ghidra_mcp/context.py`.*

## Context and Design Philosophy

Ghidra's auto-analysis output depends heavily on what it knows before it starts: debug symbols (PDBs), type libraries (GDT archives), and which analyzers are enabled with what settings. This component applies a binary's analysis options to its Ghidra program immediately before `analyzeAll` runs.

The options belong to the binary. They are supplied as arguments of `import_binary` or `reanalyze_binary`, and program-lifecycle stores them with the binary and hands them over when it analyzes it (LIFE-043). The only server-wide input is the local symbol store directory (`--symbols-path`). Every effect is a mutation of a Ghidra `Program`: analysis options, the PDB location, or function data types.

Principles:

- **Continue analysis, never silently.** A configuration step that can't be applied, whether it is a GDT archive, symbol setup, or one analyzer option, is recorded as a configuration warning on the program, and analysis continues with the rest. Warnings are visible in the project listing (program-lifecycle LIFE-037). This applies the HLD tenet *Explicit over silent* in its partial-result form: return what succeeded, with each failure marked.
- **A requested option is never silently dropped.** Every option supplied for a binary either takes effect or produces a warning.
- **One binary, one configuration.** A PDB, a set of GDTs, and analyzer tuning are given for a specific binary, so nothing has to guess which binary they were meant for (HLD tenet *Never guess for the caller*).
- **Coerce loosely typed input to what Ghidra expects** *[inferred]*. Option values arrive as JSON and are converted according to the type Ghidra reports for each option.

This component does **not** decide *whether* analysis runs, how it is scheduled, where options are stored, or when a program counts as analyzed. Those belong to program-lifecycle, whose analysis pass calls into this component (`_run_analysis`) only when auto-analysis is about to run.

## Inputs

Per binary, from the binary's record (program-lifecycle LIFE-043):

| Option | Supplied as | Default | Meaning |
|---|---|---|---|
| `no_symbols` | `import_binary` / `reanalyze_binary` argument | `False` | Disable PDB analysis for this binary |
| `pdb_path` | argument (must exist) | none | Load this PDB file for this binary |
| `gdts` | argument: an ordered list of paths (each must exist) | none | Apply these GDT archives, in order |
| `analyzer_options` | argument: an object mapping Ghidra analysis option names to values | none | Set these analysis options |

Server-wide: `symbols_path` from `--symbols-path` (default `<project_path>/symbols`).

Binaries given on the command line, and binaries already in the project, use the defaults.

## Application Order (per program)

When program-lifecycle's analysis pass decides auto-analysis will run (Ghidra says the program should be analyzed, or re-analysis was requested), `_run_analysis`, holding the `GhidraScriptUtil` bundle-host reference:

1. **GDTs** (`_apply_gdts`). Each archive is applied in the configured order, each in its own transaction (`apply_gdt`).
2. **Symbols and analyzer options** (`_configure_analysis`), together in one transaction: symbol configuration first, then each analyzer option.
3. `analyzeAll`, then program-lifecycle marks the program analyzed and saves it.

A program whose auto-analysis is skipped because it is already analyzed is left untouched.

## Symbol / PDB Configuration

Decision flow in `_configure_symbols`, with the binary's options:

```
no_symbols?
├─ yes → "PDB Universal" registered for this program?
│        ├─ yes → set it to False; log WARNING "Symbols disabled"
│        └─ no  → nothing to disable; log DEBUG
│        → done (analyzer options still apply)
└─ no  → import ghidrecomp.utility
         ├─ ImportError → configuration warning "symbol configuration skipped"; done
         └─ ok → pdb_path?
                 ├─ yes → set_pdb(program, pdb_path)
                 └─ no  → setup_symbol_server(symbols_path); set_remote_pdbs(program, True)
                 → get_pdb(program): log INFO "PDB loaded" or WARNING "No PDB found"
                 → any exception above → configuration warning with the reason
```

The symbol-server branch is the default whenever `no_symbols` is false and `ghidrecomp` is importable. *[inferred from the `ghidrecomp` function names]* It enables remote PDB retrieval, a network side effect whose servers are determined by `ghidrecomp`, not by this code.

`PDB Universal` is registered only for formats that carry PDB debug info, such as Windows PE. For an ELF or Mach-O program its option reports `NO_TYPE` (observed with Ghidra 12.1.4 on a Mach-O binary), so `no_symbols` has nothing to disable and records no warning.

## Analyzer Options

**Input shape:** `analyzer_options` is an object mapping a Ghidra analysis option name to a value, for example `{"Decompiler Parameter ID": false}`. Each pair is passed to `set_analysis_option`, which returns a warning when it leaves the option unchanged.

**Typed setter** (`set_analysis_option`): options live in `program.getOptions(Program.ANALYSIS_PROPERTIES)`, and the dispatch is on `str(opts.getType(name))`:

| Ghidra option type | Coercion | Setter |
|---|---|---|
| `INT_TYPE` | `int(value)` | `setInt` |
| `LONG_TYPE` | `int(value)` | `setLong` |
| `STRING_TYPE` | `str(value)` | `setString` |
| `DOUBLE_TYPE` | `float(value)` | `setDouble` |
| `FLOAT_TYPE` | `float(value)` | `setFloat` |
| `BOOLEAN_TYPE` | string → `value.lower() == "true"`; otherwise `bool(value)` | `setBoolean` |
| `ENUM_TYPE` | `Enum.valueOf(current.getClass(), value)`, falling back to matching `toString()` among `current.values()` | `setEnum` |
| `NO_TYPE` (an option name Ghidra doesn't recognize; observed with Ghidra 12.1.4) | n/a | warning "Unknown analysis option" |
| anything else | n/a | warning "unsupported type" |

An `ENUM_TYPE` option with no current value, or no constant matching the value, produces a warning. A value that can't be coerced (`int("abc")`) produces a warning naming the option and value, and the remaining options are still applied.

## GDT Application

`apply_gdt(program, path)`:

- Opens the archive read-only: `FileDataTypeManager.openFileArchive(File(path), False)`.
- Builds `ApplyFunctionDataTypesCmd([archive], None, SourceType.USER_DEFINED, always_replace=False, create_bookmarks=True)`. A `None` address set means the whole program *[inferred]*.
- Runs `cmd.applyTo(program, TaskMonitor.DUMMY)` inside a transaction it opens itself, committing only if `applyTo` reports success.
- Returns the result and the command's status message, and closes the archive in every case.

Verified against Ghidra's source:
- `ApplyFunctionDataTypesCmd` starts no transaction of its own, so the caller must hold one.
- With `alwaysReplace` false, a signature is replaced only when the command's source type outranks the function's most trusted existing source. Applying with `USER_DEFINED` therefore replaces default-, analysis-, and import-sourced signatures, but never an analyst's `USER_DEFINED` one.

## Configuration Warnings

Each warning names the step and the reason, and is attached to the program it concerns:

| Step | Recorded as a warning when |
|---|---|
| GDT archive | Applying it raises, or `applyTo` reports failure (the warning includes Ghidra's status message) |
| Symbols / PDB | `ghidrecomp` is not importable, so symbol configuration was skipped; or PDB-file or symbol-server setup raises |
| Analyzer option | The option is unknown; the value can't be coerced to the option's type; an ENUM option has no current value or no matching constant; the option's type is unsupported |

Warnings are also logged at WARNING level. `no_symbols` disables only PDB analysis; the binary's `analyzer_options` still apply. Each analysis pass starts with an empty warning list, so the listing shows the warnings of the latest pass (program-lifecycle LIFE-044).

## Decisions & Alternatives

| Decision | Chosen | Alternatives Considered | Rationale |
|----------|--------|------------------------|-----------|
| Where configuration comes from | Per-binary options supplied to `import_binary` / `reanalyze_binary`; only the symbol store location is server-wide | Server-wide CLI flags | A PDB matches exactly one binary, and GDTs and analyzer tuning differ per binary. Per-binary options also allow re-tuning one binary's analysis without a restart. |
| Symbol tooling | Delegate PDB and symbol-server setup to `ghidrecomp.utility` | Configure Ghidra's PDB analyzer options directly | *[inferred]* Reuse `ghidrecomp`'s existing setup. It is already used for call graphs. |
| Missing `ghidrecomp` | Continue without symbol configuration, and record a warning | Fail at startup; skip silently | `ghidrecomp` is an optional extra (README § Installation). The HLD tenet *Explicit over silent* requires the skip to be visible. |
| Disabling symbols | Turn off the single `"PDB Universal"` analyzer where it is registered (silently skip formats without it); analyzer options still apply | Skip only the symbol server; also drop analyzer options; warn on formats without the analyzer | One analyzer covers PDB loading; its name is unchanged in Ghidra 12.x (verified). Dropping unrelated requested options would be silent. A format without PDB support has nothing to disable, so a warning would only be noise. |
| Analyzer options shape | A flat object of option name → value, passed as a tool argument | A JSON file on the server, nested under extra keys | A tool argument needs no file on the server, and extra nesting carries no information. |
| Option value typing | Coerce based on Ghidra's reported option type | Require correctly typed values | *[inferred]* Values from agents and operators are loosely typed (e.g. `"true"` strings). |
| Configuration failures | Record a warning on the program and continue analysis | Fail the binary; log only | The HLD tenet *Explicit over silent*, in the partial-result form chosen for the project: one bad option or archive shouldn't cost the whole analysis, and it must not be invisible. |
| GDT archive lifetime | Close the archive after applying | Leave it open | Closing is correct and lighter. |
| GDT timing | Only when auto-analysis runs, each archive in its own transaction | Every analysis pass; once at import | Re-applying on every startup would touch already-analyzed programs, and the command requires a caller-held transaction (verified). A transaction per archive keeps one failed archive from rolling back the others. |
| GDT replace policy | `always_replace=False`, bookmarks on, source `USER_DEFINED` | `always_replace=True`; source `IMPORTED` | Analyst-set signatures must survive. With `always_replace=False`, `USER_DEFINED` replaces only lower-trust signatures (verified). `IMPORTED` would also defer to PDB-imported signatures, but would change the provenance the GDT records. |

## Open Questions & Future Decisions

### Resolved
1. ✅ **`no_symbols` scope.** It disables only PDB analysis; analyzer options still apply. (2026-10-03)
2. ✅ **Configuration errors.** A failing step is recorded as a warning on the program, and analysis continues (see Configuration Warnings). (2026-10-03)
3. ✅ **Missing `ghidrecomp`.** It is recorded as a warning and logged at WARNING. (2026-10-03)
4. ✅ **GDT archive lifetime.** The archive is closed after applying. (2026-10-03)
5. ✅ **`"PDB Universal"` name.** Unchanged in Ghidra's current source (12.x, verified). (2026-10-03)
6. ✅ **GDT timing.** Applied only when auto-analysis runs, inside a transaction (the command holds none; verified). (2026-10-03)
7. ✅ **GDT versus analyst work.** `always_replace=False`, so `USER_DEFINED` signatures are never replaced (verified semantics). (2026-10-03)
8. ✅ **Which binary a PDB belongs to.** A PDB is given per binary (`pdb_path`), so there is no ambiguity to resolve. (2026-10-03)
9. ✅ **`no_symbols` on non-PDB formats.** Skipped silently (DEBUG) when `PDB Universal` isn't registered for the program. (2026-10-03)
10. ✅ **Per-binary configuration.** Analysis options are `import_binary` / `reanalyze_binary` arguments. (2026-10-03)

### Deferred
*(none)*

### Open (observed behavior, intent unstated)
*(none)*

### Known gaps against stated intent
*(none)*

## References

- Code: `src/ghidra_mcp/context.py` (`_apply_gdts`, `_configure_analysis`, `_configure_symbols`, `set_analysis_option`, `apply_gdt`)
- Called from: program-lifecycle's analysis pass (`_run_analysis`), which supplies each binary's options (LIFE-043)
- Options supplied by: server's `import_binary` and `reanalyze_binary` tools (SRV-023, SRV-044); `--symbols-path` CLI flag
- External: `ghidrecomp.utility` (`get_pdb`, `set_pdb`, `set_remote_pdbs`, `setup_symbol_server`); Ghidra `Options`, `FileDataTypeManager`, `ApplyFunctionDataTypesCmd`
- Arrow: `docs/arrows/analysis-config.md`
