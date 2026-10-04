# Write-back Specs

**LLD**: docs/intent/write-back/write-back-design.md
**Implementing artifacts**:
- src/ghidra_mcp/tools.py (`_with_transaction`, comment, rename, variable, and prototype tool methods)

Status markers: `[x]` implemented · `[ ]` active gap · `[D]` deferred

*Tests: `tests/test_write_back.py` (and `tests/test_category_guards.py` for WB-014), with end-to-end checks in `tests/integration/test_ghidra_smoke.py`.*

---

## Transaction Contract

- [x] **WB-001**: When a write tool applies its mutation, the system shall perform the mutation inside a single Ghidra transaction.
- [x] **WB-002**: If a write tool's mutation raises an error, then the system shall roll back the transaction, leaving the program unchanged.
- [x] **WB-003**: When a write tool's mutation completes without error, the system shall commit the transaction and save the program to the project before returning.
- [x] **WB-004**: The system shall record every write-back edit with source type `USER_DEFINED`.
- [x] **WB-005**: The system shall resolve targets, decompile, and parse inputs before opening a write transaction, so that input errors do not open a transaction.
- [x] **WB-022**: If saving the program fails after a write transaction has committed, then the system shall fail the call as `stop`, stating that the edit is applied in memory but not saved.

## Comments

- [x] **WB-006**: When setting a disassembly comment, the system shall set the end-of-line comment at the given address to the given text.
- [x] **WB-007**: When setting a decompiler comment, the system shall set the pre-comment at the given address to the given text, so that it appears as a `//` comment in the decompiler view.
- [x] **WB-025**: If the address given to a comment tool is not in the program's memory, then the system shall raise a `ValueError` before opening a transaction.
- [x] **WB-027**: When a comment tool is given empty comment text, the system shall remove that kind of comment at the address, and the tool descriptions shall say so.
- [x] **WB-026**: When writing comments, the system shall use Ghidra's `CommentType` API rather than the int-constant overloads deprecated for removal since Ghidra 11.4.

## Renames

- [x] **WB-008**: When renaming a function identified by name or address (`rename_function`), the system shall resolve the function in write mode (RES-003 to RES-007, RES-021, RES-022, RES-025) and set its name to the new name.
- [x] **WB-009**: When renaming a function by address (`rename_function_by_address`), the system shall rename the function whose entry point is exactly that address.
- [x] **WB-010**: If no function's entry point is at the address given to `rename_function_by_address`, then the system shall raise a `ValueError`.
- [x] **WB-011**: When renaming data at an address that holds defined data, the system shall rename the data's primary symbol when it is a non-dynamic symbol, and otherwise (no primary symbol, or a dynamic default label) create a `USER_DEFINED` label with the new name.
- [x] **WB-012**: The `rename_data` tool description and the README shall state that the address must hold defined data, and that a label is created only when that data has no (non-dynamic) primary symbol.
- [x] **WB-023**: If Ghidra rejects a new function, data, or variable name as invalid or duplicate (`InvalidInputException` or `DuplicateNameException`), then the system shall report it as a `fix_input` failure carrying Ghidra's reason, with the transaction rolled back.

## Local Variable Edits

- [x] **WB-013**: When renaming or retyping a local variable, the system shall decompile the containing function with a 30-second timeout and locate the variable by an exact, case-sensitive match on its decompiler-displayed name.
- [x] **WB-014**: If the containing function cannot be decompiled during a variable rename or retype, then the system shall fail as `stop` with a message that includes the decompiler's message.
- [x] **WB-015**: If no local variable of the given name exists in the decompiled function, then the system shall raise a `ValueError` listing the available variable names.
- [x] **WB-016**: When renaming a local variable, the system shall update the variable's name in the program database through the decompiler's high-level model.
- [x] **WB-017**: When retyping a local variable, the system shall resolve the type string per RES-014, RES-015, RES-023, and RES-024, and update the variable's data type in the program database through the decompiler's high-level model.

## Function Prototypes

- [x] **WB-018**: When setting a function prototype, the system shall parse the prototype as a C function declaration and apply it as the function's signature (return type, parameter names, and parameter types).
- [x] **WB-019**: If a prototype cannot be parsed, or does not parse to a function definition, then the system shall raise a `ValueError` explaining the expected form.
- [x] **WB-020**: If applying a parsed prototype to a function reports failure, then the system shall roll back the transaction and fail the call as `stop`, carrying Ghidra's status message, rather than report success.
- [x] **WB-024**: When applying a prototype renames the function (because its previous name was a default name), the system shall state the function's new name in the confirmation.

## Results

- [x] **WB-021**: When a write tool succeeds, the system shall return a confirmation message describing the change.
