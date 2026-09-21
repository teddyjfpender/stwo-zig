# Obsolete executor shim deleted

Deleted `runner/execute.zig`. The canonical session no longer called it: ordinary
opcodes retire through the typed registry, and the session retirement owner
handles ECALL/EBREAK directly. The file only rejected ordinary instructions and
returned host errors, so retaining it as an oracle would preserve no independent
instruction semantics.

Removed its redundant refusal tests and assertions about its text. Retained the
source checks for typed retirement, witness construction, AIR construction and
retired semantic exports. The execution-session target now includes those source
checks alongside real host and continuation behavior. The typed registry's
existing compile-time coverage check admits no ordinary opcode without typed
authority. A guard rejects reintroduction of the old file or public export.

Validation:
- `test-execution-session`: 48 tests pass, compile six seconds, run 533 ms.
- Retirement/import guards, product closure, proposal isolation and package
  contracts: 58 tests pass.
- Frontend inventory: two tests pass.
- No Zig source still references the deleted executor.
- Formatting and diff whitespace checks pass.
- Source conformance remains at 104 size findings; no baseline suppression.

No production execution body changed and no full proof rebuild was repeated.
The last integrated typed-recursion checkpoint and these later scoped retirements
remain separately recorded. The broader baseline goal remains open.
