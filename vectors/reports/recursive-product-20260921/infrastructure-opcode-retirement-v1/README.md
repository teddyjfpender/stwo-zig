# Retired duplicate infrastructure opcode AIR

The production assembly already constructs every opcode through typed
`SemanticComponent.init`, with its separately admitted lookup component.
`RiscVTraceComponent` is constructed only for program and memory infrastructure.
The retained `.opcode` branch therefore exposed an obsolete alternative evaluator.

Removed that branch from point and prepared-domain evaluation, together with
opcode claims, opcode-only prepared state and the unused imports. Its Kind can
now represent only program and memory, retaining their old numeric discriminants.
Program/memory work accounting now has a separate owner. The program and memory
point/domain evaluation bodies match the previous source exactly; accounting
bodies match after type-binding changes and removal of unsupported opcode cases.

The independent prepared-state resource fixture now omits the deleted opcode
source-count field. This reduces the relevant resource reservation by eight
bytes on the tested host; the initial focused run detected this difference.
No equation, transcript encoding or program/memory policy was changed.

Validation:
- New `test-infrastructure-component`: eight tests pass (five-second compile,
  494 ms execution), including allocation rollback, domain ownership, exact
  memory evaluation and all four program/memory work-profile policies.
- Existing `test-semantic-component`: 10 tests pass.
- Product closure and typed proposal isolation: 44 tests pass.
- Frontend test inventory: two tests pass.
- Formatting and diff whitespace checks pass.
- Source conformance: 104 size findings, down from 105; no baseline suppression.

This is scoped validation after the final typed-recursion checkpoint. A full
CPU/Metal proof qualification was not repeated for removal of a route absent
from production assembly. The preceding frozen-source checkpoint and this
subsequent source change remain separately identified.
