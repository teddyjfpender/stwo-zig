# Canonical execution-session owners

Separated instruction retirement and borrowed diagnostic contracts from the
canonical session lifecycle. `segment_session.zig` retains initialization,
continuation admission, clock boundaries, poisoning and result publication.
Its 829 lines are below the manual-source ceiling. The retirement owner is 236
lines; observer/options contracts are 77 lines.

The public session aliases and supported profile factories remain unchanged.
Retirement is bound to the same compile-time profile, candidate flags and
extension-state type. Ordinary opcodes still retire through typed authority;
host handling and pre/post observer order are preserved.

The transfer audit compared all moved retirement/observer bodies after only
normalizing whitespace and rebinding `self` to the generic helper. Observer and
options declarations match after whitespace normalization. No equation, trace
field, error behavior or continuation contract was changed.

Validation:
- Focused `test-execution-session`: 31 tests pass, compile six seconds and run
  703 ms. Includes host and continuation behavior.
- Product closure and typed proposal isolation: 44 tests pass.
- Frontend test inventory: two tests pass.
- Formatting and diff whitespace checks pass.
- Source conformance falls from 106 to 105 size findings. No baseline suppression.

No complete-proof rebuild was repeated for the unchanged-body move. The final
qualified typed-recursion checkpoint remains the preceding implementation source;
this subsequent batch has the scoped validation above. Linux artifact publication
qualification remains valid because no artifact-store source changed.
