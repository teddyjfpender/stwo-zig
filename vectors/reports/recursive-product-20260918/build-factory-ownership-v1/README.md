# Build factories and canonical public surface

Product identity/capability declarations now have a pure build owner. CPU
executable construction is separate from product registration; five identical
observer constructors share one implementation with explicit source/binary
selectors. Transfer audits compare all eleven original constructor bodies and
seven product declarations. Behavior and protocol identity are unchanged.

Reviewed package declarations now match the earlier route retirement: removed
51 stale CPU facade exports, declared the dedicated leaf/parent verifier and
parent producer imports, replaced Metal's obsolete small-recursion runner
binding with the detached leaf/parent bindings, and declared the shared producer
allocator used by native ingress and recursive transactions. The detailed
export/import deltas are in `reviewed-package-changes.json`. No source API was
restored or widened to make the package check pass.

CPU documentation no longer advertises retired temporal and segment-outer
exports. The canonical typed-recursion guide records the supported command,
module ownership, statement-envelope distinction and final validation boundary.

Validation: all 103 package/build-architecture/product-closure/proposal-isolation
tests pass; the root build graph constructs; Zig formatting and git diff checks
pass. Logs and transfer audits are retained here. Complete proofs were not
repeated for these body-preserving build moves and declaration/documentation
repairs. The earlier typed-final-authority checkpoint remains the proof evidence
for its exact source, not for this updated tree. Final integration qualification
and the broader original baseline goal remain open.
