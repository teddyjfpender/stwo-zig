# First-accepted-block controller

Task: replace host selection of the final draw with a typed first-success scan.
For a verifier-owned capacity, consume every computed acceptance bit; pending
starts at one, selected=pending*accept, next_pending=pending-selected. Require
terminal pending zero. Only selected emits challenge coordinates and the consumed
attempt ordinal. This is a finite-state prefix scan joined by existing LogUp
wire tuples (reference https://eprint.iacr.org/2022/1530, already inspected).
No heuristic or external code. Work and rows are linear in admitted capacity.

Expose raw attempt batches from the existing hash/draw witness implementation,
without its ordered-draw public status/output anchors. Retain the legacy ordered
API; raw attempt exports have no native retry semantics until joined to the
controller. Consume all accepted candidate tuples, including padding after the
first acceptance; only the first accepted candidate reaches the destination.

Typed equations and fixed schedules must be independent of the acceptance pattern.
Prove a native two-block rejection fixture with the controller, test all short
patterns (first success / later success / exhausted capacity), and mutate state,
acceptance, selected output and count identities. Qualify the typed identity/export
and complete CPU proof in focused serial builds. Checked u64 base-counter addition
and reusable capacity admission remain a distinct following integration step;
a returned attempt ordinal alone is not a native transcript counter proof.
