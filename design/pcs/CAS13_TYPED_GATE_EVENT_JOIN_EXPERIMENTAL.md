# CAS13: typed challenge order in the four-root H1 control

**Status:** experimental protocol control. No production selector, security
bits, or P05 discharge.

This branch stacks the P07 `PairedGateEventPlanV2` wrapper on CAS12. The H1
honest proof test now obtains all challenges and raw queries through named
stage methods: fixed and main roots, interaction PoW and lookup pair,
interaction root, composition gamma/root, OOD seed and claims, batch lambda,
one fold alpha, both terminal vectors, final PoW, then queries. The wrapper
copies the fold-height roster and rejects calls out of order **when callers
use its methods without mutating its public Zig fields**. Its `channel`,
`stage` and `fold_heights` fields remain externally mutable; a selected
verifier must encapsulate the plan behind a private owner or otherwise prove
those fields cannot be altered between calls. Its source
roots and query positions still come from a synthetic fixture; a selected
verifier must derive their expected values from its sealed key, accepted
root frames and transcript query event.

The fixture has one source height and one OOD claim per column. It does not
cover the seven-height Gate roster, masks, line-tree commitments or a complete
outer proof wire. It also does not establish a theorem batch width `M`, a
source-bound release profile, or a BCS/ROM reduction. The current ordinary
Gate key's fixed log-20 table and conditional paper batching obstruction
remain unaffected by this typed event check.

Run the focused control:

```sh
zig build --build-file src/prover/build.zig test-four-root-framed-h1 -j4 -Doptimize=Debug
zig build --build-file src/prover/build.zig test-four-root-framed-h1 -j4 -Doptimize=ReleaseSafe
```
