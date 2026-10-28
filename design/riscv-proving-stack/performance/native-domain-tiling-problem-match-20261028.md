# Move native proof growth from columns into rows

Task: avoid making Merkle leaves and recursive verifier programs wider whenever
an opcode exceeds 65,536 occurrences. The native generator currently adds
another entire component and its column set at that threshold. Increasing an
execution segment therefore does not necessarily reduce opened column work.

Canonical match: blocked matrix layout / aspect-ratio selection for a batched
polynomial commitment. For a family with R occurrences and C columns, a cap B
creates ceil(R/B) copies of C columns. Increasing B can leave committed area
near C*R while reducing opened column values and component descriptors by
approximately the shard-count ratio. Padding and larger quotient/FFT domains
can offset the gain. This is a derived work model, not a block-time forecast.

Alternatives: (1) keep the 2^16 cap and combine executions (already measured);
(2) raise the native producer cap to 2^20 while preserving independently sized
families and full nonfinal shards; (3) introduce a new PCS encoding that reduces
opening width. Select (2) first because it preserves the existing STARK
equations and standard PCS and directly tests the width hypothesis. Changing
the hash or weakening query/PoW settings is outside this experiment.

The [Stwo prover](https://github.com/starkware-libs/stwo/blob/dev/crates/stwo/src/prover/mod.rs)
opens masks for the component columns and constructs the composition over their
domain sizes. [ZisK's topology](https://github.com/0xPolygonHermez/zisk/blob/1e22630bb7e143c30705a1603ed87cfd3da8c6ec/pil/zisk.pil)
uses much larger, independently selected AIR domains. These are mechanism
references, not a transferable speed ratio. No implementation is copied.

Integration: introduce one native tiling policy for accepted full-shard logs
16–20. Preserve existing log-16 statements. The first shard of each family
chooses that family's capacity; all nonfinal shards must be exactly full and
the final shard cannot exceed that capacity. Smaller single-shard families
remain legal. Opcode witness routing must derive the admitted family capacity
from its first descriptor instead of dividing every row ordinal by 65,536.
The native producer chooses 2^20; legacy construction stays at 2^16.

Identity/security: no new witness columns or equations. Every log size, row
count and column count is already bound by the native template geometry
digest and independently reconstructed at verification. The public total
retirement count, family order, physical claims, clock bound, local-x0 checks,
source seal and full global closure remain mandatory. New readers still admit
old full log-16 shards; old readers may reject the larger geometry. Do not
mislabel the new geometry as byte-identical proof output.

Prediction: at a 1.31M-cycle mixed guest, wider row domains should remove most
duplicate opcode shards and materially reduce recursive AIR area. A gain in
recursive work must survive actual collection, base proving, verification and
the same 40 GiB host budget. Reject as the default choice if complete driver
time or memory regresses substantially. Measure the original and changed
binaries sequentially on the same host, security, ELF, input and endpoints.

Qualification: full native proofs, recursive native batch and fresh global
closure at canonical q70/PoW26; independent cold receive and wrong identity /
missing proof rejection. Unit checks cover old and large shard sequences,
partial nonfinal shards, reordered families and oversized tails. Test more
than one full 2^20 shard separately if the measured guest does not cross it.
This experiment does not close all global proof families recursively and
cannot establish seconds-level Ethereum proving by itself.
