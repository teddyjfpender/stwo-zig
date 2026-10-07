# Witness-once staged block CPU production

Collection executes each guest segment once to construct its witnesses. Before
releasing that segment, it writes native and complete caller main cells as
canonical little-endian M31 columns using bounded16KiB buffers. Independent
physical roots, public/native/caller descriptors and file SHA/length pins stay
in bounded collection metadata. There is a512GiB aggregate file cap and
explicit per-file/column/reconstruction caps. All heap allocations remain
charged to the shared40GiB driver budget. Preflight planning is distinct from
execution witness generation.

After every family has supplied its first roots and the common seal is frozen,
the production driver reads staged cells instead of opening a second runner
pass. Native reconstruction restores public IO ownership, opcode/clock aliases
and exact lookup counters. It regenerates deterministic fixed columns and
recommits against the retained roots/template. That PCS moves into the native
producer; its first-round preparation hook avoids a second recommit of those
loaded cells. The producer releases the moved PCS before the staged owner.

Caller reconstruction restores all19 main blocks, Keccak counters, secp private
matrices, recovery caller rows and SHA main/fixed metadata. Signer counts come
from independently admitted descriptors; no fake affine recovery records are
allocated. Signed lookup counters are regenerated from the restored cells. A
mandatory physical recommit checks both roots and the key, and the original
warm transaction rechecks byte/counter snapshots and all sealed family entries
before publication. Its PCS is also moved rather than committed again.

Files are proposals and supply no verifier authority. Complete detached
reception remains independent. The emitted measurements report witness file
bytes and one execution-witness pass; peak RSS and complete proving time still
require a real block run.

The27-test bounded custody gate passed native and full SHA/Keccak/signer
reconstruction, all physical root/shape/counter parity, complete SHA main/fixed
row equality, first-pass publication equality, owner lifetimes, transactional
aggregate limits and file/descriptor/root mutation rejection. These fixtures
commit witnesses but do not prove execution segments. The driver compile-only
check also passed. Actual assembled canonical-security proof acceptance remains
outstanding, with segment runs stopped at the user's request.

[Qualification evidence](../../../../autoresearch/notes/2026-09-24-ethereum-block-delivery/cpu-performance-gates-v1/witness-and-direct-columns-custody.log).
