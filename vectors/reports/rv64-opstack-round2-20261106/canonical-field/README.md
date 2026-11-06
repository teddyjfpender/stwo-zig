# Canonical field and trie ownership checkpoint

All six pinned historical OP Mainnet cases match native Kona, complete RV64
execution, and independent Unicorn registers, exact retirement and service counts.
The canonical-field guest executes block 121065789 in 679,490,748 instructions
(72.83% fewer than the previous full guest's 2,500,418,167). Service RAM traffic
is 46,213,414 words: higher than the full guest's 34,927,949, but much lower than
the earlier Mont384 adapter's 162,809,929. No physical proof speedup is claimed.

`canonical` is opt-in. The guest-only Ark field patch uses canonical Fq storage
with R=R2=1 and forwards Fp2 multiply/square to the existing admitted plain Fp2
relation. The base field uses the existing arbitrary-modulus relation. Scalar
Fr and all default configurations retain upstream Montgomery behavior. Constants,
conversion, inverse, square root, serialization, pairing and group operations
are covered by 109 passing tests. The raw Montgomery-R metadata test is replaced
only in canonical mode by canonical storage checks; every prime-field semantic
test is retained. Default/Montgomery configurations still run the original test.

The 47-file Ark-ff snapshot retains upstream licenses and exact source inventory.
Only its manifest, const-construction seam and two extension arithmetic seams
change. Their default values preserve existing backends. Native Kona remains on
the registry implementation, independently of the guest patch.

Trie splits/collapses move subtrees and join packed nibbles instead of cloning
subtrees or allocating temporary paths. Eighteen offline property tests passed
before a mechanical extraction of collapse into `node_mutation.rs`; two targeted
mutation/error-preservation tests passed after extraction. A complete rerun of
that extracted module remains a final-check gate. Its canonical guest receipt
predates only this move and newly added tests, not the ownership algorithm.

These development manifests can include concurrent uncompiled edits. Exact ELF
and input hashes identify the measured artifact. The next checkpoint must cover
the combined guest and complete proof/reception. Cache preparation, GLV and
streamed metadata work in the working tree are not included in these numbers.
