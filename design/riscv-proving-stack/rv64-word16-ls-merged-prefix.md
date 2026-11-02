# LS merged local lookup prefix

Encoding-v2 keeps MAIN79 and all35 U16 and5 U8 queries. It replaces four
local lookup prefixes with one, pairs across lookup-family boundaries, and
keeps RAM14 in a separate physical prefix. Interaction width is96 instead
of116; every273 residual remains degree at most3 on the native2n domain.

There are42 affine local fractions: one negative OWNER19 occurrence,35 U16,
five U8, and one selection5. Twenty-one strict pair inverses require84 base
columns and one prefix requires4. The independent RAM inverse/prefix adds8.
This is why36 columns is not the floor for the current query roster.
Pairing OWNER with a range denominator uses numerator active*D_range+D_owner;
the other pairs use D_left+D_right. The cleared identities stay cubic.
The strict product inverse remains constrained on padding and zero weight.

The local authenticated claim is OWNER+R16+R8+selection. These remain four
additive ledger fields for global closure and publication, but the LS AIR
binds their sum. No receiver may treat an individual local ledger share as
an independently authenticated statement. RAM remains separately bound so
moving debt between RAM and OWNER while preserving the total fails physical
polynomial proving. Shared RAM is still closed only by the aggregate receiver.

The generator retains the original five running sums for histogram checking
and claim attribution. It constructs pair inverses from existing checked
range/selection dictionaries and the strict owner inverse. It writes only
one combined local prefix. Serial centering and the two-wave joined prefix
correction use exactly the same combined claim. MAIN retirement, metadata
retry on errors, worker joining and eventual metadata release are preserved.
This does not halve inversion work: range inverses were already shared.

At packet0 LS log21 the reduction saves41,943,040 committed base cells
(160MiB raw) and83,886,080 native2n point values. Current and previous OODS
openings decrease32 values. The real4,194,303-instruction proof freshly
verifies with identical CPU boundary and all708,957 RAM records. Native
same-challenge claims and projected inverses/prefixes match the independent
legacy generator. The legacy V1 closed-LS control remains byte-identical.
See the committed ls-merged-prefix-v2.json receipt for gates and artifact
hashes. The observed real run overlapped engineering and is not a speedup.

The separate owner-range induction proposal is not enabled. No canonical
input, output, clock, address, permissions, selection or range obligation is
removed by this encoding. Fixed setup and transcript identities bind the
new width, masks and encoding authority without a runtime version enum.
