# ALU sum-zero encoding v2

This replaces the experimental Word16 ALU's four zero flags, four inverses and
two product flags with one zero flag and one inverse of the sum of the four
difference limbs. FUNCTION13 operation IDs and native u64 semantics are unchanged.
There is no new runtime representation enum, CPU opcode, RAM path or recursion
interface. The existing staged signed-less coordinate stays present: inlining its
cubic expression into selector-weighted output would raise degree to four.

For native rows, mandatory physical U16 membership gives
`0 <= D0+D1+D2+D3 <= 262140 < M31_modulus`. Therefore sum zero means all four limbs
are zero. The three local identities are Boolean(z), z*sum=0 and
sum*inverse+z−1=0. They are **not** a sound equality test on arbitrary unbounded
field limbs. All twenty U16 queries and their closed physical relation remain.
No range/canonicality induction or global range-provider activation is assumed.

The regression deliberately uses canonical A=65536 and B=1 but forges
D=[p−1,1,0,0], all borrows zero, sum-zero flag one, inverse zero and false EQ=1.
Sign/low helpers remain consistent. Every local polynomial is zero. A forged
public consumer agrees with the false EQ result, so FUNCTION also closes; the
actual q70/P26 proof must fail the external U16 obligation. This bypasses the
native constructor's result check and computes literal interaction denominators.

| Quantity | Frozen encoding | Sum-zero v2 |
|---|---:|---:|
| Local main | 59 | 51 |
| Main including multiplicity | 60 | 52 |
| Local residuals | 64 | 53 |
| Full ALU residuals | 80 | 69 |
| Interaction | 52 | 52 |
| U16 queries per padded row | 20 | 20 |
| ALU masks | 122 | 114 |
| Quotient expansion | 2n | 2n |

The native inverse cache has 262141 M31 entries including index zero, rather than
65536. Indexing stays u32/usize; truncating to u16 is wrong. A=0,B=1 reaches the
maximum sum 262140 and is explicitly tested. Cache bytes rise from 262144 to
1048564, with the same additional 786420 bytes for temporary nonzero inputs.
Private per-worker counts, parallel physical fill and interaction ownership stay
unchanged. A log21 ALU main source loses 64 MiB; the nineteen log21 instances in
the pinned census model lose 1275068416 raw main bytes across the job, not as a
single-worker peak claim.

`alu_encoding.zig` is the sole immutable encoding fingerprint. It hashes its
version, exact numeric widths/query/constraint counts, sum bound and degree, and
is mixed by standalone ALU, raw V2 CPU and indexed coordinators. V2 static schema
and policy identities bind it too. BINARY v1's transcript and static fingerprint
are preserved exactly; all three retained BINARY execution proof hashes are
reproduced with a fresh receiving process. ALU and V2 proofs intentionally have
new encodings/pins. The old 007f ALU artifact is rejected under v2.

The standalone diagnostic has the same independently expected thirty-two-row
roster digest as the frozen semantic recipe, checked by a separate limb/LE32
calculation. Both the fixture's fact recipe and nativeResult specification are
source-identical to frozen commit3a42233752244e64e077b9e5b77ff6fb181f4aa0.
The small retained proof can grow despite fewer columns because transcript/query
locations change; this work does not claim old ALU proof-byte parity or a general
wire-size reduction. Complete pipeline timing is recorded separately when an
isolated matched run is available.

Later AddSub/Compare separation is only a budget model: conservative AddSub
39main/48inter/18U16 and Compare36main/40inter/14U16 retain signed-less staging.
The exact census has 27076716 AddSub and 10955559 compare operations, occupying
13+6 globally packed log21 instances. That model saves another 3263168512 raw
main/interaction bytes versus a universal sum-zero ALU; it excludes complete
setup, proof graph, scheduling and residency costs and is not implemented here.
