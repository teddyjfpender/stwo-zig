# Closed homogeneous G2 transition source

This isolated source program implements the exact doubling and mixed-addition normalization used by the existing Miller preparation oracle. It adds no VM tag, execution feature, source-suite admission or proving-speed claim. The preceding whole-pairing model is in `opstack/tools/pairing_schedule/FUSED_COST.md` at commits 228f6fc69/94d996702.

The immutable program emits 24 scalar canonical writers for doubling and 22 for addition. Each writer is a degree-two congruence over at most six/ten scalar operands. IDs increase strictly; operand IDs, zero slots, constant sources and output/fanout maps are source-derived. Doubling's half and twist B are literal initial values, not advice. The initial point and addition point in this fixture are canonical Fq coordinates. This constructor condition is not a production AIR input-canonicality proof, nor does the module prove curve membership, subgroup membership or infinity policy.

The source uses the common direct polynomial integer row authority, extended through `row.LayoutFor` to handle affine input terms as well as products. The old dense namespace remains a wrapper over the same implementation. Every write has a quotient, byte-split bounded carries and strict canonical result certificate. The common envelope independently reproduces the prior source model:

| Role | Scalar rows | Operand slots | MAIN | Quotient bytes | Carries | Carry bits | Strict residual + / − |
|---|---:|---:|---:|---:|---:|---:|---:|
| Double | 24 | 6 | 498 | 33 | 64 | 17 | 29,809,248 / 29,809,756 |
| Add | 22 | 10 | 626 | 33 | 64 | 17 | 29,809,262 / 29,809,501 |

Both offsets are 67,424 and both residual bounds are strictly below M31. The local BYTE query count is 353 per arithmetic row. Interaction width, actual source-binding geometry and physical proof cost remain pending; the earlier 40-column figure is an allowance, not a result of this source gate.

The canonical line preimages are exported separately from their immutable signed/factor-three interpretation. Doubling exports `(h,j,i)` with line `(-h,3j,i)`; addition exports `(lambda,theta,j)` with line `(lambda,-theta,j)`. No negative or factor-three-scaled noncanonical value is represented as a canonical SSA writer. A later point-scaling relation must consume these exact coefficients and signs.

ReleaseSafe source tests compare all point and line outputs against independent direct Fq2 formulas on zero, p−1 and mixed coordinates; four pinned generator/nontrivial-homogeneous cases also match the existing complete-pairing Python oracle exactly. Every scalar result, quotient and carry mutation rejects. A coherent result+p forgery retains BYTE/range and exact integer congruence validity for every writer, while its strict canonical-write certificate rejects. All old dense source/witness tests remain in the same test root.

The next gate is physical BYTE/SSA source binding and a source-owned initial/export frontier, followed by the complete positive request and recursive receiver. No full heavy replay is required for this foundation.
