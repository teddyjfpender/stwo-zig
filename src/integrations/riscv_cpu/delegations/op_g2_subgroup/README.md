# Conditional exact subgroup: closed physical foundation

This toy proves the complete canonical non-infinity affine curve/subgroup program
for an independently pinned generator Q. It does not admit a VM service, global
RAM/Wire/input packet, universal/infinity policy or complete pairing result.
FIXED includes Q-specific bytes, so the fixture key is explicitly **not reusable
production geometry**. Its B2/q12/P0 profile is for physical correctness only;
there is no128-bit security claim or production profile change.

The implementation reuses the original shared bounded quadratic arithmetic row,
the new `bn254_hint` canonical writer, and existing GP/GV GKR, local closure,
projection/prefix binding, mixed-log PCS/FRI and domain-evaluation kernels. New
protocol/source wrappers have distinct G2SUBG01 framing and source-owned instances;
existing G2 preparation and R5/R6/R7 implementations are not changed.

| Role | Active rows | log | FIXED | MAIN | INTER |
|---|---:|---:|---:|---:|---:|
| Initial +358 zero assertions |365|9|35|33|16|
| Quadratic arithmetic |4038|12|33|530|32|
| Canonical private inverse hints |352|9|3|95|32|
| BYTE provider |256|8|1|1|16|

The exact padded total is154,880 FIXED +2,236,672 MAIN +159,744 INTER =
**2,551,296 M31 trace cells**, before LDE. Arithmetic, hints and frontier are
independently sized; no4390-row combined table is padded to8192. Arithmetic uses
the qualified group1 integer carry recurrence (explicit compile-time/test guard).
Six source-defined GKR instances cover arithmeticBYTE512, hintBYTE64, tableBYTE1,
arithmeticSSA8, hintSSA1 and frontierSSA1, totaling2,163,968 padded facts. BYTE and
SSA challenges/zero-sum closures are independent. Source signed SSA mass16434
and BYTE consumer mass1,447,942 are strictly below M31 characteristic.

Initial frontier bytes come from independently expected Q and literal twistB/one.
All358 assertion rows are literalzero bytes under source-owned writer IDs:2curve,
352norm*hint−1,4endpoint. Each SSA read, writer ID, fixed fanout, operation selector
and assertion ID comes from the immutable r program; no producer validity flag or
unverified initial point can rekey the receiver. Hint95 uses source-fixed active,
ID and fanout;64BYTE lookups +31Boolean byte-carries enforce canonicality before
arithmetic inherits its bytes. The source statement/digest explicitly binds this
concrete hint implementation, rather than interpreting an older hypothetical
15-borrow layout as this proof.

Physical qualification (ReleaseSafe,2GiB cap):108,568B native PCS +38,088B local
GKR child, fresh independently reconstructed FIXED root/expected statement, all
six terminal bindings and full original equations. Eight physical/sample/point/
challenge mutations and five genuinely committed alternate FIXED controls reject
(initialID/bytes, hintfanout, arithmeticreadID and literalzero assertion). Separate
family closure rejects balanced BYTE/SSA debt. All original equations plus binding
constraints pass degree≤3 finite differences over arbitrary sampled FIXED inputs.

Strong negative: the first inverse hint becomes t+p, its wrapped canonical-distance
bytes are constructed coherently, and ALL later arithmetic is regenerated. Field
outputs, final subgroup endpoint, BYTE and SSA claims remain consistent; the
local GKR child verifies and closes. The physical native proof is retained as an
unverified failed proof and a fresh verifier rejects `OodsNotMatching`. The31st
carry/final-byte equation cannot be hidden behind modular arithmetic or a native
constructor. This closes the previously open physical hint-canonicality and
zero-assertion/SSA gates for this **conditional toy scope**.

Artifacts are retained under the receipt's directory: positive native/child and
coherent+p failed native/child. Peak requested114,169,323B under2,147,483,648B.
The entire four-test suite took5.00s OS wall including both proof attempts, fresh
controls and degree checks; this is NOT a single-prover or throughput benchmark.

Remaining gates: variable/call-bound source frontier, canonical RAM/Wire packet
binding, zero/infinity and full pairing policy, subgroup/preparation/dense/residue
composition, real source-owned native/recursive worker identities and bounded
soundness review. Existing production source-suite admission stays closed.
