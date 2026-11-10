# Closed homogeneous G2 transition source

This isolated source program implements the exact doubling and mixed-addition normalization used by the existing Miller preparation oracle. It adds no VM tag, execution feature, source-suite admission or proving-speed claim. The preceding whole-pairing model is in `opstack/tools/pairing_schedule/FUSED_COST.md` at commits 228f6fc69/94d996702.

The immutable program emits 24 scalar canonical writers for doubling and 22 for addition. Each writer is a degree-two congruence over at most six/ten scalar operands. IDs increase strictly; operand IDs, zero slots, constant sources and output/fanout maps are source-derived. Doubling's half and twist B are literal initial values, not advice. The initial point and addition point in this fixture are canonical Fq coordinates. This constructor condition is not a production AIR input-canonicality proof, nor does the module prove curve membership, subgroup membership or infinity policy.

The source uses the common direct polynomial integer row authority, extended through `row.LayoutFor` to handle affine input terms as well as products. The old dense namespace remains a wrapper over the same implementation. Every write has a quotient, byte-split bounded carries and strict canonical result certificate. The common envelope independently reproduces the prior source model:

| Role | Scalar rows | Operand slots | MAIN | Quotient bytes | Carries | Carry bits | Strict residual + / − |
|---|---:|---:|---:|---:|---:|---:|---:|
| Double | 24 | 6 | 498 | 33 | 64 | 17 | 29,809,248 / 29,809,756 |
| Add | 22 | 10 | 626 | 33 | 64 | 17 | 29,809,262 / 29,809,501 |

Both offsets are 67,424 and both residual bounds are strictly below M31. The local BYTE query count is 353 per arithmetic row. The source gate alone does not establish interaction width or physical cost; the qualification below supplies those measurements. The earlier 40-column figure was a design allowance.

The canonical line preimages are exported separately from their immutable signed/factor-three interpretation. Doubling exports `(h,j,i)` with line `(-h,3j,i)`; addition exports `(lambda,theta,j)` with line `(lambda,-theta,j)`. No negative or factor-three-scaled noncanonical value is represented as a canonical SSA writer. A later point-scaling relation must consume these exact coefficients and signs.

ReleaseSafe source tests compare all point and line outputs against independent direct Fq2 formulas on zero, p−1 and mixed coordinates; four pinned generator/nontrivial-homogeneous cases also match the existing complete-pairing Python oracle exactly. Every scalar result, quotient and carry mutation rejects. A coherent result+p forgery retains BYTE/range and exact integer congruence validity for every writer, while its strict canonical-write certificate rejects. All old dense source/witness tests remain in the same test root.

Reproduce the source and existing dense regression gate with:

```sh
zig build test-riscv64-op-g2-source -Doptimize=ReleaseSafe -j1
```

The test-count guard requires all 18 source tests. This command does not admit
the prototype into the VM, production proving or the recursive receiver.

The physical BYTE/SSA source-binding and initial/export-frontier gate is recorded below. The complete positive request and recursive receiver remain open. No full heavy replay is required for this foundation.

## Closed physical source qualification

`delegations/op_g2` now proves the transition using one arithmetic component, an independently sized initial/export frontier, one shared BYTE table, and four source-GKR instances. Arithmetic has 32 INTER columns (BYTE16 + SSA16); frontier and table each have 16. The frontier is log5 and both arithmetic/table are log8. Both local relations close separately, with full typed SSA35 tuples. Writer IDs and exact fanout come only from immutable ROM. Input byte equalities occur exclusively in the independent frontier.

The final ReleaseSafe artifacts are 67,696 native +23,688 child bytes for doubling, and 85,136 +23,688 for addition. These are correctness fixtures, not timings. The initial/export frontier explicitly accepts independently expected bytes and rejects noncanonical expected values or wrong half/B literals. Fresh reception rebuilds its FIXED commitment from pinned inputs and oracle outputs; it never adopts producer key authority. Each class rejects 11 physical binding/source controls, including a genuinely committed wrong-ID program, changed initial bytes, and replay against another coherent pinned input/output/statement class.

For each transition, a coherent internal result+p is propagated through every subsequent operation. Its local BYTE/SSA proof still closes, while the canonical writer fails physical OODS. The captured failed proof is retained and independently rejected as `OodsNotMatching`. The all-role complete equations pass degree-three testing, and the full ReleaseSafe regression also requalifies the earlier dense BYTE and two-operation SSA experiments after extending their shared BN254 emitter. Their experimental source fingerprints change; no byte-parity claim is made against prior research artifacts. Protected production/R5 authorities and selected profiles are unchanged.

The public fixture bytes are deliberately in FIXED, so this fixture key is input-specific. It is not a reusable production chip VK. A complete request provider must bind variable input/export MAIN to its authenticated external statement/Wire source and separately qualify curve, subgroup and infinity policy. Exact role geometry, positive mass bounds, artifact hashes and remaining gates are in `g2-transition-physical-v1.json`.
