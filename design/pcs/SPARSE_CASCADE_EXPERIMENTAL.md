# Sparse two-row paired FRI cascade: experimental CAS05/XDM04

The [CAS05 BCS/ROM boundary](CAS05_BCS_ROM_JOIN.md) records the exact raw
BLAKE2s transcript schedule, independent byte fixture, conditional query law,
and the theorem inputs still missing for a soundness claim.

This milestone replaces the full-fiber *opening* of CAS04 with a sparse path through the same one-root transposed source commitment. It is a mechanics fixture and is **not dispatched by production PCS**. The [S-two whitepaper](https://eprint.iacr.org/2026/532.pdf) multi-domain FRI protocol is the target for a future native refinement; this wire does not yet satisfy every published premise.

## Exact bit-reversed query schedule

Let the largest circle evaluation domain contain `N=2^k` rows in native bit-reversed order. Draw raw row `r` only after committing all roots and terminal coefficients. At source height `i`, where `0 <= i < h`, define

```text
b_i(r) = 2 * floor(r / 2^(i+1))
p_i(r) = b_i(r) + (r mod 2)
```

The selected circle point after `i` doublings is source row `p_i(r)`. The fold needs its adjacent conjugate pair, so XDM04 opens precisely source rows `{b_i(r), b_i(r)+1}`. A fold of that pair lands at line row `b_i(r)/2`; when another fold follows, CAS05 opens the two line rows `{b_(i+1)(r), b_(i+1)(r)+1}` and selects `b_i(r)/2 = b_(i+1)(r) + ((r >> (i+1)) & 1)`. This keeps the circle sign bit distinct from the line fold index. The tests exhaust every `r` in a 64-row domain at four heights and compare circle doubling, pair containment, and line selection. The [S31 Lean finite equivalence](https://github.com/teddyjfpender/s31/blob/main/formal/s31/S31/Gadgets/PcsFri/SparseCascadeQueries.lean) proves the exact `2^i` raw preimage count per projected source row. These index results do not establish hash binding or Fiat–Shamir sampling.

For example, at `r=5` and three heights:

| Height | Selected circle row `p_i` | Authenticated source pair | Fold output line row |
| --- | ---: | --- | ---: |
| 0 | 5 | 4, 5 | 2 |
| 1 | 3 | 2, 3 | 1 |
| 2 | 1 | 0, 1 | 0 |

The previous line pair for height 1 is rows 2, 3; for height 2 it is rows 0, 1. The verifier checks the fold output at the selected member of the next authenticated line pair, then checks the last output against the terminal polynomial.

## One-root transposed source authentication

The committed source tree still inserts height-`i` values at the corresponding internal nodes, with the XDM03 leaf/insertion/upper-node hash tags. XDM04 is a distinct versioned *opening* format and CAS05 uses a distinct transcript tag. Its source wire contains profile, root, each exact raw query, two canonical M31 rows per source height and column, and one ordered compressed hash witness. The source root and profile must match the independently supplied statement.

For each query, source row pairs alone do not give every child hash needed to reconstruct inserted parent nodes: the transposed tree's squaring-fiber siblings differ from the adjacent FRI fold pair. The witness supplies only missing children. The verifier first collects all source pairs from all queries, rejecting inconsistent duplicate rows, then reconstructs inserted nodes height by height in deterministic query/row order. It ascends the remaining tree using sorted unique active nodes and consumes a witness hash only when a sibling is absent. It rejects missing, extra, or inconsistent witnesses and wrong roots. It uses sparse maps with `O(s(h+k))` nodes for `s` queries rather than arrays over all `2^k` rows. Each committed line layer uses the existing sparse lifted Merkle multiproof for two rows per query.

The XDM04 decoder checks version, reserved bytes, exact total length, profile, raw bounds, all canonical source field elements, witness bound, and complete consumption *before* CAS05 transcript replay. Source values leave the authentication routine only after the expected root and exact sampled raw sequence verify. The complete CAS05 outer verifier independently binds profile, root, and OOD claims, samples its OOD point and challenges, derives its own quotients from authenticated source values, authenticates every line opening, checks every fold and terminal evaluation, and publishes caller transcript state only after success. Decoder output alone is untrusted.

The [independent scalar relation fixture](../../src/tests/native/prover/paired_fri_relation_bridge_test.zig) accepts a byte-encoded four-height proof built from nonconstant `x` and `y` source columns. It replays the transcript, checks that every XDM04 authenticated row equals the original source column, and computes each paired quotient from direct interpolation of the OOD claim and its conjugate. It compares those words with the verifier's `fromVerifiedOpenings` output. It then calculates every row of each line layer using scalar pair arithmetic without calling the prover's or verifier's fold helpers, compares queried line words, and compares every final row with the revealed terminal polynomial. At each stage it also checks the published normalized recurrence with scale `2^i`: divide both the carried and inserted pairs by `2^i`, apply the `1/2` butterflies, and multiply the result by `2^(i+1)`. This finite differential check covers the actual authenticated wire and multiple insertions. It is **not** a proof for arbitrary accepted wires or arbitrary source polynomials.

### All-query accepted-relation extractor

[`paired_sparse_relation_experimental.zig`](../../src/core/pcs/paired_sparse_relation_experimental.zig) adds an **audit-only** `verifyAndExtract` path. The outer byte-wire entry point first decodes a canonical CAS05 proof. The extractor runs the complete statement-bound verifier on a staged transcript, then replays the same transcript and reauthenticates the exact sampled XDM04 source pairs and each committed line pair. It copies all source rows, claims, challenges, line pairs, terminal coefficients, and raw queries into an owned `AcceptedRelation`. Only after its `check` method succeeds for **every raw query and every height** does it publish the staged channel. Normal verification still uses its original path, without the extractor's repeated authentication and allocations.

For source height `i`, let `Q_i^0,Q_i^1` be the two quotient-plus-original words recomputed from authenticated M31 rows by direct interpolation of the OOD claims. Write `P(a,b,u,α)=a+b+α(a−b)/u`. The extracted checker requires the following at each sampled raw query `r`:

```text
F_0(r) = P(Q_0^0, Q_0^1, y_0, α_0)
F_i(r) = P(L_(i−1)^0, L_(i−1)^1, x_i, α_i)
         + α_i² P(Q_i^0, Q_i^1, y_i, α_i)         for i > 0
F_i(r) = L_i[b_(i+1)(r) + ((r >> (i+1)) & 1)]  for i < H−1
F_(H−1)(r) = terminal(r >> H)
```

Here each `L_i` value is from a line pair reauthenticated at its committed root, and `terminal` is evaluation of the revealed ordered coefficients on the terminal line domain. The checker also confirms the circle doubling projection, overlapping-row consistency, exact profile dimensions and query range, and `F_i=2^(i+1)·G_i` for the normalized paper recurrence with the inserted height-`i` pair divided by `2^i`. Thus a **returned** certificate satisfies this explicit algebraic relation for its entire sampled query vector. A caller-built `AcceptedRelation` has no authentication status merely because its `check` method passes.

| Premise or result | Current evidence | Remaining proof obligation |
| --- | --- | --- |
| External statement, canonical bytes, transcript custody | Complete verifier is called before extraction; full replay channel state (digest and draw counter) must match; [source-order guard](../../scripts/check_cas05_relation_extractor.py) rejects removed or reordered custody checks | Zig control-flow semantics and adaptive Fiat–Shamir/BCS reduction |
| Source and line opening authentication | XDM04 and lifted line Merkle verifiers both run before rows enter the returned certificate | Concrete tagged Blake2s collision/binding bound; identification with fixed committed oracles |
| Every sampled quotient, fold, normalized insertion, and terminal check | Parameterized loops over the admitted profile; direct-interpolation relation checker; nonconstant fixture and hostile certificate/wire mutations | Formal native-to-Protocol-3 semantic refinement, polynomial degree and cross-domain correlated agreement |
| Published variable-round error expression | Short-terminal shape matches Protocol 3/Theorem 4; the eight-round roster is identified in S31 | Instantiate the exact native round/query/guarded-OOD and BCS parameters, then derive a conservative bound |

The extractor is an operational witness and source-pinned regression aid. It does not prove that BLAKE2s acts as a random oracle, that committed rows are collision-free, or that a false low-degree statement is unlikely to pass. CAS05 remains outside production PCS.

The [S31 Lean `PairedProtocolRecurrence` model](https://github.com/teddyjfpender/s31/blob/main/formal/s31/S31/Gadgets/PcsFri/PairedProtocolRecurrence.lean) proves, for arbitrary finite column rosters and all accepted heights, the `f_j, q_j` challenge-power order, equality of the native two-point line residual and direct interpolation, and the exact `2^i` normalization of the sampled fold relation. The source guard for this draft now pins the native original/quotient pairing, power advances, authenticated-batch-to-fold call path, and insertion order, with hostile mutations. The formal theorem takes successful row checks as a premise; the source guard is a regression check on Zig text. Neither establishes a whole-domain polynomial degree, a source-oracle commitment for the derived batch, or a Protocol 3 security reduction.

## Cost and fixtures

CAS04 opens `2^(h+1)-2` source rows and `2^h-2` line rows per raw query. CAS05 opens `2h` source rows and `2(h-1)` line rows, plus `O(h+k)` hash siblings per query. The host prover still constructs full committed trees and full-domain intermediate evaluations; the sparse memory claim applies to the verifier's opening authentication. XDM04 has its own `h<=8`, `k<=22`, `s<=16384` sparse verifier profile and a checked 64 MiB wire budget. The current dense host prover still inherits XDM03's `k<=16` cap, so the larger profile has a synthetic verifier-only authenticated-path fixture rather than a full honest proof.

| Fixture | CAS04 complete wire | CAS05 complete wire | CAS05 XDM04 fragment | Source rows/query CAS04 → CAS05 | Line rows/query CAS04 → CAS05 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 32/16/8, 5 raw queries | 1236 B | 1364 B | 658 B | 14 → 6 | 6 → 4 |
| 64/32/16/8, 3 raw queries | 1752 B | 1808 B | 820 B | 30 → 8 | 14 → 6 |

The outer version-6 tags change the sampled positions, which changes multiproof witness coalescing. Both tiny complete wires are larger than their CAS04 counterparts (128 B and 56 B respectively), despite fewer opened rows per raw query. These deterministic examples show geometry and wire costs only, not proving speed or security. The focused suite includes round trips, repeated raw queries, transcript rollback, root/statement/version/shape/noncanonical controls, changed source and line authentication data, and validly opened false intermediate and terminal folds.

## Theorem and release gaps

The S-two whitepaper's Protocol 3 and Theorem 4 permit a variable number of folds with a directly checked terminal polynomial. Write the initial domain as `D₀=2^k`, the blowup as `B=2^β`, and the native fold count as `H`. The paper indices are `n=k−β` and `r=H−1`; its terminal degree is strictly below `2^(k−β−H)` on a `2^(k−H)`-row domain. CAS05 serializes exactly that coefficient count. At verifier-admitted `k=22`, `B=2` (so `β=1`), and `H=8`, this is **8192 coefficients on 16384 rows**. The dense host prover cannot construct this shape yet because its XDM03 source path still caps `k` at 16. Early termination is therefore covered by the *idealized* published theorem; the full-cascade round roster must be replaced by the eight actual fold rounds when evaluating its bound.

The existing full-bundle counting lemma assumes every row of a full bundle is checked and **does not apply to the CAS05 sparse path**. Lean proves the sparse projected-row preimage count and a fixed-bad-set bound under independent ideal raw draws; it does not prove adaptive native sampling. The central unresolved join is a general native-verifier-to-Protocol-3 refinement for authenticated source and line words, two-point quotient degree and correlated agreement, exact normalized Eq. 68 scaling, circle/coset geometry, challenge order, and the terminal polynomial check. The normalized native height-`i` inserted batch requires a `2^-i` scale. The published variable-round error roster and BCS round count must be instantiated for the exact native transcript, with concrete Blake2s/Merkle collision and guarded-OOD reductions. CAS05 has no PoW stage. No native conservative security parameter is established.

Conditional OOD counting needs care. The S31 algebraic map identifies regular seed images on the QM31 circle, while the native `y.c1 != 0` guard restricts uniform regular seeds to exactly `(p²-1)²` possible points for M31 order `p`, a strict subset of the paper's circle over QM31 outside the base-field circle. This count is **conditional on an ideal uniform seed** and does not establish the adaptive Fiat–Shamir distribution or a proven collision term. CAS05 has no proven native security bits and remains production fail-closed.
