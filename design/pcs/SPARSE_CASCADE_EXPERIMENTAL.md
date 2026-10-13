# Sparse two-row paired FRI cascade: experimental CAS05/XDM04

This milestone replaces the full-fiber *opening* of CAS04 with a sparse path through the same one-root transposed source commitment. It is a mechanics fixture and is **not dispatched by production PCS**. The [S-two whitepaper Protocol 4](https://www.researchgate.net/publication/407022099_S-two_Whitepaper) is the target for a future theorem refinement; this wire does not yet satisfy every published premise.

## Exact bit-reversed query schedule

Let the largest circle evaluation domain contain `N=2^k` rows in native bit-reversed order. Draw raw row `r` only after committing all roots and terminal coefficients. At source height `i`, where `0 <= i < h`, define

```text
b_i(r) = 2 * floor(r / 2^(i+1))
p_i(r) = b_i(r) + (r mod 2)
```

The selected circle point after `i` doublings is source row `p_i(r)`. The fold needs its adjacent conjugate pair, so XDM04 opens precisely source rows `{b_i(r), b_i(r)+1}`. A fold of that pair lands at line row `b_i(r)/2`; when another fold follows, CAS05 opens the two line rows `{b_(i+1)(r), b_(i+1)(r)+1}` and selects `b_i(r)/2 = b_(i+1)(r) + ((r >> (i+1)) & 1)`. This keeps the circle sign bit distinct from the line fold index. The tests exhaust every `r` in a 64-row domain at four heights and compare circle doubling, pair containment, line selection, and the exact `2^i` raw preimage count per selected source row. A separate Lean finite-equivalence proof is being developed; neither check is a full soundness theorem.

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

## Cost and fixtures

CAS04 opens `2^(h+1)-2` source rows and `2^h-2` line rows per raw query. CAS05 opens `2h` source rows and `2(h-1)` line rows, plus `O(h+k)` hash siblings per query. The host prover still constructs full committed trees and full-domain intermediate evaluations; the sparse memory claim applies to the verifier's opening authentication. XDM04 has its own `h<=8`, `k<=22`, `s<=16384` sparse verifier profile and a checked 64 MiB wire budget. The current dense host prover still inherits XDM03's `k<=16` cap, so the larger profile has a synthetic verifier-only authenticated-path fixture rather than a full honest proof.

| Fixture | CAS04 complete wire | CAS05 complete wire | CAS05 XDM04 fragment | Source rows/query CAS04 → CAS05 | Line rows/query CAS04 → CAS05 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 32/16/8, 5 raw queries | 1236 B | 1428 B | 722 B | 14 → 6 | 6 → 4 |
| 64/32/16/8, 3 raw queries | 1752 B | 1488 B | 628 B | 30 → 8 | 14 → 6 |

Hashes dominate the smallest fixture, so the three-height byte size regresses. The four-height fixture saves 264 B. These deterministic examples show geometry and wire costs only, not proving speed or security. The focused suite includes round trips, repeated raw queries, transcript rollback, root/statement/version/shape/noncanonical controls, changed source and line authentication data, and validly opened false intermediate and terminal folds.

## Theorem and release gaps

The `h<=8` cap and small honest fixtures do not reach a realistic conservative terminal degree. For example, at verifier-admitted `k=22`, blowup `b=2`, and `h=8`, the terminal bound `2^(k-h-b)` still allows 4096 coefficients. The dense host prover cannot construct this profile yet. A release profile needs a scalable height range and a small terminal bound `B`, or a separate theorem for early terminal revelation. The published full-cascade query/fold bound cannot be transplanted into this fixture.

The existing full-bundle counting lemma assumes every row of a full bundle is checked and **does not apply to the CAS05 sparse path**. Sparse query-event reduction must account for each projected row's `2^i` raw preimages, correlations among heights and the Fiat–Shamir query schedule. Also open are the native two-point quotient degree/correlated-agreement reduction, exact normalized Eq. 68 batch scaling (the current native height-`i` inserted term has an extra `2^-i` after normalization), terminal-degree/round-error accounting, full-domain/coset checks, concrete Blake2s BCS game, PoW, and conservative error parameters.

Conditional OOD counting needs care. The S31 algebraic map identifies regular seed images on the QM31 circle, while the native `y.c1 != 0` guard restricts uniform regular seeds to exactly `(p²-1)²` possible points for M31 order `p`, a strict subset of the paper's circle over QM31 outside the base-field circle. This count is **conditional on an ideal uniform seed** and does not establish the adaptive Fiat–Shamir distribution or a proven collision term. CAS05 has no proven native security bits and remains production fail-closed.
