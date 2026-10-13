# Experimental transposed cross-domain source commitment

`S31XDM02` is a versioned, source-opening fragment for two adjacent circle heights. It follows the **tree topology** in the [S-two whitepaper, Section 5.1, Eq. 85–87 and Algorithm 1](https://www.researchgate.net/publication/407022099_S-two_Whitepaper). The separate experimental [`S31P2F02` outer proof](PAIRED_TWO_HEIGHT_V2_EXPERIMENTAL.md) now embeds this fragment, but production verification does not dispatch to either format.

## The exact two-height geometry

At largest height `k`, source rows are in native bit-reversed order. A smaller-height row `i` receives the two largest-height children

```text
c0(i) = (i & 1) + 4 * (i >> 1)
c1(i) = c0(i) + 2.
```

Thus for a four-row source bundle `4b,4b+1,4b+2,4b+3`, the smaller-domain row `2b` gets children `4b,4b+2`, and row `2b+1` gets `4b+1,4b+3`. This is circle squaring: native bit 1 is removed while the sign bit 0 remains. The ordinary `j>>1` projection would remove the sign bit and is wrong.

The commitment hashes all largest-height values at the leaves. It hashes the two child hashes together, **then inserts the smaller-height source values at that parent node**. It continues upward to one root. The experimental hash framing uses distinct Blake2s tags for leaves, upper nodes, and inserted-value nodes; its byte hashes are not asserted to be identical to the paper's abstract `H`. The insertion topology is the part matched to Eq. 87.

## Wire and verifier contract

```text
S31XDM02 | version=2:u16 | reserved=0:u16 | total_len:u32
largest_log:u32 | largest_columns:u16 | smaller_columns:u16 | query_count:u32
cross_domain_root:[32]u8
for each sampled raw query:
    raw_row:u32
    largest_source_values: M31[4][largest_columns]
    smaller_source_values: M31[2][smaller_columns]
witness_count:u32 | shared_sibling_hashes:[32]u8[witness_count]
```

The caller supplies the expected root, exact geometry, and **independently sampled raw query sequence**. The parser checks magic and version before fields, enforces exact length and canonical M31 limbs, and rejects mismatched roots, query positions, profile, malformed witness lengths, inconsistent repeated projected values, and root mismatches. The witness is one compressed multiproof across all query bundles: at each level, sorted active nodes request a sibling hash only if that sibling is not already active. The verifier reconstructs the same tree from opened source values and rejects surplus or missing hashes. `verifyAndCollect` returns source values only after the complete multiproof succeeds; `transposed_paired_answers` then derives the original/quotient paired batches from those authenticated values, externally supplied OOD claims, and one shared batch challenge. The `S31P2F02` outer transcript binds these claims and the challenge, and invokes `verifyAndCollect` internally.

The intermediate FRI line layer is a later commitment round and remains a separate native Merkle root. `S31P2F02` authenticates that line and checks two folds after source authentication. The old `S31P2F01` proof, its two independent source roots, and its verifier remain isolated and unchanged.

Native tests run 16/8, 32/16, and 64/32 rows with a repeated raw query, then compare the authenticated paired answers against the existing quotient implementation at every opened row. A two-column fixture checks the order `f0, q0, f1, q1` at both heights against independent single-column batches and rejects a changed second-column opening. These are arithmetic and authentication tests, not a proximity proof.

## Measured fixture cost

Three raw queries, including one repeat, open four largest rows and two smaller rows per query, with one source column at each height. The existing separate-root figures use their native compressed multiproofs over the same rows. The `S31XDM02` byte count includes its 60-byte header, raw rows, source values, witness count, and hashes; it does not include OOD claims, line openings, or terminal coefficients.

| Heights | Separate-root witness hashes | Shared-tree witness hashes | Source roots | `S31XDM02` bytes |
| --- | ---: | ---: | ---: | ---: |
| 16 / 8 | 4 | 4 | 2 → 1 | 276 |
| 32 / 16 | 8 | 8 | 2 → 1 | 404 |
| 64 / 32 | 12 | 12 | 2 → 1 | 532 |

The shared tree saves one 32-byte root in this fixture; it does **not** reduce witness hash count for these query sets. Complete experimental outer wire sizes are recorded in the [P2F02 brief](PAIRED_TWO_HEIGHT_V2_EXPERIMENTAL.md). No speed or security claim follows from this source-only cost table.

## Remaining theorem and integration work

1. Generalize the fixed two-height outer verifier to every committed FRI layer down to the paper's terminal bound `B`, or prove a separate bound for its early terminal reveal.
2. Map the domain-separated Blake2s hash framing, compressed multiproof order, duplicate handling, and Fiat–Shamir replay to the paper's BCS oracle game. Its abstract `H` does not prescribe this exact byte encoding.
3. Refine the two-point conjugate quotient degree and correlated-agreement argument, conditional OOD point distribution, four-row bundle query-event implication, inverse-butterfly normalization, and conservative native parameters. The 3-query cost fixture and existing 70-query paths are not proven profiles.

Until these hold, the fragment and both paired outer proofs stay experimental and production admission remains fail-closed.
