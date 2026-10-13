# Experimental transposed cross-domain source commitment

`S31XDM02` is a versioned, source-opening fragment for two adjacent circle heights. It follows the **tree topology** in the [S-two whitepaper, Section 5.1, Eq. 85–87 and Algorithm 1](https://www.researchgate.net/publication/407022099_S-two_Whitepaper). It is not a complete `S31P2F02` PCS proof and production verification does not dispatch to it.

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

The caller supplies the expected root, exact geometry, and **independently sampled raw query sequence**. The parser checks magic and version before fields, enforces exact length and canonical M31 limbs, and rejects mismatched roots, query positions, profile, malformed witness lengths, inconsistent repeated projected values, and root mismatches. The witness is one compressed multiproof across all query bundles: at each level, sorted active nodes request a sibling hash only if that sibling is not already active. The verifier reconstructs the same tree from opened source values and rejects surplus or missing hashes. `verifyAndCollect` returns source values only after the complete multiproof succeeds; `transposed_paired_answers` then derives the original/quotient paired batches from those authenticated values, externally supplied OOD claims, and one shared batch challenge. The outer transcript has **not** yet bound those claims and challenge to this fragment.

The intermediate FRI line layer is a later commitment round and remains a separate native Merkle root. A test commits, opens, and authenticates that line separately after the source round. The old `S31P2F01` proof, its two independent source roots, and its verifier remain isolated and unchanged.

Native tests run 16/8, 32/16, and 64/32 rows with a repeated raw query, then compare the authenticated paired answers against the existing quotient implementation at every opened row. A two-column fixture checks the order `f0, q0, f1, q1` at both heights against independent single-column batches and rejects a changed second-column opening. These are arithmetic and authentication tests, not a proximity proof.

## Measured fixture cost

Three raw queries, including one repeat, open four largest rows and two smaller rows per query, with one source column at each height. The existing separate-root figures use their native compressed multiproofs over the same rows. The `S31XDM02` byte count includes its 60-byte header, raw rows, source values, witness count, and hashes; it does not include OOD claims, line openings, or terminal coefficients.

| Heights | Separate-root witness hashes | Shared-tree witness hashes | Source roots | `S31XDM02` bytes |
| --- | ---: | ---: | ---: | ---: |
| 16 / 8 | 4 | 4 | 2 → 1 | 276 |
| 32 / 16 | 8 | 8 | 2 → 1 | 404 |
| 64 / 32 | 12 | 12 | 2 → 1 | 532 |

The shared tree saves one 32-byte root in this fixture; it does **not** reduce witness hash count for these query sets. Full proof-size and prover-time comparisons require a complete outer proof, realistic queries, and measured allocation/hash work. No speed or security claim follows from this source-only cost table.

## Remaining theorem and integration work

1. Introduce a distinct complete outer `S31P2F02` format and transcript. Bind the one cross-domain source root and verifier-chosen geometry before OOD sampling, then bind all claims before the shared batch challenge. Require an externally expected source commitment and claims, with failure-atomic replay.
2. Feed `verifyAndCollect` values into the full sampled FRI fold checker, authenticate the later line root/openings, and check the terminal degree relation. Keep the source-only fragment from being accepted as a complete proof.
3. Map the domain-separated Blake2s leaf/internal hash framing, compressed multiproof order, duplicate handling, and Fiat–Shamir replay to the paper's BCS oracle game. The paper's abstract `H` does not prescribe this exact byte encoding.
4. Refine the two-point conjugate quotient degree/correlated-agreement argument, the conditional OOD point distribution and rejection schedule, four-row bundle query-event implication, inverse-butterfly normalization, and conservative native parameters. The 3-query cost fixture and the existing 70-query paths are not proven profiles.

Until these hold, the new fragment and old paired proof stay experimental and production admission remains fail-closed.
