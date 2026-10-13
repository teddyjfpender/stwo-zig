# P2F02: one-root experimental paired two-height proof

`S31P2F02` is a distinct experimental proof format. It combines the [XDM02 transposed cross-domain source commitment](TRANSPOSED_CROSS_DOMAIN_EXPERIMENTAL.md) with a sampled two-height FRI relation. Production PCS has no dispatcher for this magic and remains fail-closed. `S31P2F01` retains its separate two-root format and verifier.

## What the verifier checks

The caller supplies an **independent public statement**: largest log height `k`, common blowup exponent `b`, column counts at `k` and `k-1`, query count, one expected XDM source root, and every expected OOD claim. The proof must match these fields exactly. The caller must not derive an expected root or claim from an untrusted proof. There is no self-contained, geometry-only P2F02 verifier.

The wire starts with its own magic and version, then includes the profile, one XDM root, encoded sampled OOD point and claims, an entire XDM02 source-opening fragment, one intermediate line root, short terminal polynomial, line openings, and their native Merkle witness. All integers and M31 limbs are canonical little-endian; total length is exact and capped at 64 MiB. The decoder checks both outer and inner magic/version before transcript replay. The inner XDM opening remains untrusted until its query positions and shared multiproof authenticate.

The verifier stages its transcript and publishes it only after **all** checks succeed:

1. Mix P2F02 version and the profile plus one source root. Draw one secure-field circle OOD point `Q`, reject the native zero `y.c1` denominator factor, and compare with the encoded point. No retry changes the sampling distribution.
2. Mix all externally expected claims in height/column order and draw one shared `lambda`. Draw `alpha_0`, mix the intermediate line root, draw `alpha_1`, then mix the complete terminal coefficient vector.
3. Sample raw largest-circle rows. Each query opens a four-row largest bundle and its two squaring-projected smaller rows through the one XDM tree. The XDM parser checks the exact sampled raw rows; only after the complete multiproof passes does the verifier derive `f_0 + lambda*q_0 + lambda²*f_1 + lambda³*q_1 + …` from those authenticated original values, each claim, and `Q`.
4. Authenticate both corresponding intermediate line rows and check the first circle fold, the second line fold plus inserted smaller circle fold, and terminal evaluation. Native inverse-butterfly normalization is the same as P2F01. Any late Merkle or fold error leaves the caller's channel unchanged.

For a raw row `r`, the projected smaller circle row is `((r >> 2) << 1) | (r & 1)`. This retains the sign bit and removes the squaring-fiber bit. The four-row bundle proves both local conjugate pairs; the verifier checks point doubling explicitly.

## Deterministic measurements

The focused native test uses a deterministic Blake2s channel, host polynomial interpolation, full-domain source arrays, and compressed Merkle witnesses. The complete encoded outer wire lengths are:

| Largest / smaller rows | Columns at each height | Raw queries | P2F01 two-root wire | P2F02 one-root wire | P2F02 change |
| --- | ---: | ---: | ---: | ---: | ---: |
| 16 / 8 | 1 / 1 | 4 | 748 B | 592 B | −156 B |
| 32 / 16 | 2 / 2 | 5 | 1180 B | 1012 B | −168 B |
| 64 / 32 | 1 / 1 | 7 | 1180 B | 1300 B | +120 B |

These are fixture bytes, not benchmarks or security parameters. P2F02 is **larger** in one fixture; query overlap and the XDM wrapper affect the comparison. Neither prover uses a production streaming implementation, and no proving-time speedup is established. The test runs 16/8, 32/16, and 64/32 round trips; it rejects changed expected roots and claims, wrong encoded OOD points, changed authenticated source values, and changed line values, with transcript rollback on each failure.

## Soundness status

The [S-two whitepaper, Protocols 3–4, Section 5.1](https://www.researchgate.net/publication/407022099_S-two_Whitepaper) motivates the original-plus-own-quotient ensemble, shared challenge, squaring-consistent queries, and transposed cross-domain tree. The implementation matches those **structural** features in a fixed two-height slice. The following proof obligations remain:

1. A two-height terminal polynomial at log height `k-2` is still large. This is **not** the paper's cascade down to small bound `B`; its Protocol 4 and UDR query/fold bounds cannot be plugged into an early terminal reveal. Implement all remaining FRI layers, or establish a distinct theorem for this exact early reveal.
2. Refine the native two-point conjugate quotient degree and correlated-agreement reduction, the conditional secure-field OOD seed map and rejection distribution, the exact circle query-event implication, and inverse-butterfly scaling.
3. Refine the concrete Blake2s tags, XDM02 insertion hash layout, multiproof order and duplicate behavior, line Merkle authentication, parser, and Fiat–Shamir replay into the paper's abstract BCS oracle model.
4. Prove an admitted geometry, terminal bound, query count, PoW contribution, and error bound for a conservative native profile. Neither the 4–7-query fixtures nor the existing 70-query path provides proven bits.

Until these are discharged, P2F02 remains a relation and authentication experiment, not a production PCS opening or conservative release profile.
