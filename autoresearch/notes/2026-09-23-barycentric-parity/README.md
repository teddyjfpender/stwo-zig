# Canonical barycentric derivative reuse

Investigation target: larger CSP proofs exceeded the shared coefficient-retention
budget and entered barycentric sampled-value evaluation, where Keccak/128 spent
about 2.49 seconds after parallel hash-interaction generation was installed.

`BarycentricContext.init` evaluated `cosetVanishingDerivative` at every domain
point. That routine nests doubling sequences of lengths 0 through log_size-2,
so repeating it costs O(n log² n) field work, plus repeated coset construction.
On the canonical circle domain, the quantity -2*y*V'(x) has constant magnitude
and alternates sign with bit-reversed storage parity. The existing Metal
barycentric scale kernel already uses precisely this identity.

The host context now computes the literal derivative once, fills its two parity
values and walks the domain as before. The core derivative routine and reference
weight generator remain unchanged as independent test oracles. No coefficient
cache limit, domain, proof parameter or transcript rule changed. This shared PCS
optimization is independent of the workload, hash suite and frontend.

ReleaseSafe `test-poly`: 56/56 passed. Coverage includes every point in domains
2^1 through 2^10, boundary/parity samples in 2^14, 2^18 and 2^21 domains, and
existing sampled-point weight and polynomial evaluation comparisons.

`measure.py` compares the retained preceding CPU/Metal products against the
candidate. Canonical 70 queries / 26 PoW bits, 16 workers, three samples per arm,
no explicit warmup, control then candidate. Both arms keep parallel hash
interactions enabled and the experimental barycentric-parallelism switch disabled.
It checks proof hashes against the qualified suite and independently verifies
every retained arm artifact. This is a targeted comparison, not a new full suite.

Both ReleaseFast product builds passed. All 48 measured proofs verified in
process, and all 16 retained arm artifacts freshly verified with identical
proof hashes to the preceding qualified suite. The focused sampled-value suite
also passed 22/22 tests in ReleaseSafe (`test-pcs-sampled-values`).

## Measured medians

| Case | CPU control → candidate s | Metal control → candidate s |
| --- | ---: | ---: |
| ecdsa_secp256k1-32 | 1.193989 → 1.205694 | 1.952832 → 1.968636 |
| sha256-128 | 2.878919 → 2.916228 | 3.001394 → 3.050906 |
| sha256-2048 | 7.552583 → 6.193977 | 7.594417 → 6.267659 |
| keccak-128 | 7.304750 → 5.915772 | 7.219809 → 5.890093 |

The larger cases' sampled-value stage fell from approximately 2.51–2.56 seconds
to 1.12–1.14 seconds. ECDSA and SHA/128 showed no benefit; their complete medians
varied by about 1–2%, and their sampled-value stage was already small. These
three-sample, fixed-order comparisons do not establish small performance changes.
No claim of recovering original CSP performance or a recursion speedup is made.

## Work accounting and source provenance

The optional logical-work audit now counts one derivative and the domain walk,
including constant-point construction, instead of multiplying derivative work
by the domain size. Small-domain hand counts and existing sampled-work tests
pass. A focused `test-pcs-sampled-values` build step avoids running unrelated
commitment tests during this loop.

`candidate-products` holds the exact binaries measured above. Their build occurred
before the subsequent optional work-counter correction and focused build-step
addition; those two source-only follow-ups are separately retained in
`post-measurement-source` and tested in `sampled-tests.log`. The arithmetic source
used by the measured binaries is retained under `source`. Stage profiling did
not enable detailed work capture. No proof-producing arithmetic changed after
the measured builds.

Next: bounded scheduling of the remaining sampled-value computation, then further
shared witness/commitment costs. The original CSP and broader recursion goals
remain active; parent qualification is not established by these leaf timings.
