# Blinded S31 payment proving audit — 2026-10-09

## Contract and hypotheses

Audit the existing `blinded circuit` payment path without changing the relation,
80 blinding rounds, eleven AIR components, fixed tables, transcript, 70 queries,
20-bit interaction grind, 26-bit FRI grind, or fold step 1. Fresh private entropy
remains mandatory. Successful verification and different commitments remain
validity/entropy regression evidence, not a general zero-knowledge argument.

The baseline payment witness has 85,055 raw QM31 gates and 131,072 padded gates.
Its full profile has 5,295,488 preprocessed cells. Initial native profiling shows
that witness construction is negligible; commitments, composition, FRI and the
stochastic grind dominate. Test these execution-only hypotheses:

1. Reuse the already computed preprocessed commitment and parsed AIR bundle for
   the prover's native self-verification. They come from the independently
   compiled, checked topology, never from a root supplied by the proof. This
   removes a second fixed-table commitment without removing verification.
2. Test the existing evaluations-only storage policy. It retains committed
   evaluations and avoids redundant coefficient copies/re-extension. Select it
   only if measured payment latency and memory improve. The existing R7 cached
   storage fixtures compare this path with pinned Rust proof checkpoints.
3. Measure worker-count sensitivity explicitly. A host exposing many logical
   CPUs can have a smaller container quota. Do not silently hardcode this
   benchmark host's worker count into the DSL or change security for speed.
4. The M31 channel's nonce search currently hashes and reduces all eight digest
   words per candidate. At the supported bound of at most 32 PoW bits, only the
   first little-endian word determines acceptance. Reuse the existing prepared
   40-byte BLAKE2s nonce kernel, reduce that word modulo M31 for the M31 channel,
   and compare its bit mask. Keep the canonical hi-major search, minimum nonce,
   worker failure completion and full-hash verifier unchanged. Differential
   predicates for all supported bit bounds and pinned Rust known-answer nonces
   must agree before comparing complete native-verified payment timings. Honor
   explicit scalar backend selection and targets without the SIMD hash path.

The self-verifier borrows the topology, AIR bundle, commitment root and public
words through the synchronous call. These owners outlive verification. No
process-global cache, persisted witness, seed override or additional proof
serialization is introduced. Existing commitment leases retain their existing
bounded per-proof ownership and failure cleanup.

## Audit and validation

Review source-mode propagation, canonical identity, sealed-key geometry,
unsupported profile/recursion rejection, receipt binding, integer conservation,
nullifier replay, delivery authentication and atomic ledger state. Add concrete
regressions for any defect found. Review is not an independent security audit.

Every timed proof must pass the separately built native verifier, including
cross-verification with the baseline key/verifier. Compare identical synthetic
witnesses and source/key geometry, with warmups, alternating lane order,
medians/ranges, binary hashes, CPU/quota, build mode, phase scope and peak RSS.
Report setup and verification; exclude compilation from runtime measurements.
Fresh blinding makes proof bytes and grinding costs vary between samples.

Use the existing pinned R7 storage fixtures as the independent oracle for
execution-only storage changes. Complete new-package pinned Rust acceptance
and a reviewed full-transcript privacy argument remain release gates. Preserve
the draft status until those gates pass; no production confidentiality claim.

## Decomposition

The oversized `runtime/mvp_runtime.zig` receives only call-site edits. Move
prepared native self-verification and bounded optional phase observation into
`runtime/proof_execution.zig`; keep performance orchestration in a separate
acceptance/benchmark driver. Further extraction of full gate preparation and
recursive orchestration should precede substantial growth of the runtime.

## Review findings

| Surface | Finding and boundary |
| --- | --- |
| Proof privacy | `private` is ABI visibility. The explicit mode appends the pinned random rows and fails closed on unsupported profiles, but a complete ZK argument remains absent. Keep this a research draft. |
| Verifier binding | The source-mode domain, exact policy, sealed key, recomputed topology/commitment and trusted ledger receipt bind the implemented statement. Policy stripping, reduced budgets, transparent geometry, changed envelope fields and replay are adversarial checks. |
| Amounts/state | Four u16 limbs, checked u64 additions, positive recipient and global spent-nullifier tracking preserve the prototype's payment invariants. Funded initial state and the eight-leaf capacity are explicit assumptions. A Starknet vault is absent. |
| Delivery | HMAC authenticates ciphertext, context and output commitment. The invoice key must be privately established; public-address encryption and circuit proof of ciphertext plaintext correctness remain absent. |
| Self-verification | Reusing the topology's commitment avoids redundant setup. It must never use a root decoded from the prover's proof as its expected root. Separate native verification still runs in acceptance and measurements. |
| Nonce optimization | The prepared first-word predicate must preserve M31 reduction, canonical minimum-nonce order, all supported bit bounds, scalar selection and worker failure completion. Full-hash differential checks and pinned Rust nonce/proof fixtures are required. |

The broad core suite exposed an existing ReleaseFast failure in
`fri: fold line in-place workspace matches default implementation`. Running all
16 tests in `src/core/fri/tests.zig` reproduces the failure on both the changed
tree and a clean archive of baseline `aaecd597374b0cbffe060182c86cedd5a600df8a`.
The isolated test passes in both trees and in ReleaseSafe. This order-sensitive
baseline failure is unresolved; it is not waived by successful payment proofs.
The existing global formatter failures also prevent a clean global gate.

## Measured outcome

The [bound evidence](../measurements/payments/tongo-proving-audit-v1-2026-10-09.json)
records all 44 quiet samples per lane, unchanged keys, exact compiler/binary
hashes, CPU quota, peak RSS, public synthetic witness identity and
cross-verification receipts. Median CLI latency is 2.078 s before and 1.950 s
after (6.2% lower); ranges overlap and grinding remains stochastic. The
post-proving interval falls from 160 ms to 21 ms median; peak memory remains
approximately 1 GiB. The isolated canonical nonce grind is 10.4% faster.
Evaluations-only storage was rejected after its measured latency regression.

This is useful progress, not evidence of a blazingly fast payment service.
The [performance guide](../../../src/frontends/s31/docs/payments-performance.md)
explains reproduction and the fixed-table floor. Larger latency/throughput
claims need a separately measured resident proving service or a reviewed
hash-focused AIR. Full new-package Rust acceptance and a complete privacy
argument remain open.
