# RV64 CPU row SIMD authority

The CPU domain evaluator now processes sixteen independent rows in a packet.
This packet uses the existing target-native `PackedM31` kernels; it does not
change the core SIMD width or another frontend. Native widths must divide 16.
`PackedBase` contains the native base-field packs and `PackedSecure` contains
matching secure-field packs. They are arithmetic lanes, not machine instances.

Local arithmetic, memory, division, product, shift, byte-operation and packed-PC
constraints have one lane-parameterized equation implementation. Existing QM31
function names remain wrappers around that implementation. Verifier OODS points
still use full scalar QM31. Domain local equations use packed M31. Challenges,
LogUp denominators, prefixes and random residual weights use packed QM31. A
shared mixed sink preserves the exact residual counter and reverse random-power
sequence, including skipped zero residuals. Base residuals use secure-by-base
weighting rather than a general extension-field product.

Inflation has one immutable concrete source/reconstruction plan. Its generic
apply method changes the arithmetic lane only; source masks, bit/clock/carry
substitution and the prepared-result contract are shared. Permanently omitted
logical coordinates start at zero. Every live coordinate is overwritten on
scratch reuse. No new machine/ISA/prover type factory is introduced.

The domain path loads current columns directly into lane packets. Only declared
previous masks gather partner-coset rows. A short final packet initializes its
unused lanes to zero and publishes only the admitted row count. Per-worker
scratch belongs to the coordinator, with all submitted work drained before its
owner frees it. The scalar QM31 domain path remains a test oracle.

## Functional qualification

ReleaseSafe AIR compares every local-family residual, in order, against the
existing scalar QM31 API for sixteen independent base rows and sixteen dense
extension-field rows, including arbitrary selectors, zero/one/modulus edges,
both PC control policies, product encodings, signed shifts, and prepared
inflation with reused scratch. Independent mixed secure tests cover state,
ROM, BYTE, AND, SHIFT and frame authorities. These checks do not assume valid
execution rows where an incorrect polynomial might accidentally vanish.

ReleaseSafe parallel tests compare scalar and SIMD quotients across all four
cosets and repeated additive waves, with 1/3/8/16 workers and odd scheduling
pieces that split a sixteen-row packet. Both inline and full Ethereum service
CPU routes execute on actual 256 KiB ReleaseSafe helper stacks. Allocation failure,
lease denial, submission failure and stack admission retain their cleanup gates.

The strong authenticated gate proves all 27 components with both service ABIs,
both PC encodings, and owned/borrowed storage. Recorded SIMD proofs with
3/8/16-worker scoped pools match the scalar domain reference byte for byte and
pass fresh receivers. State-policy downgrade and balanced state/hash/service
claim attacks remain rejected. Component recorder trees are private until join;
partial adoption failure preserves split ownership and retry cleanup.

Qualification logs: `/tmp/rv64-local-generic-lanes-safe.log`,
`/tmp/rv64-simd16-service-stack-safe.log`, and
`/tmp/rv64-simd16-auth-safe.log`. This records functional qualification, not a
performance result or a completed SIMD full-block run.
