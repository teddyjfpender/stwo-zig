# Reuse the independently committed recursive fixed tree

The complete CPU producer previously computed the independent fixed key and
then projected, transformed and committed identical fixed rows again when
constructing its proving plan. The live-row equality check already establishes
that the independently compiled rows and the actual live rows agree.

The new retained-commitment constructor preserves the independent setup tree.
The plan checks the exact profile, security configuration, context, row logs,
row counts, fixed-row digests, actual tree root and expected key root before
acquiring an immutable shared lease. It skips fixed-column projection and a
second commitment. The ordinary plan constructor and root-only key derivation
retain their existing behavior. No serialized cache entry is trusted and no
request's MAIN witness or transcript is reused.

The complete producer releases its independent fixed rows after cold/live
parity, and releases the setup tree lease immediately after the plan obtains
its own lease. The live fixed rows remain available for proving guards.
`Options.reuse_fixed_commitment` selects this path; the complete-root test can
select the original constructor with `STWO_V7_NO_FIXED_REUSE=1`.

Qualification is tracked separately:

- Integrated semantic compilation passed on 2026-10-29.
- A focused real-PCS test covers exact root equality, modified fixed rows,
  modified context, modified key root, and destruction of the original
  commitment owner before using the plan.
- The focused real-PCS runtime passed both tests.
- The 20,495-cycle complete-root runtime passed all 11 tests: original owners
  destroyed, final root freshly verified, 162,440 proof bytes. Diagnostic
  execution-to-verified-root time was 65.412 s, versus 67.650 s before this
  change. Tracked allocation peak was 8,032,862,762 bytes versus 8,449,757,478.
  Plan construction was 1.216 s versus 2.463 s. These observations were not an
  isolated repeated A/B experiment; they are qualification evidence, not a
  ranked performance claim. Both runs used q8/PoW0 and neither was Ethereum.

The benefit trades a retained compact setup tree during witness construction
against eliminating a later transform and commitment. Its whole-process peak
must be measured; a reduction in repeated work is not by itself a peak-memory
claim.
