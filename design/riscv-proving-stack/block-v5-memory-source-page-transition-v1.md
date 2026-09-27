# Authentic PAGE source and packed transition CPU receiver

This isolated receiver closes the PAGE source/RAM transition partition using
actual original proof bytes. It does not select a canonical driver route or
issue complete-block or self-contained recursive authority.

`block_v5_memory_source_page_transition_receiver_v1.verify(backing, pins,
page_owner, page_loader, loader, limits)` takes independent capacity
`Global.Pins`, the independently reconstructed PAGE join owner, and bounded
loaders for original native, capacity-fused, caller arithmetic, caller-fused,
and program-table proofs. It has no parameter for a proposed `Page.Open` or
accepted receipt array. The base source seal, exact lane pins/roots/range plan,
original execution/caller rosters, access witness roots, register recipe/window
policy and all-RW census are admitted before PAGE proofs are consumed.

The receiver calls the actual `Page.Owner.verify` path, which freshly verifies
all raw/fold PAGE, lane and range proofs and closes initial/final RAM source
buses under the preserved original Word prefix. It then calls the unchanged
`Programs.ForBackend(Cpu).verifyWithCompositeHooks`. That loop verifies original
capacity arithmetic/fused proofs, caller arithmetic/fused proofs and ROM
proofs. Only its borrowed fresh callbacks enter the original memory hooks.
Those hooks independently check exact execution/caller identity, access roots,
witness roots, clock frames, slots, census and byte requests. Original
`Memory.finish` closes the all-RW event count and packed transition equation.
Typed empty native access retains original exact absence admission; it neither
loads a fake memory proof nor invents a RAM root. Empty RAM still requires the
actual PAGE source/fold path. Writable input remains writable.

The only shared change is additive `Memory.admitPins`, extracted from the
existing `Memory.ForBackend.init` admission body without changing its checks.
Canonical init still runs original `sorted.verify`. The new receiver's
internal conversion into the existing accumulator's `Scoped` DTO occurs only
after actual PAGE/lane/range verification and is not transported or exported
as a legacy proof. The public result retains the distinct PAGE source result.

`Open` retains one bounded allocation owner and per-execution byte-demand
records. Original proof callbacks allocate through the supplied allocator and
transfer ownership only on success. Original verifier loops consume one proof
at a time. PAGE setup ownership remains with its independent owner, which must
outlive this call; PAGE live proof allocations are nested under the transition
budget. Failure after PAGE entry consumes that PAGE session, even if later
program/native/caller proof verification fails. Output disposal frees records
before releasing their allocator lease.

The output has `complete_block_authority = false`. Its byte requests,
ordinary/external universal opposites and native/caller residuals still need
the original scoped provider/state/register/accounting/public joins. Neither
source-seal files nor constructor manifests are proof authority. No canonical
RAM filtering or readonly relabel is enabled by this module.

## Genuine final-parent integration still required

Lane and range adapters already expose actual original claim bytes through
`ram_lanes_recursive_public_bus.Values.mix` and
`range16_recursive_public_bus.Values.mix`. The lane claim frame contains
transition, predecessor, initial, endpoint, the original seventeen range sums,
endpoint/range counts and event census. Range exports its original shard,
count and provider sum. Their original fresh leaf verification and independent
scope/key/schedule/plan policies remain mandatory.

PAGE presently has only an original fresh `verifyOwned` result. A metadata
`VerifiedPage`, final-channel hash, scalar sum or host receipt cannot supply
its recursive verifier. The next coherent layer needs:

1. Additive owned/borrowed PAGE capture sharing the exact original verifier
   kernel, with all nine trace trees and ten total commitments, independent
   fixed reconstruction, full component claim closure, DEEP/FRI/Merkle/PoW,
   original six-premix-root replay, shared Source9/Indexed13 epoch and separate
   page-local relation/semantic channel framing.
2. Actual typed symbolic composition/transcript/roots/DEEP adapters for this
   geometry. Existing three/four-tree DEEP specialization alone is insufficient.
   Bind raw eleven source sums plus indexed and fold ten sums to exact original
   public claim-frame bytes; retain independent local wire/core closures.
3. Versioned exact raw/fold recursive coverage and bounded parent child
   selection, then same-parent byte-sourced equations for raw/fold source,
   predecessor, initial/endpoint signs, per-range-shard provider closure,
   transition and all-RW census. Do not cancel page-local universal wire/core
   sums across pages. Their original PAGE proof closes those independently.
4. Bind source initial image, touch/endpoints and public input to independently
   reconstructed public job authority. Original B5PD input linkage needs the
   genuine tail carrier, matching consumer protocol and ancestor equality/use
   equations. That input link and complete source/global topology remain OPEN.

No PAGE capture surrogate or complete recursive block token is implemented by
this CPU partition receiver.

## Qualification candidate

Root: `src/frontends/riscv/block_v5_memory_source_page_transition_test_root.zig`.
Filter: `source PAGE transition:`. Six authored behavioral tests plus one
body-retention marker; run both genuine policy runners independently. The
marker retains actual receiver, original composite program/PAGE/lane/range
verification, memory init/admission/hooks/finish and output disposal bodies
without invoking any proof or guest.

The source-only author ran formatting, not compiler/tests/proofs/segments.
Scalar metadata/equation fixtures test negative checks and disposal; none is
promoted into a fresh proof receipt. A positive genuine end-to-end proof and
full verifier allocation-failure sweep remain unrun.
