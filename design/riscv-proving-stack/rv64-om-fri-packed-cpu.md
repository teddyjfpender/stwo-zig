# Concrete packed CPU OM31 FRI

The stronger beta2/q256/P0/fold4 candidate spends100.75 summed worker seconds in
FRI quotient build and commitment,98.39 of these in25 CPU proofs. Its complete
block takes305.85s proving; overlapping worker intervals are not additive wall
time. Other measured major stages are streaming commitment preparation129.30s
(78.79 transform,50.49 leaf hashing) and composition115.26s. This change targets
real candidate FRI work without changing security/profile/transcript parameters.

The prior OM-specific FriBackend forwarded only Merkle methods. Generic fallback
circle and line folds used scalar extension arithmetic, and packed-leaf
transposition ran serially. The new concrete OM module uses existing packed OM31
arithmetic and scoped RowWork; it does not create a global pool or generic frontend.

First-circle folding uses an explicit FRESH overwrite hook. The ordinary core
accumulation API is unchanged; arbitrary destination values are not assumed zero.
The fresh hook avoids the unnecessary accumulation multiply into the first-line
zero evaluation. It validates domain size, all eight coordinate lengths and
power-of-two destination before the shared core coordinate walk/workspace. Base
coordinate generation and batch inversion reuse the original authorities. Rows
apply the original inverse butterfly and alpha fold using packed OM arithmetic.

Parallel in-place line prefix folding would overwrite unread source ranges.
Instead, one fresh half-length scratch allocation pingpongs with the original
owner. Every row wave has disjoint source and destination; all jobs join before
advancing alpha/domain. The original full allocation remains owned on errors,
though its prefix may have been folded, matching the existing contract. Scratch
is freed before final realloc so that its fallback copy never overlaps that
extra owner. A128MiB per-proof scratch cap covers candidate log22 CPU/beta2:
FRIlog24 ->first line2^23 OM values ->half scratch2^22*32=128MiB exactly. An explicit
larger-geometry cap refusal uses the old scalar law; actual allocator OOM is
propagated. `STWO_ZIG_PROFILE_OM_FRI=1` exposes requested scratch and route selection.

Packed FRI leaf transposition uses existing preallocated buffers and disjoint
pooled leaf ranges for OM only. It preserves exact coordinate/offset leaf order,
including repacking during decommitment. QM31 backend dispatch is unchanged.
The fresh optimization does not manufacture the old accumulation work receipt;
unsupported work-profile auditing is marked incomplete rather than reporting
operations that were removed. Protocol hashes and proofs do not use this receipt.

Safe/Fast gates cover scalar/core agreement across tiny and parallel sizes,
three workers and held-lease fallback, arbitrary high coordinates, zero-fold and
multi-fold schedules, allocation failures, explicit scratch refusal and malformed
fresh-domain/length refusal. Actual native OM proofs retain all pinned SHA values
under uniform/mixed/hybrid storage and fold1/fold4, with fresh file receivers;
retained QM31 integration also passes. Independent source review found no concrete
ownership, aliasing or arithmetic blocker.

One stronger-candidate CPU0 old/new pair produced eight identical authoritative
artifact hashes and both old frozen fresh receivers accepted. Proving17.245s ->
16.061s, quotient3.094s ->2.120s, FRI decommit0.581s ->0.084s; composition and commit
remained roughly flat and RSS stayed12.104GB. The6.9% total difference is a single
pair, not a full-block or tightly controlled speedup claim. Its logs confirm the
dominant128MiB route selected packed execution. The later domain-shape guards do
not change valid inputs. Complete candidate block measurement remains required.

The two core files exposing the existing coordinate walk, and the modified
prover files, are absent from the current RV32 Lean manifest's declared production
and proof source lists (rebind8ce5fb0a7). No RV32 AIR custody pin is changed by this
slice. This is engineering evidence, not a whole128 or recursive security theorem.
