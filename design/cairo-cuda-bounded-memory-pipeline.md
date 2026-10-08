# Bounded-memory Cairo CUDA proof pipeline

The current resident plan retains all main and interaction LDE evaluations
from their commitments through decommitment. This is the largest memory
opportunity for Pedersen-dense Cairo PIEs. The 15590913_15590913 plan has a
103.367 GB allocated request arena and a 102.324 GB maximum live set. Its
exact stage inventory is recorded in
[`geometry-dense.txt`](../vectors/reports/cairo-cuda-h100-managed-20261007/geometry-dense.txt).

| Stage | Live GiB | Largest live allocations |
| --- | ---: | --- |
| Trace generation | 68.19 | lookup inputs 27.87, coefficients 16.03, writer scratch 12.40 |
| Trace commit | 95.27 | evaluations 32.06, lookup inputs 27.87, coefficients 27.74 |
| Constraint evaluation | 95.30 | evaluations 55.97, coefficients 27.74, Merkle hashes 7.00, LDE tile 3.56 |
| OODS | 92.19 | evaluations 55.97, coefficients 27.74, Merkle hashes 7.00 |
| Quotient | 64.25 | evaluations 55.97, Merkle hashes 7.00 |
| Decommit | 65.74 | evaluations 55.97, Merkle hashes 7.00, FRI hashes 2.00 |

These are planner live bytes, not sampled HBM usage. Merely enabling
`cudaMallocManaged` lets an H100 finish this proof but leaves the 103.367 GB
plan unchanged and causes expensive migration. Stage prefetch does not solve
the allocation problem.

An opt-in `capacity` placement policy now moves the lookup slab before the
writers and host-places evaluation arrays before their commitments. On the
H100 it lowered the sampled dense-PIE peak from 79.177 to 56.487 GiB and the
second Pedersen-dense PIE from 79.177 to 48.362 GiB, with byte-identical verified
proofs. This is a physical HBM reduction, but the logical plan and its live
sets above remain unchanged. In the dense PIE,
`partial_ec_mul_window_bits_18` produces 15.59 GiB of the 27.87 GiB lookup
slab in one writer launch. Offloading after whole components therefore cannot
bound its own peak; the lookup replay/chunking step below must split rows
within that writer.

## Implementation sequence

1. **Replay lookup inputs in bounded chunks.** The current writer emits a
   27.87 GiB lookup slab and holds it through the main-root transcript
   challenge. Generate exactly the same lookup values only when the relation
   phase consumes them, in bounded component/chunk order, using the retained
   authenticated input. The main trace has already been transformed in place;
   replay must never overwrite it. First compare replayed lookup chunks against
   the current writer output, then compare full proof bytes and verifier
   acceptance. This removes the slab from the trace-commit overlap. The
   recorded-witness launch ABI currently has one `row_count` and no row-start
   argument; the largest partial-EC writer needs a chunk-aware kernel ABI and
   a relation consumer that can read or replay the same canonical word-major
   ranges without changing transcript order.

2. **Keep coefficients and commitment hashes; stream LDE evaluations.**
   Build each column/cohort LDE and its Merkle contribution in bounded storage,
   then release the evaluation chunk. Retain the 27.74 GiB coefficients and
   7.00 GiB Merkle hashes. After the interaction root fixes the challenge,
   reconstruct bounded LDE chunks for constraint evaluation and quotient.
   For decommitment, regenerate only queried evaluation leaves while using the
   retained authenticated Merkle paths. The commitment root and every opened
   leaf must match the current path byte for byte. A first implementation may
   use explicit host-backed chunks to reduce HBM; subsequent deterministic
   recomputation can reduce total storage as well. Whole-array UVM migration
   is not an acceptable substitute for bounded chunks.

3. **Bind phase-aware storage to the request layout.** The current
   `resident_plan.zig` and arena allocator express whole-buffer lifetimes.
   Introduce explicit bounded scratch extents and a chunk schedule; include
   their geometry and ordering in the plan identity. Reserve a fixed HBM
   ceiling before launching the request, and fail admission if any single
   column/chunk plus persistent hashes exceeds it. This prevents an apparent
   average reduction from hiding a largest-column failure.

4. **Measure the next bottleneck.** Once evaluations and lookup input are
   bounded, trace-generation writer scratch (12.40 GiB) and the largest
   coefficient cohort become the next targets for a 48 GB class GPU. Reuse
   scratch across components or stream writer output only after the exact
   proof and peak-memory comparison establishes the first two changes.

For scale, removing the retained evaluation array would reduce the
constraint-stage live set from 95.30 to about 39.33 GiB; removing the lookup
slab would reduce trace-commit phase 0 from 95.27 to about 67.40 GiB.
Removing the slab from trace generation would lower that stage from 68.19 to
about 40.32 GiB. **These are arithmetic estimates, not achieved peaks.**
Replacement chunks, memory alignment, cache allocations, and runtime
overheads must fit within the remaining headroom. A 48 GB target needs a
smaller bounded tile and the writer-scratch follow-up.

The transcript order is fixed: main root, interaction challenge and root,
composition challenge and root, OODS challenge, quotient/FRI, then queried
openings. No optimization may derive a witness value or challenge from a
future transcript state, change column order, or accept unchecked supplied
columns. The qualifying gates are exact proof-byte equality to the current
canonical prover on ordinary and Pedersen-dense PIEs, independent official
Rust verification, the same authenticated input and registry identities, and
whole-device peak and publication-time receipts on an otherwise idle GPU.
