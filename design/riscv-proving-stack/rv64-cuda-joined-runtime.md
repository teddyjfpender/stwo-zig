# Joined numerical qualification and resident binding witness

This slice qualifies complete joined OODS equations for 49 layouts and connects
an actual device GKR traversal to its derived binding metadata and Eq/prefix
witness. It does not produce an accepting Ethereum proof. GPU dispatch remains
closed until the remaining complete-proof gates pass.

## Native authority and invocation metadata

`joined_parameters.zig` assigns 942 semantic slots independently of live field
values and IR parameter discovery order. Five separately retained namespaces
hold public base words, local challenges, terminal binding values, shared
RAM/KIO/Wire challenges, and physical claims. The public namespace zero-lifts
canonical M31 words; the others contain OM31 AoS values. The local reservoir
uses the existing ten-namespace/31-slot relation layout. Wire has 35 tuple
coordinates, independently of the local relations' maximum arity of 30.

The immutable device address map gathers only parameters used by a given
executable. Native range custody rejects foreign, undersized and overlapping
allocations before dispatch. Device checks reject invalid namespace/index
pairs and noncanonical fields with a sticky verdict. Equal and zero live
parameters do not change executable identity or merge semantic slots.

The cold native oracle evaluates original MAIN, local GKR binding and global
obligations in their exact emission order. All 49 layouts match for base rows,
full extension-field OODS rows, and equal/zero challenge cases. GPU OODS then
matches the same oracle in 147 invocations, with seven metadata poison cases
and all four Compute Sanitizer tools reporting zero errors. These are synthetic
polynomial fixtures; their arithmetic rows are not an execution statement.

## GKR continuation and witness

`gkr_binding_metadata_on` reads a completed, immutable parent state. It checks
phase, cursor, chain, instance count, height, source variables and canonicality.
It copies the final channel locally and draws the same late eta as native
`child.zig`; it never rewinds or modifies the completed parent. For each
instance it selects the suffix of the common GKR point, splits row and lane
coordinates, and derives lane weights, target/row, Eq anchors and carry values.
Degenerate row coordinates are rejected. Failed jobs expose a poisoned seed.

The full binding Eq entry point is separate from the GKR sumcheck half-table.
Both reuse the existing four-level tile arithmetic. Binding projection computes
Eq times the projected N+eta*D, subtracts the uniform target, and leaves an
eight-coordinate contribution for the common prefix scan. Base and secure
numerators are covered by the same typed interface.

The prefix scan uses 128-thread chunks, recursively scans narrow chunk totals,
then propagates carries. Only the first level maps logical coset indices to
physical circle order. Local binding requires a zero total. Classic mode emits
the physical claim and centers every prefix by that claim. Both share the same
kernel hierarchy, scratch plan, alias checks and completion rules. Scratch is
independently sized, rather than padded to a CPU trace or provider width.

Eight complete native GKR fixtures, including mixed heights and 64 instances,
produce 172 exact metadata and Eq/prefix comparisons. Eleven binding mutations
are rejected, in addition to nine original GKR mutations. Numerical arrays do
not return to the host between GKR, metadata, Eq, projection and scan. All four
sanitizer gates pass. An independent sequential host oracle additionally checks
17 scan cases through 2^22 rows, centered/closed modes, canonicality, sticky
verdicts, nonzero debt, alias rejection and allocation padding/guard words.

## Build evidence and remaining gates

ReleaseSafe and ReleaseFast each pass 61 integration tests and compile the real
native FFI. Receipts are in `vectors/reports/rv64-cuda-joined-runtime-20261103/`.

An O1 compiler experiment did not materially improve the widest OODS cold
build: aggregate runs took 1381 and 1370 seconds under concurrent engineering
load. The O1 fallback is not adopted. The qualification builder now caches by
actual compiler dependency manifests, flags, source and object hashes, so
unrelated header edits need not invalidate immutable executables. Cold code
size remains an engineering issue; these timings are not prover speedups.

The generated joined domain kernels still need hardware qualification. Derived
public auxiliaries must be evaluated from the admitted point, never admitted
as free producer values. Truth witnesses and interactions, physical source
root binding, global manifest challenge derivation and closure, the complete
OM31 PCS/OODS/DEEP/FRI/opening controller, proof framing and fresh whole-block
receiver acceptance remain mandatory. Root closure of the local lookup sum
also remains a required accepting-controller check; the numerical traversal
fixtures intentionally support unclosed synthetic roots. No GPU Ethereum
speed, recursion qualification or new security certificate is claimed here.
