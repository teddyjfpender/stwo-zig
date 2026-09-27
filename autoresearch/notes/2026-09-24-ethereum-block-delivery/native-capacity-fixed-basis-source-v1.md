# Native capacity fixed basis: source handoff

Status: source frozen, unqualified. This optional producer optimization extends
the versioned B5CT capacity path; it does not activate capacity templates in
canonical block production or replace the independent CPU receiver. The prior
capacity qualification receipt refers to the pre-basis snapshot and remains
separate. No build, test, STARK, FRI, guest, segment, device, or benchmark was
run for this batch.

`block_v5_native_capacity_fixed_basis_v1.ForBackend(Backend).Owner.init` builds
exactly one capacity-only fixed commitment and keeps its original polynomial
coefficients. It resolves commitment work and promotes the complete tree with
`share` before returning. Each acquisition checks the independently supplied
shape, ordered capacity/family recipe, execution profile, full PCS config,
template identity, actual fixed root, trace and committed column logs,
coefficient inventory, live phase and retained bound. Logical rows remain
instance authority; two shapes in one admitted bucket may share a fixed tree.
Old NativeV3 template identities cannot select this basis.

The optional real producer entrypoints are:

- `ForBackend(Backend).collectWithBasis(..., *FixedBasis)`;
- `ForBackend(Backend).commitPhysicalWithBasis(..., *FixedBasis)`;
- `ForBackend(Backend).commitFirstRoundWithBasis(..., *FixedBasis)`.

They share the existing uncached main commitment kernel. Only fixed acquisition
changes: the existing `block_v5_shared_first_round_v1.copyFixed` retains the
immutable PCS tree and mixes its real root into the instance's fresh channel.
Source native cells, dynamic activity/count columns, public admission,
interaction columns, composition, query randomness and FRI remain per proof.
No proof, receipt, main tree or public admission is cached. Uncached APIs and
independent `verifyOwned` reconstruction of fixed rows/root are unchanged.

The Owner is move-only and must not be copied after publication. Its mutex
serializes acquisition and teardown; a caller must keep the object itself alive
during acquisition. Existing proof leases may outlive `deinit` because the tree
uses the existing atomic shared-owner lifetime. Releasing one proof's
coefficient view does not free the basis polynomial. Each scheme has its own
twiddle provider and container allocations. Final tree release uses the original
owner allocator, which must support the releasing thread. Device payload/read
thread safety is a backend responsibility; current fixture scope is CPU only.

Limits are explicit: at most 514 fixed columns, trace log at most 24, and by
default a 1 GiB conservative retained host payload bound. Before generating
fixed values, the checked estimate sums all column LDE and coefficient values,
twice the largest LDE's BLAKE3 digest bytes for complete Merkle layers, twice
that LDE's M31 bytes for the possible exact-log forward/inverse twiddle caches,
and 64 KiB of bounded descriptors. The supplied allocator still governs cold
scratch and backend residency. This is not a measured RSS guarantee or a
standalone device-memory budget.

Qualification root:
`src/frontends/riscv/block_v5_native_capacity_fixed_basis_test_root.zig`.
Use the distinct filters:

- `capacity fixed admission`: two pure/resource and retained-body tests;
- `capacity fixed lease`: four tiny physical CPU ownership/parity/fault tests.

The lease filter commits fixed/main trees with hard trace-log cap 3, at most two
columns per fixture tree, and 128 KiB basis cap. It does not execute a guest,
generate interactions, invoke engine proving, fold FRI or access a device. It
checks cold/warm transcript and root parity across counts 5/7, actual shared
buffer identity, different instance main roots, configuration/profile/capacity/
family/template/legacy-ID/root/log rejection, stale acquisition, coefficient
view release, owner-before-lease teardown and every allocation-failure path.
The main columns in the lease fixtures are actual committed activity/count
columns, not a claimed native execution proof. The retained-body fixture keeps
cached and uncached production lifecycle and fresh receiver functions live
without invoking them.

Remaining: root qualification of this new snapshot; actual fresh capacity proofs
with reused fixed leases; catalog admission, typed artifacts, fused and recursive
receivers; canonical policy/driver activation. Reusing the fixed commitment
alone does not establish reusable recursive setup or complete roadmap IDs 12/13.

Root qualification now passes9/9: six named checks and three imports. The four
lease checks perform only explicitly capped tiny CPU fixed/main commitments
(trace log<=3), including actual shared buffer/coefficient identity and original
owner teardown before surviving leases. Actual cached/uncached producer and fresh
receiver bodies compile without invocation. All ten frozen hashes match.
Evidence: `cpu-performance-gates-v1/native-capacity-fixed-basis-qualified-v1.json`.
No STARK, FRI, guest, segment, device or throughput benchmark was run.
