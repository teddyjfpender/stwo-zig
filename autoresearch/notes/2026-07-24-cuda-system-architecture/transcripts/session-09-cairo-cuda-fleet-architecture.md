# Session 09: Cairo CUDA Fleet Architecture

## Scope And Source Identity

This is a design audit, not a runtime or performance claim. It defines the
statement-preserving fleet architecture to implement after one complete
single-device Zig CUDA SN PIE proof exists.

The audit covers:

- Zig CUDA at `6e3b386acc0732b5fa1083b043289c53bc0dd118`;
- Rust stwo-cairo at
  `6a9c1c895b821eb5542843e7d9398e02e8f378d0`; and
- its compatible Rust Stwo CUDA implementation at
  `1d1d10c31fdac45c9ecb7aee9d3e8935b5cf8035`.

The near-term hardware order is deliberate:

1. compile and exercise every new shard kernel on inexpensive RTX 4090s;
2. establish exact one-, two-, four-, and eight-rank proof behavior on shapes
   that fit those devices;
3. use one H100 only for the large single-device SN PIE reference and profile;
4. make four RTX 4090 ranks the first practical SN2 fleet target; and
5. qualify multi-host transport only after the same-host fleet is exact.

The H100 result is an oracle and stage baseline. It must not become the
production architecture.

## Audit Verdict

Zig already has the right semantic boundary. `ProofProgram` describes the AIR,
statement, protocol, columns, commitments, transcript barriers, quotient, FRI,
buffers, and operation DAG independently of CUDA placement. The current Cairo
emitter is still `production_ready = false` and proof-derived, so it is not yet
source authority. Its nodes also carry parallelism classes and work estimates,
not exact buffer effects, kernel bindings, or shard-launch derivations.

The current `CudaPlan`, `Session`, and `ResidentProofTransaction` are
intentionally single-device: one thread-owned context, one coordination
stream, one arena, one transcript spine, and one terminal proof read.
`max_lane_streams` is zero and the scheduler does not execute the node
parallelism hints. Fleet placement must therefore consume a sealed CUDA
executable-lowering receipt with exact effects and partition authority; it
must not infer pointer ranges or shard geometry from estimates.

The Rust `fleet_plan` is useful but is not a fleet prover:

- `FleetProofPlan` is a detailed address-free placement and validation model.
- `simulate_structural_closure` explicitly executes no CUDA kernel or transfer
  and synthesizes transcript phases.
- `require_real_sn_runtime()` unconditionally returns
  `MissingInstalledRuntime`.
- `FleetWorkerDeviceInstall` installs rank-local arena windows but no complete
  worker executor consumes them.
- SN2 Base and Interaction commitment-batch placement is exercised by tests,
  not by the production proof entry point.
- host spill and VMM records are planning contracts, not an executed spill
  pipeline.
- the only real cooperative proving entry point is
  `prove_resident_blake2s_with_fleet_pow`: rank 0 performs the proof and a
  second rank assists only the two PoW searches.
- that PoW runtime is hard-coded to two ranks and uses a same-node Unix
  transport.
- there is no full-rank daemon, NCCL path, inter-node path, distributed FRI,
  distributed quotient, distributed decommitment, or fleet proof benchmark.

This code should therefore be mined for contracts, not copied as a purported
runtime.

## Rust Concepts To Port

The following concepts are sound:

| Concept | Port decision |
| --- | --- |
| semantic DAG separated from physical placement | Preserve. Fleet scheduling must never mutate `ProofProgram`. |
| canonical plan encoding and identity | Preserve as a runtime identity distinct from proof meaning. |
| exact partition authority and granularity | Preserve. A shard launch must be mechanically derived from a validated full launch. |
| deterministic contiguous minimax placement | Preserve for component islands and whole commitment batches. |
| explicit owner, replica, transfer, liveness, alias, and storage records | Preserve in a smaller Zig fleet plan. |
| coordinator-owned transcript barriers and causal arrivals | Preserve; only one rank may advance Fiat-Shamir state. |
| dedicated IPC exchange allocations | Preserve for same-host rank edges; never export a proof arena. |
| generation-bound publish/consume/reclaim/arm state | Preserve and extend to every transport. |
| authenticated control frames bound to plan, generation, rank, and sequence | Preserve. |
| canonical PoW lattice partition and minimum valid nonce reduction | Generalize to 1/2/4/8 ranks. |
| whole-batch progressive commitment placement | Use as the first exact commitment path, then profile its bandwidth. |
| fail-closed admission and non-admitting structural simulation | Preserve as a pre-hardware gate. |

The following pieces must not be mistaken for finished runtime code:

| Rust item | Limitation |
| --- | --- |
| structural closure receipt | It proves metadata closure only. |
| device install | It allocates and binds windows but does not execute a proof. |
| Base/Interaction batch compiler | It validates placement but has no production multi-rank execution. |
| two-rank PoW coordinator | It distributes only PoW and is fixed at two ranks. |
| Unix PoW transport | It is local, scalar, and PoW-specific. |
| CUDA IPC exchange | It is a useful same-host primitive, not an inter-node transport. |
| spill/VMM plan | It does not perform the planned DMA and reclaim sequence. |
| `ConsumerGpuClass` variants | They are descriptive plan values, not hardware qualification. |

## Non-Negotiable Invariants

One proof has one immutable semantic identity:

```text
semantic_id =
  PIE/adapted-input digest
  + Cairo statement digest
  + AIR/source-authority digest
  + protocol digest
  + ProofProgram semantic digest
```

Fleet topology is not part of the statement or transcript. It has a separate
execution identity:

```text
fleet_id =
  ProofProgram program digest
  + placement schema
  + ordered rank roster and device UUIDs
  + per-rank SM/driver/runtime/AOT identities
  + storage and transfer plan
  + transport mode
```

Consequently:

- 1/2/4/8 ranks must produce the same canonical proof bytes;
- SM89 and SM90 may use different AOT binaries but must realize the same
  semantic operations;
- a retry generation, worker hostname, rank count, and transport route must
  never be mixed into Fiat-Shamir;
- every write is disjoint or has an explicit canonical reduction;
- no cross-rank atomic target is admitted;
- every transcript input has one canonical ordered encoding;
- proof assembly happens once, on the coordinator, in canonical proof order;
- the pinned Rust verifier remains the final correctness oracle; and
- a verifier-accepted but byte-different fleet proof is a diagnostic failure,
  not parity.

## Process And Ownership Model

Use one long-lived process per GPU rank. Each rank owns:

- one CUDA device and primary context;
- one strict-AOT `Session`;
- one persistent shape cache;
- one fixed-address request arena;
- one control connection to the coordinator;
- bounded point-to-point exchange buffers; and
- monotonically increasing attempt and exchange generations.

Rank 0 is the logical coordinator. Its CUDA device owns the only transcript
state and final proof bundle. The host coordinator owns scheduling and
receipts, but does not evaluate the AIR, hash proof data, reduce fields, or
replay the transcript.

The coordinator compiles one immutable `FleetPlan` from `ProofProgram`. The
plan contains:

- homogeneous rank requirements, initially SM89 RTX 4090 only;
- component-island ownership;
- exact operation shards;
- rank-local buffer lifetimes and peak bytes;
- canonical reduction trees;
- transcript barrier producers;
- point-to-point spans and generations;
- Merkle subtree ownership;
- FRI dependency exchanges;
- final proof-fragment ownership; and
- the only legal failure and teardown sequence.

The semantic `ProofProgram` remains unchanged. A backend-owned
`CudaExecutablePlan` binds each semantic node to authenticated AOT entries,
device-buffer effects, exact full launches, and mechanically derived shard
launches. `FleetPlan` places that executable plan without becoming AIR
authority. All three identities are retained separately.

Every rank independently validates the complete plan and then installs only
its projection. A rank must reject a projection whose full-plan identity,
semantic identity, roster, AOT pack, device UUID, or capacity does not match.

## Stage Placement

### 1. Ingress And Fixed Data

The coordinator decodes and adapts the PIE once, derives the canonical compact
statement, and hashes every ingress artifact. Large CASM rows are split into
exact contiguous ranges and uploaded directly to their owners.

Program ROM, preprocessed columns, curve tables, twiddles, and other immutable
shape data are process-cache objects. Replication is allowed only when the
fleet plan charges every copy. A cached object is admitted by content digest,
shape, protocol, AOT identity, and device generation, never by path.

### 2. Witness And Interaction Traces

The unit of placement is a dependency-closed component island, not an
arbitrary file or kernel. `producer_edges` and capacity feeds must remain on
one rank unless the plan materializes an exact transfer before the consumer.

Each component normally owns all rows of its output columns. This matches the
column-wide circle transforms and keeps local constraint evaluation possible.
Exact row-shard kernels remain legal for oversized components, but the plan
must include their later column assembly. An indivisible live buffer larger
than one rank's budget rejects the plan.

After the main root and interaction PoW barrier, rank 0 broadcasts the exact
lookup challenges. Each rank generates interaction columns for its owned
components. Component claimed sums are returned as canonical
`(component_ordinal, value)` records; rank 0 assembles them in statement order.

Global memory/fixed-table multiplicities may not use cross-device atomics.
Their producer feeds are either kept in one dependency island or transferred
as exact event/count ranges to one declared owner before finalization.

### 3. Main And Interaction Commitments

The first exact implementation uses the existing progressive Blake2s
semantics:

1. assign whole canonical column batches to ascending ranks;
2. transform each owned column locally;
3. initialize the per-row progressive state on the first owner;
4. absorb batches in canonical column order;
5. transfer the complete state to the next owner; and
6. let the last owner finalize canonical leaves.

The compatible Rust planner identifies the handoff as 24 words, or 96 bytes,
per evaluation row. That cost is real and must appear in the fleet prediction.
It is acceptable for the parity MVP, but not assumed to scale well.

After leaf finalization, scatter equal contiguous leaf ranges to active ranks.
Each rank builds its lower Merkle subtree. Rank 0 gathers the ordered subtree
roots and hashes the top `log2(active_ranks)` levels in canonical left/right
order. Each owner retains its lower layers for later openings; rank 0 retains
the upper tree.

This produces exactly the single-device root. A later optimization may replace
the progressive state pipeline with a column-to-row all-to-all, but only after
the transfer model shows it wins across SN PIE shapes.

### 4. OODS And Composition

Each column owner evaluates its own columns at the requested OODS points.
Results are tagged by canonical tree, column, and sample ordinal. Rank 0 checks
coverage, assembles the canonical sampled-value vector, advances the
transcript, and broadcasts the resulting challenges.

Composition evaluation uses a deterministic component reduction:

1. each rank evaluates owned components in ascending component order;
2. it accumulates rank-local four-coordinate partial vectors;
3. partial vectors are reduce-scattered by output row range;
4. field addition kernels consume source ranks in ascending rank order; and
5. the resulting four composition columns remain row-sharded.

The composition commitment then uses the ordinary contiguous-subtree merge.
No rank needs all Cairo trace columns, and no host performs a field reduction.

### 5. Quotient

The same component-local pattern applies after the OODS challenge:

- trace sources stay resident with their component owner;
- each rank evaluates its component numerator contribution over the complete
  quotient domain;
- rank-local partial QM31 vectors are produced in canonical coefficient order;
- an explicit rank-ordered reduce-scatter creates one contiguous output range
  per active rank; and
- those ranges become the initial distributed FRI evaluation.

NCCL must transport these bytes, not define their arithmetic. Secure-field
addition remains an authenticated CUDA kernel with a fixed reduction order.

### 6. FRI

FRI remains serial across transcript rounds and parallel within each round.
For every layer:

1. assign contiguous canonical output/leaf intervals to active ranks;
2. derive each output interval's exact input indices from the FRI geometry;
3. transfer only missing input spans;
4. fold locally with the broadcast challenge;
5. build a local Merkle subtree;
6. merge ordered subtree roots on rank 0;
7. advance the sole transcript; and
8. broadcast the next challenge.

The compiler must derive the fold stencil. It may not assume adjacent inputs:
circle and line folds can map an output interval to separated source ranges.
When a layer has fewer independent intervals than ranks, excess ranks are
explicitly idle.

The final line is gathered in canonical coefficient order to rank 0. Query PoW
is partitioned over all ranks using the same global candidate lattice as the
single-device prover. Rank 0 independently verifies and absorbs the minimum
valid nonce.

### 7. Decommitment And Assembly

Queries are routed to the rank owning each requested leaf. A worker returns:

- requested trace/FRI values;
- lower authentication siblings up to its shard root; and
- a receipt binding tree, query, generation, range, and payload digest.

Rank 0 appends upper-tree siblings, sorts all fragments by canonical proof
position, and writes the ordinary resident proof bundle. The only proof-data
device-to-host read is the final bundle. The Rust verifier receives that
ordinary proof; there is no fleet proof format.

## Transcript Protocol

One barrier follows this sequence:

```text
workers finish declared kernels and transfers
  -> workers emit completion receipts
  -> coordinator validates complete producer coverage
  -> proof values move device-to-device into rank 0 canonical slots
  -> rank 0 launches exactly one transcript segment
  -> rank 0 publishes a challenge receipt
  -> challenge bytes move device-to-device to declared consumers
  -> the next barrier becomes executable
```

Each receipt binds:

- semantic and fleet identities;
- attempt generation;
- barrier and message sequence;
- rank and device UUID;
- exact output ranges;
- payload digest;
- CUDA event completion;
- AOT entry identity; and
- fallback/allocation/synchronization telemetry.

Large-payload digests remain device values and are checked on rank 0 before a
transcript input is admitted. A host control receipt binds the corresponding
device slot and completion event; it does not read proof payloads back merely
to authenticate control traffic.

No worker may speculate past a missing challenge. No coordinator may synthesize
a root, claim, PoW candidate, transcript value, or completion receipt.

## Transport Decision

Same-host 4090 development uses explicit CUDA peer transport:

- one process per rank;
- dedicated 2 MiB-rounded exchange allocations;
- CUDA IPC memory and interprocess events;
- `publish -> consume -> reclaim -> arm` generations; and
- exact byte spans declared by the fleet plan.

The Rust IPC primitive is a good starting contract. It correctly avoids
exporting proof slabs and orders reuse with events. Hardware admission must
still measure the actual P2P matrix because many multi-4090 systems expose
PCIe/ACS topologies without usable peer access.

NCCL is introduced behind the same transfer contract:

- same-host NCCL is optional for batched send/receive after it beats explicit
  peer copies;
- multi-host NCCL carries exact `uint8` payloads and is performance-admitted
  only when telemetry proves the intended GPUDirect RDMA route;
- custom field arithmetic and canonical reduction order stay in CUDA kernels;
- scalar control frames use an authenticated host control plane; and
- host-bounce transport, if admitted at all, is explicit telemetry and is
  ineligible for a no-bounce performance claim.

CUDA IPC is same-host only. NCCL is not semantic authority. Either transport
must produce the same proof bytes.

## Memory Admission

An RTX 4090 has insufficient margin for the current roughly 31-33 GiB
single-device SN2 resident peak. Two 24 GiB ranks may satisfy aggregate bytes,
but duplication, exchange reserves, coordinator state, and indivisible buffers
make two ranks a correctness target, not the initial production promise.

The first practical SN2 target is four RTX 4090 ranks. Every rank must retain:

```text
peak live request bytes
+ immutable process-cache bytes
+ CUDA graph/module/context bytes
+ maximum concurrent exchange bytes
+ allocator fragmentation allowance
+ operational safety reserve
<= admitted device capacity
```

Initial performance admission should cap planned arena plus caches near 20 GiB
per 4090, leaving explicit exchange and CUDA headroom. The exact cap is set
from clean-process measurements, not a nominal 24 GiB label.

The compiler reports peak bytes per rank and per stage, largest indivisible
buffer, duplicate immutable bytes, transfer volume, and maximum concurrent
exchange. It rejects oversubscription before creating any CUDA allocation.
Runtime memory observations must not exceed the plan.

## Failure And Retry

An attempt is identified by semantic identity, fleet identity, rank roster,
attempt generation, and input digest. Generation is monotonically increasing
within every retained worker process.

Any rank loss, timeout, CUDA error, stale frame, duplicate frame, invalid
payload digest, missing receipt, capacity violation, or transcript mismatch:

1. poisons the whole attempt;
2. prevents proof publication;
3. drains or destroys all outstanding transport generations;
4. returns every session to a synchronized idle state or destroys it; and
5. retries from transcript initialization with a new generation.

There is no mid-transcript replay after worker replacement. A replacement
roster produces a new fleet identity but must still produce identical proof
bytes. Late messages from an old generation are rejected before touching a
device slot.

## Required Gates

### Host And Single-Device Gates

- `ProofProgram` semantic digest is invariant under 1/2/4/8-rank placement.
- Fleet plan encoding is deterministic under input enumeration order.
- Every semantic operation and output range has exactly one owner or declared
  reduction.
- Liveness, aliases, transfer extents, barriers, and memory peaks validate.
- Every exact shard is differentially compared with the full kernel, including
  first/last granule and non-even shard seams.
- One-rank fleet execution is byte-identical to the existing single-device
  CUDA execution.

### Rank Matrix

For 1, 2, 4, and 8 ranks, where the shape fits:

- transcript state snapshots match at every barrier;
- all commitment and FRI roots match;
- OODS sampled values and interaction claims match;
- PoW nonces match the single-device global winner;
- final proof size, bytes, and SHA-256 match;
- the Zig verifier accepts;
- the pinned Rust verifier accepts; and
- no CPU proving fallback occurs on any rank.

Small mixed-height Cairo fixtures run the complete 1/2/4/8 matrix first.
Canonical SN PIE gates then require:

- one-rank H100 versus 2/4/8-rank 4090 exact proof equality for SN2;
- 1/2/4/8 equality for every smaller PIE that fits one 4090; and
- all four canonical PIEs accepted by the pinned Rust verifier.

### Adversarial Gates

Inject and require fail-closed behavior for:

- dropped or duplicated rank completion;
- stale attempt and exchange generations;
- reordered barriers;
- mutated root, claimed sum, challenge, proof fragment, and IPC descriptor;
- incorrect rank/device/AOT identity;
- worker exit during a transfer or kernel;
- missing P2P route;
- insufficient exchange or arena capacity;
- query fragment omission or duplication; and
- retry after a poisoned attempt.

### Residency And Performance Gates

Every rank reports:

- context and process reuse;
- AOT hits and zero JIT;
- kernel, graph, transfer, allocation, synchronization, and fallback counts;
- per-stage device critical path;
- bytes sent and received by route;
- P2P, RDMA, or host-bounce mode;
- planned and observed peak device bytes; and
- one terminal proof read on the coordinator.

No fleet MHz number is headline-eligible until exact parity and the Rust
oracle pass. Scaling reports include total prove time, useful row-MHz,
committed cells/s, aggregate GPU-seconds, peak bytes per rank, transfer
fraction, barrier idle fraction, and efficiency against the single-H100
reference and the equivalent one-rank shape.

## Delivery Order

1. Finish and freeze the single-device Zig CUDA SN PIE proof.
2. Add a pure Zig `FleetPlan` compiler and structural/adversarial tests.
3. Add one-rank fleet execution as an exact refactor gate.
4. Add two-rank same-host CUDA IPC and exact component/witness partitioning.
5. Add progressive Base/Interaction commitment handoffs and subtree merge.
6. Add distributed OODS, composition, quotient reduce-scatter, and FRI.
7. Close two-rank proof bytes and Rust verification.
8. Generalize the same plan and protocol to four and eight ranks.
9. Run canonical SN2 as H100-one-rank versus 4x4090 exact parity.
10. Profile transfer and barrier costs before choosing progressive state
    handoff versus column-to-row all-to-all.
11. Introduce NCCL byte transport and qualify multi-host 4090 fleets.

This order keeps cheap 4090 compilation and differential testing on the
critical path. H100 time is reserved for the final large reference, parity,
and profiling checkpoints.
