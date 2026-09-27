# Block-v5 performance roadmap: work reduction before kernel tuning

Status: source-based audit of canonical mainnet-v3, stopped at the user's request.
No proposed speedup below is a measured end-to-end result. Security remains 70
queries and 26 PoW bits. No proposed optimization changed the measured baseline.

## Actual workload and observations

- Block 24,628,607: 139,214,856 guest cycles, 67 execution segments.
- Complete first pass: 356,303,914 sorted events, 85 memory instances, four
  field-safe range16 shards, 14 lookup groups, 622 admitted base proof files.
- Collection, sorting, global first commitments and admission: 1,650.976 s.
- First nine execution segments published native proofs and recursive
  leaves. Sidecar stages took approximately 80 s each; leaf stages took
  17.6–22.4 s. The leaf timer includes native-file publication and recursive
  proving; it does not include native-proof generation. The user stopped
  production during segment 10 sidecar proving. No full-block proof, forest or
  complete receiver result exists. External process time was 2,758.73 s and peak
  RSS was 10,183,507,968 bytes; these partial-run resources do not establish
  complete proof performance.
- A one-second sample during segment 3 recursive interaction commitment found
  generic CPU BLAKE3 compression and FFT/LDE preparation. It did not profile
  sidecar internals, so the 80-second sidecar cost is not apportioned yet.

Binary searches of the immutable space-major sorted file, reading individual
17-byte records rather than scanning 6 GB, give this exact census:

| Event space | Events | Share |
|---|---:|---:|
| Registers | 298,427,187 | 83.756% |
| RW memory | 57,876,727 | 16.244% |
| Total | 356,303,914 | 100% |

Register x0 accounts for 11,118,792 events; the input region accounts for
2,162,856 RW events. These are subsets, not additional events.

The sorted-memory AIR has 36 main, 22 fixed and 84 interaction base columns.
Its 85 log22 trace domains cover about 50.6 billion base-field cells before
degree expansion. Range16 consumes 21–22 requests per actual event, roughly
7.5–7.8 billion requests. Its quotient adapter evaluates log24 domains with a
serial scalar QM31 row loop.

## Full implementation inventory

| ID | Change | Concrete payoff and engineering boundary |
|---|---|---|
| 1 | Move register custody into native execution | Prove previous-access links, value continuity and strict clock order on the same committed execution cells; link bounded window flushes and global endpoints. Generic RAM rows fall from 356.3M to 57.9M, a 6.156× workload reduction, and log22 RAM instances fall from 85 to 14. Register access constraints remain; at most 32×67 = 2,144 flush endpoints are not the total register proving work. Caller register accesses must join the same register relation. |
| 2 | Specialize constant and immutable sources | Constrain x0 directly and distinguish input/ROM reads from writable memory. Remove generic read/write custody only where the consumer proves the constant or trusted input relation, including exact multiplicities. |
| 3 | Reuse quotient-domain column recovery across sidecar slots | Ordinary-memory access slots independently recover/evaluate overlapping full family column ranges. Native lookup partitions likewise recover overlapping spans. Share bounded per-family/domain evaluations or fuse evaluators while preserving full degree checks and all sample masks. Fixed/main PCS trees are already leased and must not be counted as a new reuse gain. |
| 4 | Parallelize and vectorize quotient evaluation | Replace the serial scalar QM31 loop with shared-core SIMD and disjoint row tiles; later compile exactly those equations to GPU kernels. Keep scalar OODS evaluation as an independent correctness oracle. |
| 5 | Reduce memory and range witness width | Nine main columns duplicate predecessor fields available through authenticated previous-row openings. A versioned layout can target those columns and eight repeated predecessor range requests/event, about 2.85 billion requests on this census. Preserve first-row and cross-instance boundaries. Derive fixed selectors where supported and select trusted clock widths from public bounds. Pair-batched range fractions and chunked batch inversions are already implemented. |
| 6 | Fuse compatible same-root proof projections | Consolidate ordinary memory, lookup requests and compatible caller projections into fewer interaction/composition/FRI proofs. This targets the 622-file architecture, including repeated independent proof overhead. Preserve independently closed buses and publish a versioned verifier/protocol change. |
| 7 | Pack multiple operations per row | Use lanes for execution and RAM, including ordered equal-value access packing where justified. Current 36-column word packing packs representation, not several events per row. Enforce inter-lane ordering, exact event count and endpoint continuity. Wider lanes do not automatically reduce total field cells. |
| 8 | Choose capacities after reducing width | Select larger independently sized execution/memory AIRs to reduce leaf and base-proof counts. Larger domains alone do not remove per-event work and can exceed memory caps; first narrow/stream the evaluation buffers. Exact proof counts and independent component sizing are already present. |
| 9 | Generate witnesses once with bounded replay | Avoid running the full guest twice by staging a compact, immutable witness stream or reusable execution records. Reconstruct admitted columns and commitments from that stream without treating host records as verification authority. Replace costly per-record work with bulk buffers and parallel witness generation. |
| 10 | Pipeline independent families under one budget | After the common first-root seal is frozen, schedule native, caller, memory/range, ROM and lookup-provider jobs through bounded queues. The current execution lease and warm callbacks are synchronous; four workers do not mean four concurrent segments. Charge all live jobs to one resource budget. |
| 11 | Overlap recursion with base proving | Publish leaves to the existing exact dependency DAG and start ready parent folds before later execution/global proofs finish. The current driver waits for base/provider completion before the forest. Preserve challenge ordering and exact topology. |
| 12 | Reuse capacity-based native setup | Exact step counts, external retirements and component row counts currently enter template identity. Move variable activity into constrained dynamic selectors/public counts in a new protocol so equal capacities can share setup. Removing identity fields alone is unsound. |
| 13 | Cache recursive parent setup and keep workers alive | Parent folds derive fixed keys and initialize fixed commitments repeatedly. Cache the complete authenticated immutable setup, with bounded entries/bytes and dynamic admission rebinding. Production forest currently uses one lane; schedule independent folds within measured memory limits. Quartet aggregation is already implemented. |
| 14 | Fuse recursive witness generation and scatter | Generate the committed witness columns directly instead of materializing verifier row structures and subsequently projecting them. Consuming row release is already implemented; this removes construction and copy work that still remains. |
| 15 | Batch and specialize host BLAKE3 hot paths | The live recursive sample shows generic CPU BLAKE3 compression. Batch independent tree leaves/nodes and specialized transcript frames using SIMD, retaining exact framing and digest parity. BLAKE3 migration itself is already done on this route. |
| 16 | Complete resident v5 GPU proving | Integrate every v5 native/caller/memory/range/ROM/lookup/recursive AIR into the resident CUDA contract. Supply authenticated witness/quotient AOT kernels and protocol-compatible hashing. Keep LDE, commitments, interactions, composition and FRI resident; download final proof material only. This is an integration, not a backend-alias substitution. |
| 17 | Add GPU prefetch, completion rings and batching | Prepare the next job while the device proves the current one; use persistent arenas and completion events instead of per-proof host synchronization. Batch matching geometries while keeping separate transcripts. Avoid round trips after each transform/commitment. |
| 18 | Scale the full dependency graph across GPUs | Shard independent AIR instances and recurse as results become available; balance by measured work and VRAM. Kernels on eight GPUs cannot accelerate a serial host dependency chain or repeated transfers. CPU runs cannot establish NVIDIA occupancy or speedup. |
| 19 | Reduce redundant producer-side capture and verification | Share immutable proof views and independently derived fixed setup through staging; avoid needless encode/decode and fixed-tree reconstruction. Keep the final independent complete receiver and fresh-process verification. Measure this slice before prioritizing it above AIR work. |
| 20 | Recursively close all global families | Eventually include caller, memory, range, ROM and lookup verification and global relation closure in the recursive final statement. Today's outer compresses native execution only; the complete receiver also needs the other base families. Hashing artifacts or using host receipts is not recursive verification. This is an architectural completeness step, not a promised immediate prover speedup. |
| 21 | Share the sealed range16 inverse table | A range16 denominator depends only on its value in 0..65535 and the shared challenge. Build a bounded 65,536-entry QM31 inverse table once per challenge, rather than repeatedly batching the same denominators across billions of requests. Keep the exact equations, zero-denominator handling and value-bound checks. This is distinct from existing per-chunk batch inversion. |
| 22 | Reduce sorted replay traffic | The current 5,437 initial runs require five eight-way merge passes; raw production plus read/write passes imply about 72.7 GB of aggregate event traffic. After register specialization, use resource-admitted larger chunks/radix sorting and preserve exact replay order. Existing readers/writers already buffer 1,024 records; this is not a per-event unbuffered syscall problem. |

## ZisK comparison and expected limits

ZisK's [v1.3.0-alpha release](https://github.com/0xPolygonHermez/zisk/releases/tag/v1.3.0-alpha)
documents larger variable-height AIRs, lane packing, bulk Keccak witness work,
setup-time GPU expression kernels, device prefetch, completion-slot rings and
recursion/base-proof overlap. Its
[Main AIR](https://github.com/0xPolygonHermez/zisk/blob/v1.3.0-alpha/state-machines/main/pil/main.pil)
contains register access links and bounded flush windows. These are concrete
design precedents; they do not establish a speedup in this implementation.

The read-only local comparison used `/tmp/stwo-zisk-v1.3.0-alpha`, tag
`v1.3.0-alpha`, HEAD `02d2ae7b711454ce4574d852f8bfbddbfcbb1d67`.
Its selected AIRs use four Main lanes, four RAM lanes plus dual operations,
and separate input/ROM families. The CUDA memory planner uses persistent
buffers, four streams and CUB sorting. Sorted-file census layout and order
are defined in `src/frontends/riscv/air/block/memory_spool.zig`.

CUDA can substantially accelerate independent finite-field transforms,
quotient rows, interactions, FRI and commitment hashing. The full gain needs
work reduction, device residency and a concurrent scheduler. Tensor/gaming
performance figures do not predict M31/QM31 or BLAKE3 prover throughput.

Even for the simplified 80 s sidecars +22 s leaf subtotal, making sidecars
10× faster yields only 102/(8+22) = 3.4×. Native proving, collection and global
proofs make the true whole-run gain smaller. Eliminating one cost is therefore
insufficient. Do not multiply estimated gains from overlapping changes.

## Implementation and qualification order

1. Preserve the current full baseline and measure family/stage times separately.
2. Implement register-local custody and same-root sidecar/domain reuse, then
   SIMD/parallel quotient evaluation; qualify complete CPU closure and memory.
3. Add proof fusion, capacity templates, reusable parent setup and bounded DAG
   overlap; qualify exact odd segment counts and dynamic admission.
4. Add full resident v5 GPU kernels and pipeline scheduling; validate proof
   interoperability on the CPU receiver, then benchmark one GPU and multi-GPU.
5. Extend recursive global-family closure to a self-contained final proof.

Each experiment must report canonical end-to-end proof time, stage time, peak
RSS/device residency, base/recursive proof counts and successful independent
verification on unchanged program/input/security. Small meaningful gates
precede an expensive full-block comparison; compilation stays outside timings.
