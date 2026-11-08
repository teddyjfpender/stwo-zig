# RV64 M8 GPU-native request: the architectural jump

Status: build contract (2026-11-06). It supersedes the hybrid passes (native-hybrid, outer-fold, feeder) as the M8 target.
Base: `codex/rv64-m8-gpu` = integration head `c72b51646` + native-hybrid + feeder (`c8c9b131a`), contract commit on top.
Contract code: `src/integrations/riscv_cuda/rv64/jobs/gpu_native.zig` (+ stubs `driver.zig`, `native_device.zig`, `outer_device.zig`, `truth_job.zig`).
Builds on: `rv64-m8-job-architecture.md` §3–§5 (job API, worker, device channel, slab), `rv64-frontier-gpu-delta.md` §4 (plan of record).
Labels: **[M]** measured, **[D]** derived from measured numbers, **[E]** estimate. Unlabelled numbers are code constants.

> Owner directive: "make the thing GPU native, totally remove the idea that anything needs to be using the CPU."

The hybrids proved that the device kernels, the device transcript and the enqueue-only PCS produce byte-identical proofs (26235156 32/32 and 24628607 39/39 [M]). They also proved that wrapping those jobs in the legacy orchestration makes the request **slower**: the warm native window went 2.92 → 5.05 s on 26235156 and 4.03 → 5.31 s on 24628607 [M]. Stage-2 GPU time is about 0.23 s per segment [M], but host framing (0.27–1.21 s per segment [M]) and host assembly (0.26–3.13 s per segment [M]) dominate. So this pass stops wrapping legacy and replaces the request path.

---

## 1. End-state request flow (`STWO_RV64_M8_JOBS=1`)

```
capture thread (CPU, the ONLY request-path compute)          GPU 0 / GPU 1 (exec streams; one job in flight + one staged)
  emulate -> TraceChunk ring (pinned) --h2d--> witness(seg) -> FIXED adopt (class cache) -> MAIN commit (main_resident)
  sealed_segment(s)   ------------------------------------> local GKR + binding           [Stage1, device channel]
                                                             root/claims -> exchange slot --peer copy--> other GPU
                                                             device seal (seal GPU): manifest digest, chi, mix -> seal slot --peer-->
                                                             Stage2(seg): globals, INTER, composition, OODS, PCS,
                                                                          device checks -> status words, encode -> slab
                                                             TruthJob(t) (fills the seal barrier)
                                                             leaf(seg) as soon as Stage2(seg) encodes; folds on children; root
                                                             -> D2H of each GPU's slab segment (GPU 1 event -> GPU 0 stream)
host: ONE wait (root GPU's final event) -> publish(): check every status word, slice encoded proofs -> write out/ -> answer
```

- **Host does only:** run capture; enqueue pre-built per-class graphs / job enqueues; one wait per request; one D2H per GPU segment (enqueued, not waited separately); `gpu_native.publish` (status words + slicing); write files and the spool answer.
- **Per-class setup** (component Sets, mask points, `PcsJob.prepare`, composition/INTER plans, GKR/binding plans, outer node plans/tapes/stream plans/PCS framing, FIXED trees, twiddles, captured graphs, slab directory prefix) is built once per class at install/warm time in a `ClassCache` and is device-resident where kernels read it. A class miss on the request path is an error (`GpuNativeClassNotWarmed`), not a slow path.
- **MAIN stays device-resident** from witness to PCS in the `main_resident` region; no legacy replay, no copy.
- **Proof bytes** are byte-identical to the frozen D2 golden: the same transcript operations in the same order, encoded on device into the slab. Fresh CPU receivers in the gate verify outputs off the request path.

---

## 2. Inventory: every host computation and host wait on the JOBS=1 request path today

Source: code at `c8c9b131a` (feeder: legacy orchestration drives, both hybrids selected), `vectors/reports/rv64-m8-20261106/native-hybrid/diagnostic-timing.json` (24628607 and 26235156, cold and warm), outer-fold receipts (`outer-fold-p3`, `outer-fold-review`), P1 checkpoint (24628607 warm medians, legacy default).

| # | host work / wait | where (file:function) | per-request cost | GPU-native replacement | stream |
|---|---|---|---|---|---|
| H1 | capture / emulation, whole block before stage 1 | `GE/ethereum` capture via `resident_batch.zig` | 2.106 s median [M] (24628607); stage 1 waits for full capture + global inventory (1.32 → 2.55 s [M], delta §3.7) | **stays CPU** (allowed) but streams: `CaptureSink.chunk` per `TraceChunk`, `sealed_segment` releases Stage 1 per segment; exposed capture ≈ last segment tail, 0.3–0.5 s [E] | driver |
| H2 | admission / permit / two-lane machinery around every stage | `admission_runtime.zig`, `global_admission.zig`, `native_stage1_admission.zig` | host waits per stage; not separately measured | **frozen, not instantiated**: one static `MemoryPlan` per GPU | driver |
| H3 | per-job arena windows: unpark/park around each Stage1/Stage2 job; one window per GPU at a time | `native_hybrid.zig runWindowed`, `outer_job_factory.zig Hybrid.open/endRequest` | 2 windows per segment + recursion window; unpark 22–135 ms [M]; serializes native vs truth leases | **one plan, installed once**; no park/unpark on the request path | driver |
| H4 | native witness generation with contributor joins | legacy `CpuWorker` witness / `device_source.zig` contributors | inside native prove 4.434 s [M]; joins [E] 0.1–0.3 s/segment | device witness job from uploaded `TraceChunk`s, no joins, writes `main_resident` | native |
| H5 | legacy MAIN commit on the owner thread (callback + full lane join), then MAIN copied into the job (`copyColumns`) | `prepareMain` (legacy owner), `native_hybrid_jobs.zig Stage1Job.enqueue copyColumns` | 1 owner round trip + D2D copy per segment [M, counted, not timed] | MAIN commit kernels inside Stage1, output in `main_resident` | native |
| H6 | Stage 1 host prep: `NG.Plan.init`, `NG.Gkr.init`, `NB.Plan.init`, column tables, `fixedKey` SHA-256 over FIXED words | `native_hybrid.zig Hybrid.prove` | not split out [M]; stage1 wait 45–77 ms/segment [M] | GKR/binding plans in the class cache; FIXED from the class cache (device) | native |
| H7 | Stage 1 finish: GKR section decode `Section.read` + `section.proof`; binding `NB.checkAuthority` in `bind()` | `native_hybrid.zig prove/bind` | per segment [M, not split] + 1 host wait/segment | section stays in the slab (device-encoded); `Check.binding_authority` kernel | native |
| H8 | global χ seal / inventory: host barrier, `pending.checkPhysicalRoots`, manifest digest, `mixManifestAndClaims` on the host `Om31Channel` (`NS1.seedOf(worker.channel)`) | legacy coordinator + `native_hybrid.zig stageTwoInner` | a host barrier per request; host transcript per segment | roots/claims via `PeerExchange` slots; **device seal** job on the seal GPU (manifest Blake2s, χ, mix) writes the 16-word seal checkpoint slot; `Check.global_seal`, `Check.exchange_complete` | driver (seal kernel: native) |
| H9 | Stage 2 host framing: `Components.Set.init`, `provers`, `CompRoles.fromItemsWith`, `NGl.Plan.init` per slot, `NC.CommitPlan.init`, `NComp.Plan.init`, `maskPointsWithWorkCapture`, `NP.PcsJob.prepare` | `native_hybrid.zig stageTwoInner` | **0.27–1.21 s/segment [M]**; warm 24628607 sum 4.11 s [D] | per-class framing cache built in `NativeFactory.warm` (the framing is challenge-independent: placeholder OODS point today) | native |
| H10 | Stage 2 acceptance on the host: `global_status` loop, `S2.accept`, `CW.publicClaims` | `native_hybrid.zig stageTwoInner` | inside assembly [M] | `Check.global_status`, `composition_accept`, `public_claims` (device reduction vs request public inputs) | native |
| H11 | Stage 2 assembly: `pcs.decode`, a second `Components.Set.init` with real claims + `evalCompositionPolynomialAtPoint` (OODS constraint check), `WP.encodePhysical` | `native_hybrid.zig stageTwoInner` | **0.26–3.13 s/segment [M]**; warm 24628607 sum 3.17 s [D] | `Check.oods_constraint` (point-eval instance of the AOT composition codegen), `ProofEncoder` writing `encodePhysical` bytes into the slab | native |
| H12 | legacy MAIN replay before Stage 2 (`worker.replay.restore`) | `native_hybrid.zig stageTwoInner` | 1 owner round trip + recommit per segment [M, counted] | deleted: MAIN resident (H5) | native |
| H13 | host waits on the native path: 2 per segment (Stage1, Stage2) + owner joins | worker `finish` per job | 14 job waits on 24628607 [M] | 0 per job; 1 per request (driver) | driver/native |
| H14 | truth/service proofs on the legacy owner; ~14.75 GB truth-composition `cudaMalloc` lease outside job windows (OOMs against retained MAIN 4.15/3.23 GB [M]) | legacy truth stages (`truth_source/composition/pcs` behind callbacks) | owner round trips per truth; the lease forced the hybrid to give up MAIN residency | `TruthJob` inside the plan (arena class with measured peak), device checks + encoding | recursion |
| H15 | native verify side thread: CPU re-verification of native proofs inside the request | legacy pipeline (`native_verify_s`) | 1.589 s median [M] (overlapped with recursion, CPU-bound) | removed from the request path; device checks + fresh CPU receivers in the gate | driver |
| H16 | leaf verifier graph / seed tape built on the host per leaf | `rv64_recursion/om31_native/execution_wrap.zig runImpl` (graph_ns), leaf tape | per leaf [M, `graph_ns`, not in receipts here] | class topology in the cache; **device seed fill** from the child's encoded slab region with a per-class seed program | recursion |
| H17 | fold seed tape recorded on the host from the converted capture | `om31_native/fold_tape.zig record` | per fold [M, not split] | same device seed fill (`fold_tape.record` becomes the warm-time seed-program generator; `Check.seed_tape`) | recursion |
| H18 | `Assignment.Prepared.init` per node (tasks, levels, launch symbols) | `outer_job_factory.zig prepareHost`, `outer_job_prestage.zig prestage` | per node [M, part of prestage] | per-class `Prepared` in the cache (only seeds vary per node) | recursion |
| H19 | host transcript prefix per node (`prove.begin` + `MC.mixRoot`), class key hashing, statics acquire | `outer_job_prestage.zig hostCheckpoint/prestage` | per node | class checkpoint (config/profile) in the cache; statement + FIXED root mixed on device | recursion |
| H20 | `initWhole` + footprint: stream plans, placeholder PCS framing | `outer_job_factory.zig Prover.prove` (`init_ns`) | **5.26 s / 6.48 s summed per warm request [M]** (26235156 / 24628607), ~0.35 s/node | per-class plan in the cache | recursion |
| H21 | FIXED precommit `FixedJob` per node, own host wait | `outer_job_factory.zig precommitFixed` | 0.76–0.94 s stage + 0.27–0.34 s wait per warm request [M] | FIXED tree per class resident in `class_cache`; no per-node FIXED work | recursion |
| H22 | node finish: `decodeProof` (lane thread) + `assemble` (`Outer.prove.bind` + host `evalCompositionPolynomialAtPoint`) | `outer_job_factory.zig`, `outer_job_prestage.zig assemble` | decode 0.22–1.11 s per warm request [M]; finish 0.05–1.09 s [M]; assemble per node [M] | `Check.lookup_sum`, `node_oods_constraint`, `node_pcs_status`; device encoding of the om31 wire proof | recursion |
| H23 | per-node host wait (1 per node + 1 per FIXED job); one node per lane per device at a time | worker `finish`, lane threads | 2 waits/node, ~38 per request [M]; recursion host-bound: 12.1 s recursion vs 2.7 s GPU/GPU [M, 26235156] | whole-node per-class CUDA graph, chained on device by DAG order; 0 waits per node | recursion + driver |
| H24 | direct enqueue on graph-cache misses (capture after 2 sightings per device, class not pinned to a device) | `outer_graph_cache.zig` | 1359 launches on a direct node vs 2 replayed [M] | capture every (class, device) at warm; ≤ 50 launches/node | recursion |
| H25 | per-node host verify / restore / serialize / write of fold proofs | `execution_wrap.zig combine` (`verify_ns`, `save`) | per fold [M, logged, not in receipts here] | deleted from the request path: device checks; one publication pass after the single readback | recursion + driver |
| H26 | root verify on the host | `execution_wrap.zig runImpl` (`root_verify_ns`) | per request [M, logged] | off-path fresh CPU receiver (gate) | driver |
| H27 | feeder ledger accepted from host-side hybrid checks | `jobs/provider.zig Ledger`, `m8_feeder.zig` | per job | ledger derived from slab status words in `publish()` | driver |
| H28 | publication: combined entry, files, spool answer | `combined_publication.zig`, `jobs/request.zig serve` | small [M, not split] | **stays host** (publishes the sliced bytes) | driver |

Discarded: the unfinished feeder `provider.zig` WIP (`Tenancy`: a host mutex serializing native windows against truth leases per device). It adds a host wait to work around H14; the memory plan removes the collision instead.

---

## 3. Components

### 3.1 Per-class setup cache (`gpu_native.ClassCache`)

- Built during service install (`warm` phase) from the manifest's class mix: native segment classes (row log, slot layout, GKR roster), truth classes, leaf/fold/root classes.
- An entry holds: the stream-owned host plan (immutable after warm), device regions per GPU (`class_cache` region of the memory plan), `max_encoded_bytes`, extra checks, and a captured graph executable per GPU.
- `seal()` closes the warm phase. In `request` phase a miss or a build fails closed (`GpuNativeClassNotWarmed`, `GpuNativeClassBuildOnRequestPath`). A new class seen on a request is a refused request plus a warm hint, never a silent slow path.
- What moves in (from §2): H6, H9 (framing at the placeholder point is challenge-independent; the device substitutes the drawn point, as `native_pcs.zig` already does), H16–H21, H24, and the slab directory prefix.

### 3.2 Native segment, fully on device (stream native)

Stage 1 per segment, released by `sealed_segment` while capture continues:
1. witness from `TraceChunk`s (contributor kernels without joins) → MAIN columns in `main_resident`;
2. FIXED adoption: class tree root from the cache, mixed on device;
3. MAIN commit (`trace_commit` kernels), root mixed on device, root and claims published to the exchange slots;
4. local GKR on the device channel (no `partiallyVerifyBatch`), binding; `binding_authority` check; GKR section written for the encoder.

Device seal (one small job on the seal GPU, after `awaitSlot` of every root/claims slot): manifest digest (Blake2s over the same preimage the host builds today, from exchange slots + class statement constants), global χ, `mixManifestAndClaims`; writes the 16-word seal checkpoint slot, peer-copied to the other GPU. Stage-2 channels start from it.

Stage 2 per segment: global interaction (claims stay on device) → INTER commit → composition (device coefficient) → OODS (device point) → enqueue-only PCS → checks (`global_status`, `composition_accept`, `oods_constraint`, `public_claims`, `pcs_status`, `root_match`, `channel_order`) → `ProofEncoder` (exact `WP.encodePhysical` bytes) → slab. MAIN region of the segment is released after its PCS (stream-ordered free).

### 3.3 Recursion and truth, fully on device (stream recursion)

- **TruthJob:** `truth_source` → `truth_composition` → `truth_pcs` as one arena job with a measured class peak (replaces the 14.75 GB lease [M]); `truth_status`, `pcs_status`, encoding.
- **Outer node** (leaf/fold/root): device seed fill from the children's encoded slab regions (own segment or the peer replica) using the class seed program (generalized `fold_tape.record`, built at warm) → MAIN assignment → TC MAIN → statement/FIXED/MAIN mixed on device → z, α → INTER → `lookup_sum` → claims → TC INTER → composition → OODS → PCS → `node_oods_constraint` → encode. Node outputs come from the assignment's output variables on device (no host `expected`).
- **Whole-node graph per (class, device)** captured at warm; per node only pointer rebinding (`cudaGraphExecUpdate`) and one launch. Target ≤ 50 host launches per node [measured today: 2 when replayed, 1359 when direct, M].
- Nodes are chained on device in DAG order (stream order on one GPU, cross-GPU events for children on the other GPU). No per-node host wait.

### 3.4 Slab contract (`gpu_native.RequestLayout`)

One slab **segment per GPU**, with a pinned host mirror of the same size. Word offsets, regions 64-word aligned:

| region | words | written by | content |
|---|---|---|---|
| header | 16 | host (prefix, per class mix) | magic `RVGN`, contract version, request id (low 32 bits), device, entry count, status words, exchange/encoded offsets and sizes |
| directory | 8 per proof (`Entry`) | host (prefix) | kind, ordinal, status_first/count, encoded_offset, capacity, check table index |
| status | Σ checks per proof (7–10 per proof) | device checks | `Verdict` words: `0xffffffff` unset (driver memsets at request start), `0` accepted, `check<<16 \| detail` reject |
| exchange | `Exchange.words()` | producers + peer copies | per segment MAIN root (8) and claims (8 × claims_per_segment); per device χ/LogUp partial (8); seal checkpoint (16); one written-flag word per slot |
| encoded | per proof: 1 length word + ⌈max_encoded_bytes/4⌉ | `ProofEncoder` | the exact proof bytes today's host writes |

- Required checks per kind: `gpu_native.requiredChecks` (native segment 10, truth 4, node 7, request pseudo-proof 2). A stream may append extra checks per class.
- Status-word ids are stable and range-partitioned: `0x01xx` driver, `0x02xx` native, `0x03xx` recursion.
- **Sizes [E]:** proof capacities come from class constants. Today root 749,464 B (26235156) and 749,688 B (24628607) [M]; an outer node wire proof 632,624 B with a 1,554,264 B PCS slab [M, fixture]. 24628607 has 39 artifacts [M] → request slab ≤ ~48 MB across both GPUs [E]; one D2H per GPU at ~25 GB/s ≈ 1–2 ms [E]. The exchange region is under 16 KB for 7 segments [E].
- PCS working slabs (`slab.zig ProofLayout`) stay job-internal device scratch; only the encoded bytes and status words go into the request slab.

### 3.5 Device acceptance checks (`gpu_native.DeviceCheck`)

Each check is an enqueued kernel that reads device inputs and writes exactly one `Verdict` word; it never reads back and never branches the host. A check that never ran leaves `unset`, which rejects. `publish()` refuses the whole request on the first non-accepted word and names it (`Rejection`). Mapping from today's host checks:

| check | today (host) |
|---|---|
| `binding_authority` | `native_binding.checkAuthority` in `native_hybrid.bind` |
| `global_status` | `job.global_status` loop |
| `composition_accept` | `native_stage2.accept(job.composition_status)` |
| `oods_constraint` | second `Components.Set` + `evalCompositionPolynomialAtPointWithWorkCapture` |
| `public_claims` | `CW.publicClaims` |
| `pcs_status`, `node_pcs_status` | PCS status plane decode |
| `root_match` | `pending.checkPhysicalRoots` |
| `global_seal`, `exchange_complete` | host seal barrier |
| `lookup_sum` | OuterNodeJob finish lookup status |
| `node_oods_constraint` | `outer_job_prestage.assemble` composition check |
| `seed_tape`, `child_binding` | host graph build / fold_tape check mode |
| `truth_status` | legacy truth closure |
| `encode_bounds` | — (new: encoder wrote ≤ capacity) |
| `channel_order` | device channel step/chain latch (exists in `NAT/rv64/channel.cu`) |

### 3.6 Peer exchange and the seal barrier

- `PeerExchange.publish(src, slot)`: `cudaMemcpyPeerAsync` of the slot into every other GPU's replica on the source GPU's exec stream, then set the flag word, then record the slot event.
- `awaitSlot(device, src, slot)`: `cudaStreamWaitEvent` on the consumer GPU. The host never reads an exchanged value.
- Traffic per request: 7 roots + 7 claim blocks + 2 partials + 1 seal checkpoint (< 16 KB [E]). Children of a node on the other GPU are read from the peer replica of their encoded region (peer copy of the child's encoded bytes, ~0.6–0.75 MB [M sizes] per cross-GPU edge).

### 3.7 One memory plan per GPU (`gpu_native.MemoryPlan`)

32 GB RTX 5090. Regions, fixed at install, ordered `class_cache, graph_exec, main_resident, arena, truth, exchange_slab, reserve`:

| region | sizing source |
|---|---|
| class_cache | FIXED trees, twiddles, class tapes/plans: 2.5–3.1 GB long-lived today [M] |
| graph_exec | graph budget 256 MB/worker [default, outer_graph_cache] |
| main_resident | MAIN of the segments placed on this GPU: 4.15 GB (dev0) / 3.23 GB (dev1) on 24628607 [M] |
| arena | two-sided job arena: one job in flight + one staged; fold/root peak 21.5–21.8 GB [M] |
| truth | 0: truth jobs are arena classes with measured peaks (the 14.75 GB lease [M] becomes an arena job) |
| exchange_slab | slab segment ≤ ~24 MB/GPU [E] |
| reserve | CUDA/driver headroom, 1 GiB today [default] |

- Class 3.1 + graphs 0.25 + MAIN 4.15 + slab + reserve 1.0 ≈ 8.5 GB leaves ≈ 23 GB arena [D]. That holds a fold peak (21.8 GB [M]) but not a fold plus a staged next input. So the plan is **two-phase** (ZisK phase A/B re-split, delta §4.2): in phase A (native window) `main_resident` is live and the arena runs Stage1/2, truths and leaves that fit (leaf peaks 3.1–18.2 GB [M]); in phase B, once a GPU's last Stage 2 freed its MAIN, the arena grows over `main_resident` for folds and the root. The region boundary moves only at a phase change, stream-ordered on the device.
- Invariant: no `cudaMalloc` on the request path outside these regions. Today's outside-window allocations (retained regions, persistent regions, leases) all map into a region. The driver enforces this with the allocation observer (`allocation_observer.zig`) in the acceptance test.
- Per-class peaks come from the existing sweep (`plan.zig`, `scripts/rv64_m8_plan_sweep.py`); the plan is a pinned unit test (layout arithmetic, delta §4.3).

### 3.8 Scheduling

- DAG per request: `stage1(seg)` on release → `seal` (after all roots/claims) → `stage2(seg)`; `truth(t)` (independent, fills the seal barrier); `leaf(seg)` on its segment's encode; folds on children; root. Built by the driver from `ready_dag.Plan` and the manifest.
- Placement: a segment's Stage1 and Stage2 run on the same GPU (MAIN never moves). Recursion nodes follow key affinity (warm graph for the class on that GPU) and then root-critical priority first; the root chain is placed to minimize cross-GPU edges.
- One job in flight + one staged per worker (existing 3-stage worker). All submission happens at plan time, with device events as dependencies. The worker's per-job event wait is replaced by **one request completion event**, so the host never waits per job.
- The native barrier is filled by truth jobs and by the **previous request's** recursion tail, so the GPUs never idle during the seal.
- Host waits: 1 per request (the root GPU's final event, after its stream waited for the other GPU's completion event and both segment D2Hs were enqueued).

---

## 4. Byte identity and correctness

- Every transcript operation keeps its order and inputs: the device seal performs today's `mixManifestAndClaims` with the same manifest preimage; Stage 2 and outer nodes start from the same checkpoints. The channel parity harness (`channel_parity.zig`) compares boundary snapshots against the host engine on both blocks.
- Encoders reproduce `WP.encodePhysical` (native) and the om31 wire encoding (outer). The gate compares every artifact against the frozen D2 golden (32/32, 39/39).
- Checks fail closed: unset words reject, a reject anywhere refuses publication, and an encoder overrun refuses publication. Negative tests corrupt each input class and expect the named check to fire.
- Fresh CPU receivers and the 19-case corpus in the gate verify off the request path. Removing H15/H25/H26 from the request path does not remove verification: it moves it to the gate and the receivers.

## 5. Expected effect [E] vs baselines [M]

24628607, 2×RTX 5090, warm request:

| stage | today [M] | GPU-native [E] | why |
|---|---|---|---|
| capture exposed on the critical path | 2.106 s (whole capture before stage 1) | 0.3–0.5 s | streaming; Stage 1 per sealed segment |
| native window | 4.03 s legacy / 5.31 s hybrid | 1.6–2.0 s | job GPU time 1.04 s Stage1 + 1.78 s Stage2 summed over 7 segments [M] → ~1.4 s per GPU [D] plus witness/MAIN on device; no framing/assembly (H9 + H11 = 7.3 s summed warm [D]); 0 per-job waits |
| native verify | 1.589 s side thread [M] | 0 on the request path | gate receivers |
| recursion after native | 5.538 s legacy / 13.07 s hybrid | 2.8–3.3 s | kernel-bound: 26235156 warm node GPU 5.4 s over 2 GPUs [M] → 2.7 s/GPU [D]; 24628607 has more nodes; init 6.48 s + FIXED 1.3 s + decode/assemble moved to warm/device; leaves overlap the native window |
| tail (readback + publish) | not split [M] | ≤ 0.1 s | one D2H per GPU (~48 MB) + file writes |
| **request** | **12.33 s median [M]** | **~6–7 s** | — |

Floor check: the warm legacy request runs 10.58 kernel GPU-seconds [M], which is 5.29 s per GPU if perfectly balanced [D]. With today's kernels the GPU-native request cannot beat about 5.3 s. ≤ 5 s needs kernel work as well: memory techniques, fewer leaves, Poseidon2 leaves, the windowed sumcheck (delta §4.1, §4.4). This pass removes the host from the critical path. The kernels are the next pass.

---

## 6. Streams: exactly three, disjoint files

Branches are cut from the contract commit on `codex/rv64-m8-gpu`. Each worktree is `~/Coding/ge-wt/rv64-m8-gpu-<s>`, its branch `codex/rv64-m8-gpu-<s>`, and its pod source `/workspace/m3/src/m8-gpu-<s>`. Gate: `rv64_gate.sh --stream m8-gpu-<s>`. Interface requests go to `/workspace/m3/M8-INTERFACES.md` under the `m8-gpu-<s>` section (append only, `flock m8-interfaces.lock`). The contract (`gpu_native.zig`) is stewarded by **driver**: changes are additive, announced, and never break the other two streams' builds.

### 6.1 Ownership table

| stream | owns (edit) | creates (new) | reads only |
|---|---|---|---|
| **driver** | `rv64/jobs/{gpu_native,driver,api,worker,channel,channel_parity,slab,scheduler,request,provider,mod,plan,retained,ops,fake,lint}.zig` and their `*_test.zig`; `rv64_jobs_test_root.zig`, `rv64_jobs_sched_test_root.zig`, `rv64_jobs_parity_main.zig`; `rv64/m8_feeder.zig`; `rv64/resident_batch.zig`, `rv64_combined_ethereum_main.zig` (the request switch only); `NAT/rv64/jobs/{runtime,channel_ops,slab_ops}.cu`; `build.zig` (riscv_cuda); `scripts/{rv64_gate.py,rv64_m8_jobs_addon_build.py,rv64_m8_plan_sweep.py}` | `rv64/jobs/driver_*.zig` (DAG, placement, seal barrier, memory plan install, publication), `rv64/m8_capture_stream.zig` (capture → `CaptureSink`), `NAT/rv64/jobs/peer_ops.cu` | legacy admission files (frozen: not instantiated under GPU-native), GE capture sources |
| **native** | `rv64/jobs/native_*.zig` (incl. `native_hybrid_jobs.zig`, `native_device.zig`) and tests; `rv64_jobs_native_test_root.zig`; `rv64/native_hybrid.zig` (retired at the end); `NAT/rv64/jobs/{pcs_enqueue.cu,pcs_enqueue.h,oods_points.cu,native_*.cu}`; `tests/cuda/rv64/jobs/pcs_enqueue_parity.cu` | `rv64/jobs/native_{witness,framing_cache,checks,encode,seal}.zig`, `NAT/rv64/jobs/native_{witness,checks,encode,seal}.cu` | legacy native witness/commit/global kernels, `composition_codegen.zig` |
| **recursion** | `rv64/jobs/outer_*.zig` (incl. `outer_device.zig`) and `rv64/jobs/truth_*.zig` and tests; `rv64_jobs_outer_test_root.zig`; `rv64/outer_job_factory.zig`, `rv64/outer_job_prestage.zig`; `NAT/rv64/jobs/outer_*.cu` | `rv64/jobs/{outer_seed,outer_checks,outer_encode,truth_*}.zig`, `rv64/outer_seed_program.zig` (warm-time generator from `fold_tape`/leaf tape), `NAT/rv64/jobs/{outer_seed,outer_checks,outer_encode,truth_*}.cu` | `om31_native/{fold_tape,execution_wrap}.zig`, `outer_assignment.zig`, `outer_source.zig`, legacy truth kernels |

Shared rules: `pcs_enqueue.*` is native's file and recursion calls it. A recursion change to it goes through INTERFACES. A new test file is added to the stream's own test root (each root is owned by one stream). A new `build.zig` step is requested from driver.

### 6.2 Briefs

**driver.** Make `jobs.serve` / `request.Provider` the JOBS=1 request driver and retire the feeder's legacy orchestration:
- capture streaming (`m8_capture_stream.zig` → `CaptureSink`) with upload on the h2d stream;
- the DAG and placement (§3.8);
- the per-GPU `MemoryPlan` installed once, two-phase (§3.7), with no outside-region allocation;
- `PeerExchange` over `peer_ops.cu`;
- the request slab: prefix upload, unset memset, one D2H per GPU, ONE host wait;
- `publish()` → ledger → files.

Admission and two-lane are frozen: not instantiated under the new path, files kept. Land it behind `STWO_RV64_M8_GPU_NATIVE=1` (requires JOBS=1, contract stub today). When native and recursion pass, flip JOBS=1 to mean GPU-native and delete the intermediate flag (fewer flags).

**native.** Native segments fully on device:
- witness from `TraceChunk`s, no joins;
- FIXED from the class cache;
- MAIN resident from witness to PCS;
- Stage 1 and Stage 2 as `NativeFactory` jobs;
- the device seal kernel (manifest digest, χ, mix);
- the per-class framing cache (H9) built in `warm`;
- device checks (`binding_authority` … `root_match`);
- the device encoder producing `encodePhysical` bytes.

Delete the per-segment host framing/assembly and the legacy MAIN replay from the GPU-native path.

**recursion.** Recursion fully on device:
- `TruthJob` inside the plan;
- per-class node plans, seed programs, FIXED trees and stream/PCS framing in `warm` (H16–H21);
- device seed fill from child slab regions;
- whole-node graph per (class, device) captured at warm, ≤ 50 launches/node;
- device `lookup_sum` / `node_oods_constraint` / `seed_tape` / `child_binding` checks and device om31 encoding;
- nodes chained on device with no per-node host wait.

### 6.3 Acceptance tests

**driver**
- D1 (host, fake device, `zig build test-rv64-jobs`): a request with fake native/recursion factories on 2 fake GPUs has exactly 1 host wait and exactly 1 D2H per GPU; zero allocations after install outside plan regions; the seal runs only after every root/claims slot `awaitSlot`; `publish` refuses on an unset word, a reject code, an overrun or a stale header; two pipelined requests do not cross slabs.
- D2 (lint): `lint.zig` scans `driver*.zig` and the capture hand-off; extend it to forbid `cudaMalloc` outside `worker.zig` install.
- D3 (pod, both 5090s): `peer_ops.cu` publish/await round trip for every slot kind, flags, cross-device event chain with one host wait (`rv64-jobs-channel-parity`-style binary).
- D4 (integration, after native + recursion land): `rv64_gate.sh --env STWO_RV64_M8_JOBS=1 --env STWO_RV64_M8_GPU_NATIVE=1` PASS on 26235156 and 24628607 (byte-identical, receivers, corpus), with `m8-jobs.json` showing `host_waits=1` per request and `d2h=2`.
- D5: the canonical 3+3 interleaved runner, request and stage medians, kernel GPU-s and busy via `nvtx_gpu_proj_sum`.

**native**
- N1 (host): the class framing cache equals the per-request framing of `stageTwoInner` (PcsJob request words, mask points, composition and INTER plans) on fixtures.
- N2 (pod): channel parity for the device seal + Stage 2: boundary snapshots equal the host engine on both blocks.
- N3 (pod, negatives): corrupting one input per check makes exactly that status word non-zero (all native checks), and the request is refused.
- N4 (pod): device-encoded bytes equal `WP.encodePhysical` for every segment of both blocks (all segments byte-identical to the golden).
- N5 (receipt): per-segment host time ≤ 5 ms [M]; 0 legacy replay or owner calls; MAIN allocation count 1 per segment (resident witness → PCS).
- N6: the gate default PASS, and the gate with the native factory under the driver (D4) PASS.

**recursion**
- R1 (host): the warm-time node plan equals `prestage` output (class/graph keys, image layout, checkpoint prefix); the seed program equals `fold_tape.record` and the leaf tape on fixtures.
- R2 (pod): device seed fill equals host seeds for every node of both blocks.
- R3 (receipt): ≤ 50 host launches per node, 0 host waits per node inside a request, FIXED never recommitted per node.
- R4 (pod, negatives): corrupting each input fires `lookup_sum`, `node_oods_constraint`, `seed_tape`, `child_binding`, `truth_status`.
- R5 (pod): device-encoded node proofs are byte-identical (16/16, 20/20 nodes) and the root is 749,464 / 749,688 B identical.
- R6: `TruthJob` truth proofs are byte-identical, the footprint sits inside the plan, and the allocation observer reports no outside-region allocation.

## 7. Landing order

1. Contract (this commit): `gpu_native.zig` + stubs, gate default PASS.
2. In parallel, each behind `STWO_RV64_M8_GPU_NATIVE=1`:
   - driver: D1–D3 with fake factories;
   - native: N1–N5 through a native-only harness;
   - recursion: R1–R6 through the outer fixture plus a truth harness.
3. Driver composes the real factories: D4 on both blocks, then D5.
4. Promotion: JOBS=1 means GPU-native. Delete the feeder, hybrids and the intermediate flag. Admission/two-lane stay frozen until deleted in the simplification pass.
