# gn-node: GPU-native recursion node — device seed fill, device statement/FIXED mix, seed_tape / child_binding checks

Branch `codex/rv64-m8-gn-node` (from `codex/rv64-m8-gpu` @ b289b021f). Labels: [M] measured, [D] derived, [E] estimate.
Design of record: `design/riscv-proving-stack/rv64-m8-gpu-native.md` §3.3–3.5 (host work H16, H17, H19; checks `seed_tape`, `child_binding`, `channel_order`).

## What landed (all default off; no proof byte changes)

| piece | files | replaces (host) |
|---|---|---|
| Seed program (per class, built at warm) + bit-exact host mirror | `jobs/outer_seed_device.zig` | `fold_tape.record` (folds/root), the leaf graph / `leaf_tape.cpu|truth` proof part (leaves) |
| Device seed fill + statement kernel | `NAT/rv64/jobs/outer_seed.cu` (`stwo_rv64_outer_seed_fill_v1_on`, 4 launches) | `fromNativeCapped` + `merkle.hostCap` + `Emit.proof`; `om31_outer.expectedDigest` (fold outputs); `outer_job_prestage.hostCheckpoint` (`prove.begin` + `MC.mixRoot`) |
| Verdicts | same kernel | `seed_tape` 0x0305 (program, region, image header, raw query range, canonical values, cap coverage / agreement, every cap or full path hashes to its committed root); `child_binding` 0x0306 (wire magic, profile, child authority identity, output count, child FIXED root, canonical outputs) |
| GPU-native node job | `jobs/outer_device.zig` `Recursion.node` → `NodeJob` | per-node host prep of the recursion request layer: children read from the request slab (own segment, peer copy for a child on the other GPU), seeds/checkpoint/outputs written into the class template's node region, then the class's whole-node job (device encoder into the node's slab region, PCS image tail for the parent), `lookup_sum` and `channel_order` words |
| Class products | `rv64/outer_job_factory.zig` `NodeClasses` (harvested from a warm check-mode request), `jobs/outer_encode_job.zig` (`outputs_device`, `image_tail`) | H18/H19/H20 per node (class Staged template, descriptor, OODS program built once) |
| In-service check | `rv64/outer_job_factory.zig` `GnCheck` (`STWO_RV64_M8_GN_NODE=check`) | — (proves every node from device-filled inputs inside today's hybrid recursion; host seed limbs and checkpoint are zeroed before staging) |
| Recorder + piece harness | `rv64/outer_seed_record.zig` (`STWO_RV64_M8_GN_NODE_RECORD=<dir>`, one hook line in `pcs_native.zig`), `jobs/outer_seed_harness_test.zig` | — |

Child seed-source convention (M8-INTERFACES "m8-gn-node"): a child's request-slab encoded region holds `[byte length][encoded proof bytes]` and, in its LAST words, the child's enqueue-only PCS readback image (hybrid_pcs.decodeWords layout). A leaf's native child additionally appends the leaf statement tail (the seeds `leaf_tape` emits after the proof) and the leaf outputs. Every gather offset is a class constant, so the per-node device work is a fixed-shape gather plus Merkle-cap hashing (capturable).

Profile facts the program encodes (found on real data): fold children are om31 node proofs under the diet-wire profile (fold Merkle cap 2^3: per-query paths truncated at the cap, 2^3 cap nodes derived and hashed to the root); the fold tape carries each child's claims (`F.guess`, 11 OM31) after its outputs; leaf children are native proofs verified with FULL paths (no cap); the seed fill re-hashes every full path to its root.

## Evidence

### Recorded real inputs (legacy path)
- [M] Recording runs (proof-only runner `gn_prove.py` = the gate's small-block-proof step + frozen-D2 parity; a25 base `m7-combined-residency` + jobs addon `b1` linked against it, the r-node recipe): `STWO_RV64_M8_OUTER_JOBS=1 OUTER_DEVICE_CHECKS=1 GN_NODE_RECORD=<dir>`.
  24628607 cold + warm byte-identical to the frozen D2 golden (39/39 artifacts each); 26235156 cold + warm 32/32.
  Records (pod, deleted after the harness for disk; per-file sha256 in `rec-24628607.sha256` / `rec-26235156.sha256`): 19 nodes + 14 native/truth PCS images (280 MB) / 15 + 11 (219 MB); proof.json sha256 3815a2c4… / 0a8a4f20….

### Piece-only harness on the GPU (`jobs/outer_seed_harness_test.zig`, one RTX 5090, addon `b3x` sha256 7eb639dc…)
Every node of both recorded blocks, children from their recorded regions; compared record for record with the legacy host values.

| block | nodes | device seed records == legacy host seeds | device checkpoint == hostCheckpoint | device fold outputs == expected | GPU time / node (CUDA events) | host enqueue / node | launches |
|---|---|---|---|---|---|---|---|
| 24628607 | 19 (5 folds incl. root, 14 leaves) | 19/19 | 19/19 | 5/5 | folds 480–542 us, leaves 345–2917 us; 17.5 ms / request [M] | 18–28 us (first call 1.9 ms) | 4 |
| 26235156 | 15 (4 folds incl. root, 11 leaves) | 15/15 | 15/15 | 4/4 | folds 477–528 us, leaves 339–2900 us; 14.4 ms / request [M] | 17–32 us (first 1.9 ms) | 4 |

- Seeds per node [M]: folds 0.54–1.19 M records, leaves 0.12–0.49 M (proof part 0.12–0.49 M from the native image; statement tail 40–8,804 = the native producer's words).
- Host mirror (`fillHost`) == device bit for bit on all 34 nodes; it is a diagnostic only (17–40 ms per node on the host [M]), never on the request path.
- Warm-time program build per class [M]: folds 0.22–0.69 ms (`buildFold`).
- [M] Negatives (fold 4 of each block; device word == mirror word on every case): Merkle path sibling flipped → seed_tape 0x03050006; queried value := p → 0x03050005; raw query out of range → 0x03050004; image header → 0x03050003; empty region → 0x03050002 (+ child_binding 0x03060001); wire magic → child_binding 0x03060002; child identity → 0x03060004; child output count → 0x03060005; child FIXED root → seed_tape 0x03050008 + child_binding 0x03060006. 9/9 fail closed per block.
- Machine-readable: `harness-24628607.json`, `harness-26235156.json` (`scripts/rv64_m8_gn_node_summary.py harness <log>`).

### In-service: every node proved from device-filled inputs (`STWO_RV64_M8_GN_NODE=check`)
Proof-only runner (`pod/gn_prove.py`: the gate's small-block-proof step + frozen-D2 parity) with `STWO_RV64_M8_OUTER_JOBS=1 OUTER_DEVICE_CHECKS=1 GN_NODE=check OUTER_GRAPH_THRESHOLD=1`, driver b6, addon b6 (a25 base). Before staging, every node's host seed limbs and transcript checkpoint are ERASED (and the staged expected outputs); the device seed fill + statement kernel writes them from the children's sources (legacy natives' PCS images via the recorder hook, proved nodes' wire + PCS image), and the node body proves from them.

| block | node proofs from device inputs (cold + warm) | device outputs == legacy | device checkpoint == legacy | seed_tape / child_binding accepted | request artifacts vs frozen D2 | seed-fill GPU (CUDA events) |
|---|---|---|---|---|---|---|
| 24628607 | 38 / 38 | 38 / 38 | 38 / 38 | 38 / 38 | **39/39 + 39/39 byte-identical** | 0.37–1.99 ms / node, 34.1 ms over 38 nodes [M] |
| 26235156 | 30 / 30 | 30 / 30 | 30 / 30 | 30 / 30 | **32/32 + 32/32 byte-identical** | 27.3 ms over 30 nodes [M] |

- [M] Negative arm (`STWO_RV64_M8_FAULT_INJECTION=1 GN_NODE_FAULT_ORDINAL=4`, 24628607): one MAIN-tree Merkle path word of fold 4's first child flipped → `seed_tape` 0x03050006 on device → node refused (`GnNodeDeviceRejected`), request fails as intended (`arm-n-24628607-4`).
- Check-mode host costs (child-source assembly, MAIN-root child search, program build per node: 2–620 ms [M]) are harness scaffolding: production builds programs at warm and reads children from the slab.
- Machine-readable: `service-g-24628607.json`, `service-g-26235156.json`.

### In-service: the production GPU-native node job (`STWO_RV64_M8_GN_NODE=job`)
Every node is proved a second time through `outer_device.NodeJob` over its `NodeClasses` template (children in a node-local stand-in of the request slab: image in the last region words), device encoder into the node's region (image tail on, outputs from device memory, `device_publish`: no host decode in finish), and the bytes are compared with the published host bytes.


Cold request of each block (driver b9, addon b6; `job-cold-<block>.txt` = the GN_NODE_JOB lines):

| block | nodes through the production node job | device-encoded bytes == published host bytes | own PCS image tail == node image | all 7 slab verdict words accepted | host launches / node | NodeJob host stage+enqueue / node |
|---|---|---|---|---|---|---|
| 24628607 | 19 (14 leaves, 5 folds incl. root) | 19/19 | 19/19 | 19/19 | 7 (seed fill 4 + lookup copy + channel verdict + 1 graph launch of the body; encoder/OODS/tail inside the made job) | 42–87 us [M] |
| 26235156 | 15 (11 leaves, 4 folds incl. root) | 15/15 | 15/15 | 15/15 | 7 | 37–74 us [M] |

- Verdict words read back from the node's region: seed_tape, child_binding, lookup_sum, channel_order, node_pcs_status, encode_bounds, node_oods_constraint.
- [M] Worker stage of the made job (hybrid window): leaves 27–192 ms, folds 138–322 ms per node — the template's node region (zeroed seeds, up to 24 MB) and, under the hybrid window's per-job class-region policy, the class schedule are re-packed and uploaded per node, plus the check-mode child-region upload. With persistent class regions (the GPU-native install) the schedule is uploaded once per worker; the seeds section needs the `device_inputs` flag requested in M8-INTERFACES.
- [M] Body GPU wait 77–422 ms (leaves) / 243–533 ms (folds) per node: the whole-node prove itself.
- Warm request of the same services failed in job mode (`InvalidDevicePcsColumn`): the class template borrowed its node's Authority-owned FIXED log table, freed after the cold request. Fixed in 131005f81 (templates own it; the Blake sample tape is handed over per node). Re-run below.

### Host tests (laptop, memguard 6 GB)
- [M] `zig build test-rv64-jobs-outer` and `test-rv64-jobs` PASS. `outer_seed_device.zig`: synthetic children with real Merkle trees (trace + FRI), caps and full-path roots verified, five negative classes. `outer_device.zig`: the GPU-native node job end to end on the fake device (2 GPUs, the fold's second child on the peer GPU: one peer copy; seeds/outputs/checkpoint == mirror; seed_tape / child_binding / lookup_sum / channel_order words accepted in the request slab), and its negatives (corrupted peer child path → seed_tape reject, bad channel latch → channel_order reject, publish refuses; unknown child / wrong child count / unplanned class fail at plan time).

## Remaining host work on the GPU-native node path (per node unless noted)

| item | where | state |
|---|---|---|
| Template seeds/checkpoint/outputs still PACKED and uploaded by `OuterNodeJob.stage` (zeros the device overwrites: up to 24 MB for a fold) | `jobs/outer_job.zig` stage / `jobs/outer_staged.zig` pack (not this stream's files) | fix: a `device_inputs` flag that skips the seeds/channel_seed/expected sections and keeps the seed variables in the class region; request filed in M8-INTERFACES |
| Leaf statement tail + outputs (ordinal, statement/manifest digests, GKR transcript values, encoded claims, request words) | native Stage 2 / TruthJob producers | supplied from the legacy host values in check mode and the harness; request filed (child seed-source convention) |
| Leaf Blake sample prefill tape (`blake_sample_inputs`, STWO_RV64_BLAKE_SAMPLE_PREFILL=1) | leaf_graph (om31_native, read-only) | still host-derived per leaf; proof-neutral (producer-only shadow inputs): drop it or derive on device |
| `OuterNodeJob.finish`: outer section decode (status latches, claims) + a 1.5 MB copy of the PCS image (`defer_decode`) | `jobs/outer_job.zig` | small; publish-only path should skip both (the device words carry the verdicts) |
| Class products need one warm legacy request (`NodeClasses` harvest under GN_NODE=check) + authority registration by the binder | gn-bind / driver install | API in place (`NodeClasses.get`, `Entry.programFor`, `Recursion.register(.node)`) |
| Children found by MAIN-root search in the host seeds (check mode only) | `GnCheck` | production gets children from the driver DAG (`RecursionFactory.node(children)`) |

## Binding (for gn-bind / the driver)

1. Install: one warm request proved through the hybrid recursion with `STWO_RV64_M8_OUTER_JOBS=1 STWO_RV64_M8_OUTER_DEVICE_CHECKS=1 STWO_RV64_M8_GN_NODE=check` harvests one `outer_job_factory.NodeClasses.Entry` per node class (class Staged template, seed-program inputs, encoder descriptor, OODS program).
2. For each entry: `entry.programFor(child_region_words)` with each child's request-slab region words (1 + the child class's encoded capacity; om31 children: `entry.max_encoded_bytes / 4 + 1` of the child entry), set `entry.graphs[d]` to device d's Prover graph cache, then `outer_device.Recursion.register(id, child_class_keys, key, .{ .plan, .node = &entry.node, .max_encoded_bytes = entry.max_encoded_bytes })`.
3. `Recursion.device = .{ .seed = outer_seed_device.Symbols.load(&addon), .d2d = <base stwo_exec_context_memcpy_d2d_async>, .peer = ops.Peer.open(&addon) }`.
4. Per request: the driver already calls `class_of` (plan) then `node(ctx, id, children, device)` (make); after publication `Recursion.end(request)`.
5. Producers: om31 nodes write their PCS image tail themselves (`EncodedNode.image_tail`); native Stage 2 and TruthJob must write `[image][leaf statement tail][leaf outputs]` after their bytes (M8-INTERFACES "m8-gn-node").
