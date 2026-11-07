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
  Records: `/workspace/m3/runs/m8-gn-node/rec-24628607` (19 nodes + 14 native/truth PCS images, 280 MB), `rec-26235156` (15 + 11, 219 MB); proof.json sha256 3815a2c4… / 0a8a4f20….

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
