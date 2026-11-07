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

(see `harness.json`, `service.json`, `gates.json`; raw logs and records on the pod under `/workspace/m3/runs/m8-gn-node/`)
