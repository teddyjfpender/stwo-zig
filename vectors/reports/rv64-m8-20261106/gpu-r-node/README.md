# gpu-r-node: device encoding + device checks of outer (leaf/fold/root) nodes

Branch `codex/rv64-m8-gpu-r-node` (from `codex/rv64-m8-gpu` @ 28ae81a58). Labels: [M] measured, [D] derived, [E] estimate.
Design of record: `design/riscv-proving-stack/rv64-m8-gpu-native.md` §3.3–3.5 (host work H22/H25, checks `node_pcs_status`, `node_oods_constraint`, `encode_bounds`).

## Landed (all default off; no proof byte changes)

| piece | files | what it replaces |
|---|---|---|
| Device proof encoder | `jobs/outer_encode.zig` (descriptor, image layout, bounds, bit-exact host mirror `encodeHost`), `NAT/rv64/jobs/outer_encode.cu` (`stwo_rv64_outer_encode_v1_on`) | host `hybrid_pcs.decodeWords` + `pcs_assembly.assemble` + `encodeProofBytesBinary` + om31 `wire.encode` (H22 decode/assemble, H25 serialize) |
| `node_pcs_status` (0x0304) | same kernel | `decodeWords` header/numerical/channel latches, `checkRoots`, canonical values, duplicate-query consistency (trace + FRI), section status latches, canonical claims/outputs |
| `encode_bounds` (0x0104) | same kernel | new: bytes fit the slab entry; length word 0 otherwise |
| `node_oods_constraint` (0x0303) | `jobs/outer_encode_oods.zig` (program ABI), `outer_job_prestage.oodsProgram` (per-class program builder), `NAT/rv64/jobs/outer_checks.cu` (`stwo_rv64_outer_oods_check_v1_on`) | `assemble`'s host `evalCompositionPolynomialAtPoint` vs `extractCompositionOodsEvalWithSplit` |
| In-stream wrapper | `jobs/outer_encode_job.zig` `EncodedNode` (job-slab field for check mode, or `Target` = request-slab encoded region + status words via `SegmentLayout`) | — |
| Class bound | `outer_device.ClassInfo.encode_descriptor` → `max_encoded_bytes` = encoder class bound | — |

Flags: `STWO_RV64_M8_OUTER_DEVICE_ENCODE=check` (encode + OODS check after every whole node; the node fails closed unless device bytes == host-mirror bytes == host `wire.encode` bytes and the device OODS values == `assemble`'s values). Negative tests (two-key with `STWO_RV64_M8_FAULT_INJECTION=1`): `STWO_RV64_M8_OUTER_ENCODE_FAULT_ORDINAL=n` (one PCS image word := 0xffffffff on device), `STWO_RV64_M8_OUTER_OODS_FAULT_ORDINAL=n` (one composition sample coordinate := 0 on device, still canonical).

Encoder design: one launch, one block (512 threads). Thread 0 runs the sorted-merge decommitment walks (no hash maps) and lays out the payload; all threads do the canonical / consistency checks (rank sort, bsearch over per-level lists) and the copies. Several refusing threads keep the lowest rank of the host's check order (`detail_order`), so device and mirror name the same detail.
OODS design: each component part's authenticated AIR bytecode with every mask read resolved at warm to a PCS-image sample index; one thread per part computes its Horner partial (× inverse coset vanishing at the doubled point); thread 0 folds partials in order with `coeff^n_roots` and reconstructs the composition-tree value. Exact OM31 arithmetic (om31.cuh basis).

## Evidence

### Host (laptop, memguard 6 GB)
- [M] `zig build test-rv64-jobs-outer` PASS. `outer_encode.zig`: mirror == transliterated reference assembler + wire writer on 160 random class shapes (1–4 trees, 1–12 columns, fold 1–4, heavy query duplication, envelope on/off); the bound holds; capacity refusal; 13 negative cases (one per detail) — the reference refuses the image-side ones too; descriptor refusals. `outer_device.zig`: descriptor sets the slab bound; invalid descriptor refused. `outer_encode_oods.zig`: builder relocation + bounds validation.

### Pod, outer-job fixture node (one 5090; `rv64-m8-outer-job-fixture`, 4 runs = direct, captured, rebound + 4 concurrent lanes)
- [M] device bytes == host mirror bytes == host `wire.encode` bytes: 8/8 node proofs, 631,024 B, sha256 6560a41d5fb0e9e9….
- [M] encoder GPU time (CUDA events around the launch): 2.91–2.98 ms per node. Host mirror (diagnostic only): 0.79–0.98 ms.
- [M] OODS check: values identical to `assemble` 8/8; 11 parts; GPU time 1.31–1.35 ms per node.
- [M] negatives: encode fault → `node_pcs_status` 0x03040008 (noncanonical), `encode_bounds` 0x01040002, node refused (`OuterDeviceEncodeRejected`); OODS fault → 0x03030004 (mismatch), node refused (`OuterDeviceOodsRejected`).
- Artifacts: `/workspace/m3/runs/m8-gpu-r-node/fx1`, `fx3` (addon sha256 dc7b9ee3…bf39 `jobs-addon-d3`, fixture sha256 d9d3cd5e…f646).

### Gates
- [M] `rv64_gate.sh --stream m8-gpu-r-node` default 26235156 at c25698ca5: **PASS** (`/workspace/m3/runs/m8-gpu-r-node/g2/gate-d-26235156`).
- [M] Check-mode arms (`STWO_RV64_M8_OUTER_JOBS=1 OUTER_DEVICE_CHECKS=1 OUTER_DEVICE_ENCODE=check`, addon `jobs-addon-d3`), full gate (build, unit, cold+warm small-block proofs vs the frozen D2 golden, fresh CPU receivers, corpus):
  - 26235156 **PASS**: device-encoded node proofs byte-identical to the host bytes 15/15 cold + 15/15 warm; device OODS values identical 15/15 + 15/15.
  - 24628607 **PASS**: 19/19 + 19/19 byte-identical; OODS 19/19 + 19/19.
- [M] Negative arms on 26235156 node 4 (gate FAILS as intended): encode fault → `node_pcs_status` 0x03040008 / `encode_bounds` 0x01040002, `OuterDeviceEncodeRejected`; OODS fault → `node_oods_constraint` 0x03030004, `OuterDeviceOodsRejected`.
- [M] Warm request GPU time of the new kernels (CUDA events, summed over nodes): 26235156 encoder 54.9 ms + OODS 20.5 ms vs node bodies 5.26 s; 24628607 encoder 69.4 ms + OODS 25.9 ms vs 6.51 s (≈1.4 % of node GPU time [D]).
- [M] Host time the device pieces make removable on the GPU-native path (warm, summed over nodes, lanes overlap): decode 0.14 / 0.09 s, assemble 0.29 / 0.23 s (26235156 / 24628607). Still on the host in this hybrid path: prestage 2.79 / 2.93 s, init 7.41 / 6.42 s (CLASS_PLAN off: see below), stage 1.70 / 1.77 s, enqueue 1.63 / 2.08 s, wait 4.02 / 4.92 s.
- [M] Graph cache: 0 of 68 node bodies replayed (all `direct`, 489–1359 launches per node). Body launch counts of the same node differ between the cold and the warm request: the leaf/fold verifier topology depends on the child proof (data-dependent decommitments), so a per-class captured graph needs a class-fixed topology first (seed program, design §3.3).
- Not this stream's code, found by these runs (reported in M8-INTERFACES.md): `STWO_RV64_M8_NATIVE_JOBS=1` OOMs on 26235156 (native hybrid truth stage two); `STWO_RV64_M8_OUTER_CLASS_PLAN=1` fails every node on 24628607 with `OuterClassPlanAllocatorMismatch`. The arms run without both.
- Machine-readable: `gates.json`, `summary-e-26235156.json`, `summary-e-24628607.json` (from `scripts/rv64_m8_rnode_summary.py`).

## Not landed (remaining in this piece)
See the stream's final report (remaining_host_work). In short: the GPU-native `RecursionFactory.node` job still fails closed — it needs the device seed fill from the children's encoded slab regions and the device statement/FIXED mix (H16, H17, H19), which nothing on this branch provides yet; `seed_tape`, `child_binding` and `channel_order` node checks depend on it. Whole-node graphs are still captured on the second sighting inside requests (outer_graph_cache threshold), not at warm.

## Review 1 (r-node: byte identity, device gating, lifetimes, remaining host work)

Every finding was checked against the code. Confirmed findings were fixed in `c1ff3f2e4`.

| # | finding | disposition |
|---|---|---|
| R1 | Two host acceptance checks of an outer node had no device form. The first is `InvalidOm31DeviceFixedRoot`: the FIXED root the node commits and mixes into its transcript must equal the class root. The encoder compared only the image tree-0 root with the class root, so a GPU-native publication gated only on status words could ship a proof whose transcript mixed a different FIXED root. | **fixed**: descriptor `flag_fixed_root`. `node_pcs_status` requires expected root 0 == class root (detail `root`), and `EncodedNode` passes the section `fixed_root` when the node commits FIXED itself. Mirror and kernel apply the same rule; host test refuses the mismatch. |
| R2 | The second host-only check is `InvalidOuterOodsPoint`: the native_pcs OODS point status word must be 0. `node_oods_constraint` read only x/y. | **fixed**: the kernel reads the 33-word field and refuses a nonzero status (detail `point`, 0x03030005). Custody range 16 → 33 words. New two-key negative `STWO_RV64_M8_OUTER_OODS_POINT_FAULT_ORDINAL`. |
| R3 | `EncodedNode.finish` ran the host reference (`inner.finish`) before reading the device verdicts. A fault both sides catch (e.g. the point status) was reported as the host's refusal, and the device verdict was never shown. | **fixed**: device verdicts first (encode, then OODS), then `inner.finish`, as `outer_job.finish` does for `lookup_sum`. |
| — | Class bounds (`bounds`): payload, ops and scratch are worst case for every walk (`levelBound`, `n_reps ≤ q`, `fn·slots ≤ q·slots`). Every kernel exit writes both status words and the length word last. The request-slab words start `unset` (driver memset), so a check that never runs fails closed. | verified, no change |
| — | Stream order: encoder and OODS check run on the lane exec stream after the body, before the single slab D2H. Event timing resolves in finish (no added sync). The transcript is not touched (pure re-layout). The fault knobs are two-key. | verified, no change |
| — | The OODS kernel does not re-check sample canonicity; it relies on `node_pcs_status` over the same image. | by design: publish must require both words (the slab layout already lists both) |
| — | The kernel does not re-validate `logs[c] ≤ tree_log` in the descriptor. The descriptor is host-built at warm (`buildDescriptor` enforces it) and content-keyed. | accepted (trusted class product) |

Remaining host work (not fixed here): in check mode `EncodeCheck.init` rebuilds the descriptor and `oodsProgram` (an `Outer.prove.bind` of every component) **per node**. On the GPU-native path both must be warm class products (`ClassInfo.encode_descriptor` + program), built once. The host mirror and `wire.encode` compare are check-mode diagnostics only. `RecursionFactory.node` still fails closed (seed fill / statement mix H16/H17/H19), and whole-node graphs need a class-fixed topology.

Re-test at `c1ff3f2e4` (addon `jobs-addon-rev1`, sha256 0fe8e3c1…2f38; `gates.json` `review1`):
- [M] Check-mode arms PASS. 26235156: 30/30 device-encoded node proofs byte-identical to the host bytes, and 30/30 OODS values identical. 24628607: 38/38 and 38/38. The default gate on 26235156 also PASSes.
- [M] Negative arms fail closed with the device verdict:
  - point-status fault → `node_oods_constraint` 0x03030005;
  - sample fault → 0x03030004;
  - PCS image fault → `node_pcs_status` 0x03040008 / `encode_bounds` 0x01040002.
- The FIXED-root rule is covered by the host mirror test. No gate arm exercises an in-node FIXED commit with a corrupted section root.

Recursion-stream gates `rec-gates2` (`/workspace/m3/runs/m8-gpu-recursion/g2`, read only; not restarted):
- the default arm d-26235156 PASSes;
- c-*, j-* and f-26235156-4 fail with `OuterClassPlanAllocatorMismatch` (STWO_RV64_M8_OUTER_CLASS_PLAN=1);
- b-24628607 fails with `CudaAllocationFailed` in native hybrid truth stage two (STWO_RV64_M8_NATIVE_JOBS=1).

These are the same two open issues listed above.
