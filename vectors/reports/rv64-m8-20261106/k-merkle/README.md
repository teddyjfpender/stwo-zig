# k-merkle: T6 fused-Merkle call sites, stream chunk knobs, T2 retune (M8, 2026-11-07)

Branch `codex/rv64-m8-k-merkle`. Owned product files:
`rv64/{pcs_pipeline.cuh, jobs/pcs_enqueue.cu, trace.cu, fri.cu, circuit_fill_chain.cu}`, `riscv_cuda/rv64/trace_commit.zig`.

## What changed
- **T6 call sites.** The 5 contiguous-tree layer loops call `stwo_blake2s_merkle_layers_on` (commitment/merkle.cu):
  `pcs_pipeline.cuh` and `jobs/pcs_enqueue.cu` through the shared `pcsMerkleLayers`, plus `trace.cu`, `fri.cu` and
  `trace_commit.zig` streamRoot. The binding is weak in CUDA and an optional lookup in Zig, so an image without the entry keeps the old loop.
  - `STWO_RV64_M8_MERKLE_FUSED` unset or 0 (default): the entry runs the same per-layer loop (same kernels, same launches).
  - Set to 1: fused 3-level subtrees plus one tail CTA. Every node is bit-identical.
- **T2 removed.** On the real-node replay no `chain_flow` width beats `chain_run` (table in `../T2-assignment-chain/README.md`).
  `circuit_fill_chain.cu` is back to its pre-T2 text plus the `STWO_RV64_M8_ASSIGNMENT_DUMP` diagnostic hook, and
  `STWO_RV64_M8_ASSIGNMENT_FLOW` is gone.
- **Image recipe** `compose_image.py`: the opt-combined 25d0e62f link command, with only the named TUs recompiled. The link now runs under the
  caller's build lock (it used to take build.1 inside a build.2 hold and queued behind other streams for over an hour).
  - img1 = trace, fri and pcs_native recompiled → lib 4ec3f61c.
  - img2 = img1 plus circuit_fill_chain → lib 9175bcb0 (2.06 GB; img1 deleted).

## Review findings (verified against the code)
- **Byte identity, flag off.** `stwo_blake2s_merkle_layers_on_impl` mode 0 is the callers' loop:
  - same `stwo_blake2s_layer_on_impl<true>`, same offsets `tree + off`, `tree + off + n`;
  - pow2 and null-stream refusals equal those of `layer_on`;
  - fri.cu keeps its trailing `cudaPeekAtLastError`.
- **Fused path.** It uses 16-byte `uint4` loads and stores, while the entry checks only 4-byte `Hash` alignment. Every caller's tree is a pool
  or lease base, or a 32-byte multiple past one (arena allocations are ≥ 256-byte aligned), so this is not reachable today. A misaligned
  base would raise a CUDA fault (fail closed), not wrong bytes.
- **Zig streamRoot.** It passes the lane stream exactly as the old `layer` call did. The `2 * leaves - 1` capacity argument is exactly the node range the old loop wrote (checked arithmetically only; no new custody claim).
- **jobs/pcs_enqueue.cu** compiles (ENQ_EXIT=0). Its addon image is out of scope here; the JOBS path is not default.

## Gates (rv64_gate.sh, all PASS, byte-identical to frozen D2, 2/2 fresh CPU receivers, 19-case corpus) [M]
See `gates-summary.json`.

| gate | block | image | source | env | result |
|---|---|---|---|---|---|
| gate-1 | 26235156 | img1 4ec3f61c | e86105e09 | default | PASS |
| gate-2 | 24628607 | img1 4ec3f61c | e86105e09 | MERKLE_FUSED=1, PCS/TRACE_STREAM_CHUNK_WORDS=2^28, OUTER_ASSIGNMENT_GRAPH=1 (+ assignment dump) | PASS |
| gate-3 | 24628607 | img2 9175bcb0 | f7d22ccc8 | default | PASS |
| gate-4 | 26235156 | img2 9175bcb0 | f7d22ccc8 | MERKLE_FUSED=1, chunk 2^28, OUTER_ASSIGNMENT_GRAPH=1 | PASS |
| gate-5 | 24628607 | img2 9175bcb0 | ba9757375 (rebased on integrate 786429aca) | default | PASS |

On the default runtime (25d0e62f, which already exports the T6 entry) only the Zig streamRoot change is live: with the flag unset it runs the same loop.
The CUDA call-site changes reach a runtime once an image includes them. img2 (`/workspace/m3/build/m8-k-merkle/img2/runtime.json`) is ready to adopt.

## Defaults
Not flipped. `STWO_RV64_M8_MERKLE_FUSED` and the 2^28 stream chunk words stay default-off until the canonical 3+3 shows a win.
- Presets: `ab-fused.json` and `ab-chunk.json`, both on 24628607.
- Pod run: `pipe2.sh` with `STEPS="gate5 ab"`.
- Both first attempts (pipe1, img1) were refused by the quiet admission. The pod was under sustained foreign compiles and receivers
  (load 25-47), and no timing was taken.
- Any chunk-default flip also needs the owner of `pcs_allocation_cost.zig` (`default_chunk_words`) to match it.
