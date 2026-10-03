# Circuit recursion on Metal

`stwo-circuit-recursion-metal` uses the same `leaf-wrap`, `fold-tree`,
`fold-stage`, `fold-stage-campaign`, `fold-stage-root`,
`circuit-params`, and `verify` CLI and proof formats as the CPU product. Its
leaf Cairo proof and circuit proofs use the Metal backend. Its `leaf-wrap`
input accepts official adapted JSON or lossless compact CPI through
the Cairo frontend's canonical reader. This lets a CPU preparation service
publish compact inputs once for Metal and CUDA workers.

The pinned `proving@5a7c5ed` leaf protocol commits some Merkle trees above their largest
column; the Metal backend re-commits resident trees at the explicit height on
the device before mixing their roots into the transcript. Small trees follow
its declared host commitment path.

Build on macOS from the repository root:

```sh
cd src/integrations/circuit_metal
zig build -Doptimize=ReleaseFast
```

The binary is `src/integrations/circuit_metal/zig-out/bin/stwo-circuit-recursion-metal`.
Use `tools/starknet-block-collector/circuit_pipeline.py --backend metal` to
prove a contiguous PIE sequence through one recursive root, recording per-stage
time and peak memory. The two committed mainnet PIEs for blocks 15,627,902–907
produce leaf proofs and all three root files byte-identical to CPU and pinned
Rust. See the collector's README for the full measured receipt.

On that sequence, the authenticated Cairo composition library placed 70 of 79
components on Metal; the nine missing kernels used the declared host path.
Circuit composition placed all 11 components on Metal. The `time -l` peak
memory footprint includes unified GPU memory and should be considered alongside
process RSS.
