# Circuit recursion on Metal

`stwo-circuit-recursion-metal` proves Cairo leaves and recursive circuit folds
with the Metal integrations. It shares the CPU product's `leaf-wrap`, `prove-cairo`,
`fold-tree`, `fold-stage`, `fold-stage-campaign`, `fold-stage-root`,
`circuit-params`, and `verify` commands and proof formats. The
[CPU product guide](../circuit_recursion_cpu/README.md) documents the common
CLI, manifests, and output files; the
[Metal integration guide](../../integrations/circuit_metal/README.md) documents
device admission and focused tests.

The Cairo input reader accepts official adapted JSON or lossless compact CPI.
The pinned `proving@5a7c5ed` circuit protocol commits some trees above their
largest column; the Metal backend re-commits resident trees at the required
height before mixing their roots. Small trees use the integration's declared
host commitment path. This is a hybrid execution policy within one canonical
proof protocol, not a separate Metal proof format.

## Build and run

Build on macOS with the Apple Metal SDK, from the repository root:

```sh
zig build --build-file src/integrations/circuit_metal/build.zig \
  -Doptimize=ReleaseFast
```

The package build installs
`src/integrations/circuit_metal/zig-out/bin/stwo-circuit-recursion-metal`.
Use the [Starknet block collector](../../../tools/starknet-block-collector/README.md)
with `circuit_pipeline.py --backend metal` for a continuous PIE sequence. The
collector authenticates inputs, records adaptation and proving stages, and
checks the resulting root against the pinned Rust reducer when requested.
Run focused Metal parity checks through the
[integration build](../../integrations/circuit_metal/README.md#build-test-and-run)
before publishing a new result.

## Retained two-PIE qualification

On an M5 Max on 30 September 2026, two consecutive mainnet PIEs for blocks
15,627,902–907 reached one root in **75.98 s** of serial wall time, including
adaptation, two Cairo proofs, two circuit wraps, and one fold. The three root
files were byte-identical to the pinned Rust reducer; Metal leaf and root
proofs were byte-identical to the CPU run. Of 79 Cairo composition components,
70 ran on Metal and nine used the declared host path; all 11 circuit
composition components ran on Metal. macOS `time -l` recorded a **34.75 GB**
process-memory footprint including unified GPU allocations, which must not be
confused with the smaller peak RSS.

A fresh run on 1 October reused those adapted inputs and passed the retained
digest gate. It took **72.828 s** from driver input handling to the root file.
These are individual runs, not latency percentiles or whole-block proof
measurements. The [collector receipt and phase breakdown](../../../tools/starknet-block-collector/README.md#two-leaf-circuit-root-on-m5-max)
provide the inputs, security settings, timing boundaries, and remaining
aggregator limitation.
