# Ethereum block experiment archive

The block-v5 Ethereum proof architecture is preserved at
`archive/riscv-ethereum-block-v5-20261006` (commit `f374b1db6`). This includes
its block producer, provider/planning variants, Stage101 experiments, and
their historical build commands. The current main-facing RISC-V product no
longer exposes `riscv-ethereum-block-proof` or compiles those variants.

The retained RISC-V path is typed RV32IM execution, native CPU and Metal
proving, the canonical CSP guest/precompile benchmarks, shared SHA-256,
Keccak-f and secp256k1 precompiles, and the detached SegmentV2 leaf/parent
protocol. The CSP guest's Ethereum proof artifact is still supported; it is
not a whole-block proof. Detached SegmentV2 demonstrates bounded execution
and recursive aggregation. It does not establish complete block memory,
ROM, lookup or provider closure.

The active qualification gates are described in the CPU and Metal integration
READMEs. A two-segment detached CPU tree can be run with
`scripts/riscv_segment_v2_detached_tree_gate.py` and the pinned
`vectors/reports/recursive-product-20260918/canonical-ladder-2-v1/admission.json`.
The gate produces and independently verifies both leaves and their parent.
The repository's CSP fixture root is `vectors/riscv_csp`.
