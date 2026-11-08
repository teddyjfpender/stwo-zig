# Design documents

`design/` holds documentation only. Nothing here is a build input, a runtime
preset or a machine-read pin; those live in `src/`, `conformance/` and
`vectors/`.

| Directory | Contents |
|---|---|
| [`repository/`](repository/) | Repository structure, restructuring plan, production scope, package release policy |
| [`riscv/`](riscv/) | RISC-V / RV64 proving stack: AIR, services, recursion, CUDA and the current M8/M9 work. Start at [`rv64-gpu-hygiene.md`](riscv/rv64-gpu-hygiene.md), [`rv64-m9-plan.md`](riscv/rv64-m9-plan.md) and [`rv64-archive-index.md`](riscv/rv64-archive-index.md) |
| [`starknet/`](starknet/) | Starknet proving pipeline and circuit recursion design |
| [`typed-air/`](typed-air/) | Typed-AIR language: charter, IR, soundness, validation and numbered decisions |
| [`soundness/`](soundness/) | Soundness contracts, verification status and the evidence roadmap |
| [`decisions/`](decisions/) | Dated repository-level goals, amendments and audits that still bind current work |

## Moved out of `design/`

| Former path | Current path |
|---|---|
| `design/typed-air/artifacts/` | `src/frontends/riscv/air/lang/artifacts/` (embedded by the riscv package) |
| `design/riscv-proving-stack/m7-handoff/*.json` | `conformance/rv64/presets/` |
| `design/typed-air/performance/m5-m9-protocol-v1.json` | `conformance/typed-air/m5-m9-protocol-v1.json` |
| `design/riscv-proving-stack/` | `design/riscv/` |
| `design/starknet-proving-pipeline/` | `design/starknet/` |
| `soundness/` | `design/soundness/` (`air-ir-v2.schema.json` → `conformance/schemas/`) |

## History

Dated receipts, superseded milestone notes (M3–M7 handoffs, gpu-2s research,
typed-AIR receipts and notes), `vectors/reports/` and `conformance/evidence/metrics-v2`
were removed from the source tree. They remain available, byte for byte, at
the archive tag
[`archive/pre-restructure-20261108`](https://github.com/teddyjfpender/stwo-zig/tree/archive/pre-restructure-20261108)
— for example
[`design/riscv-proving-stack/`](https://github.com/teddyjfpender/stwo-zig/tree/archive/pre-restructure-20261108/design/riscv-proving-stack)
and
[`vectors/reports/`](https://github.com/teddyjfpender/stwo-zig/tree/archive/pre-restructure-20261108/vectors/reports).
