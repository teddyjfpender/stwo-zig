<div align="center">

# Stwo Zig

**A high-performance Zig implementation of the Stwo prover and verifier.**

Protocol parity with Rust. Portable CPU execution. Resident GPU proving on Metal.

[![CI](https://github.com/teddyjfpender/stwo-zig/actions/workflows/ci.yml/badge.svg)](https://github.com/teddyjfpender/stwo-zig/actions/workflows/ci.yml)
[![Benchmark Pages](https://github.com/teddyjfpender/stwo-zig/actions/workflows/benchmark-pages.yml/badge.svg)](https://github.com/teddyjfpender/stwo-zig/actions/workflows/benchmark-pages.yml)
[![Zig 0.15.x](https://img.shields.io/badge/Zig-0.15.x-F7A41D?logo=zig&logoColor=white)](https://ziglang.org/)
![Backends: CPU and Metal](https://img.shields.io/badge/backends-CPU_%7C_Metal-2563EB)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-0F766E)](LICENSE)

</div>

---

`stwo-zig` is a parity-first port of [StarkWare's Stwo](https://github.com/starkware-libs/stwo).
It brings Stwo's circle-STARK protocol to Zig while making memory, vectorization, and device
execution explicit. The result is one proving stack: pure Stwo with native examples,
an official-oracle-gated Cairo CPU frontend, and independently owned GPU products.

> [!IMPORTANT]
> The [pin ledger](conformance/upstream.md) names a separate authority for each
> frontend. Native proofs use pinned Rust Stwo; RISC-V decode and retirement use
> pinned Sail, with Spike and the architectural tests as independent checks.

## Backends

| Backend | Execution model | Focus |
| :--- | :--- | :--- |
| **Zig CPU / SIMD** | Portable scalar backend with hardware-native SIMD hot paths | Predictable execution and broad compatibility |
| **Metal** | Persistent resident runtime for Apple GPUs | Device-only production proofs with exact runtime identity |
| **CUDA** | Unavailable product descriptors only | No release-gated implementation or implicit selection |

## Frontends

| Surface | Current status |
| :--- | :--- |
| **Native Stwo** | Blake, Poseidon, Plonk, state-machine, wide-Fibonacci, and XOR AIRs |
| **Cairo** | Official Stwo-Cairo `1.2.2` CPU/SIMD and authenticated Metal proofs, compiled JSON and Cairo 2.20 executable execution |
| **RISC-V** | Release-gated Sail RV32IM zkVM frontend with sharded AIR components, CPU/SIMD and Metal proving, independent verification, and pinned formal evidence |

## Quick Start

Requires **Zig 0.15.x** and **Python 3**. Rust parity tooling uses
`nightly-2025-07-14`.

```sh
zig build test-stwo-core -Doptimize=ReleaseFast
zig build test-stwo-prover -Doptimize=ReleaseFast
zig build test-native-cpu-product -Doptimize=ReleaseFast
zig build test-native-metal -Doptimize=ReleaseFast  # macOS with Metal
```

### Product support

| Product | Host | State |
| :--- | :--- | :--- |
| `stwo-core` / `stwo-prover` | Zig-supported hosts | Released focused libraries |
| `stwo-native-cpu` | Zig-supported hosts | Released CPU/SIMD CLI |
| `stwo-native-metal` | macOS with Apple Metal | Parity-gated, source-JIT, device-only CLI |
| `stwo-zig` | Zig-supported hosts | Released CPU aggregate; Metal only with `-Daggregate-metal=true` on macOS |
| `stwo-zig-riscv-cpu` | Native host; static x86_64 Linux artifact | Release-gated RV32IM prove, verify, and benchmark CLI |
| `stwo-zig-riscv-metal` | macOS with Apple Metal | Parity-gated, device-only RV32IM prove-and-verify CLI |
| `stwo-cairo-cpu` | Zig-supported hosts with Rust build tooling | Released CPU/SIMD CLI; complete admitted corpus accepted by official Rust |
| `stwo-cairo-metal` | macOS with Apple Metal | Parity-gated authenticated-AOT CLI; exact CPU parity, zero-fallback telemetry, and official Rust acceptance across the release corpus |
| CUDA products | No production host | Explicitly unavailable; no fallback or placeholder execution |

The checked four-PIE Cairo coverage record is proof-independent: PIE bytes
select decoding and component coverage only, never component semantics or
correctness authority. Validate its source reconciliation with
`python3 scripts/cairo_four_pie_source_coverage.py check-record`; add
`--require-coverage-ready` to fail on every recorded source-coverage blocker.
Source-semantic packs themselves are generated separately with
`scripts/generate_cairo_source_semantic_pack.py` from an authenticated checkout.

Library consumers can select the smallest public module they need:

| Import | Contract |
| :--- | :--- |
| `stwo_core` | Fields, circle domains, transcript, proof types, and verification |
| `stwo_prover` | `core`, backend contracts, and the backend-generic prover |
| `stwo` | Aggregate compatibility SDK |

```zig
const stwo_zig = b.dependency("stwo_zig", .{ .target = target, .optimize = optimize });
root.addImport("stwo_core", stwo_zig.module("stwo_core"));
root.addImport("stwo_prover", stwo_zig.module("stwo_prover"));
```

`zig build stwo-core` and `zig build stwo-prover` compile the focused library
surfaces without installing unrelated executables. Their corresponding
`test-stwo-*` steps include transitive purity and external-consumer gates.

The root build is a compatibility dispatcher. Product construction lives under
`build_support/products/`, backend integration under `build_support/backends/`,
benchmarks under `build_support/benchmarks/`, and policy under
`build_support/gates/`. The default install contains only the CPU aggregate CLI;
Metal enters that aggregate only with `-Daggregate-metal=true`. Machine-readable
build contracts are available through `product-matrix-identity`,
`identity-stwo-{core,prover,zig}`, and `build-configure-closure`.

### Package owner guides

Every first-party package has an owner guide tied to its machine-readable
contract. Start with the smallest package that owns the behavior being changed:

| Layer | Package guides |
| :--- | :--- |
| Protocol and contracts | [`stwo_core`](src/core/README.md), [`stwo_backend_contracts`](src/backend/README.md), [`stwo_prover_api`](src/prover_api/README.md), [`stwo_prover_engine`](src/prover/README.md), [`stwo_proof_wire`](src/interop/proof_wire/README.md) |
| Backends | [`stwo_cpu_backend`](src/backends/cpu_scalar/README.md), [`stwo_metal_backend`](src/backends/metal/README.md), [`stwo_cuda_backend`](src/backends/cuda/README.md) |
| Frontends and services | [`stwo_riscv_frontend`](src/frontends/riscv/README.md), [`stwo_cairo_frontend`](src/frontends/cairo/README.md), [`stwo_native_examples`](src/examples/README.md), [`stwo_metal_session`](src/tools/metal_session/README.md) |
| CPU integrations | [`stwo_riscv_cpu_integration`](src/integrations/riscv_cpu/README.md), [`stwo_cairo_cpu_integration`](src/integrations/cairo_cpu/README.md) |
| Metal integrations | [`stwo_riscv_metal_integration`](src/integrations/riscv_metal/README.md), [`stwo_cairo_metal_integration`](src/integrations/cairo_metal/README.md) |
| CUDA integrations | [`stwo_native_cuda_integration`](src/integrations/native_cuda/README.md), [`stwo_cairo_cuda_integration`](src/integrations/cairo_cuda/README.md) |

The workspace checker rejects a missing or contract-stale package README. The
[two-pass documentation review](conformance/2026-07-28-package-readme-review.md)
records the technical and editorial acceptance criteria.

## Prove

Build the focused CPU product, produce one self-verified proof, then verify its
versioned Rust-compatible artifact in a separate invocation:

```sh
zig build stwo-native-cpu -Doptimize=ReleaseFast

zig-out/bin/stwo-zig-native-cpu prove \
  --example xor --log-size 12 --protocol secure \
  --proof-artifact-out proof.json

zig-out/bin/stwo-zig-native-cpu verify \
  --artifact proof.json --protocol secure
```

`bench` uses the same proving transaction and verifies every warmup and timed
sample. `stwo-zig-native-metal` admits only its exact source-JIT identity and
fails rather than entering a CPU commitment path. Run `applications` on any
CLI for its compiled capability registry.

Native workloads default to the conservative `standard` resource profile
(2^25 committed cells, 512 MiB admission-accounted memory). Large evidence is
an explicit opt-in: pass `--resource-profile large` to admit at most 2^27
committed cells and 2 GiB accounted memory. The large profile admits wide
Fibonacci `--log-n-rows 20 --sequence-len 100`, but still rejects log22 x100
and maximum-width shapes. Report schema v7 records the selected profile,
checked geometry, accounting factor, and both budgets so benchmark evidence is
independently auditable.

## Cairo frontend

The focused CPU product accepts an official `ProverInput`, a compiled Cairo
JSON program, or a modern Cairo 2.20 executable. Its adjacent identity-bound
Cairo VM adapter executes programs under `all_cairo_stwo`; Zig owns every
proving and verification stage.

```sh
zig build stwo-cairo-cpu -Doptimize=ReleaseFast

zig-out/bin/stwo-cairo-cpu run-and-prove \
  --program program.executable.json \
  --program-type executable \
  --arguments arguments.json \
  --proof proof.json \
  --verify
```

Run `zig build test-cairo-cpu-oracle -Doptimize=ReleaseFast` to replay the
serial corpus and require acceptance from the exact official Rust
`verify_cairo`.

The focused Metal product admits only an authenticated offline core library.
On a full-Xcode host the build produces, probes, retains, installs, and consumes
that bundle automatically:

```sh
zig build stwo-cairo-metal -Doptimize=ReleaseFast
zig build test-cairo-metal-oracle -Doptimize=ReleaseFast
```

Another macOS host can consume the retained directory without installing
Xcode:

```sh
zig build stwo-cairo-metal -Doptimize=ReleaseFast \
  -Dmetal-core-aot-bundle=/absolute/path/to/native-metal-core-aot
```

The bundle path is not trusted. Its canonical manifest digest is embedded in
the product identity, and runtime admission remeasures the manifest, shader
library, ABI, exports, and compiler artifacts before creating the Metal
runtime. The serial Metal oracle gate covers both official inputs, all released
proof transports, the builtin/opcode program corpus, and a Cairo 2.20
executable. Focused product tests additionally require deterministic
missing-device failure, repeated authenticated sessions, allocation rollback,
and resident-buffer-safe teardown.

## RISC-V frontend

The release-gated frontend accepts an `rv32im-zkvm-v1` ELF, executes it, builds
the sharded witness, proves it through the same PCS/FRI core, self-verifies
before publication, and emits a bounded schema-v3 artifact. A separate process
must verify that artifact against a caller-supplied expected-statement digest.
The exact pinned [Sail RISC-V model](https://github.com/riscv/sail-riscv) is the
semantic authority; Spike is an independent executor and Stark-V is retained
only as legacy proof-layout provenance. Published artifacts carry the immutable
`release_gated` status.

```sh
zig build stwo-zig -Doptimize=ReleaseFast

zig-out/bin/stwo-zig prove \
  --elf vectors/riscv_elfs/branch_fib.elf \
  --backend cpu --protocol functional \
  --output riscv-proof.json --report-out riscv-report.json

STATEMENT_DIGEST=$(python3 -c \
  'import json; print(json.load(open("riscv-report.json"))["statement_sha256"])')
zig-out/bin/stwo-zig verify \
  --artifact riscv-proof.json --protocol functional \
  --expect-statement-digest "$STATEMENT_DIGEST"
```

`functional` is the fast development profile. Use `secure` when collecting release evidence.

```sh
zig build test-riscv -Doptimize=ReleaseFast         # runner + trace suites
zig build test-riscv-prover -Doptimize=ReleaseFast  # prove + verify roundtrips
zig build test-riscv-metal -Doptimize=ReleaseFast   # macOS, no CPU fallback
zig build riscv-bench -Doptimize=ReleaseFast        # CPU benchmark CLI
zig build riscv-metal-bench -Doptimize=ReleaseFast  # Metal commitments CLI (macOS)
zig build riscv-trace-dump -Doptimize=ReleaseFast   # trace dumper for equivalence runs

python3 scripts/riscv_formal_tools.py verify \
  --workspace /tmp/stwo-riscv-formal
python3 scripts/riscv_trace_vectors.py \
  --sail-bin /tmp/stwo-riscv-formal/source/sail-riscv/build/c_emulator/sail_riscv_sim \
  --spike-bin /tmp/stwo-riscv-formal/install/spike/bin/spike
```

Run the same standard gate used by hosted CI:

```sh
python3 scripts/ci.py
```

For release evidence, use `python3 scripts/ci.py --strict`. Enable the versioned fast pre-commit
and product-scoped pre-push checks once per checkout with:

```sh
python3 scripts/install_hooks.py
```

## Explore

| | |
| :--- | :--- |
| **[Conformance](conformance/upstream.md)** | Pinned oracle revisions, API parity ledger, and the source-conformance baseline |
| **[RISC-V release goal](conformance/2026-07-18-riscv-release-goal.md)** | Executable checkpoints, evidence requirements, and the fail-closed promotion contract |
| **[Autoresearch](autoresearch/README.md)** | The stwo-perf harness: judged scoring, submissions, ledger, and site feed |
| **[Benchmark dashboard](bench/README.md)** | Formal CPU/SIMD and Metal results with commit, machine, capture time, and oracle provenance |
| **[Benchmark history](vectors/reports/benchmark_history/index.json)** | Immutable judged runs, deltas, and bundles under human-readable run ids |
| **Design archive** | Prose architecture and history live in the sibling `stwo-zig-og-docs` directory |
| **[Contributing](CONTRIBUTING.md)** | Zig, SIMD, Metal, correctness, and engineering standards |

The compatibility target is pinned to upstream commit
[`a8fcf4bd`](https://github.com/starkware-libs/stwo/commit/a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2).
Claims of equivalence apply to that revision and the committed conformance matrices.

## License

Licensed under [Apache 2.0](LICENSE), matching upstream Stwo.
