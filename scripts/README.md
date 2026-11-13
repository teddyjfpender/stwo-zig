# Production automation boundary

`scripts/` contains only automation that is reachable from a current build,
installed workflow, correctness or soundness contract, release process, hook,
or production owner guide. Retained profiling helpers live under `tools/perf/`;
one-off benchmark exploration, peer comparison, and diagnostics are not kept in
the repository (the retired research tree is preserved on the
`archive/pre-restructure-20261108` branch).

## Layout

The top level holds only the developer entry points:

| Entry point | Purpose |
|---|---|
| `dev_test.py` | local developer test runner |
| `ci.py` | CI driver (`--fast` is static; `--check-toolchains` checks declarations; `--installed-toolchains cpu\|oracles\|formal` executes and fingerprints the selected installed tools) |
| `rv64_gate.sh` | RV64 / CUDA gate on the pod (implementation in `rv64/rv64_gate.py`) |
| `rv64_m8_bench15.py` | 15-block RV64 benchmark |

Everything else lives in one area package, each a Python package
(`__init__.py`) importable as `scripts.<area>.<module>`:

| Area | Contents |
|---|---|
| `architecture/` | architecture host gate, authority and receipt tooling |
| `bench/` | benchmark, profiling and performance-epoch tooling |
| `cairo/` | Cairo / Starknet proving, fixture and report tooling |
| `cuda/` | CUDA build, AOT, device smoke and product closure |
| `interop/` | Rust/Zig interop, parity and circuit-frontend harnesses |
| `metal/` | Metal AOT receipt and profile tooling |
| `native/` | Native-example proof matrix, profiling and product checks |
| `release/` | release packaging and release evidence |
| `repo/` | repository-wide CI scope, package workspace, conformance, hooks, Zig lock |
| `riscv/` | RV32IM AIR, refinement, Sail and product tooling |
| `rv64/` | RV64 / Ethereum proving, CUDA-native and measurement tooling |
| `sm83/` | SM83 frontend gates and benchmarks |
| `typed_air/` | typed-AIR performance protocol, captures and Zig lane |
| `tests/` | the Python test suite (`python3 -m pytest -q scripts/tests`) |

Toolchain declarations and artifact fingerprints live in `toolchain.json`.
Run `python3 scripts/ci.py --check-toolchains` to check all declarations, then
invoke `scripts/ci.py --installed-toolchains cpu` with the exact declared Python
to execute and fingerprint the installed Python and Zig. The `oracles` profile
also checks every declared Rust channel, component and target without selecting
a global default. `formal` checks the exact Lean and Sail tools on its declared
Linux host; it does not replace live Sail/Lean/source-binding qualification.

Missing tools fail with explicit setup recipes. Verify the pinned archive hash
before extracting Zig or Sail, and prepend an isolated directory to `PATH`.
For Python, `uv python install --no-bin <toolchain.json version>` avoids replacing
system executables; use the installed interpreter explicitly. No admission check
downloads tools or falls back to a different installed version. Archive pins and
the invoked executable fingerprints are distinct; the report does not certify
the complete dynamic-library closure or establish proof/device correctness.

Imports are always fully qualified (`from scripts.riscv import riscv_refinement`,
`from scripts.cuda.cuda_build_lib import ...`); never put an area directory on
`sys.path`. A script that is executed directly (`python3 scripts/<area>/x.py`)
puts the repository root on `sys.path` in its preamble; `python3 -m
scripts.<area>.x` works without it. Script basenames stay unique across areas.

The boundary is enforced rather than maintained by convention:

- `scripts/tests/test_script_reachability.py` rejects every unreachable
  script and any new file at the top level of `scripts/`. Historical prose is deliberately not a
  root, so a stale mention cannot keep dead automation alive.
- `scripts/tests/test_source_conformance.py` checks entrypoint size, package
  ownership, and declared dependency direction.
- `scripts/tests/test_ci_package_graph.py` and
  `scripts/tests/test_focused_ci_contract.py` require script changes to select
  bounded hosted lanes rather than the full product matrix.

Only two human-operated entrypoints are intentionally not installed as gates:
`performance_epoch_gate.py` manages authenticated performance epochs, and
`riscv_operand_classes.py` regenerates the Sail-derived operand corpus. Their
owner and purpose are declared in the reachability test.

Support packages use the `<entrypoint>_lib/` convention where practical. An
independent Rust oracle, sidecar, or fixture generator belongs in `tools/` and
must be registered in
[`conformance/tooling-surface-v1.json`](../conformance/tooling-surface-v1.json).
Retired implementations remain recoverable from Git; they are not carried as
disabled jobs, dormant parsers, or archival compatibility layers on `main`.
