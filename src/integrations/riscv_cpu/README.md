# RISC-V CPU integration

This package binds the backend-neutral typed RV32IM frontend to the CPU prover engine. The RISC-V runner, witness, AIR, and statement rules remain owned by `src/frontends/riscv`; this package selects the CPU backend and supplies the proof adapter used by the released CPU product and CSP benchmarks.

The public module is [`mod.zig`](mod.zig). Its supported surface consists of `CpuProverEngine`, native proof and verification entry points, the Poseidon2 guest profile, the CSP-compatible Ethereum guest proof artifact, and the generic recursive FRI outer verifier. The Ethereum guest profile remains because CSP ECDSA uses it. It is distinct from the archived Ethereum **block** proving experiment.

The CPU package also builds four detached SegmentV2 tools. They prove and verify bounded execution leaves and parent nodes; they do not claim whole-block memory/provider closure:

```sh
cd src/integrations/riscv_cpu
zig build build-recursive-segment-v2-detached-verifier \
  build-recursive-segment-v2-detached-parent-verifier \
  build-recursive-segment-v2-detached-leaf-producer \
  build-recursive-segment-v2-detached-parent-producer \
  -Doptimize=ReleaseSafe
```

Run `zig build test -Doptimize=ReleaseSafe` for package contracts and the retained detached-protocol tests. The genuine child-capture test additionally requires `STWO_SEGMENT_V2_CHILD_BUNDLE`, `STWO_SEGMENT_V2_CHILD_KEY_SHA256`, and `STWO_SEGMENT_V2_CHILD_EXPECTED_WIRE` pointing to the admitted fixture. Focused proof/verify checks are `test-secp256k1-precompile-proof` (set `STWO_CSP_FIXTURE_ROOT` to the absolute `vectors/riscv_csp` directory), `test-segment-v2-native-proof`, and `test-universal-typed-proof`. Use [`scripts/riscv_recursive_product.py`](../../../scripts/riscv_recursive_product.py) for the end-to-end 1/2/4/8-segment development gate. The released CPU product and CSP benchmark route build from the repository root with `zig build stwo-zig-riscv-cpu` and `zig build riscv-csp-bench`.

The former Ethereum block-v5 architecture, provider experiments, and their build commands are preserved at `archive/riscv-ethereum-block-v5-20261006` (commit `f374b1db6`), rather than part of the supported package. A future block pipeline must define and verify its complete block statement, including memory and provider closure, before it is exposed here.


The experimental concrete [`rv64`](rv64.zig) API proves bounded RV64IM execution
with verifier-owned program/state, local register consistency and authenticated
RAM transitions in one STARK. `prove` builds the witness once; `provePrepared`
accepts untrusted prepared rows. `verifyOwned` consumes a proof on every path.
For repeated verification, retain `PreparedSetup`, independently derived from
expected program/path/final-PC bytes; request state and transcript stay fresh.
Run `zig build test-riscv64-air test-riscv64-proof -Doptimize=ReleaseSafe` from
the repository root. This separate bounded profile is not the released ELF/CSP
or OP guest proof route. See [the AIR contract](../../../design/riscv-proving-stack/rv64-air.md).

The experimental [`rv64_full`](rv64_full.zig) API admits one complete execution
in one shared PCS/composition/FRI proof. Its immutable program ROM and byte/AND/
shift tables have independent heights. `PreparedSetup` separates program-derived
ROM from geometry-specific fixed roots; callers retain it across verification
requests. Statements bind the complete initial/final state, permissions, clocks
and admitted opcode set. The AIR forbids opcodes outside that set and closes
all state and lookup claims. `proveTrace` consumes physical column storage after
commitment, allowing the capture journal to be freed first. The CSP tools verify
separately against an independently checked ELF/input/output contract; a producer's
statement file alone is not application authority. This remains an experimental
profile, separate from the bounded `rv64` format and the Rust five-opcode fixture.

Build `rv64-csp-full` and `rv64-full-verify` with
`zig build rv64-csp-full rv64-full-verify -Doptimize=ReleaseFast`. Run the complete benchmark with
`scripts/riscv64_csp_full_proofs.py`, supplying `--execution-report`, `--work-dir`
and `--report`; `--prover` and `--verifier` allow immutable measured binaries.
`--profile-only` explicitly does not establish a proof. The driver independently
checks expected ELF/input/output authority and runs the receiver in a new process.
The [17-case comparison CSV](../../../vectors/reports/rv64-qualification-20261030/csp-full-comparison.csv)
records serial/parallel measurements; all 17 statement, claim and proof byte
streams match exactly. Focused tests are `test-riscv64-air`,
`test-riscv64-program`, `test-riscv64-program-proof`, `test-riscv64-providers`,
`test-riscv64-coset`, `test-riscv64-parallel`, `test-riscv64-full-capture` and
`test-riscv64-full-proof`.


Whole-prover profiling is enabled with `--profile-stages` in the CSP driver.
It uses the shared stage recorder without task/work capture and preserves the
exact transcript and proof. The [performance comparison](../../../vectors/reports/rv64-performance-20261030/comparison.csv)
records all 17 cases, checked against equal input, geometry, security, worker
count and serialized proof bytes. Full ECDSA now takes approximately 21 seconds
end to end on the measured host. See the [study](../../../vectors/reports/rv64-performance-20261030/README.md)
for attribution, repeat ranges and the remaining constraint-row cost.

The [second performance round](../../../vectors/reports/rv64-performance-round2-20261030/README.md)
retains universal memory-polynomial factoring and an owned main-witness handoff
to PCS. All 17 statements, claims and proofs remain byte-identical. ECDSA takes
about 19.6 seconds in the matched suite; composition still sets the 12.78 GiB
caller peak. Rejected scheduling/zero-shortcut experiments are documented.
