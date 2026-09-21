# Canonical typed RISC-V and detached recursion

The supported route is typed RV32IM execution, native segment proof, detached
leaf proof, detached recursive parents, then standalone verification of the
serialized root. CPU and Metal select backend engines for this shared route.

## Complete-proof command

From the repository root, using Zig 0.15.2 and a new output directory:

```sh
python3 scripts/riscv_recursive_product.py --backend cpu --output /tmp/typed-cpu-new
python3 scripts/riscv_recursive_product.py --backend metal --output /tmp/typed-metal-new
```

Metal requires a physical Mac and the Xcode Metal toolchain. The command builds
matching binaries and authenticated AOT assets, checks independently pinned
admissions, produces a four-segment tree, exits the producer and verifies in
fresh processes. It also rejects malformed proofs and same-geometry statement
substitutions. `product.json` records source, binary and input hashes and results.
Do not edit source during this qualification run.

## Implementation owners

| Boundary | Owner |
| --- | --- |
| Terminal and resumable execution | Frontend `ExecutionSession` and shared statement geometry |
| Native typed infrastructure admission | `air/native_infrastructure_typed_admission.zig` in the RISC-V frontend |
| Native proof ingress | CPU integration `recursive_segment_v2_native_ingress.zig` |
| Detached leaf production | CPU integration `recursive_segment_v2_detached_leaf_producer.zig`, shared by backend runners |
| Detached parent production | Dedicated `stwo_riscv_detached_parent_producer` module |
| Shared recursion preparation and publication | RISC-V frontend `recursion/` |
| Standalone verification | Dedicated `stwo_leaf_verifier` and `stwo_parent_verifier` command modules |

The producer wrappers must not import historical proof harnesses or the broad
CPU integration namespace. Verifier dependencies exclude witness generation and
producer preparation. The product-closure checks enforce these boundaries.
Native executable specializations are admitted against typed equations; they
cannot independently define a different accepted AIR.

Terminal V1 statements bind public input/output entries. Resumable V2 statements
have a different public-data envelope over shared typed execution. These are
supported statement contracts, not competing interpreters. Historical binary-composition, temporal
and segment-outer public facades and alternative parent admission are retired.
Independent test oracles remain test-only.

## Development loop and completion evidence

Use package, import-closure and affected semantic checks while changing owners.
For VM profile identity, registry facts and admission mutations, run
`zig build test-vm-air-profile-authority-v2 --build-file src/frontends/riscv/build.zig -Doptimize=ReleaseSafe -j1`.
The broader `test-vm-air-profile-v2` additionally covers composition and provider
programs; use it when those contracts change.
For detached boundary graph inputs, identities, memory roots and clock constraints,
use `zig build test-detached-boundary --build-file src/frontends/riscv/build.zig -Doptimize=ReleaseSafe -j1`.
Run the complete-proof command after a coherent integration batch. A release
checkpoint must identify the exact qualified source and include authenticated
continuation and standalone root verification at 1/2/4/8 segments.

The [typed recursion cleanup checkpoint](../../vectors/reports/recursive-product-20260921/typed-recursion-closure-qualified-v1/README.md)
records complete-proof and continuation evidence, including legacy executor/opcode AIR retirement, test-oracle isolation,
shared commitment/session ownership and the narrow execution/host boundary.
Its frozen source passed all CPU/Metal/AOT and 1/2/4/8 gates; subsequent source
changes require their own scoped validation.
The admitted q193 profile is a development profile; Metal execution is hybrid.
Production-security qualification, strict GPU execution and Ethereum expansion
are separate work.
