# RV64 foundations and matched CSP execution

Local Apple M5 Max measurements, Zig 0.15.2 / ReleaseFast. This is execution evidence; RV64 AIR, recursion and SP1 runtime support remain unimplemented. No RV64 proving time is reported.

All 17 software cases pass on both frontends and independently in Unicorn 2.1.4, with exact agreement on outputs and instruction counts. Both ISAs use nightly-2026-03-04 and the same Rust source, dependencies and optimization flags. SHA/Keccak use a shared small runtime adapter because the upstream glue is RV32-only. These matched recompiled RV32 guests are distinguished from the committed canonical RV32 ELFs in the raw report. No precompile is enabled.

## Matched software CSP results

Ratio is RV32 instructions divided by RV64 instructions. Sizes are message bytes for SHA/Keccak, field elements for the M31 extension and 32 digest bytes for ECDSA. RV64 times are seven-sample medians of retirement plus completion detection, without a retained trace.

| Workload | Size | RV32 instructions | RV64 instructions | Ratio | RV64 execution (ms) |
| --- | ---: | ---: | ---: | ---: | ---: |
| SHA-256 | 128 | 14,060 | 14,035 | 1.002× | 0.158 |
| SHA-256 | 256 | 22,908 | 22,941 | 0.999× | 0.246 |
| SHA-256 | 512 | 40,604 | 40,753 | 0.996× | 0.414 |
| SHA-256 | 1024 | 75,996 | 76,377 | 0.995× | 0.759 |
| SHA-256 | 2048 | 146,780 | 147,625 | 0.994× | 1.436 |
| Keccak-256 | 128 | 18,629 | 8,721 | 2.136× | 0.073 |
| Keccak-256 | 256 | 36,513 | 16,671 | 2.190× | 0.139 |
| Keccak-256 | 512 | 72,205 | 32,501 | 2.222× | 0.268 |
| Keccak-256 | 1024 | 143,589 | 64,161 | 2.238× | 0.511 |
| Keccak-256 | 2048 | 286,381 | 127,510 | 2.246× | 0.975 |
| Poseidon2-M31 extension | 2 | 82,297 | 81,898 | 1.005× | 0.573 |
| Poseidon2-M31 extension | 4 | 164,403 | 163,666 | 1.005× | 1.093 |
| Poseidon2-M31 extension | 8 | 328,615 | 327,202 | 1.004× | 2.273 |
| Poseidon2-M31 extension | 12 | 492,827 | 490,738 | 1.004× | 3.410 |
| Poseidon2-M31 extension | 16 | 657,039 | 654,274 | 1.004× | 4.674 |
| secp256k1 ECDSA | 32 | 5,425,005 | 1,625,938 | 3.337× | 21.598 |
| secp256k1 ECDSA — invalid signature | 32 | 5,428,253 | 1,627,849 | 3.335× | 18.339 |

SHA-256 and this existing M31 guest gain little from XLEN=64; the M31 implementation retains its RV32-oriented limb algorithm and example permutation constants. Keccak and secp256k1 benefit from native 64-bit arithmetic. Instruction reductions do not establish proving speedups: RV64 AIR can require more work per instruction.

RV32 public-value derivation also constructs witnesses and committed trees. Its process wall time is retained in JSON for diagnostics, but is deliberately not compared against RV64 execution-only timing. Neither quiet-host admission nor a standardized CSP hardware result is claimed.

## Paired foundation kernels

Seven samples per arm, randomized paired order, identical ReleaseFast harness and checked final-state checksums. The source snapshot reconstructs the original implementation in temporary storage; generated executables are removed. Setup is outside execution/memory timers. The bulk timer includes page allocation and copying.

| Kernel | Original median (ms) | Current median (ms) | Speedup |
| --- | ---: | ---: | ---: |
| execution | 102.857 | 42.401 | 2.43× |
| memory | 371.232 | 27.434 | 13.53× |
| bulk | 5.409 | 1.338 | 4.04× |

## Validation and reproduction

- 49 focused Zig tests pass in Debug and ReleaseSafe, including RV32 decoder regressions.
- 14,815 oracle vectors cover all 63 retiring opcodes on each of the cached and uncached paths.
- Three Python tests cover ELF32/ELF64 symbol extraction and malformed header rejection.
- Allocation injection covers page inventory rollback, existing-byte preservation and exact batch retry. Warmed session execution allocates nothing.

```sh
zig build test-riscv64-execution
python3 -m unittest scripts.tests.test_riscv64_tools
/tmp/stwo-rv64-oracle-venv/bin/python scripts/riscv64_differential.py
/tmp/stwo-rv64-oracle-venv/bin/python scripts/riscv64_csp_compare.py --work-dir /tmp/stwo-rv64-csp-comparison --report /tmp/csp-execution.json --samples 7 --oracle
python3 scripts/riscv64_foundations_benchmark.py --report /tmp/paired-execution.json
```

The oracle venv requires Unicorn 2.1.4. The pinned Rust toolchain needs rust-src and cached crate dependencies. The comparison builds the tier-3 RV64IM core from source.

Raw evidence: [CSP cases](csp-execution.json), [paired kernels](paired-execution.json), [original source snapshot](baseline-source.json), [oracle vectors receipt](oracle.json). The original snapshot is diagnostic evidence, not a second production implementation.

Broader repository gates remain red on pre-existing issues: circuit provenance drift, package ownership/API findings and missing entries in the old test inventory. Source conformance retains the same 96 base errors with no new findings. The focused RV64 target and its test-count floor pass.
