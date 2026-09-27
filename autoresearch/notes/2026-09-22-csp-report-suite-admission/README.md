# CSP report suite admission

2026-09-22. Benchmark and fresh-verification reports use schema v2 and an explicit
suite/version/hex-digest transcript receipt. Reader validates the receipt shape,
artifact version/hasher tuple and fresh verifier equality, and carries suite and
artifact version into retained rows. Old report schemas reject instead of acquiring
an inferred suite. Protocol types and production defaults remain unchanged.

101 focused Python reader, wiring and provenance tests pass. ReleaseFast CPU
product build passed. A real canonical 70-query/26-PoW-bit ECDSA precompile CLI
proof and separate verification produced identical v1/BLAKE2s transcript receipts.
Proving measured 0.798874416 s, execution 0.001829334 s, verification 0.146700416 s.
This is one dirty-worktree qualification sample, not a full-suite result. The
CLI JSON digest was checked as a 64-character string. CPU production still selects
BLAKE2s; BLAKE3 product default and Metal remain pending.

Commands: `python3 -m unittest scripts.tests.test_riscv_csp_precompile
scripts.tests.test_riscv_csp_benchmark scripts.tests.test_riscv_csp_benchmark_wiring
scripts.tests.test_riscv_csp_benchmark_provenance`; `python3
scripts/zig_serial_build.py stwo-zig-riscv-cpu -Doptimize=ReleaseFast --summary all`.
CLI used ecdsa-csp-bench (warmups 0, samples 1, workers 16) and ecdsa-csp-verify
with the manifest-selected ELF and canonical input. Reports/logs/source snapshots
are retained here; proof remains in the temporary run directory identified below.
/var/folders/b6/t439mlp94rj6rzwbkbyrl5qc0000gn/T/stwo-csp-report-v2-3tmaog8_
