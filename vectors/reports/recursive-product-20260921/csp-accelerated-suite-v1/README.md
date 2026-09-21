# Full CSP suite with ECDSA precompile — 2026-09-21

The ECDSA row is a **complete RISC-V guest proof**, including the typed recovery
provider, caller/memory relations, low-S and public-key checks, canonical public
input/output and successful completion. Both backend means are below one second.
It is not the older isolated-provider measurement.

| Backend | Mean prove | Median prove | Sample range | Mean verify |
| :--- | ---: | ---: | ---: | ---: |
| CPU | **881.6 ms** | 877.5 ms | 873.8–899.8 ms | 171.2 ms |
| METAL | **863.7 ms** | 862.6 ms | 855.1–880.3 ms | 100.5 ms |

Parameters: **70 FRI queries, 26 PoW bits**, log blowup 1, last-layer log degree 0,
fold step 1. Apple M5 Max, ReleaseFast, 16 workers, one warmup and ten measured
verified samples per workload/backend. Proving time includes execution, recovery
selection, witness generation and proving. Verification is separate; command
startup, artifact encoding and build time are excluded from the proving metric.
Every measured ECDSA sample independently decodes and verifies its full artifact.

Clean source snapshot: `af05b7401a7799015e76c1e35352c72d373669a7` ([snapshot provenance](snapshot.json)).
Both product identities advertise `csp-ecdsa-typed-recovery-v1` and have
`source.dirty=false`. [CPU report](cpu.json), [Metal report](metal.json).

## Complete results

All rows use the same clean implementation snapshot. ECDSA uses the authenticated
precompile guest; the remaining workloads use their canonical software guests.
Poseidon2-M31 is the documented field-native extension, not upstream BN254 Poseidon2.

| Workload / size | CPU prove (s) | Metal prove (s) | CPU verify (s) | Metal verify (s) | Proof (KiB) | CPU peak (GiB) | Metal peak (GiB) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| sha256 / 128 | 0.776 | 0.442 | 0.127 | 0.104 | 816.9 | 1.29 | 1.85 |
| sha256 / 256 | 0.697 | 0.447 | 0.134 | 0.105 | 825.9 | 1.28 | 1.84 |
| sha256 / 512 | 0.603 | 0.456 | 0.141 | 0.110 | 820.1 | 1.31 | 1.87 |
| sha256 / 1024 | 0.698 | 0.457 | 0.139 | 0.107 | 818.2 | 1.36 | 1.89 |
| sha256 / 2048 | 0.672 | 0.460 | 0.145 | 0.106 | 836.4 | 1.45 | 1.91 |
| keccak / 128 | 0.541 | 0.415 | 0.138 | 0.103 | 820.0 | 1.29 | 1.86 |
| keccak / 256 | 0.614 | 0.424 | 0.146 | 0.104 | 820.4 | 1.30 | 1.85 |
| keccak / 512 | 0.591 | 0.432 | 0.142 | 0.104 | 822.2 | 1.36 | 1.86 |
| keccak / 1024 | 0.633 | 0.442 | 0.147 | 0.100 | 818.4 | 1.42 | 1.92 |
| keccak / 2048 | 0.796 | 0.484 | 0.150 | 0.101 | 871.9 | 1.65 | 2.00 |
| poseidon2_m31 / 2 | 0.617 | 0.511 | 0.148 | 0.101 | 849.6 | 1.32 | 1.63 |
| poseidon2_m31 / 4 | 0.680 | 0.539 | 0.152 | 0.101 | 870.8 | 1.38 | 1.68 |
| poseidon2_m31 / 8 | 0.969 | 0.530 | 0.149 | 0.101 | 910.6 | 1.61 | 1.77 |
| poseidon2_m31 / 12 | 0.805 | 0.556 | 0.171 | 0.107 | 982.1 | 1.77 | 1.82 |
| poseidon2_m31 / 16 | 1.260 | 0.590 | 0.160 | 0.106 | 1068.8 | 2.01 | 1.91 |
| ECDSA (precompile) / 32 | 0.882 | 0.864 | 0.171 | 0.100 | 3660.3 | 1.29 | 1.63 |

Peak memory is process-lifetime physical footprint, including self-verification.
Proof size excludes artifact framing. ECDSA executes 1,828 guest instructions;
the STARK proof is 3,748,143 bytes and the full artifact is 3,778,701 bytes.
The guest's canonical 161-byte input and expected 32-byte digest are unchanged.

## Retained verification and rejection evidence

- 320 measured proofs and 32 warmups completed with verification.
- Every retained positive artifact was verified again in a fresh CLI process.
- CPU and Metal match on proof bytes, statement hash and output for all 16 rows.
- The bad-signature fixture has a full software rejection proof on each backend,
  independently verified. These two validation proofs are excluded from timings.
- Unsupported fast-path inputs select the software guest; host routing is never
  accepted as a signature verdict. Fast and software ELF sources are authenticated.
- Each accelerated Metal sample records 103 GPU dispatches and 4 CPU fallbacks;
  quotient construction remains on the GPU. Detailed counters are in the reports.
- [Validation record](validation.json): 113 focused Python tests, reproducible guest
  binaries, full-guest proof gate, mutation/substitution checks and clean builds.

Each report names its retained `.evidence-*` directory, containing all proof
artifacts, native benchmark reports, fresh-verifier receipts, logs and terminal
progress. Original paths are preserved in the reports; all named evidence files
are retained beside this README. `SHA256SUMS` authenticates the packaged files.

## Reproduce

Build the clean snapshot's products, then run from that checkout:

```sh
python3 scripts/zig_serial_build.py stwo-zig-riscv-cpu stwo-riscv-metal riscv-trace-dump -Doptimize=ReleaseFast
python3 scripts/riscv_csp_benchmark.py --backend cpu --execution-mode precompile --workers 16 --warmups 1 --samples 10 --report-out /tmp/csp/cpu.json
python3 scripts/riscv_csp_benchmark.py --backend metal --execution-mode precompile --workers 16 --warmups 1 --samples 10 --report-out /tmp/csp/metal.json
```

For the small development loop, add `--targets ecdsa_secp256k1 --sizes 32
--warmups 0 --samples 1`. `ecdsa-csp-bench --profile-out PATH` captures hierarchical
stage timings without a full-suite run. See [the measured Metal optimization](research/README.md)
for the before/after experiment; its development timings are separate from these
clean qualification results.
