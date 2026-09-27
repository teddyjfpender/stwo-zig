# Full-width BLAKE3 ReleaseFast E2E measurements

Current source-pinned working tree, Apple M5 Max / 64 GiB, AC power.
This is a diagnostic performance measurement, not admission to the clean-source
CSP suite. No dirty-source gate was bypassed. The complete Zig/Python source
snapshot and per-file hashes are retained alongside the current git revision.
No other build or proving job overlapped the measured ECDSA samples.

## CPU ECDSA

Canonical 161-byte CSP input and odd-parity typed precompile guest; 1,828 steps,
70 queries / 26 PoW bits, 16 workers, one warmup and three measured samples.
Each measured transaction includes fresh verification after witness destruction.
An additional independent CLI verification of the retained artifact passed.

| Phase | Median seconds |
| --- | ---: |
| execution | 0.000414208 |
| witness | 2.714516292 |
| admission | 0.396531541 |
| proving | 7.414464584 |
| artifact_encoding | 0.065575042 |
| fresh_verification | 0.539395500 |
| total | 11.124404458 |

Per-phase medians need not sum to the median total. Individual total samples:
11.124404458 s, 11.054629750 s, 11.138489333 s.

Tracked host peak: 3,384,008,876 bytes. Process-lifetime physical peak:
3,635,533,368 bytes. Retained artifact and raw JSON are authoritative.

This does not establish an end-to-end speedup. Current latency is substantially
higher than historical ~0.882 s ECDSA proving. The historical route already used
core BLAKE3 but retained the older execution-memory commitments, and excluded
fresh verification from its proving metric. Those changes prevent attributing
the difference solely to the hash function; they do not make current latency
acceptable as a performance improvement. The earlier 18.414 s ReleaseSafe run
also had concurrent compilation, so its ratio to this result is not an isolated
optimization speedup.

The 19.74x G-row reduction measures shared versus independent full-width BLAKE3
memory paths; it does not compare BLAKE3 with the old commitment architecture.

## Reproduction

```sh
python3 scripts/zig_serial_build.py --cwd . stwo-zig-riscv-cpu -Doptimize=ReleaseFast --summary all
zig-out/bin/stwo-zig-riscv-cpu ecdsa-csp-bench --elf vectors/riscv_csp/guests/ecdsa_secp256k1_precompile_odd.elf --input vectors/riscv_csp/inputs/ecdsa_secp256k1.bin --proof-out /tmp/blake3-e2e-releasefast-cpu.b3proof --report-out /tmp/blake3-e2e-releasefast-cpu.json --warmups 1 --samples 3 --workers 16 --host-byte-budget 38654705664
```

The four-worker parent qualification and Metal ECDSA measurements are below.
The parent run using product allocator/worker settings is complete below.

## Canonical parent qualification timing

The four-worker ReleaseFast leak-checking fixture passed with 70/26 for both
leaf and parent. Parent-only time from an authenticated leaf capture was
101.969332 s: preparation 32.644251 s, admission 3.626392 s, worker initialization
3.715119 s, proving 61.817331 s, cleanup/encoding 0.045478 s, fresh verification
0.120761 s. The worker tracked peak was 15,439,320,038 bytes. Compilation and
leaf proving are excluded. This fixture uses std.testing.allocator, unlike the
product's SMP allocator, and only four workers. It is a qualification timing,
not the final product-settings performance result.

A separate benchmark entry point retains the same fixture and independent
verification but uses the product's SMP allocator and sixteen workers. Its three
changed test/helper source files are archived under parent-benchmark-source;
apply those over source.tar.gz to reproduce this follow-up. Existing test entry
points retain their allocator and worker count. No proving implementation or
security parameter is changed by this follow-up.

## Metal ECDSA

Same canonical workload, one warmup and three samples, 16 workers, ReleaseFast.
Median complete transaction: **11.100503458 s**, samples 11.048685250,
11.100503458, 11.163158667 s. Median witness 2.652185084 s, admission
0.430604625 s, proving 7.437362834 s, fresh verification 0.525067000 s.
Tracked peak: 3,061,590,108 bytes; physical process-lifetime peak:
5,451,110,568 bytes. GPU dispatches: 1,730; CPU fallbacks: 233 per sample.
This is hybrid execution. No meaningful CPU/Metal latency advantage is shown by
these samples. Both retained artifacts are byte-identical, and independent CPU
verification of the Metal artifact passed.

The first launch was rejected before proving because an older AOT bundle did
not match the new executable's trust anchor. That failure is retained. The
successful run used the authenticated bundle installed alongside the executable;
its manifest and metallib are retained in metal-aot. No admission was bypassed.
Use the CPU command above with stwo-zig-riscv-metal, fresh output paths, and
unset STWO_RISCV_METAL_AOT_BUNDLE to select that installed bundle.

## Canonical parent with product allocator and worker settings

The separate benchmark passed in ReleaseFast with the SMP allocator, sixteen
workers, one cold sample, and 70 queries / 26 PoW bits on both leaf and parent.
The fixture is one guest-Poseidon invocation. Parent timing begins at an already
authenticated leaf capture; leaf execution/proving and compilation are excluded.
This is not an Ethereum-block result or an ECDSA recursive-parent result.

| Phase | Seconds |
| --- | ---: |
| Parent row preparation | 7.003637 |
| Key derivation and admission | 1.516745 |
| Persistent worker initialization | 1.475145 |
| Parent proving | 45.468925 |
| Worker/row cleanup and artifact encoding | 0.030583 |
| Fresh decoding and verification | 0.009445 |
| Total | **55.504480** |

Worker tracked peak: 15,464,486,038 bytes. Parent artifact: 867,999 bytes.
Prepared rows retained 2,707,426,052 bytes. The verifier runs after worker and
rows are destroyed. The product-settings result supersedes the four-worker test
allocator timing as the performance baseline. Their ratio is not a proving-code
optimization or hash-function speedup: both allocator and worker count changed.
Only one parent sample was measured, so this is a cold baseline, not a median.

```sh
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments -Doptimize=ReleaseFast '-Driscv-test-filter=canonical parent ReleaseFast benchmark' --summary all
python3 autoresearch/notes/2026-09-23-blake3-releasefast-e2e/analyze.py
```

## Decision for the next experiment

No E2E speedup is established. Parent proving is 81.9% of this cold total;
preparation is 12.6%, admission plus worker construction 5.4%. A preparation-only
optimization cannot supply the desired order-of-magnitude reduction on this
fixture. The earlier row census implicates the large hash circuit, but row counts
are not a runtime profile. Next instrument commitment, composition, sampled-value
opening and FRI phases within the 45.47 s proving phase before choosing a change.
Use the same fixture, parameters, allocator, worker count, timing boundary and
fresh verification for subsequent paired comparisons. Do not score historical
0.882 s ECDSA or the old recursion architecture as a matched hash-only baseline.

The broader objective remains active: authenticated persistent plans and bounded
preparation/proving overlap; fused PCS/DEEP beyond existing fma/dot4; direct final
layout witnesses; and a separately reviewed parameter experiment. Existing plan
reuse and direct-layout work are partial progress, not evidence that all four
requirements or the 10x objective are complete. Shared opening topology remains
unwired, and its current row estimate alone does not cross a smaller padded
hash-domain boundary.
