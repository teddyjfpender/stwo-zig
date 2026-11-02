# RV64 whole-prover performance qualification — 2026-10-30

All 17 complete CSP cases pass native proving, independent ELF/input/output
binding, and fresh-process verification after optimization. Every statement,
claim and serialized proof byte matches the previous implementation. Geometry,
security (70 FRI queries, 26 PoW bits), instruction counts, and the maximum
18-worker pool are unchanged. The production verifier and AIR remain authority;
the new relation cache is untrusted prover witness data.

## Whole-job measurements

These are process wall times, including capture, setup, physical witness,
commitments, interactions, composition, FRI, openings, serialization and native
verification. The host is the same 64 GiB, 18-core Apple machine and Zig 0.15.2
ReleaseFast CPU backend. The CSV contains all 17 cases and per-stage timings.

| Workload | Previous total | Optimized total | Speedup |
| --- | ---: | ---: | ---: |
| SHA-256 / 2048 bytes | 9.479 s | 2.211 s | 4.29× |
| Keccak / 2048 bytes | 4.638 s | 1.137 s | 4.08× |
| Poseidon M31 / 16 | 37.075 s | 9.174 s | 4.04× |
| ECDSA / valid | 80.381 s | 20.624 s | 3.90× |
| ECDSA / invalid | 80.330 s | 20.946 s | 3.84× |

[Full comparison](comparison.csv), [validated comparison JSON](comparison.json),
[original report](../rv64-qualification-20261030/csp-full-parallel.json), and
[final report](optimized-final.json) retain raw measurements and provenance.
These are single runs per workload, not a throughput distribution. Additional
isolated ECDSA runs were 21.075–21.241 s (median 21.120 s, three runs); the fresh
baseline rerun was 76.248 s. Thus the repeat evidence supports roughly 3.6×,
while the full-suite pair reports 3.9×. See [repeat summary](repeat-summary.json).

The first cold Keccak-128 process wall measurement was 1.736 s versus 1.543 s
previously, even though its timed proving improved from 0.520 s to 0.247 s.
Approximately 1–1.4 seconds fell outside the instrumented application phases on
those first invocations. Five warm paired runs gave medians 0.544 s versus
0.278 s. The cold rows remain in the raw comparison; startup cost is not silently
removed from the table or attributed to prover arithmetic.

## Attribution and retained changes

Representative ECDSA stage samples (inclusive parents must not be summed with
children) explain the original cost and resulting reduction:

| Phase | Original profile | Final profile |
| --- | ---: | ---: |
| Physical witness | 9.456 s | approximately 0.65 s |
| CPU interactions | 24.887 s | 0.598 s |
| Composition | 36.763 s | 12.275 s |
| Three trace commitments | 3.882 s | 3.949 s |
| OODS sampled values | 0.520 s | 0.512 s |
| FRI quotient build/commit | 1.246 s | 1.254 s |
| Trace openings | 0.933 s | 0.872 s |

The baseline stage profile is a separate representative run (68.56 s proving)
from the original full-suite timing (70.52 s proving). Exact same-proof parity
is checked in both. Raw hierarchy: [baseline](baseline-ecdsa-profile.json),
[baseline analysis](baseline-analysis.json), and final report above.

1. Interaction generation previously reconstructed full logical/frame rows
   twice and gathered a wide, bit-reversed matrix. Construction now retains
   active-only native state words/clocks and compact range/table indices. CPU
   main storage is released immediately after commitment; its coefficients and
   narrow metadata retain the remaining obligations. No execution replay or
   extra wide trace is retained.
2. Native clock/value validation remains ordered. Each hint is generated once,
   in physical row order, through bounded workers using private histograms and
   disjoint output rows. Counts merge only after the joined wave. Canonical
   padding is constructed once. Decode metadata is reused, and advice is built
   directly in M31. Immutable geometry belongs only to PreparedSetup.
3. Interaction inverses and row contributions are independent physical-row
   work. Workers share immutable dictionaries, own 128 KiB of budgeted scratch,
   and allocate nothing. The existing prefix slots temporarily hold row
   contributions; one joined logical scan produces the original prefixes.
   Failed work drains before cleanup; metadata retires only after closure.
4. Quotient source FFTs previously called a serial entry point despite pooled
   row evaluation. Column FFT waves now use the existing worker pool with the
   same FFT arithmetic, bounded leases, disjoint buffers and joined barriers.
5. Domain accumulation uses already assigned random-coefficient powers and
   base-field multiplication instead of a long full-extension Horner dependency.
   The same Sink retains point evaluation, scaling, zero runs and exact order.
6. Immutable inflation/gather maps are compiled once. Worker logical storage is
   zeroed once per wave; every live value is overwritten and omitted coordinates
   stay zero. No per-row 2371-element zero-fill or repeated support classification
   remains. A retained test oracle checks arbitrary QM31 values and reused poison.
7. BYTE lookup products use one universal elementary-symmetric polynomial over
   QM31, with challenge powers prepared once per component. For three values,
   d=alpha^3-alpha^2*s1+alpha*s2-s3 and n=3*alpha^2-2*alpha*s1+s2.
   Domain s1/s2/s3 are base-field values, so extension products become base-field
   products; OODS uses the exact same polynomial over arbitrary QM31. Batch
   sizes, degree, witness inverses, transcript and constraints remain unchanged.

Peak caller allocation remains approximately 12.78 GiB for ECDSA. The temporary
relation cache (~403 MB) and worker histograms (~9.3 MiB) die before the peak
composition phase. Caller peaks exclude process-wide worker stacks and OS memory.
No wide witness/quotient files are written. Compact cases, measured binaries and
private source/sampling references are retained locally under the ignored
`vectors/reports/interop_artifacts/rv64-performance-20261030` directory.

## Experiments rejected

- A direct narrow column-gather interaction variant regressed to 32.9 s; a
  bounded row cache helped, but the retained row-major metadata design was faster.
- A larger hint rewrite was declined after sampling showed hint bit work was
  minor. Projection recipes gave no reliable gain after fused stores and were
  removed rather than keeping an extra execution path.
- Larger streaming batches and tiled commitments preserved authenticated
  openings but did not improve representative commit time. Commitments are
  already a small fraction of the full job. Production retains stream8.
  [PCS study](pcs-study.json) records the generic experiment and its limits.
- No second pool, weaker proof configuration, shortened guest, hidden precompile,
  reduced verification, or modified proof format is used.

## Remaining cost and reproduction

The final ECDSA composition sample spends 9.93 s evaluating constraint rows and
2.24 s on source FFTs. This is now the main bottleneck. The representation still
has 519 main and 260 interaction columns over 2^21 rows: roughly 6.11 GiB of raw
CPU trace cells. Further large gains require reducing encoded constraint work
and measuring its impact on interaction columns, padding, openings and providers;
this phase does not establish an optimal representation or OP block throughput.
Full-profile Rust proof acceptance and the OP guest ABI remain separate work.

Build tools with `zig build rv64-csp-full rv64-full-verify rv64-quotient-benchmark pcs-commit-profile -Doptimize=ReleaseFast`. Add `--profile-stages` to
`scripts/riscv64_csp_full_proofs.py` for whole-prover stage capture. Its
`--profile-only` flag remains execution-only and never establishes a proof.
Use `python3 scripts/riscv64_prover_profile_compare.py --baseline BEFORE.json --candidate AFTER.json --output comparison.json --csv comparison.csv` to reject
mismatched coverage, workload, security, worker count or proof bytes before
reporting a speedup. `quotient-kernel-final.json` is an arithmetic microbenchmark;
it does not substitute for the complete proofs.
