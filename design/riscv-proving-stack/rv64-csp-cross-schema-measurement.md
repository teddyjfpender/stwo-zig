# Complete CSP comparison across execution schemas

The legacy Full prover and the joined Word16 prover execute the same pinned
software RV64IM ELF and input. Their physical layouts and transcripts differ.
Proof-byte equality is not the comparison criterion. Each proof is verified by
an independently started receiver before the statement adapter runs.

`scripts/riscv64_csp_cross_schema.py` maps the genesis Word16 statement and its
bounded binary RAM sidecar to the complete legacy public Statement. It compares
all 64-bit PCs and register values, register clocks, sorted RAM address coverage,
initial/final word values, read/write rights and memory clocks. It independently
checks the full program and CSP initial image/output through the existing ELF
statement validator. Epoch zero-to-one framing is checked explicitly; it is not
discarded. Unknown public schemas fail closed. The native opcode histograms must
match, including declared arithmetic and load/store request counts. This is
observed native coverage, not an extra public per-opcode AIR counter claim.

Both producer and fresh receiver must report the actual q70/P26 PCS configuration,
ReleaseFast mode and eight workers. A successful report adapter is not itself a
proof verifier. The runner requires successful exits from the pinned proof and
fresh-verifier executables, retains their stdout/stderr and hashes the artifacts.
Fresh verification still owns all physical claim and geometry admission.

The benchmark runner rejects existing output directories and runs one prover at
a time. For example, after freezing and hashing the four installed tools:

```
python3 scripts/riscv64_csp_cross_schema_benchmark.py \
  --tools /tmp/rv64-controlled-csp-sail-tools-v1/bin \
  --assets /tmp/rv64-controlled-csp-sail-prep-v1 \
  --output /tmp/rv64-controlled-csp-runs-UNIQUE \
  --host-contention 'record actual coordinated window and observed background work'
```

The default sequence is legacy/single/single/legacy followed by
single/ladder/ladder/single. Every producer has a fresh verifier. Whole-process
wall, user/system CPU and maximum RSS are recorded with `time -l`. Darwin peak
memory footprint is a separate field. Nested process-usage stage intervals are
not additive. Legacy native INTER cell counts are derived from its verified
physical roster; fixed/MAIN lengths and all proof sample/hash counts come from
actual allocations or proof objects. Word16 cells come from its concrete shapes.
These are source cells, not a claim about every FFT, LDE or hash touch.

Legacy `prove_ns` and Word16 `prove_ns` do not include identical preparation
work. Compare whole-process times first; keep capture/setup/source/proof phases
separate. In-process verification and publication are also included in whole
producer wall time. Worker count, security, ELF, input and full statement match;
this does not assert equal AIR or identical implementation costs.

The continuous Sail tool proves and fresh-verifies its complete 63-opcode
ordinary RV64IM execution and checks every retirement against RVFI during native
capture. Its fresh receiver does not read RVFI. Current Sail reports only coarse
phase timings. There is no qualified legacy continuous-Sail full-proof CLI in
this comparison, and no Rust same-AIR result is inferred.

## Frozen CPU50 observations, 2026-11-01

The receipt is
`vectors/reports/rv64-word16-execution-20261101/csp-sail-cross-schema-controlled-v1.json`.
All runs use the same 1,625,938-step ECDSA ELF/input and q70/P26, ReleaseFast,
eight workers on a 64-GiB Apple M5 Max. All 32 registers, clocks and the same
1,814 RAM words/permissions match. The complete normalized statement digest is
`5ad4b952aa5b46189d694d431d3d3ca3abe34ccfb70015b74add6d32ad885c12`.

The final direct legacy/Word16/Word16/legacy sequence ran after an explicit
fully-idle release. These are means of two observations, not confidence bounds:

| Complete software prover | Wall seconds | User+system seconds | Maximum RSS, decimal GB | Native source cells | Proof bytes | OODS samples |
|---|---:|---:|---:|---:|---:|---:|
| Legacy Full, packed PC | 13.895 | 84.345 | 13.313 | 1,600,197,632 | 659,720 | 898 |
| Word16, single LS, absent DIV | 5.335 | 22.985 | 3.824 | 481,390,912 | 716,840 | 1,182 |

This workload's observed wall ratio is 2.60, source-cell ratio 3.32 and RSS ratio
3.48. The Word16 proof remains 8.7% larger. Fresh receiver wall observations were
0.13/0.14 seconds legacy and 0.17/0.17 seconds Word16. This compares different
AIR/layout/ownership implementations under the same execution and security;
it is not an Ethereum, Rust, GPU or recursion speed claim.

The first controls had retained an unused DIV role at log5. Actual executed DIV
requests were zero. Switching the CSP producer to the qualified
`Prepared.geometryOmittingEmptyDivision()` class removed 1,151 actual OODS samples
and reduced proof bytes from 1,072,920 to 716,840, while removing only 36,672 native
source cells. Counts come from captured requests, not ROM opcode presence. The
fresh receiver requires zero DIV request/claim and physical FUNCTION closure;
its unserved-DIV countermodel test remains rejecting. The original controls are
retained and are not presented as the optimized layout's inherent opening cost.

A separate balanced absent-DIV single/ladder/ladder/single sequence gave:

| Word16 LS class | Wall seconds | Maximum RSS, decimal GB | Native source cells | Proof bytes | OODS samples |
|---|---:|---:|---:|---:|---:|
| Single log20 | 5.515 | 3.824 | 481,390,912 | 716,840 | 1,182 |
| Head log19 + tail log15 | 5.180 | 3.543 | 417,493,312 | 755,960 | 1,321 |

The ladder reduces padded source cells but increases openings and proof size.
PoW work also changes with the transcript; individual phase/process vectors are
retained rather than attributing all wall differences to constraint evaluation.
The earlier present-DIV controls, present/absent-DIV comparison and one
compiler-contended final attempt are retained separately. The contended attempt
is excluded from the final timing table. External processes were not controlled;
the coordinated windows retain host snapshots.

The current continuous Sail run proves 1,032,240 instructions covering all 63
ordinary retiring RV64IM opcodes. Every retirement was checked against RVFI,
and a fresh receiver with a nonexistent RVFI path accepted. Its single observed
producer wall/RSS were 3.18 seconds/2.286 GB; fresh receiver 0.36 seconds/0.778 GB.
The proof is 1,029,376 bytes. Coarse source/prove times were 0.099/1.740 seconds;
whole-process time also includes image and RVFI handling. A metadata-complete
fresh receiver was rebuilt and accepted the same retained proof. There is no
paired legacy continuous-Sail or Rust same-AIR result.
