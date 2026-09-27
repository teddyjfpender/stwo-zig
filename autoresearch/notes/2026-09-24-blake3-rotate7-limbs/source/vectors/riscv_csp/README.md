# RISC-V EthProofs CSP fixtures

This directory contains the self-authenticating workload boundary for the
standard RISC-V client-side proving benchmark. Its authority is
[`manifest-v2.json`](manifest-v2.json), not the filenames alone.

The manifest pins:

- `privacy-ethereum/csp-benchmarks` commit
  `269c43cc32d3127e3d9ce74d20652887d894cca3`;
- the CSP input generators, size metadata, Rust toolchain, and the
  source-isolated adapter used for k256 and M31 values;
- every guest source, manifest, lockfile, target configuration, and linker
  script used by the workload;
- the committed RV32IM ELF bytes;
- deterministic target-specific inputs;
- expected output digests and exact retirement counts; and
- whether each target uses a precompile.

The current matrix has sixteen proof rows:

| Target | Sizes | Input contract | Classification |
| :--- | :--- | :--- | :--- |
| SHA-256 | 128, 256, 512, 1024, 2048 bytes | CSP-seeded bytes | canonical CSP zkVM workload |
| Keccak-256 | 128, 256, 512, 1024, 2048 bytes | CSP-seeded bytes | canonical CSP zkVM workload |
| Poseidon2-M31 | 2, 4, 8, 12, 16 field elements | CSP-seeded canonical M31 elements | field-native extension |
| secp256k1 ECDSA | one 32-byte digest | CSP k256 digest, uncompressed SEC1 key, and `r || s` signature | canonical CSP zkVM workload |

The original manifest describes software RV32IM workloads (`uses_precompile=false`).
The additional authenticated [ECDSA precompile manifest](ecdsa-precompile-v1.json)
provides the accelerated full-guest path selected with `--execution-mode precompile`.
Other targets retain their software guests.
SHA-256 and Keccak inputs are a little-endian `u32` byte length followed by
the shared message. Poseidon2-M31 inputs are a little-endian element count
followed by canonical little-endian M31 elements. ECDSA inputs are
`digest[32] || public_key[65] || signature[64]`.

Poseidon2-M31 is deliberately not called CSP's canonical `poseidon2` target.
The latter is BN254 in the pinned generic CSP generator. This row instead uses
the repository's M31-native Poseidon2 guest with CSP's exact seeded M31 input
convention and is reported as `csp_field_native_extension`. Classic Poseidon,
BN254 Poseidon2, and P-256 ECDSA remain explicitly unsupported rather than
being represented by near-matches.

Ordinary benchmark execution trusts neither an ambient CSP checkout nor an
unrecorded Rust toolchain. The driver authenticates every committed file before
execution, checks the guest output and cycle count through the trace diagnostic,
generates a secure proof, validates the benchmark/report contract, and verifies
the retained proof in a separate process.

The negative fixture changes one byte of the exact k256 signature. The software
guest must return the all-zero rejection value at the pinned retirement count;
the driver proves and independently verifies this rejection separately from the
positive performance rows. In precompile mode it is explicitly recorded as a
software fallback, not a fast rejection proof.

Use the repository build step:

```sh
zig build riscv-csp-bench -Doptimize=ReleaseFast
```

To audit fixture derivation, first build the locked CSP utility in a clean
checkout at the pinned commit, then pass that checkout to:

```sh
python3 scripts/riscv_csp_benchmark.py \
  --audit-csp-source /path/to/csp-benchmarks \
  --targets ecdsa_secp256k1 --sizes 32 --warmups 0 --samples 1
```

The source audit recompiles
[`upstream_fixture_dump.rs`](upstream_fixture_dump.rs) against the pinned CSP
`utils` library and regenerates all eleven distinct inputs plus the invalid
signature fixture. It does not substitute generated values after a mismatch.

The repository-owned guests are reproducible with their checked-in locked
toolchains:

```sh
(cd vectors/riscv_guests/poseidon2_m31 && cargo build --release --locked)
(cd vectors/riscv_guests/ecdsa_secp256k1 && cargo build --release --locked)
```

The resulting release ELFs must be byte-identical to the copies under
`vectors/riscv_csp/guests/`; the manifest authenticates both sources and
committed binaries.

The benchmark driver rejects source-pin drift, dirty upstream state, fixture
mutation, output mismatch, retirement-count drift, dirty prover identity,
unverified proofs, and proof/report/receipt binding mismatches.

`manifest-v1.json` remains only as provenance for the earlier retained
SHA-256/Keccak report. New benchmark runs use v2.

## Latest full suite with ECDSA precompile — 2026-09-21

These are full guest proofs at **70 queries / 26 PoW bits**, on Apple M5 Max,
from clean snapshot `af05b7401a77`. One warmup and ten measured verified samples
per workload/backend; means include execution + witness + proving, with verification
reported separately. **ECDSA now uses the authenticated precompile guest.**

| Backend | Mean prove | Median prove | Sample range | Mean verify |
| :--- | ---: | ---: | ---: | ---: |
| CPU | **881.6 ms** | 877.5 ms | 873.8–899.8 ms | 171.2 ms |
| METAL | **863.7 ms** | 862.6 ms | 855.1–880.3 ms | 100.5 ms |

| Workload | Size | CPU prove (s) | Metal prove (s) |
| :--- | ---: | ---: | ---: |
| sha256 | 128 | 0.776 | 0.442 |
| sha256 | 256 | 0.697 | 0.447 |
| sha256 | 512 | 0.603 | 0.456 |
| sha256 | 1024 | 0.698 | 0.457 |
| sha256 | 2048 | 0.672 | 0.460 |
| keccak | 128 | 0.541 | 0.415 |
| keccak | 256 | 0.614 | 0.424 |
| keccak | 512 | 0.591 | 0.432 |
| keccak | 1024 | 0.633 | 0.442 |
| keccak | 2048 | 0.796 | 0.484 |
| poseidon2_m31 | 2 | 0.617 | 0.511 |
| poseidon2_m31 | 4 | 0.680 | 0.539 |
| poseidon2_m31 | 8 | 0.969 | 0.530 |
| poseidon2_m31 | 12 | 0.805 | 0.556 |
| poseidon2_m31 | 16 | 1.260 | 0.590 |
| ECDSA (precompile) | 32 | 0.882 | 0.864 |

All 320 measured proofs verified. Retained proofs were independently verified
again, and both backends produced matching proof bytes and statements for every
workload. Each backend also proved and independently verified the bad-signature
fixture's software rejection. ECDSA is 1,828 guest instructions, with a 3,748,143-byte
proof; the timings include caller/memory composition and guest checks.

[Detailed results, memory, proof sizes, raw evidence and reproduction](../reports/recursive-product-20260921/csp-accelerated-suite-v1/README.md).
Use `--execution-mode precompile` for these results; software remains an explicit
comparison mode and the default for historical runner consumers.

## Recorded full software suite — 2026-09-21

Measured on Apple M5 Max, ReleaseFast, 70 queries / 26 PoW bits, one warmup
and ten measured verified samples per row. Values are mean execution + witness
+ proving seconds; verification is separate. This table is the software baseline,
not the accelerated ECDSA result. [Raw CPU/Metal reports and provenance](../reports/recursive-product-20260921/csp-current-suite-v1/README.md).

| Workload | Size | CPU prove (s) | Metal prove (s) |
| :--- | ---: | ---: | ---: |
| sha256 | 128 | 0.754 | 0.441 |
| sha256 | 256 | 0.670 | 0.411 |
| sha256 | 512 | 0.582 | 0.403 |
| sha256 | 1024 | 0.668 | 0.428 |
| sha256 | 2048 | 0.640 | 0.429 |
| keccak | 128 | 0.523 | 0.388 |
| keccak | 256 | 0.594 | 0.402 |
| keccak | 512 | 0.574 | 0.418 |
| keccak | 1024 | 0.614 | 0.427 |
| keccak | 2048 | 0.779 | 0.461 |
| poseidon2_m31 | 2 | 0.602 | 0.428 |
| poseidon2_m31 | 4 | 0.660 | 0.448 |
| poseidon2_m31 | 8 | 0.921 | 0.489 |
| poseidon2_m31 | 12 | 0.778 | 0.515 |
| poseidon2_m31 | 16 | 1.217 | 0.572 |
| ecdsa_secp256k1 | 32 | 3.737 | 1.937 |

Poseidon2-M31 rows are the field-native extension described above. These retained
historical reports checked the negative fixture by execution; the current runner
also produces a full rejection proof. Their schemas and original claims remain
unchanged.

## Accelerated ECDSA execution

```sh
python3 scripts/riscv_csp_benchmark.py --backend cpu --execution-mode precompile \
  --targets ecdsa_secp256k1 --sizes 32 --workers 16 --report-out /tmp/csp/cpu.json
python3 scripts/riscv_csp_benchmark.py --backend metal --execution-mode precompile \
  --targets ecdsa_secp256k1 --sizes 32 --workers 16 --report-out /tmp/csp/metal.json
```

Omit `--targets` and `--sizes` to run the complete mixed suite. This mode proves
the RISC-V caller, memory bindings, recovery computation, low-S/key checks and
public output. Host parity selection is not a trusted verdict. Unsupported inputs
receive full software proofs. See the [guest contract](../riscv_guests/ecdsa_secp256k1_precompile/README.md)
and [runner documentation](../../design/riscv-proving-stack/csp-benchmarks.md).
The earlier 228/165 ms figures measured an isolated provider and are not full
CSP guest results.

## BLAKE3 migration qualification — 2026-09-22

A full ECDSA precompile guest now proves and independently verifies with BLAKE3
commitments/transcript at **70 queries / 26 PoW bits**, using the new v6 Ethereum
artifact. On Apple M5 Max, ReleaseFast, 16 CPU workers, one qualification sample:

| Execution | Proving, including witness | Independent verification | Cycles | Inner proof bytes |
| ---: | ---: | ---: | ---: | ---: |
| 0.001978 s | 2.489486 s | 0.188206 s | 1,828 | 3,748,258 |

This is a single dirty-worktree qualification sample, not the complete CSP suite
or an A/B speedup result. Serialization/startup are outside proving time. Current
product defaults and existing suite tables remain unchanged; Metal is pending.
Input/ELF/proof substitution and low-S routing checks pass, and fixture pins were
verified. Raw logs, host details, sample JSON and sources are retained in the
[BLAKE3 qualification evidence](../../autoresearch/notes/2026-09-22-blake3-canonical-csp-ecdsa/README.md).

### Transcript receipt qualification — 2026-09-22

The canonical CPU ECDSA gates now compare typed receipts from proving and
independent verification. BLAKE3 receipts include the full 64-bit draw counter.
Protocol plus both suite gates pass 8/8 tests at ReleaseFast; ECDSA retains
70 queries/26 PoW bits and 1,828 guest cycles.

| Suite | Execution (s) | Proving (s) | Verification (s) | Inner proof bytes |
|---|---:|---:|---:|---:|
| BLAKE3 | 0.002079 | 2.506949 | 0.191967 | 3,748,258 |
| BLAKE2s | 0.000897 | 0.851909 | 0.290428 | 3,748,143 |

Single qualification samples; PoW variation prevents a controlled speedup claim.
Production defaults, Metal and full-suite BLAKE3 results remain pending.
[Logs, independent vectors and source pins](../../autoresearch/notes/2026-09-22-suite-transcript-receipts/README.md).

CSP benchmark/verification report schema v2 now records the suite and transcript
receipt, checked against the artifact and fresh verifier. CPU CLI qualification
with the unchanged BLAKE2s default measured 0.798874 s proving, 0.001829 s execution
and 0.146700 s verification at canonical parameters (one sample, 16 workers).
[Report admission evidence](../../autoresearch/notes/2026-09-22-csp-report-suite-admission/README.md).

### BLAKE3 slowdown attribution — 2026-09-22

Canonical ECDSA stage profiling measured BLAKE3 at 2.523295 s proving versus
BLAKE2s at 0.858627 s, with precompile enabled in both. PoW accounts for 1.640898 s
versus 0.125382 s, explaining 91% of the measured delta. BLAKE3 still uses a serial
reference grinder while BLAKE2s uses pooled batched search. Excluding PoW leaves
0.882397 s versus 0.733245 s; this subtraction is not a canonical total or a speedup.
Both proof/verification gates pass. Fix BLAKE3 PoW before promotion, then investigate
the remaining commitment costs. These are single stage-attribution samples.
[Stage profiles and source evidence](../../autoresearch/notes/2026-09-22-csp-blake3-slowdown-profile/README.md).

### Pooled BLAKE3 PoW — 2026-09-22

BLAKE3 now uses the bounded prover pool for PoW, preserving the lowest valid
nonce and canonical predicate. The 70-query/26-bit ECDSA precompile qualification
measured 1.000019 s proving, 0.122675 s PoW and 0.197667 s verification, versus
the previous BLAKE3 2.523295 s proving/1.640898 s PoW. Eight focused tests pass,
including worker-count parity and independent full-proof verification. These are
single before/after samples; no statistical verdict, subsecond canonical total,
or improvement over the historical ~0.882 s result is claimed. Defaults and Metal
are unchanged. [Pooled search evidence](../../autoresearch/notes/2026-09-22-blake3-pooled-pow/README.md).

### Bulk BLAKE3 leaf integration — 2026-09-22

BLAKE3 now uses bulk canonical leaf encoding and the existing tiled builder's
packed-byte interface. Eight ReleaseSafe protocol tests pass, including byte
and streaming equivalence. A canonical ECDSA proof plus independent verification
passed at 0.994176 s proving, 0.123395 s PoW, 0.188772 s verification and
0.001713 s execution (70 queries/26 bits, 1,828 cycles, 3,748,258 proof bytes).
This is neutral against the previous 1.000019 s sample; local leaf-probe gains
do not demonstrate a CSP end-to-end improvement. Defaults/Metal remain pending.
[Source, counters and qualification logs](../../autoresearch/notes/2026-09-22-blake3-leaf-bulk/README.md).

### Metal BLAKE3 migration coverage — 2026-09-22

Actual Metal BLAKE3 PoW now matches the CPU's lowest nonce at 26 bits (63,024,448;
61 bounded dispatches, zero CPU fallback). This is a PoW parity test, **not a new
CSP benchmark result**. BLAKE3 Merkle/FRI/resident-transcript support and full
canonical Metal CSP runs remain pending.
[Device qualification](../../autoresearch/notes/2026-09-22-metal-blake3-pow/README.md).

### Canonical BLAKE3 ECDSA on Metal source JIT — 2026-09-22

The full precompile guest proof and independent verification pass at 70 queries,
26 PoW bits and 16 workers. One ReleaseFast sample: execution 0.000764458 s,
proving **0.902787958 s**, verification 0.087134666 s, 1,828 cycles and 3,748,258
proof bytes. The shared CPU/Metal harness also checks suite receipts and rejects
wrong inputs, wrong ELF and tampered proofs. Diagnostic source JIT is explicitly
selected; authenticated AOT remains pending. Whole-test telemetry reports 128
Metal dispatches and 5 CPU fallbacks (including negative-check activity).
This is a single qualification sample, not a demonstrated speedup over the
historical 0.882 s baseline or a controlled CPU/Metal comparison.
[Logs and source snapshots](../../autoresearch/notes/2026-09-22-metal-blake3-csp-ecdsa/README.md).

### Canonical BLAKE3 ECDSA on authenticated Metal AOT — 2026-09-22

The freshly built current core AOT bundle passes the full precompile proof,
independent verification and negative checks at 70 queries / 26 PoW bits,
16 workers. One ReleaseFast sample: execution 0.000743667 s, proving
**0.881876417 s**, verification **0.085001875 s**, 1,828 cycles,
3,748,258 proof bytes. This is approximately the historical 0.882 s baseline;
no statistical speedup claim is made. Runtime setup is outside proof timing.
Whole-test telemetry has 128 Metal dispatches, 5 small circle LDE fallbacks,
and 25 CPU composition component placements (separate from fallback totals).
This is hybrid CPU/Metal execution. Full BLAKE3 CSP suite results remain pending.
[Authenticated manifest, logs and source snapshots](../../autoresearch/notes/2026-09-22-metal-blake3-csp-aot/README.md).

### Ordinary SHA-256 BLAKE3 product qualification — 2026-09-22

The canonical 128-byte SHA-256 guest (14,056 cycles, 70 queries / 26 PoW bits)
passes authenticated-AOT Metal product proving, independent CPU and Metal CLI
verification, and benchmark aggregation. Its v5 proof bytes and typed transcript
match the CPU product exactly. Explicit wrong-suite verification is rejected.
One diagnostic prove command measured 0.366627334 s proving and 0.0976185 s
verification; these dirty-development products are not a clean full-suite cohort
or repeated speedup study. Full BLAKE3 suite results remain pending.
[Retained proof, receipts and build evidence](../../autoresearch/notes/2026-09-22-blake3-metal-product-proof/README.md).

## Full BLAKE3 CSP matrix — 2026-09-22

Completed all 16 cases on CPU and authenticated-AOT Metal from clean local source
snapshot `348b9a02c2bfc33487a1f653aef7152ce83ae2b0` (not published).
Every retained proof independently verified; both backends also proved and verified
the bad-signature rejection case. All rows use 70 queries and 26 PoW bits, with
recursion disabled. ECDSA uses the typed recovery precompile; other targets execute
software guests, including the intentionally preserved Poseidon guest workload.

Apple M5 Max, 16 workers, ReleaseFast, one sample, no warmups, battery power.
These are local qualification measurements, not a controlled performance comparison.
Prove includes execution, witness and proof generation; verification is separate.

| Workload | Size | CPU prove (s) | CPU verify (s) | Metal prove (s) | Metal verify (s) |
|---|---:|---:|---:|---:|---:|
| sha256 | 128 | 2.074658 | 0.192373 | 0.421341 | 0.094871 |
| sha256 | 256 | 2.206294 | 0.191040 | 0.452077 | 0.096447 |
| sha256 | 512 | 2.295138 | 0.193408 | 0.423100 | 0.093192 |
| sha256 | 1024 | 3.894334 | 0.192097 | 0.508788 | 0.093122 |
| sha256 | 2048 | 2.719380 | 0.196893 | 0.458731 | 0.093496 |
| keccak | 128 | 2.585501 | 0.194410 | 0.413153 | 0.099302 |
| keccak | 256 | 1.805518 | 0.198111 | 0.408048 | 0.095944 |
| keccak | 512 | 3.879529 | 0.257437 | 0.443229 | 0.092867 |
| keccak | 1024 | 3.596645 | 0.225637 | 0.472704 | 0.094817 |
| keccak | 2048 | 3.811401 | 0.267551 | 0.471172 | 0.106059 |
| poseidon2_m31 | 2 | 2.457577 | 0.224616 | 0.479333 | 0.098394 |
| poseidon2_m31 | 4 | 2.285950 | 0.223041 | 0.519534 | 0.098360 |
| poseidon2_m31 | 8 | 1.712028 | 0.217501 | 0.514272 | 0.107732 |
| poseidon2_m31 | 12 | 2.197131 | 0.232287 | 0.551292 | 0.099131 |
| poseidon2_m31 | 16 | 3.596061 | 0.245193 | 0.606420 | 0.098611 |
| ecdsa_secp256k1 | 32 | 1.096581 | 0.166682 | 0.907835 | 0.091660 |

The earlier 2.523295 s BLAKE3 ECDSA CPU result included 1.640898 s of serial
PoW search; profiling attributed 91% of its difference from the paired BLAKE2s
measurement to PoW. Bounded pooled search fixed that regression. Current full-suite
ECDSA measures 1.096581208 s CPU and 0.907834583 s Metal, versus the historical
approximately 0.882 s reference. The separate Metal AOT harness measured
0.881876417 s witness/proving plus 0.000743667 s execution. Do not interchange
harness witness/proving, suite execution-inclusive proving, verification, or process
wall time. Single samples cannot establish a residual regression or its cause.

This qualifies explicit BLAKE3 suite selection; it does not promote defaults or
complete the remaining Poseidon statement-identity and recursion migration.

[Raw reports and evidence](../../autoresearch/notes/2026-09-22-blake3-full-csp-matrix/README.md).


### Full-width BLAKE3 ECDSA migration — qualification pending (2026-09-23)

The BLAKE3 dedicated ECDSA command now uses the shared full-width memory and
program commitment route. Its fresh verification command requires
`--expect-statement-digest` from the producer report's `statement_blake3` field,
provided as a separately retained pin. The verifier enforces the canonical CSP
output, halt completion and exactly one signer call. Reports use
`riscv_full_width_execution_v2`; `--profile-out` contains phase timings.

The earlier 1.096581 s CPU / 0.907835 s Metal matrix entries used BLAKE3 for the
core proof but retained the previous memory commitment route. They are historical
measurements, **not full-width migration timings**. New full-width ECDSA and full
suite results are pending; do not relabel the old matrix as those results.


Qualification update: both dedicated command products compile, but the canonical
CPU ECDSA ReleaseSafe run was stopped at a measured 81.2 GiB footprint; it did
not publish a verified artifact or timing result. A follow-up removes retained
coefficient duplicates and bounds borrowed-column preparation to eight columns.
Complete PCS proof parity and failure-ownership checks pass; ECDSA memory/runtime
qualification remains outstanding. See `autoresearch/notes/2026-09-23-blake3-csp-shared-route`.


Bounded follow-up: `ecdsa-csp-bench --host-byte-budget BYTES` optionally caps host
allocations inside the BLAKE3 product transaction and reports diagnostic geometry.
A 36 GiB qualification failed cleanly: 1,828 guest steps expanded to 9,660,448
BLAKE3 G rows through independent per-word Merkle paths. No new ECDSA timing is
available. Shared-path topology is tested; its prover/AIR integration is pending.


### Shared-path full-width BLAKE3 ECDSA — qualified 2026-09-23

Canonical input, 70 queries / 26 PoW bits, 16 workers; one sample, zero warmups.
These are **dirty ReleaseSafe functionality/resource qualifications**, with other
qualification compilation overlapping, not clean ReleaseFast benchmark results.

| Backend | Complete transaction including fresh verification | Tracked host allocation peak |
| --- | ---: | ---: |
| CPU | 18.414376 s | 3.152 GiB |
| Metal | 18.742173 s | 2.851 GiB |

Both produced the same 3,782,051-byte artifact (3,740,508-byte STARK
payload), passed fresh CSP checks and cross-verification. Metal used 1730 device
dispatches and 233 CPU fallbacks. Shared Merkle paths reduced G rows from
9,660,448 to 489,328; this is not an E2E speedup claim. Previous sub-second results
still describe the old memory commitment route.

[Reports, artifact, receipts and source snapshots](../../autoresearch/notes/2026-09-23-blake3-shared-path-ecdsa/README.md).

Measured process-lifetime physical peaks for these qualification runs were **3.340 GiB CPU / 5.018 GiB Metal**. These include more than the tracked host-allocation table above.


### BLAKE3 default selection (2026-09-23)

The CPU/Metal RISC-V CLI and CSP benchmark runner now default to BLAKE3. The
runner passes the selected suite explicitly on every proving and verification
command, including the ECDSA precompile route. Canonical parameters remain
70 queries / 26 PoW bits. Use `--proof-suite blake2s` explicitly when reproducing
historical measurements or verifying their artifacts. Prior tables above retain
their recorded suites and timings; this default change supplies no new timing
claim. Full-width BLAKE3 uses a different execution-commitment contract from the
historical 0.882-second ECDSA measurement.

Both extension profiles have now qualified canonical recursion on CPU and Metal;
see [extension recursion evidence](../../autoresearch/notes/2026-09-23-blake3-extension-recursion/README.md).
The new default's product build/runtime receipts will be recorded in
[default promotion evidence](../../autoresearch/notes/2026-09-23-blake3-default-promotion/README.md).


The current products now generate BLAKE3 proofs exclusively. Explicit BLAKE2s
selection retains historical verification; reproducing old BLAKE2s benchmark
numbers requires the corresponding historical executable. Current products
reject legacy generation with `LegacyProofGenerationRemoved`. The CSP script's
explicit suite selection is retained for those older executables.


### Full-width BLAKE3 ReleaseFast E2E diagnostic (2026-09-23)

Canonical precompiled ECDSA, CPU, 70 queries / 26 PoW bits, 16 workers,
one warmup and three samples on Apple M5 Max: **11.124404 s median complete
transaction**, including fresh verification (range 11.054630–11.138489 s).
Median witness generation is 2.714516 s; proving 7.414465 s; fresh verification
0.539396 s. Independent retained-artifact verification passed.

This source-pinned dirty-tree diagnostic is not a clean-source suite result and
**does not demonstrate a speedup**. The historical ~0.882 s route used older
execution-memory commitments and a different timing boundary. The 19.74x
reduction in full-width BLAKE3 hash rows is not an E2E comparison against it.

[Raw reports, source snapshot, artifact and reproduction](../../autoresearch/notes/2026-09-23-blake3-releasefast-e2e/README.md).

Metal follow-up under the same settings: **11.100503 s median complete
transaction**, range 11.048685–11.163159 s. It produced exactly the same artifact
as CPU and passed independent CPU verification. Each sample recorded 1,730 GPU
dispatches and 233 CPU fallbacks. These samples show no meaningful backend
latency advantage. Physical process-lifetime peaks: 3.386 GiB CPU / 5.077 GiB
Metal. Raw reports and the authenticated Metal bundle are in the evidence link
above.

Related recursion diagnostic (separate guest-Poseidon fixture, not CSP ECDSA):
a canonical 70/26 leaf-to-parent run with the product SMP allocator and sixteen
CPU workers measured **55.504480 s for the parent**, including 7.003637 s row
preparation and 45.468925 s proving. Leaf proving and compilation are excluded;
one cold sample, fresh verification passed. This establishes a current baseline,
not a recursion speedup. Full phase breakdown and limitations are in the same
evidence report.

Recursion optimization follow-up: bounded parallel lookup registration reduced
the separate canonical parent fixture from **55.068716 s to 42.495006 s median**
in a same-binary comparison (two cold samples per arm, identical verified proof
hashes). This is **1.296x faster / 22.83% less time** within the BLAKE3 path,
not a BLAKE3-versus-Poseidon comparison or a new ECDSA result.
[Profile, paired samples and source](../../autoresearch/notes/2026-09-23-blake3-parent-stage-profile/README.md).


### CSP regression recovery — in progress (2026-09-23)

Bounded parallel lookup counting plus at most 1 GiB of retained coefficients per
proof reduce canonical full-width ECDSA to **6.349760 s CPU / 6.790643 s Metal**
median complete transactions (two cold samples per arm). Same-binary controls
were 11.094906 s / 11.389569 s. All proofs freshly verified with identical proof
bytes and unchanged 70/26 parameters. **Historical approximately 1-second ECDSA
performance is not restored.**

The full diagnostic suite is running. Its first SHA-256/128 CPU case verified at
**85.044773 s**, reaching 36.620 GiB physical memory—substantially worse than the
historical approximately 2.07 s proving result. Do not generalize the ECDSA gain
to recovery of the suite. Full reports and incremental results are retained in
[the CSP regression investigation](../../autoresearch/notes/2026-09-23-blake3-csp-regression/README.md).


### Complete full-width BLAKE3 baseline (2026-09-23)

Apple M5 Max / 64 GiB; ReleaseFast; 16 workers; canonical inputs and ELF routes;
70 queries / 26 PoW bits; one cold sample per case. All 32 proofs independently
verified. Source-pinned dirty-tree diagnostics, not clean-source release admission.
These binaries include parallel lookup counts and bounded coefficient retention,
but precede public-program preprocessing and word-memory commitments.

| Workload | CPU complete seconds | Metal complete seconds |
| --- | ---: | ---: |
| sha256-128 | 85.044773 | 92.526896 |
| sha256-256 | 86.553799 | 93.401719 |
| sha256-512 | 82.243874 | 95.538633 |
| sha256-1024 | 89.891422 | 95.626872 |
| sha256-2048 | 86.786921 | 98.325996 |
| keccak-128 | 82.595478 | 88.866426 |
| keccak-256 | 83.396983 | 89.419049 |
| keccak-512 | 83.656043 | 95.091462 |
| keccak-1024 | 80.313545 | 93.597853 |
| keccak-2048 | 90.055408 | 96.531528 |
| poseidon2_m31-2 | 22.306563 | 21.741383 |
| poseidon2_m31-4 | 22.900549 | 22.719878 |
| poseidon2_m31-8 | 24.552476 | 22.807238 |
| poseidon2_m31-12 | 24.074095 | 23.939452 |
| poseidon2_m31-16 | 26.362065 | 25.248587 |
| ecdsa_secp256k1-32 | 6.767174 | 6.901187 |

ECDSA uses the pinned odd-parity precompile ELF, with 1,828 execution steps.
Raw reports and retained proofs are in the
[complete baseline evidence](../../autoresearch/notes/2026-09-23-blake3-csp-regression/BASELINE_RESULTS.md).
The public-program and word-memory changes are undergoing separate qualification;
this table must not be presented as their performance results.


### Word-memory CSP recovery (2026-09-23)

Source-pinned dirty-tree diagnostics on Apple M5 Max / 64 GiB, ReleaseFast,
16 workers, canonical inputs and ELF routes, 70 queries / 26 PoW bits. One cold
sample per full-suite case, all 32 independently verified. Baseline and candidate
use the same parallel lookup counting and bounded coefficient retention. Candidate
adds authenticated public-program preprocessing and full-word memory commitments;
this is an architectural comparison across explicitly versioned root contracts,
not an isolated hash-algorithm comparison or clean-source release qualification.

| Workload | CPU seconds | CPU speedup | Metal seconds | Metal speedup |
| --- | ---: | ---: | ---: | ---: |
| sha256-128 | 6.074877 | 14.00x | 5.447985 | 16.98x |
| sha256-256 | 6.082393 | 14.23x | 5.613816 | 16.64x |
| sha256-512 | 5.991633 | 13.73x | 5.755869 | 16.60x |
| sha256-1024 | 6.056150 | 14.84x | 6.005951 | 15.92x |
| sha256-2048 | 11.696571 | 7.42x | 10.994910 | 8.94x |
| keccak-128 | 10.955671 | 7.54x | 10.569008 | 8.41x |
| keccak-256 | 11.044977 | 7.55x | 10.578587 | 8.45x |
| keccak-512 | 12.072798 | 6.93x | 10.872646 | 8.75x |
| keccak-1024 | 11.691241 | 6.87x | 11.072095 | 8.45x |
| keccak-2048 | 13.610164 | 6.62x | 11.999579 | 8.04x |
| poseidon2_m31-2 | 2.523052 | 8.84x | 2.382662 | 9.12x |
| poseidon2_m31-4 | 3.039839 | 7.53x | 2.829680 | 8.03x |
| poseidon2_m31-8 | 3.569993 | 6.88x | 3.578220 | 6.37x |
| poseidon2_m31-12 | 4.227793 | 5.69x | 4.020119 | 5.95x |
| poseidon2_m31-16 | 5.258890 | 5.01x | 4.801477 | 5.26x |
| ecdsa_secp256k1-32 | 3.659416 | 1.85x | 3.783270 | 1.82x |

## Matched ECDSA measurements

Separate baseline/candidate/candidate/baseline runs, two cold processes per arm
and backend, with identical stage diagnostics enabled in both arms and each
artifact freshly verified using its matching CLI. Both
use the pinned odd-parity precompile ELF and 1,828 execution steps. Medians:

| Backend | Baseline seconds | Candidate seconds | Speedup |
| --- | ---: | ---: | ---: |
| cpu | 6.902855 | 3.557679 | 1.94x |
| metal | 7.097355 | 3.822391 | 1.86x |

Raw reports include execution, witness, admission, proving, artifact encoding,
fresh verification and process-lifetime memory. Historical 0.881876 s CPU ECDSA
used an earlier execution-memory contract; these results do not redefine that
historical measurement. Recursive qualification is recorded separately and must
not be presented as a matched recursion speedup.

[Source, qualification and raw benchmark evidence](../../autoresearch/notes/2026-09-23-blake3-word-memory/README.md).

## Shared CPU PoW batching checkpoint (2026-09-23)

A subsequent shared CPU prover optimization precomputes the public BLAKE3
prefix and searches four nonces per SIMD batch. Canonical parameters remain
70 queries and 26 PoW bits; the ECDSA precompile and workload are unchanged.
Matched baseline/candidate/candidate/baseline runs (two cold processes per arm,
16 workers, identical diagnostics) measured:

| Measurement | Before | After | Speedup |
| --- | ---: | ---: | ---: |
| CPU ECDSA end-to-end median | 3.129957 s | 2.503791 s | 1.25× |
| CPU PoW stage median | 0.791831 s | 0.148075 s | 5.35× |

All four proofs freshly verify and have identical bytes. Timing differs from
the earlier checkpoint; use the matched baseline above for attribution. This
change applies to the shared CPU pool, not just ECDSA. Metal uses its existing
GPU search and was not remeasured for this CPU-only change. The historical
0.881876-second CPU result has not been recovered.

[Source, tests and raw paired results](../../autoresearch/notes/2026-09-23-blake3-pow-batch/README.md).

## Compact-provider CSP results (2026-09-23)

Apple M5 Max / 64 GiB, ReleaseFast, 16 workers. Three samples per positive
workload, zero explicit warmups; the table reports full end-to-end medians.
All use canonical inputs and 70 queries / 26 PoW bits. Timings include execution,
witness generation, key admission, proving, artifact encoding and fresh verification.
All 32 retained positive proofs and both software rejection proofs independently
verify in separate processes. These are source-pinned local dirty-tree results.

The compact range providers are selected by the shared product request path for
base RISC-V and both extension profiles. ECDSA uses the pinned precompile guest
(1,828 RISC-V steps); its result is not an isolated precompile timing.

| Workload | CPU seconds | Metal seconds |
| --- | ---: | ---: |
| sha256-128 | 4.184246 | 4.098316 |
| sha256-256 | 4.267653 | 4.248658 |
| sha256-512 | 4.620403 | 4.484166 |
| sha256-1024 | 4.769043 | 4.652974 |
| sha256-2048 | 9.430245 | 9.424749 |
| keccak-128 | 9.237800 | 9.031566 |
| keccak-256 | 9.318880 | 9.156700 |
| keccak-512 | 9.569116 | 9.512179 |
| keccak-1024 | 9.883510 | 9.799122 |
| keccak-2048 | 10.832139 | 10.638965 |
| poseidon2_m31-2 | 2.178520 | 1.466811 |
| poseidon2_m31-4 | 1.615393 | 1.500965 |
| poseidon2_m31-8 | 1.939909 | 1.824423 |
| poseidon2_m31-12 | 2.057391 | 2.016272 |
| poseidon2_m31-16 | 2.263120 | 2.317605 |
| ecdsa_secp256k1-32 | 1.480730 | 2.195562 |

Metal ECDSA records 1,666 GPU dispatches and
232 CPU fallbacks per proof. This is the Metal backend's
mixed execution path, not an exclusively GPU proof; raw reports retain
the device counts for every workload and sample.

The bad-signature software fallback also proves rejection: CPU **61.889560 s**,
Metal **62.730673 s** (one sample each). These are
separate rejection proofs, not accelerated ECDSA performance rows.

The historical 0.881876-second CPU ECDSA result also used precompiles.
The current CPU result has not recovered that historical latency.
Compact-child recursion is separately qualified at 70 queries / 26 PoW bits
for base RISC-V, Ethereum and guest Poseidon; those tests are not CSP timings.

[Source, qualification and all raw reports/proofs](../../autoresearch/notes/2026-09-23-compact-range-provider/README.md).

### Comparison with the original CSP qualification

The BLAKE3 candidate remains a substantial regression against the September 21
qualification, even after matching timing scope. Execution + witness + proving
now takes approximately 3.495 s / 3.423 s (CPU / Metal) for SHA-256/128,
8.290 s / 8.077 s for Keccak/128, and 1.262 s / 1.972 s for precompiled ECDSA.
Original corresponding results were 0.776 s / 0.442 s, 0.541 s / 0.415 s, and
0.882 s / 0.864 s. Original means and current medians use different sampling
protocols; these are retained-evidence comparisons, not a new controlled A/B.
See [the regression assessment](../../autoresearch/notes/2026-09-23-compact-range-provider/REGRESSION.md)
for scope, implementation costs and attribution limits.

### Shared parallel hash-interaction follow-up (2026-09-23)

Targeted canonical 70-query / 26-PoW comparisons, three measured samples per arm,
16 workers, with ECDSA precompile enabled. These are complete-transaction medians,
including admission, encoding and fresh verification; this is not a new full suite.

| Workload | CPU serial → parallel | Metal serial → parallel |
| --- | ---: | ---: |
| ecdsa_secp256k1-32 | 1.363 s → 1.179 s | 2.155 s → 1.947 s |
| sha256-128 | 4.146 s → 2.912 s | 4.307 s → 3.004 s |
| keccak-128 | 9.084 s → 7.162 s | 9.055 s → 7.178 s |

All 36 measured proofs verified; every retained arm artifact independently verified
and matched the preceding suite's proof bytes. The shared hash-interaction stage
improved approximately 4.7–6.1×. Original CSP performance remains unrecovered.
[Source, commands, stage profiles and qualification](../../autoresearch/notes/2026-09-23-parallel-hash-interactions/README.md).

### Shared sampled-value follow-up (2026-09-23)

The host PCS now computes canonical barycentric derivative magnitude once per
domain and fills alternating signs, removing repeated derivative evaluation.
The controls below already include parallel hash-interaction generation. Three
samples per arm, canonical 70 queries / 26 PoW bits, 16 workers, ECDSA precompile;
complete-transaction medians in seconds, including fresh verification.

| Workload | CPU control → candidate | Metal control → candidate |
| --- | ---: | ---: |
| ecdsa_secp256k1-32 | 1.193989 → 1.205694 | 1.952832 → 1.968636 |
| sha256-128 | 2.878919 → 2.916228 | 3.001394 → 3.050906 |
| sha256-2048 | 7.552583 → 6.193977 | 7.594417 → 6.267659 |
| keccak-128 | 7.304750 → 5.915772 | 7.219809 → 5.890093 |

All 48 measured proofs verified; all 16 retained artifacts independently verified
and matched the preceding suite proof hashes. The large-domain sampled-value stage
fell by approximately 2.2×. Small-case differences are not established gains or
regressions by this three-sample comparison. This is a targeted qualification,
not a replacement full suite; original CSP performance remains unrecovered.
[Evidence and source provenance](../../autoresearch/notes/2026-09-23-barycentric-parity/README.md).

### Bounded sampled-value scheduling follow-up (2026-09-23)

Large evaluation-form trees now use explicit worker leases for weight and column
evaluation, without overlapping other tree jobs. Small proofs retain the prior
schedule. Three samples per arm, canonical 70 queries / 26 PoW bits, 16 workers,
ECDSA precompile; complete-transaction medians in seconds.

| Workload | CPU control → candidate | Metal control → candidate |
| --- | ---: | ---: |
| ecdsa_secp256k1-32 | 1.175027 → 1.173042 | 1.964997 → 1.949444 |
| sha256-128 | 2.881582 → 2.919877 | 3.068465 → 3.123020 |
| sha256-2048 | 6.121019 → 5.283915 | 6.316128 → 5.476615 |
| keccak-128 | 5.974515 → 5.105069 | 5.968896 → 5.111196 |

All 48 measured proofs verified; all 16 retained arm artifacts independently
verified with unchanged proof bytes. The large-domain sampled-value stage is
approximately 6x faster. Small-case differences are not established performance
changes by this sampling protocol. This targeted comparison does not replace the
full suite; original performance remains unrecovered.
[Evidence, scheduling contract and source](../../autoresearch/notes/2026-09-23-sampled-scheduling/README.md).

### Shared hash-plan reuse and census follow-up (2026-09-23)

Canonical hash plans are shared across routing, sizing and row emission, and
sparse-tree sizing counts canonical templates instead of constructing every row.
Three measured samples per arm, 16 workers, 70 queries / 26 PoW bits, ECDSA
precompile; complete-transaction medians in seconds.

| Workload | CPU control → candidate | Metal control → candidate |
| --- | ---: | ---: |
| ecdsa_secp256k1-32 | 1.171250 → 1.143680 | 1.973087 → 1.892300 |
| sha256-128 | 2.894887 → 2.717680 | 3.039789 → 2.855889 |
| sha256-2048 | 5.205837 → 5.052357 | 5.448285 → 5.269701 |
| keccak-128 | 5.077804 → 4.849863 | 5.067962 → 4.801889 |

All 48 measured proofs verified; every retained arm artifact freshly verified and
matched preceding proof bytes. This is a modest setup improvement and a targeted
comparison, not a new full suite or a recovery of original CSP performance.
[Evidence and source](../../autoresearch/notes/2026-09-23-hash-plan-reuse/README.md).

### Memory-bounded commitment batching follow-up (2026-09-23)

Shared BLAKE3 proving paths now use the PCS default column cap with a 256 MiB
source-plus-LDE staging estimate per batch. The estimate is not a total-memory
limit. This replaces the fixed eight-column batches across base, extension and
native parent paths. Same-binary control uses `STWO_RISCV_SMALL_COMMIT_BATCH=1`.
Three samples per arm, 16 workers, canonical 70 queries / 26 PoW bits, ECDSA
precompile; complete-transaction medians in seconds:

| Workload | CPU control → candidate | Metal control → candidate |
| --- | ---: | ---: |
| ecdsa_secp256k1-32 | 1.137550 → 1.115520 | 1.938628 → 1.602451 |
| sha256-128 | 2.721946 → 2.704167 | 2.896569 → 2.857306 |
| sha256-2048 | 4.999730 → 4.976469 | 5.318041 → 5.304764 |
| keccak-128 | 4.810958 → 4.715889 | 4.913408 → 4.844106 |

All 48 measured proofs verified, and all 16 retained artifacts freshly verified
with unchanged proof bytes. Metal ECDSA dispatches fell 1,666 → 317 and fallback
events 232 → 35; main commitment median fell 0.252 → 0.126 s, interaction
commitment 0.299 → 0.156 s. Other small timing differences are not established
gains. Memory footprints were approximately stable. This targeted experiment
does not replace the full suite; original CSP performance remains unrecovered.
[Evidence, source and qualification](../../autoresearch/notes/2026-09-23-bounded-commit-batches/README.md).

Canonical base child/parent qualification also passed after this change, both at
70 queries / 26 PoW bits with independent verification and transcript replay.
This functional check does not establish a recursion performance improvement.

### Streaming coefficient arena follow-up (2026-09-23)

Shared streaming commitments now preserve coefficient arenas instead of copying
coefficients into separate allocations. Exclusive trees release these buffers
after sampling; shared owners retain their storage. Same-binary control uses
`STWO_ZIG_DETACH_STREAMING_COEFFICIENTS=1`. Three samples per arm, 16 workers,
canonical 70 queries / 26 PoW bits, ECDSA precompile; complete-transaction medians:

| Workload | CPU control → candidate s | Metal control → candidate s |
| --- | ---: | ---: |
| ecdsa_secp256k1-32 | 1.189341 → 1.174051 | 1.519465 → 1.360765 |
| sha256-128 | 2.738117 → 2.799034 | 2.722207 → 2.663813 |
| sha256-2048 | 5.021833 → 5.126343 | 4.850162 → 4.912029 |
| keccak-128 | 4.751197 → 4.773890 | 4.520814 → 4.584280 |

All 48 measured proofs verified and all 16 retained artifacts freshly verified
with unchanged proof bytes. Metal ECDSA sampling fell 0.210 → 0.037 s; its total
fell 10.4%. Other small, mixed differences do not establish performance changes.
Eleven focused ownership tests passed, including allocation-failure cleanup.
This targeted experiment does not replace the full suite; original performance
remains unrecovered.
[Evidence, frozen binaries and source](../../autoresearch/notes/2026-09-23-streaming-coefficient-arenas/README.md).

### Streaming LDE arena follow-up (2026-09-23)

Shared streaming commitments retain LDE preparation arenas with their allocation
alignment, avoiding detachment copies. Explicit file-backed storage retains its
relocation path. Same-binary control uses `STWO_ZIG_DETACH_STREAMING_LDE=1`.
Three measured samples per arm, 16 workers, 70 queries / 26 PoW bits, ECDSA
precompile; complete-transaction medians:

| Workload | CPU control → candidate s | Metal control → candidate s |
| --- | ---: | ---: |
| ecdsa_secp256k1-32 | 1.188439 → 1.194217 | 1.479434 → 1.493740 |
| sha256-128 | 2.802411 → 2.857686 | 2.737400 → 2.636422 |
| sha256-2048 | 5.074681 → 5.160547 | 4.898770 → 4.752674 |
| keccak-128 | 4.818844 → 4.852295 | 4.603177 → 4.406811 |

All 48 measured proofs verified, and all 16 retained artifacts freshly verified
with unchanged proof bytes. Twenty-five focused ownership/storage tests passed.
Larger Metal cases improved roughly 3–4% in this sample; CPU differences were
small and slightly slower, and ECDSA did not improve. These results do not
establish a reliable CPU change or replace the full suite.
A separate diagnostic reduced ECDSA quotient source runs 1,305 → 279 while its
quotient time stayed near 245 ms, ruling out fragmentation as the main remaining
cost in that stage. Original CSP performance remains unrecovered.
[Evidence and source](../../autoresearch/notes/2026-09-23-streaming-lde-arenas/README.md).

Canonical base child/parent qualification also passed after this layout change,
both at 70 queries / 26 PoW bits with independent verification and replay.

### Grouped flat quotient follow-up (2026-09-23)

Flat Metal inputs now use the existing native-height quotient grouping planner
when its checked work reduction and 1 GiB scratch bound admit the shape. The
fused quotient/FRI route also honors the independent CPU-output parity diagnostic.
Three samples per arm, 16 workers, canonical 70 queries / 26 PoW bits, ECDSA
precompile; complete-transaction medians:

| Workload | Metal direct → grouped s |
| --- | ---: |
| ecdsa_secp256k1-32 | 1.484736 → 1.260305 |
| sha256-128 | 2.580736 → 2.596795 |
| sha256-2048 | 4.620741 → 4.673753 |
| keccak-128 | 4.354035 → 4.358828 |

All 24 timed proofs verified and all eight retained artifacts freshly verified
with unchanged proof bytes. Separate ECDSA and SHA-2048 diagnostics compared
every quotient value against CPU. Thirteen focused FRI/parity tests passed.
ECDSA quotient-build/commit fell 0.269 → 0.093 s and complete time fell 15.1%.
Its execution + witness + proving subtotal is 1.072 s, still above the original
0.864 s Metal result. SHA/Keccak total differences are small and mixed.
Process footprints rose approximately 37 MB for ECDSA and 124 MB for the larger
cases because grouping retains a bounded temporary. CPU is unchanged.
This targeted experiment does not replace the full suite; original performance
remains unrecovered.
[Evidence, source and qualification](../../autoresearch/notes/2026-09-23-flat-quotient-groups/README.md).

### Tiled witness projection follow-up (2026-09-23)

The shared small-chunk witness writer now projects bounded 128-row tiles one
column at a time. Same-binary control uses `STWO_ZIG_ROW_MAJOR_WITNESS_COPY=1`.
Three samples per arm, 16 workers, canonical 70 queries / 26 PoW bits, ECDSA
precompile; complete-transaction medians:

| Workload | CPU row-major → tiled s | Metal row-major → tiled s |
| --- | ---: | ---: |
| ecdsa_secp256k1-32 | 1.133750 → 1.111691 | 1.232744 → 1.122357 |
| sha256-128 | 2.669495 → 2.501617 | 2.581133 → 2.412677 |
| sha256-2048 | 4.827809 → 4.867072 | 4.707550 → 4.826029 |
| keccak-128 | 4.600288 → 4.609555 | 4.440568 → 4.411457 |

All 48 measured proofs verified; all 16 retained artifacts freshly verified with
unchanged proof bytes. Focused projection tests cover independent inverse mapping,
wide rows, tile boundaries and untouched padding. ECDSA witness time fell roughly
35%; SHA-128 witness time roughly 19%. Larger-case total differences are small and
mixed. Original-scope ECDSA is now 0.950 s CPU / 0.948 s Metal, still above original
0.882 / 0.864 s. Historical means and current three-sample medians differ in
sampling. This targeted result does not replace the full suite.
[Evidence, source and sampling basis](../../autoresearch/notes/2026-09-23-tiled-witness-copy/README.md).


### Native BLAKE3 four-message experiment — not promoted (2026-09-23)

A shared CPU candidate batched BLAKE3 streaming blocks, lifted leaves, Merkle
parents and first-FRI leaves into four SIMD lanes while retaining standard-library
chunk-tree handling. All 25 focused tests passed, and the final comparison's 24
timed proofs plus eight fresh artifact verifications preserved canonical proof
hashes (70 queries / 26 PoW bits, 16 workers, ECDSA precompile).

CPU control → candidate medians: ECDSA 1.114206 → 1.095495 s; SHA128
2.507878 → 2.465622 s; SHA2048 4.694066 → 4.747142 s; Keccak128
4.360601 → 4.447353 s. Three samples per arm, fixed order, no explicit warmup.
Results are mixed and do not establish an E2E benefit. The candidate was removed
from the production path; the preceding implementation remains in place. No Metal
or recursion speedup is claimed. The original CSP suite remains the target.

[Candidate source, binaries, tests, rejected initial experiment and measurements](../../autoresearch/notes/2026-09-23-blake3-stream4/README.md).


### Shared BLAKE3 bounded-tail prefix reuse — 2026-09-23

The native-hash follow-up found that the previous SIMD experiment missed the
bounded-tail builder used by main commitments. Ordinary BLAKE3 proving replayed
lower-height columns at final-domain multiplicity; recursion already enabled the
existing two-parity-state reuse path. Full-width BLAKE3 now defaults to that same
shared reuse policy. A diagnostic Keccak run reduces repeated tail absorptions
from tens/hundreds of millions to zero per inspected commitment, adding 3.9 MB of
bounded worker cache while preserving prefix and leaf allocations.

| Workload | CPU replay → reuse s | Metal replay → reuse s |
| --- | ---: | ---: |
| ECDSA precompile | 1.122576 → 0.991615 | 1.164118 → 1.024815 |
| SHA-256 128 | 2.477623 → 2.398359 | 2.356127 → 2.269805 |
| SHA-256 2048 | 4.746020 → 4.327492 | 4.503548 → 4.050913 |
| Keccak 128 | 4.496416 → 4.330236 | 4.175478 → 3.996826 |

Complete transaction medians, three samples per arm, no explicit warmup, fixed
order, same binary per backend. Canonical 70 queries / 26 PoW bits and 16 workers.
All 48 timed proofs and all 16 freshly verified retained artifacts passed with
unchanged proof hashes. Focused ReleaseSafe tests compare every BLAKE3 Merkle
layer across budgets, chunk boundaries and workers; all 18 tests in the root pass.
Both ReleaseFast product builds pass.

On the original execution+witness+proving boundary, ECDSA is 0.839459 s CPU /
0.865337 s Metal, versus historical means near 0.882 / 0.864 s. Sampling differs;
this is around the original ECDSA performance range, not evidence that the whole
migration is faster. Large SHA/Keccak cases still regress substantially against
the original suite. No new recursion speedup or full-suite qualification is claimed.

[Source-pinned comparison and verification evidence](../../autoresearch/notes/2026-09-23-blake3-prefix-reuse/README.md).
[Native throughput and commitment geometry investigation](../../autoresearch/notes/2026-09-23-blake3-throughput/README.md).


### Bulk updates in the shared Merkle tail — 2026-09-23

The reused tail builder now gathers up to 64 M31 values in a 256-byte buffer and
absorbs each tile through the existing canonical encoder. This replaces per-word
hash updates in cached groups and final-height columns. Prefix reuse and proof
semantics remain unchanged. The old behavior is available for research through
`STWO_ZIG_SCALAR_TAIL_UPDATES=1`.

| Workload | CPU per-word → bulk s | Metal per-word → bulk s |
| --- | ---: | ---: |
| ECDSA precompile | 1.011363 → 0.981782 | 1.195213 → 1.130256 |
| SHA-256 128 | 2.371110 → 2.318434 | 2.279543 → 2.214367 |
| SHA-256 2048 | 4.168196 → 4.042697 | 4.029157 → 3.882486 |
| Keccak 128 | 4.299384 → 4.114806 | 4.012373 → 3.833193 |

Complete transaction medians; three samples per arm, fixed order, no explicit
warmup, canonical 70 queries / 26 PoW bits, 16 workers and ECDSA precompile.
All 48 timed proofs and 16 freshly verified artifacts match preceding proof
hashes. All 18 focused ReleaseSafe tests and both ReleaseFast product builds pass.
CPU Keccak main/interaction commitment medians fall from 436/472 to 351/390 ms;
this supports a modest shared commitment improvement, not a whole-suite recovery.

Metal ECDSA composition was slower in this session. A subsequent frozen previous
binary check also measured higher composition time, so cross-experiment absolute
ECDSA differences are not an isolated measure of this change. Supplemental
previous/bulk/scalar/previous runs and all primary data are preserved. No new
recursion speedup or full-suite qualification is claimed.

[Source, verification and timing evidence](../../autoresearch/notes/2026-09-23-bulk-tail-updates/README.md).


### Bounded parallel witness-column projection — 2026-09-23

The refreshed post-tail profile still identifies column projection as a substantial
serial witness-preparation cost. Wide chunks now write disjoint column ranges
using at most four leased workers, joining before the source rows are released.
Small chunks and unavailable capacity retain serial execution. Focused tests cover
exact domain mapping, padding, partial/full chunks, uneven splits and occupied-pool
fallback. Both product builds and canonical recursive-parent qualification pass.

| Workload | CPU serial → parallel s | Metal serial → parallel s |
| --- | ---: | ---: |
| ECDSA precompile | 0.995144 → 1.007585 | 1.104352 → 1.092782 |
| SHA-256 128 | 2.337734 → 2.290275 | 2.190672 → 2.132204 |
| SHA-256 2048 | 4.028111 → 3.950977 | 3.787798 → 3.716176 |
| Keccak 128 | 4.024792 → 3.941043 | 3.730229 → 3.644266 |

Complete transaction medians; three samples per arm, fixed order, no explicit
warmup, same binary per backend, 16 workers, canonical 70 queries / 26 PoW bits.
All 48 measured proofs and 16 fresh artifact verifications pass with unchanged
proof hashes. Larger-case witness times fall about 10–13%: CPU Keccak 0.910 →
0.789 s, Metal Keccak 0.887 → 0.779 s. ECDSA differences are small and mixed;
this is not a full-suite qualification or a demonstrated recursion speedup.

The focused canonical base-parent test independently verifies child and parent,
replays the transcript and confirms fixed-plan reuse, worker rekey, and output
lifetime. The wider performance goal remains open.

[Source, timings, tests and parent qualification](../../autoresearch/notes/2026-09-23-parallel-column-projection/README.md).
[Refreshed diagnostic CPU profile](../../autoresearch/notes/2026-09-23-post-tail-profile/README.md).


### Admitted witness-emission plan reuse — 2026-09-23

Witness preparation now passes its source-derived, admitted commitment plan to the
shared emitter instead of allocating and building a duplicate plan. Admission is
still revalidated before row writes. The focused ReleaseSafe integration test
passes column/interaction parity, changed-plan rejection, stale-view invalidation
and successful buffer-reusing retry. No new E2E result is claimed; preceding
benchmark artifacts remain tied to their frozen source snapshots.

[Source and focused validation](../../autoresearch/notes/2026-09-23-admitted-emission-plan/README.md).


### Batched memory-frontier extraction — 2026-09-23

Shared memory commitments now extract frontier subtrees without reconstructing
an entire source tree for each sibling. This removes a sparse-memory scaling
problem; it does not change AIR rows or establish a substantial CSP speedup.

| Workload | CPU control → candidate (s) | Metal control → candidate (s) |
| --- | ---: | ---: |
| ECDSA precompile / 32 | 0.962251 → 0.950485 | 1.013951 → 1.009734 |
| SHA256 / 128 | 2.217996 → 2.225670 | 2.136901 → 2.141443 |
| SHA256 / 2048 | 3.914027 → 3.900223 | 3.846354 → 3.854102 |
| Keccak / 128 | 3.958487 → 3.941130 | 3.798553 → 3.778929 |

Complete-transaction medians of six samples per arm, collected in two blocks
(control/candidate/candidate/control), zero warmups, same binary per backend,
16 workers, canonical 70 queries / 26 PoW bits. All 96 timed proofs and 32 fresh
artifact verifications passed with unchanged full-suite proof hashes. Small mixed
differences do not demonstrate a CSP performance win. Original Poseidon baseline
recovery and full-suite qualification remain unfinished. The separate synthetic
frontier diagnostic must not be presented as a prover speedup.

[Implementation, measurements and scaling diagnostic](../../autoresearch/notes/2026-09-23-batched-memory-frontier/README.md).


### Authenticated GPU BLAKE3 interactions — 2026-09-23

The shared execution and extension prover now generates hash interactions on Metal
using kernels exported from all eight authenticated typed commitment AIRs.
Existing final-layout columns are passed directly; unsupported programs/backends
retain CPU generation. No proof or security-parameter change was made.

| Workload | Metal with CPU interactions → GPU interactions (s) |
| --- | ---: |
| ecdsa_secp256k1-32 | 0.991766 → 0.962908 |
| sha256-128 | 2.072203 → 1.875904 |
| sha256-2048 | 3.630096 → 3.242240 |
| keccak-128 | 3.583377 → 3.154529 |

Complete-transaction medians, six samples per arm, control/candidate/candidate/
control ordering, three samples per block, zero warmups, 16 workers, canonical
70 queries / 26 PoW bits. ECDSA uses the precompile guest. All 48 timed proofs and
16 fresh artifact verifications passed with unchanged retained proof hashes.
Hash-interaction time falls from 0.532 to 0.145 s for SHA256/2048 and from 0.544 to
0.150 s for Keccak/128, including staging and output copies. Larger-case E2E gains
are about 9–12%; this is not a full-suite qualification or recovery of the original
Poseidon SHA/Keccak baseline. No new CPU or recursion timing is claimed.

[Source, AOT authority, safety checks and measured evidence](../../autoresearch/notes/2026-09-23-blake3-device-interactions/README.md).


### Authenticated GPU BLAKE3 composition — 2026-09-23

Core Metal now admits eight generated typed BLAKE3 composition kernels. Streamed
host commitments use bounded exact-domain staging; missing resident handles no
longer disable independently supported framework components. Exact committed
columns avoid another FFT. Proof semantics and security parameters are unchanged.

| Workload | Complete time (s) | Composition (s) | Peak process footprint (GiB) |
| --- | ---: | ---: | ---: |
| ecdsa_secp256k1-32 | 0.974180 → 0.735410 | 0.303651 → 0.065190 | 1.52 → 1.74 |
| sha256-128 | 1.905213 → 1.768019 | 0.272147 → 0.132722 | 4.31 → 4.53 |
| sha256-2048 | 3.254150 → 2.907799 | 0.603590 → 0.255626 | 7.82 → 8.04 |
| keccak-128 | 3.170560 → 2.850824 | 0.573330 → 0.259414 | 7.57 → 7.79 |

Same binary, 16 workers, canonical 70 queries / 26 PoW bits, ECDSA precompile guest.
Six samples per arm, zero warmups, control/candidate/candidate/control blocks.
Both arms retain GPU interactions. Complete transaction medians include admission,
encoding and fresh verification; footprint is the maximum process lifetime peak
across two blocks. All 48 timed proofs and 16 fresh retained verifications pass
with unchanged full-suite proof hashes. The focused safety suite passes 21 tests.
Staging adds about 0.22 GiB; this is not a memory-saving result. Larger SHA/Keccak
baseline recovery, the complete CSP basket and recursion qualification remain open.

[Implementation, scope-aligned proving means and evidence](../../autoresearch/notes/2026-09-23-blake3-device-composition/README.md).


### Bounded GPU streaming leaves — 2026-09-24

Streaming PCS now hashes BLAKE3 leaves on Metal in parity-preserving tiles, with
at most 64 MiB of device scratch per commitment. Small native-height columns pack
into bounded dispatch groups. Parent layers and Merkle ownership remain on the host.
The default route is enabled; `STWO_ZIG_CPU_STREAM_LEAVES=1` restores the control.

| Workload | Complete time (s) | Main commitment (s) | Interaction commitment (s) |
| --- | ---: | ---: | ---: |
| ecdsa_secp256k1-32 | 0.746314 → 0.747673 | 0.088342 → 0.101383 | 0.091969 → 0.116923 |
| sha256-128 | 1.770857 → 1.696814 | 0.154752 → 0.126226 | 0.163059 → 0.135292 |
| sha256-2048 | 2.917031 → 2.790789 | 0.300801 → 0.252144 | 0.325606 → 0.275855 |
| keccak-128 | 2.834862 → 2.694932 | 0.295735 → 0.249275 | 0.324114 → 0.258945 |

Same-binary comparison, six samples per arm, three-sample blocks in
control/candidate/candidate/control order, zero warmups, 16 workers, 70 queries,
26 PoW bits. ECDSA uses the precompile guest. Both arms retain GPU interactions
and composition. Complete times include admission, encoding and fresh verification.
All 48 timed proofs and 16 fresh verifications preserve the earlier proof hashes.

The retained default product also passes all 16 positive CSP cases with one proof
and fresh verification each; those runs qualify correctness rather than full-suite
timing. Peak process footprint is effectively unchanged. Larger-case speedups are
4–5%; ECDSA is flat overall and its commitment stages regress, so this is not an
ECDSA speedup. Full Poseidon-basket recovery and recursion qualification remain open.

[Source, tests, narrower proving metric and complete evidence](../../autoresearch/notes/2026-09-24-bounded-metal-stream-leaves/README.md).


### Overlapped Metal streaming leaves — 2026-09-24

The generic streaming PCS path now overlaps CPU staging with GPU leaf hashing
through two slots and reuses a bounded shared scratch pool. Leaf arenas are
64 MiB; at most two buffers are active or idle, and idle caching is capped at
128 MiB per buffer. Large composition allocations are freed after use.
`STWO_ZIG_SYNC_STREAM_LEAVES=1` selects the synchronous/fresh-allocation control.

| Workload | Complete median (s) | Candidate execution+witness+prove mean (s) | Peak footprint (GiB) |
| --- | ---: | ---: | ---: |
| ECDSA precompile / 32 | 0.762405 → 0.671348 | 0.519456 | 1.74 |
| SHA256 / 128 | 1.704583 → 1.645509 | 1.190503 | 4.53 |
| SHA256 / 2048 | 2.796937 → 2.671250 | 2.061876 | 8.04 |
| Keccak / 128 | 2.719645 → 2.622831 | 2.041129 | 7.79 |

Same binary, six samples per arm, three-sample blocks in control/candidate/
candidate/control order, zero warmups, 16 workers, canonical 70 queries / 26 PoW
bits. Both arms keep GPU leaf hashing, interactions and composition enabled.
Complete time includes admission, encoding and fresh verification; the separate
proving mean matches the historical timing scope, but this short experiment does
not replace the original one-warmup/ten-sample CPU/Metal suite qualification.
All 48 timed proofs and 16 fresh artifact verifications retain prior proof hashes.
The focused ReleaseSafe suite passes 23 tests, including buffer capacity, idle
cache eviction and pending-command cleanup. Footprints are effectively unchanged.
An earlier cache policy increased memory and was rejected; its evidence is retained.

Full Poseidon-basket recovery and recursion qualification remain open. The next
substantial target is the shared G witness and interaction width: the largest SHA
case has a million-row G domain with 124 main and 132 interaction columns.

[Implementation, comparison receipts and rejected-policy evidence](../../autoresearch/notes/2026-09-24-overlapped-metal-stream-leaves/README.md).

The retained default product additionally passes all 16 positive CSP workloads,
with one proof and independent artifact verification per case and unchanged proof
hashes. These basket runs qualify correctness, not statistical timing. The separate
negative guest and CPU/recursive products were not rerun in this checkpoint.


### Shared BLAKE3 G width reduction — 2026-09-24

The shared typed G now uses 16-bit addition limbs and omits redundant range
lookups on reassembled rotation bytes. Main columns fall 124 → 112, interaction
columns 132 → 124, and direct constraints 80 → 56; degree remains two.
Core and recursive Metal catalogs are regenerated under core shader ABI 23.
This changes authenticated AIR identities and proof bytes.

| Workload | Complete median (s) | Peak physical footprint (GiB) | Candidate execution+witness+prove mean (s) |
| --- | ---: | ---: | ---: |
| ECDSA precompile / 32 | 0.676341 → 0.677494 | 1.74 → 1.72 | 0.536322 |
| SHA256 / 128 | 1.633717 → 1.605834 | 4.53 → 4.22 | 1.143242 |
| SHA256 / 2048 | 2.648323 → 2.593264 | 8.04 → 7.53 | 1.978277 |
| Keccak / 128 | 2.581169 → 2.493022 | 7.79 → 7.28 | 1.915439 |

Frozen prior/candidate products, 16 workers, six samples per arm in three-sample
control/candidate/candidate/control blocks, zero warmups. Canonical 70 queries /
26 PoW bits and identical guest/input/output identities. GPU leaf overlap,
interactions and composition remain enabled in both arms. All 48 timed proofs
and 16 separate artifact verifications pass. Candidate proof bytes change with
the authenticated layout and remain deterministic within the arm.

ECDSA time is flat; larger-case complete time improves 1.7–3.4% and peak memory
falls roughly 6–7%. This short comparison does not supersede the original full
CPU/Metal Poseidon suite or establish recursive latency. Six focused arithmetic/
wire tests and eight shader-authority tests pass, including independent arithmetic
comparison and malformed-witness rejection.

[Design reasoning, source pins and raw results](../../autoresearch/notes/2026-09-24-blake3-g-width/README.md).

The retained narrower layout also passes all 16 positive Metal CSP cases with
fresh artifact verification. A canonical CPU child/parent fixture passes at
70 queries / 26 PoW bits, including transcript replay, fixed-plan reuse, rekey
and ownership checks. Whole-tree recursion and the full CPU CSP basket remain
unqualified by this checkpoint. Old-layout artifacts are rejected by admission.

### Shared base-field lookup visitation — 2026-09-24

| Workload | Complete median (s), prior → candidate | Reduction | Candidate execution+witness+prove mean (s) |
| --- | ---: | ---: | ---: |
| ECDSA precompile / 32 | 0.685503 → 0.670229 | 2.2% | 0.526907 |
| SHA256 / 128 | 1.611874 → 1.524971 | 5.4% | 1.061632 |
| SHA256 / 2048 | 2.633728 → 2.533698 | 3.8% | 1.918155 |
| Keccak / 128 | 2.540282 → 2.416209 | 4.9% | 1.837668 |

Frozen prior/candidate ReleaseFast products, 16 workers, canonical 70 queries /
26 PoW bits, blowup 1, fold step 1 and last-layer degree 0. Six samples per arm,
in three-sample control/candidate/candidate/control blocks; zero warmups.
All 48 timed proofs and 16 fresh artifact verifications pass. Every case preserves
guest/input/output/config identity and exactly matches the prior proof bytes.
GPU interactions, composition and overlapped leaves remain enabled in both arms.

Physical peaks are essentially unchanged; exact process-lifetime peaks are in
csp-summary.json. The complete median includes admission, encoding and fresh
verification; the last column matches the historical timing scope. This subset
is not the final one-warmup/ten-sample CPU/Metal basket and does not supersede the
original Poseidon results. The broader baseline gap remains open.

[Source snapshots, raw reports and reproduction scripts](../../autoresearch/notes/2026-09-24-base-lookup-visitation/README.md).

### Bounded and mixed GPU sampling — 2026-09-24

| Workload | Complete median (s), control → candidate | Interpretation | Candidate execution+witness+prove mean (s) |
| --- | ---: | --- | ---: |
| ECDSA precompile / 32 | 0.658878 → 0.656465 | Unchanged route; effectively flat | 0.513404 |
| SHA256 / 128 | 1.496055 → 1.498202 | Unchanged route; effectively flat | 1.042104 |
| SHA256 / 2048 | 2.463129 → 2.352676 | 4.5% faster | 1.755999 |
| Keccak / 128 | 2.384991 → 2.269827 | 4.8% faster | 1.703684 |

Same frozen ReleaseFast binary, 16 workers, canonical 70 queries / 26 PoW bits,
blowup 1, fold step 1 and last-layer degree 0. Six samples per arm, in three-sample
control/candidate/candidate/control blocks; zero warmups. All 48 timed proofs and
16 fresh artifact verifications pass. Guest/input/output/config identity and
proof bytes match the preceding qualified implementation.

SHA256/2048 sampled-value time drops 0.183 to 0.081 s, and Keccak/128 drops
0.180 to 0.076 s. CSP physical peaks remain effectively unchanged. The complete
median includes admission, encoding and fresh verification; the last column
uses the historical execution+witness+prove timing scope.

This four-case Metal comparison does not supersede the full original Poseidon
CPU/Metal basket. Final full-basket qualification, recursive scheduling overlap,
deeper PCS/DEEP fusion, remaining intermediate witness storage and the separately
reviewed recursion-parameter experiment remain open.

[Implementation, memory measurements and raw evidence](../../autoresearch/notes/2026-09-24-host-barycentric-staging/README.md).

### Default bounded-limb BLAKE3 precompile — 2026-09-24

The shared G precompile now uses 90 main columns rather than 112 and is the
ordinary commitment and native-recursion default. Its generated Metal kernels
are refreshed under ABI24; the canonical GPU tree gate requires exact hash-kernel
coverage before proving. No workload-specific fast path or security-parameter
change is involved.

All 32 positive CPU/Metal cases and both bad-signature rejection proofs pass fresh
independent verification. The following are **single-run local qualification**
measurements on M5 Max / ReleaseFast, with zero warmups and canonical 70 queries /
26 PoW bits (blowup 1, fold step 1, last-layer degree 0). The environment requests
16 workers; ECDSA explicitly reports 16. Times are execution + witness + prove,
excluding admission, encoding and verification. Dirty build provenance is retained;
these observations do not supersede the historical ten-sample Poseidon results.

| Workload | CPU (s) | Metal (s) |
| --- | ---: | ---: |
| SHA256 / 128 | 1.434585 | 0.949233 |
| SHA256 / 256 | 1.607891 | 0.986743 |
| SHA256 / 512 | 1.699606 | 1.027794 |
| SHA256 / 1024 | 1.540815 | 1.064012 |
| SHA256 / 2048 | 2.545874 | 1.587823 |
| Keccak / 128 | 2.358332 | 1.474446 |
| Keccak / 256 | 2.491983 | 1.524815 |
| Keccak / 512 | 2.528864 | 1.559536 |
| Keccak / 1024 | 2.921106 | 1.686181 |
| Keccak / 2048 | 2.917653 | 1.820710 |
| Poseidon2 M31 guest / 2 | 0.660669 | 0.394154 |
| Poseidon2 M31 guest / 4 | 0.926435 | 0.504163 |
| Poseidon2 M31 guest / 8 | 0.928582 | 0.617456 |
| Poseidon2 M31 guest / 12 | 1.186136 | 0.727847 |
| Poseidon2 M31 guest / 16 | 1.146036 | 0.838370 |
| ECDSA precompile / 32 | 0.715774 | 0.495651 |

ECDSA uses the pinned 1,828-instruction precompile guest. Including admission,
encoding and fresh verification, its complete times are CPU **0.860641 s** and
Metal **0.646243 s**. The separate invalid-signature software guest proves rejection
in 10.852153 / 8.248589 s (CPU / Metal, execution+witness+prove).

A separate matched canonical four-leaf recursion-tree comparison improves
43.202 → 40.589 s median (6.0%) and 44.452 → 38.975 GB peak physical memory (12.3%).
That is two samples per arm and a tiny six-cycle workload, not a CSP or Ethereum
block timing. The broader performance goal remains open.

[Full timings, raw proofs, provenance, source snapshots and reproduction scripts](../../autoresearch/notes/2026-09-24-blake3-rotate7-limbs/README.md).
