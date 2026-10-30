# RV64 prover performance: second round, 2026-10-30

All 17 complete CSP cases pass native proving, independent ELF/input/output
binding and fresh-process receiver verification. Statements, claims and proof
bytes match the first performance round exactly. Instruction counts, geometry,
70 FRI queries, 26 PoW bits and the maximum 18-worker pool are unchanged.

## Complete-job measurements

ReleaseFast, Zig 0.15.2, 64 GiB Apple Mac17,7. Process wall time includes
capture, setup, witness, proving, codec, verification and startup. These are
single matched suite runs; they are not a latency distribution.

| Workload | Previous total | This round | Ratio |
| --- | ---: | ---: | ---: |
| SHA-256 / 2048 bytes | 2.211 s | 1.985 s | 1.11x |
| Keccak / 2048 bytes | 1.137 s | 1.048 s | 1.08x |
| Poseidon M31 / 16 | 9.174 s | 8.888 s | 1.03x |
| ECDSA / valid | 20.624 s | 19.594 s | 1.05x |
| ECDSA / invalid | 20.946 s | 19.610 s | 1.07x |

[All 17 rows and before/after stages](comparison.csv), [strict parity gate](comparison.json),
[final raw suite](optimized-final.json). First cold Keccak-128 wall time rose
from 1.736 to 1.849 seconds; the original measurement is retained. Startup and
run variation must not be presented as arithmetic improvements. An additional
isolated final ECDSA run took 18.058 seconds, illustrating this variation.

## Retained implementation

1. Memory constraints share expected load bytes/sign fill by width and factor
   unchanged store bytes. All 154 ordered residuals match the old evaluator for
   arbitrary QM31 values, including dense, unaligned and out-of-width selectors.
   Both domain and OODS use this one polynomial authority. An isolated sample
   reduced CPU rows from 10.211 to 8.424 seconds and composition from 12.584 to
   10.575 seconds; these are separate runs from the suite table.
2. The main witness allocation reserves a provider tail. At commitment, only
   provider multiplicities are copied into that tail; PCS adopts the original
   CPU matrix as coefficients through its existing owned API. Provider originals
   remain live for post-challenge closure. Header construction happens once.
   Allocator mismatch fails before mutation; allocation/shape failures before
   transfer retain ownership, and the consuming PCS call owns cleanup afterward.
   The backend uses its existing uniform arena/preparation policy, with no
   frontend column-count thresholds and no core PCS changes.
3. The comparison tool now retains both versions' phase costs and memory.
   Missing instrumentation remains unknown, rather than a zero-duration phase.
   Generic PCS diagnostics cover widths 2/64/65/127/128, actual mixed component
   heights, coefficient aliasing, roots, transcripts and authenticated openings.

In the full-suite ECDSA sample, main commitment fell from 2.566 to 1.612 seconds;
composition fell from 12.275 to 11.780 seconds. Interaction commitment rose
from 1.292 to 1.580 seconds. The table reports the complete job, including that
regression. Peak caller allocation remains **12.78 GiB**: composition, not main
commitment, determines the whole-job peak. Worker stacks and OS allocations are
outside caller accounting. No wide trace or quotient file is written.

The isolated eight-worker generic PCS study reduced commitment-stage charged
peak from 9.44 to 5.32 GB and commitment time from 2.94 to 2.30 seconds. It is a
commitment-only experiment, not a whole-proof memory or speed claim.
[Raw study and qualification controls](pcs-owned-study.json).

## Rejected work and remaining cost

Dynamic row tiles were equal in the first pair and slower in the repeat;
static ranges remain. A weighted-Sink exact-zero shortcut also reversed its
initial gain in a warmed pair and was removed. Additional runtime paths are
not retained for noisy improvements. The paired raw evidence is retained.

A proposed division-tail omission was rejected on polynomial grounds:
forbidden instruction selectors remain committed coordinates at OODS points.
Separate zero constraints do not make all dependent polynomials identically
zero. A regression test preserves this counterexample.

The CPU still commits 519 main and 260 interaction columns at 2^21 rows for
ECDSA. CPU constraint evaluation and expanded coset storage remain the largest
costs. [Geometry accounting](geometry-model.json) separates cells, provider
sizes and sign-bit pressure. Changing that representation needs a new complete
cost and soundness qualification; this round makes no such layout claim.

This remains native RV64IM CSP qualification. It does not establish full Rust
verifier compatibility, OP guest runtime support or Ethereum block proving.
