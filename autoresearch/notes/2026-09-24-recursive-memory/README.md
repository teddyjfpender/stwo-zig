# Recursive memory scaling — 2026-09-24

CPU qualification of accelerated Ethereum authentication followed by a verified
recursive root. This is one executed leaf plus its recursive wrapper, not a full
Ethereum block, EVM execution, or a GPU measurement.

## Results

Final results are generated from retained `*-prove-balanced.invocation.json`,
reports and `/usr/bin/time -l` logs by `python3 summarize.py`; see `summary.json`.
The original comparison is in `../2026-09-24-ethereum-recursive-comparison/RESULTS.md`.

| Transactions | Verified root | Peak process GiB | Worker peak GiB | End-to-end seconds |
| ---: | :---: | ---: | ---: | ---: |
| 1 | Yes | 16.02 | 16.02 | 31.01 |
| 16 | Yes | 23.15 | 23.11 | 52.63 |
| 32 | Yes | 31.19 | 30.28 | 73.96 |
| 64 | Yes | 55.42 | 47.85 | 143.31 |

Original 16-transaction run: **failed** at 55.68 GiB process footprint. The
final 16-transaction run completes at **23.15 GiB**, a **58.4% reduction**.
The original 1-transaction run completed at 30.44 GiB; final footprint is
16.02 GiB (**47.4% lower**). At 64 transactions the final worker uses
47.85/48 GiB, leaving only about 149 MiB of tracked allocation headroom.

All final runs retain **70 queries, 26 PoW bits, 16 requested CPU workers and a
48 GiB worker allocation limit**. Each successful case checks its public output
against the retained oracle, encodes/decodes its proof, independently verifies
the recursive node, and checks root completion. These are single observations,
not medians. Process footprint and worker allocation peak measure different
things; worker accounting is not a whole-process or future VRAM limit.

## Implementation

- Typed BLAKE3 G: 90 → 82 main columns and 112 → 80 authenticated interaction
  columns. Fused three-input additions retain boolean carry checks, exclude
  carry 3, and stay below the M31 modulus. Existing XOR lookups supply byte
  bounds previously requested redundantly. Arithmetic degree is unchanged.
- Four independently sized G components bound the largest domain and reduce
  power-of-two padding. The largest permitted partition is selected from
  `ceil(active_rows / 4)`; a greedy power-of-two placement fills the components.
  Logical rows, fixed schedules and wire identities are preserved. Allocation
  failure preserves the source, and repeated finalization is idempotent.
- One-shot parent workers and native/execution/tree pipelines release source
  rows after interaction generation. Reusable borrowed worker APIs remain.
- Memory-custody preparation reconstructs one trusted update at a time and
  retains only fixed metadata rather than accumulating full trusted witnesses.
- CPU PCS and FRI commitments drop four bottom Merkle layers on large domains,
  reconstructing queried paths exactly from retained committed columns. The
  streaming PCS path applies the same policy. Small commitments are unchanged.
- Core barycentric openings retain base-field points and two alternating
  derivative constants: context storage drops from 48 to 8 bytes per point
  (plus two constants); scratch drops from 48 to 32 bytes per point.

The AIR roster and semantic digests change, so keys must be regenerated.
`deriveKey*` finalizes the preparation in place before deriving its identity.
Historical proofs require their historical keys/verifier; no compatibility
claim is made across this AIR change. The opening-storage change alone was
separately shown to preserve the 16-transaction proof byte for byte.

## Scope and remaining scaling limits

The qualified sizes are 1, 16, 32 and 64 transactions. Four G components have a
structural ceiling of 4 × 2^24 active rows; this does not promise that this host
can prove that ceiling. Other component domains and the explicit host budget
remain limits. At 64 the worker is close to its cap. Larger jobs still need
budget admission and segmentation; this change does not establish unbounded
constant-memory proving. Direct emission into partitions could further reduce
preparation peak, which still temporarily holds unpartitioned rows.

Original 1/16 guest binaries and inputs are retained for direct comparison.
32/64 use the expanded guest (16 KiB input region, maximum batch 64); the runner
pins ELF, binary, input and oracle hashes for every invocation. The operation
remains EIP-1559 authentication with Keccak and elliptic-curve precompiles.

## Validation and reproduction

Focused evidence: `test.log` (224 hash/reference/mutation/committed-proof tests),
`test-barycentric-final.log` (101 opening/allocation/work-pool checks),
`test-merkle.log` (17 exact Merkle decommitment checks for both hashers),
`test-storage.log`, `test-append.log`, `test-common.log`,
`test-partition-balanced.log`, and `test-tree-final.log` (8 recursive aggregation checks).
Partition tests check row permutation, padding, bounded domain sizing,
idempotence and allocation-failure rollback. Tree qualification exercises
actual recursive aggregation and pipeline ownership using its diagnostic
profile; canonical security is exercised by the recorded benchmark roots.

Build and proof scripts share `/tmp/stwo-zig-build.lock` to avoid competing
builds/proofs. Run from the repository root:

```sh
python3 autoresearch/notes/2026-09-24-recursive-memory/build_local.py
python3 autoresearch/notes/2026-09-24-recursive-memory/run.py local batch-64 prove FRESH_LABEL
python3 autoresearch/notes/2026-09-24-recursive-memory/summarize.py FRESH_LABEL
```

Use a fresh label: evidence files cannot be overwritten. `local-host-balanced`
is the measured executable; `balanced-source.tar.gz` records the source files,
and `SHA256SUMS` pins retained evidence. Test-only and documentation fixes after
the measured build are identified in provenance. Previous failed attempts are
retained and excluded from successful timing claims. See `INITIAL-NOTES.md`
for the intermediate experiments.

The first balanced 64 run overlapped briefly with a subsequently stopped source
archive operation, so its time is not an isolated performance benchmark. The
process/worker memory figures belong to the prover process; no speedup claim is
based on that 64 timing.
