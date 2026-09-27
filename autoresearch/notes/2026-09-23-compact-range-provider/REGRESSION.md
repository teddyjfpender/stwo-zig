# CSP regression against the original qualification

The compact-provider candidate has not recovered the original CSP performance.
Gains against earlier, slower BLAKE3 checkpoints are not evidence that migration
improved end-to-end performance.

Original: `vectors/reports/recursive-product-20260921/csp-accelerated-suite-v1/README.md`.
Current: `suite-cpu/results.json` and `suite-metal/results.json` in this directory.
Both use canonical 70 queries / 26 PoW bits; both ECDSA cases use the precompile.
Original figures below are ten-sample means after one warmup; current figures
are medians of three samples without explicit warmup. They are not a controlled
same-run A/B experiment. Normalize current scope to execution + witness + proving,
excluding admission, encoding and fresh verification, to match the original
reported scope as closely as the retained phase data permits.

| Case | Original CPU s | Current CPU s | Original Metal s | Current Metal s |
| --- | ---: | ---: | ---: | ---: |
| SHA-256 / 128 | 0.776 | 3.495 | 0.442 | 3.423 |
| Keccak / 128 | 0.541 | 8.290 | 0.415 | 8.077 |
| ECDSA precompile | 0.882 | 1.262 | 0.864 | 1.972 |

Thus the approximate CPU regressions are 4.5x, 15.3x and 1.43x;
Metal regressions are 7.7x, 19.5x and 2.28x. Removing newly reported overhead
does not remove the regression. CPU Keccak proving alone is 7.170 s.

## Concrete implementation costs and attribution limits

The current shared BLAKE3 G AIR has 124 main columns, 16 fixed columns and
132 interaction columns (33 interaction batches for 66 relation events).
This is 272 field columns per padded G row, before low-degree extension,
commitment buffers, composition work and other components. A domain of 2^19
therefore accounts for 544 MiB of raw four-byte field cells in this component
alone; 2^16 accounts for 68 MiB. This is a geometry calculation, not a measured
allocation peak or a runtime attribution. Reducing G row count alone does not
establish a cheap proof when each row is this wide.

Retained Metal ECDSA reports also show 1,666 dispatches and 232 CPU fallbacks
per proof, versus the original report's 103 dispatches and 4 fallbacks.
That is evidence of substantially changed backend execution, not a measured
claim that dispatch overhead alone accounts for the regression.

Host hash throughput and the cost of proving the hash operations must be
measured separately. Full-width memory commitments and their typed hash/wire
relations impose proof work that faster native BLAKE3 hashing does not eliminate.
The current evidence does not isolate every stage's share of this overhead.
Next isolate G interaction/composition/commitment costs and the Metal fallback
sites before choosing another structural change. Preserve full digest binding,
canonical parameters and independent verification throughout.

## Qualification checkpoint

The compact-provider adjacent base and Ethereum segment tests passed, including
base parent-of-parent verification (`compact-segment-aggregation.log`). These
segment tests use diagnostic 8-query / zero-PoW parameters and establish
functional coverage, not canonical performance. Canonical standalone parent
qualification is recorded separately in the parent logs.
