# Plain batch stage accounting

This is block 24,628,607, packet 0: 4,194,303 guest instructions, no services.
The new route proves a closed genesis prefix, not the complete Ethereum block.
Telemetry source is commit `5b8be3eb1`; the optional allocator probe changes
operational allocation only. All probes retain native proof SHA256
`46d18eef8e69bea3839e832b3828d7050fbd0dd8cdc2b26b34af59fa3b8b407c`.

`paired-v7.json` records the fresh-process legacy/new comparison, exact input
receipt hashes, per-stage process usage and logical cells, active/padded rows,
opening masks, native evaluation and hash-tree models. Missing legacy witness
resource counters are explicitly unknown. Whole-process intervals include all
threads. Children, adopted coset intervals and parents must not be added together.

| Measurement | Legacy | Word16 |
|---|---:|---:|
| Whole-process wall | 29.28 s | 15.54 s |
| Whole-process user CPU | 189.66 s | 61.04 s |
| Whole-process system CPU | 6.21 s | 21.74 s |
| MAIN source cells | 2,001,831,312 | 593,751,776 |
| INTER source cells | 712,893,184 | 659,524,096 |
| MAIN streaming batches | 54 | 203 |
| INTER streaming batches | 78 | 80 |

The source reduction is 2.166x overall, but 3.371x for MAIN and only 1.081x for
INTER. Wall speedup is 1.884x. Aggregate CPU work falls 2.366x: the wall/cell gap
is not evidence of more arithmetic per cell. Word16 interaction generation
accounts for 17.22 of its 21.74 system seconds, including 13.26 in memory
interactions. Those intervals also record disproportionate minor faults.

## Operational allocator probes

`allocator-probes-v1.json` retains the cap, counters, measured RSS, stage usages
and exact proof parity. Fresh independent receivers accepted both cached probes.

| Free-cache cap | Wall | System CPU | Peak RSS |
|---|---:|---:|---:|
| bypass | 15.54 s | 21.74 s | 11.60 GB |
| 4 GiB | 14.52 s | 21.13 s | 15.78 GB |
| 16 GiB | 15.18 s | 18.66 s | 24.63 GB |

These are single diagnostic observations, not a speedup distribution. The
16 GiB run overlapped a small focused compile. No default allocator change is
qualified. The benchmark accepts a final `--recycler-cap-mib=N`; zero bypasses
the wrapper. The cap bounds cached free blocks, not live allocations or RSS.
Ownership transfer and page-scatter improvements require separate measurement.

## Geometry corrections

The retained per-chip model is `per-chip-v6.json`; v7 has the same layout.
The packed SHIFT table has 65,536 physical rows, 18/16/36 FIXED/MAIN/INTER
columns, and 4,587,520 total cells. Its 1,048,576 semantic facts are packed.
U16/U8/AND/SHIFT fixed commitments are retained per immutable setup identity;
request multiplicities and interactions remain request dependent.

Incremental lifted hashing processes column payloads at native LDE heights,
then copies hasher states during lifting and finalizes at the largest height.
Charging every column's payload at the largest height is incorrect. Maximum
height state bandwidth, final leaf hashes and parents remain real costs.

Empty DIV has only 36,672 source cells but 1,151 of 2,464 logical component
OODS samples. Its opening width deserves measurement independent of source cells.
Current tiny MUL/DIV force a common composition split of two; other native AIR
matrices still evaluate at their own 2n domains. Weighted secure quotients are
extended into the common bound. A degree-3 rewrite cannot be advertised as
halving all existing native composition work.

Merged interaction estimates must use actual fractions and degrees. The CPU's
40 columns already contain one prefix and nine inverses. Quadratic REG,
FUNCTION and ROM denominators cannot be blindly paired at degree three.
The LS relation has 44 affine queries, not fifteen, and its RAM debt remains
separate from local lookup closure in the global protocol. Current paired
Keccak is 1923/2596; standalone quartet batching is 1923/1948 at degree five,
not an unchanged degree-three alternative.

## Reproduce accounting

```sh
python3 autoresearch/benchmarks/rv64-stage-accounting/summarize.py \
  --word16 /tmp/rv64-word16-execution-real-packet0-v7-process \
  --legacy-report /tmp/rv64-word16-paired-legacy-process-v2.stdout.json \
  --legacy-stages /tmp/rv64-word16-paired-legacy-process-v2/batch-000000.stages.json \
  --chip-accounting vectors/reports/rv64-word16-execution-20261031/stage-accounting/per-chip-v6.json \
  --word16-time /tmp/rv64-word16-execution-real-packet0-v7-process.time \
  --legacy-time /tmp/rv64-word16-paired-legacy-process-v2.time \
  --out /tmp/paired-stage-accounting.json
```

Cell and hash counts are logical cost models, not measured traffic, hardware
compression counts, a whole-block throughput projection or a GPU prediction.
Query70/PoW26 receipts remain nominal qualifications, not a whole-protocol
128-bit security claim. GPU/circuit throughput does not establish RV64 cells/s.
