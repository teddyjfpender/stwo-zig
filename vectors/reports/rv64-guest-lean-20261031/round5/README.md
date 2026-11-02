# Round-five complete block proof

Mainnet block **24,628,607**, pinned round-five services guest: all
**104,253,913 instructions** were proved in **25 batch proofs plus a terminal
certificate**. A fresh process verified the complete chain, expected output,
final PC and all 32 registers. Those endpoints also match the archived native
executor and independent Unicorn oracle.

| Metric | Observation |
| --- | ---: |
| Producer wall | 716.99 s (11m57s) |
| Fresh receiver wall | 7.16 s |
| Producer peak RSS | 41.86 GB |
| Producer peak memory footprint | 50.26 GB |
| Receiver peak RSS | 6.09 GB |
| Proof files including terminal | 72,851,424 bytes |
| Keccak / secp ADD / DOUBLE calls | 32,835 / 11,496 / 9,768 |

One isolated run on M5 Max/64 GiB with 16 workers. It uses the legacy CPU,
root-linked RAM, recycler and committed-interaction retirement. There is **no
recursive aggregation, thin-CPU activation, GPU execution or OP derivation
proof**. The guest and allocator/lifetime configuration changed since round one;
the time difference is not an isolated kernel speedup. Memory targets remain
unmet. A 16 GiB free-buffer cache is additional to live proof allocations.

[Complete pins and receiver result](complete-block-isolated-v1.json) include
all proof, receipt and profile identities, input/ELF/executable identities and
native/oracle endpoint checks. [Full per-batch data](batch-bottlenecks-v1.json)
and [CSV](batch-bottlenecks-v1.csv) retain the measured phase details.

## Per-batch costs

Times are seconds. “After native” includes witness/setup/proving/local verification
and publication. FFT and row times are INSIDE composition; interaction children
are INSIDE interaction generation. Never add parent and child measurements.
Sampled per-batch RSS is an observed lower bound; process peaks above are from
`/usr/bin/time`. Source cell totals are cumulative, not resident memory.

| Batch | Steps | Keccak | ADD/DOUBLE | Prove | Composition | Interactions | Witness | Observed RSS GB |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 4,194,303 | 0 | 0/0 | 21.66 | 8.47 | 3.55 | 4.95 | 33.87 |
| 1 | 4,194,303 | 0 | 0/0 | 16.20 | 6.38 | 1.80 | 1.42 | 33.77 |
| 2 | 4,194,303 | 0 | 0/0 | 16.96 | 6.82 | 1.87 | 1.48 | 33.79 |
| 3 | 4,194,303 | 336 | 817/680 | 20.33 | 7.53 | 3.32 | 2.19 | 36.13 |
| 4 | 4,194,303 | 185 | 3,753/3,184 | 25.50 | 8.85 | 7.06 | 2.87 | 39.27 |
| 5 | 4,194,303 | 89 | 3,683/3,152 | 24.97 | 8.65 | 6.97 | 2.76 | 39.15 |
| 6 | 4,194,303 | 7,719 | 1,482/1,252 | 30.56 | 12.33 | 6.53 | 6.92 | 41.86 |
| 7 | 4,194,303 | 3,496 | 0/0 | 26.78 | 12.41 | 3.80 | 4.97 | 40.09 |
| 8 | 4,194,303 | 9,823 | 0/0 | 44.17 | 22.94 | 6.58 | 8.76 | 39.56 |
| 9 | 4,194,303 | 55 | 0/0 | 27.16 | 12.27 | 3.27 | 3.34 | 32.30 |
| 10 | 4,194,303 | 195 | 295/252 | 25.20 | 11.10 | 3.31 | 2.77 | 31.06 |
| 11 | 4,194,303 | 253 | 0/0 | 23.87 | 10.67 | 2.78 | 2.58 | 31.30 |
| 12 | 4,194,303 | 218 | 0/0 | 23.05 | 10.26 | 2.68 | 2.47 | 31.40 |
| 13 | 4,194,303 | 178 | 0/0 | 22.23 | 9.77 | 2.72 | 2.49 | 31.50 |
| 14 | 4,194,303 | 225 | 146/124 | 22.23 | 9.41 | 2.76 | 2.45 | 31.58 |
| 15 | 4,194,303 | 283 | 0/0 | 21.93 | 9.44 | 2.71 | 2.47 | 31.80 |
| 16 | 4,194,303 | 181 | 0/0 | 20.99 | 9.21 | 2.50 | 2.10 | 31.62 |
| 17 | 4,194,303 | 211 | 0/0 | 21.04 | 9.21 | 2.47 | 2.09 | 31.72 |
| 18 | 4,194,303 | 235 | 586/504 | 22.27 | 9.29 | 3.32 | 2.18 | 32.56 |
| 19 | 4,194,303 | 241 | 292/248 | 22.08 | 9.51 | 3.04 | 2.49 | 32.84 |
| 20 | 4,194,303 | 243 | 442/372 | 22.46 | 9.80 | 3.16 | 2.48 | 32.91 |
| 21 | 4,194,303 | 213 | 0/0 | 22.14 | 9.64 | 2.68 | 2.45 | 32.94 |
| 22 | 4,194,303 | 2,884 | 0/0 | 25.38 | 11.20 | 3.74 | 3.96 | 34.79 |
| 23 | 4,194,303 | 3,477 | 0/0 | 26.16 | 11.76 | 3.99 | 4.87 | 37.77 |
| 24 | 3,590,641 | 2,095 | 0/0 | 40.65 | 22.56 | 5.69 | 9.18 | 41.13 |

Across the run, composition took 269.47 s, interaction generation 92.29 s,
main commitment 76.86 s, interaction commitment 34.51 s, FRI build/commit
59.21 s and trace decommitment 41.87 s. The listed top-level phases account
for all but 5.10 s of 615.99 s inside proving. Witness construction adds
86.66 s outside that interval.

CPU FFT/row scopes total 134.03/97.42 s inside composition. Their per-batch
costs vary despite the constant CPU height; timings alone do not establish
whether scheduling, allocator residency, thermal behavior or other contention
causes the variation. A matched retained-packet experiment is needed before
attributing a cause or claiming a fix.

The qualified thin CPU and shared provider prototypes address the representation
cost but are not used by this run. Full ISA, global RAM closure, specialized
recursion and a bounded resident GPU route remain required.

## Opcode census and packing

The bounded packet inspector now reuses admission's existing immutable-ROM
walk to count opcodes. All 65 opcode totals across the 25 retained packets
match the separately recorded native execution summary exactly; packet RAM
root boundaries and step counts match the accepted proof receipts. This is planning evidence, not
a cryptographic opcode-count claim.

[Full census](opcode-census-v1.json) and [CSV](opcode-census-v1.csv).

| Category | Retirements | Share |
| --- | ---: | ---: |
| alu | 28,802,270 | 27.627% |
| binary | 13,582,670 | 13.028% |
| shift | 12,715,792 | 12.197% |
| load_store | 33,457,230 | 32.092% |
| branch | 9,230,005 | 8.853% |
| dynamic_jump | 2,337,567 | 2.242% |
| static_result | 2,454,866 | 2.355% |
| multiplication | 1,610,965 | 1.545% |
| division | 6,270 | 0.006% |
| service | 54,099 | 0.052% |
| fence | 2,179 | 0.002% |

SHIFT is bursty: batches 1/2 contain 1,227,493/1,261,585 calls, exceeding
the proposed log20 capacity. BINARY likewise overflows that capacity in three
batches. A fixed local log20 SHIFT policy needs 27 instances, compared with
13 under ideal whole-execution packing. Sharing a table across independent
proofs additionally requires authenticated shared challenges and claim closure;
immutable setup caching alone does not supply that protocol.

The census report compares explicit padding/table-sharing source-cell models.
Those models exclude common CPU/range work and are not timing forecasts. In
particular, the packed Word16 table candidate still needs physical proof and
complete cost qualification.
