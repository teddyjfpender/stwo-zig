# Actual source-operation census and provider priority

This measurement freshly verifies the existing compact small OP native bundle and builds each complete recursive source graph in trace-only mode. It does not construct recursive Authorities or prove recursive STARKs. All three native fragments pass the fresh receiver. Total time was 4.975 s and peak requested allocation 2.293 GB; source graph construction took 92/111/73 ms for CPU/Keccak/SHA. These are census costs, not proving benchmarks.

| Source | Actual QM31 rows | Full OM31 multiply rows | Inner multiply rows | OM31 add rows |
|---|---:|---:|---:|---:|
| CPU | 4,818,570 | 825,659 (17.1%) | 972,846 (20.2%) | 1,061,874 (22.0%) |
| Keccak | 6,709,108 | 641,743 (9.6%) | 2,010,822 (30.0%) | 2,104,290 (31.4%) |
| SHA | 4,426,562 | 517,567 (11.7%) | 1,131,516 (25.6%) | 1,252,894 (28.3%) |

The combined 15,954,240 QM31 rows include 1,984,969 full-multiply rows: 12.44%. Counters are disjoint and count emitted rows, including structural simplifications, rather than multiplying call counts by a fixed seven. Unclassified rows remain explicit; they include direct QM31 builder work and finalization. CPU phase data independently places DEEP at 2,106,832 rows (43.7% of CPU) and local GKR at 318,917 (6.6%).

A full OM31 multiplication provider could use 24 MAIN, 9 FIXED and 24 OM31 INTER M31 columns: 57 cells per active row, versus 252 across seven generic QM31 rows. This 4.42x local ratio is not a whole-prover prediction. In particular, removing the measured full-multiply rows from Keccak still leaves 6.067M QM31 rows, above the same 2^22 threshold; an added independent component can increase padded work despite reducing active work. CPU and SHA cross that threshold, but source geometry, new provider padding and lifted openings still require complete accounting.

The priorities are therefore structural service-local GKR first (remove the very wide classic interaction commitments/openings, retain global KIO/Wire), then a secure×M31 dot provider that targets the inner-multiply/add chain, then full OM31 multiplication where the remaining census justifies it. The dot proposal must preserve complete QM31 Var tuples for scalar inputs, with all upper coordinates constrained to zero. Its row counts, weights, padding and authentic producer/consumer authority remain an implementation gate.

The diagnostic counter records no new gates, witnesses or transcript messages. Focused ReleaseSafe tests compare control and instrumented complete operation lists and show one full product emits seven rows, one inner product two, and one add two. No production roster, security profile or protected hybrid/tuple authority changed.
