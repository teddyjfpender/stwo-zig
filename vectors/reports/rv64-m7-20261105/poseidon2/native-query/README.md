# P2v2 complete native query graph [M scoped]

The pod gate constructs a genuine RV64 ALU-only OM31 native proof with Poseidon2 v2 PCS and Fiat-Shamir, accepts it with the native verifier while capturing the transcript, then constrains the complete PCS/FRI query verifier with dedicated Poseidon rows. Both FRI folds 1 and 4 accept and reproduce the final native transcript exactly. Changing a guessed authentication-path word fails circuit validation.

| Measured geometry | Fold 1 | Fold 4 |
|---|---:|---:|
| Poseidon permutations | 236 | 184 |
| Circuit variables | 18,940 | 17,450 |
| Classic padded trace cells, all five components | 1,442,544 | 1,438,960 |
| Hybrid interaction model cells [E, unproved] | 1,397,488 | 1,393,904 |

The full range-check table and every component padding rung are charged. This fixture uses a small ALU-only AIR, two queries and P0: it establishes verifier compatibility, not a complete CPU execution, production security, recursive proof, Ethereum request or comparative performance result. It does not establish a 3-5x reduction on the real leaf graph.

The generic proof-capture conversion preserves legacy Blake aliases. The actual legacy OM31 PCS/capture/CPU wrap regression passed after the refactor (`test-riscv64-om31-native-pcs`, 2/2 build steps, 6m, 5G peak build RSS). The Poseidon query gate passed (`test-riscv64-poseidon2-gadgets`, 2/2 steps, 39s, 727M peak build RSS). Build duration is not proof latency. These are CPU gates on the GPU pod; no GPU performance is claimed. Raw logs and exact source SHA-256 values are adjacent.
