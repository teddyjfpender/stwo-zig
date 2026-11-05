# Poseidon decision measurements — 2026-11-05

Decision: continue the structural Poseidon prototype. Production/default activation remains NO-GO. These measurements do not establish an Ethereum request speedup.

| Evidence | Blake control | Poseidon candidate | Boundary |
|---|---:|---:|---|
| M: RTX5090 resident 479-column × 2^20-row slab, complete retained Merkle tree, median GPU time | 1.36784005 ms | 15.9717121 ms | Matched geometry; numeric kernels, no FFT/transfer/FS/openings |
| M: Same GPU geometry, 128 columns | 0.438656002 ms | 5.33011198 ms | All retained roots repeat and match reference variants |
| M/D: Full CPU leaf padded cells, same five-step JUMPDEST CPU0, b4/q54/P20/fold4 | 554,830,848 | 106,332,160 | Blake native proof and numerical graph accepted; P2 candidate is source-exact AST only |
| M: Accepted mixed P2 physical-PCS + residual Blake full CPU leaf, b4/q54/P0/fold4 | — | 247,794,688 | Numeric and trace-only counts agree; 91,229,184-cell XOR floor remains |
| D: Pure-P2 b2/q108/P20 candidate cells | — | 206,110,720 | Source-exact AST; 1.938× b4 candidate, no accepted native counterpart |

The matched cell candidate is 5.218× smaller (80.84% fewer cells). This is a structural opportunity, not a measured outer proof improvement. The complete Blake control passes fresh native verification/global closure and numerical full-leaf graph validation; its trace-only fingerprint agrees. The pure-P2 alternative deliberately changes GKR/shared/receipt/frame domains and uses all nine M31 digest limbs. It has no compatible native assignment, standalone receiver, accepted recursive proof, or Ethereum root yet. The accepted mixed graph retains Blake in local GKR/shared/manifest/scope/frame, so it cannot represent the all-Poseidon target.

The final arithmetic falsifier uses production common M31 add/multiply and exact 31-bit rotation for power-of-two diagonal coefficients. It reduces the original 479×2^20 prototype from 63.109 ms to 15.972 ms. Across the nine tested width/height classes P2 remains 11.68–13.36× slower than Blake for this hashing operation. Independent official/dense permutation vectors, complete small retained-tree parity, and identical large roots qualify numerical equivalence. The production GPU PCS backend is unchanged. No further kernel tuning is charged to this decision pass.

The source-height prefix-bank work model, calibrated against the final large-tree classes, gives warm native-only P2 hash scenarios of 0.519–1.528 GPU-s for 24628607 and 0.357–1.051 GPU-s for 26235156; Blake scenarios are 0.040–0.120 and 0.028–0.085 GPU-s. These are extrapolation scenarios, not measured block timings or confidence bounds. The exact source-height counts are useful; a P2 prefix-bank runtime is not implemented. FFT/LDE time, FS, PoW, openings, bank I/O, allocations/transfers, witness/setup/verification and the outer proof budget are absent. Own-height LDE work volumes are 40.638/28.488 GiB cold for these blocks, not peak memory requirements.

GO requires preserving this cell opportunity while implementing a genuine matched native P2 protocol and recursive assignment. Production NO-GO remains until native/outer profile authority and framing, prefix-bank GPU PCS/FS, global memory admission, tamper corpus, fresh receivers, and both development-block request measurements close. Do not extrapolate the accepted M6 outer 10.054 GPU-s by the tiny-fixture cell ratio.

Receipts: [matched Blake](matched-blake-cpu-census/receipt.json), [final GPU gate](gpu-commit-common-rotate/receipt.json), [pure P20 AST](full-pure-cpu-matched-p20/receipt.json), [accepted mixed census](full-mixed-cpu-leaf-census/receipt.json). The final GPU directory also contains both explicitly unqualified native hash-budget scenarios.
