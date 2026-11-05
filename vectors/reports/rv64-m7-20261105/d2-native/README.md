# Experimental raw-Blake D2 native profile

Status: scoped native proof gates and exact constructed recursive graph census PASS. No Ethereum, GPU performance or outer-proof claim.

The explicit `d2_native_b4_q54_p20_fold4` runtime profile uses log-blowup2 (4× LDE),54 queries,P20 and fold-step4. It has a new experimental domain, pins the real ten-relation roster and separate candidate specification, and leaves both historical identity goldens and the default profile unchanged. The native receiver derives source bounds before checking the D2-aware conditional algebraic/raw-hash budget. The128-bit FRI figure remains conjectured; no whole-protocol certificate is issued.

Two actual CPU proofs execute a five-instruction jumpdest/cross-epoch-RAM fixture. Independently reconstructed receiver keys accept both, durable bundle write/reload accepts, and default-profile/query-count/PoW mutants reject. The full native D2 test target and all profile/default/golden controls pass. An initial test-only O_PATH directory caused fsync failure; the corrected readable test directory preserves durable fsync and passes. Its negative log is retained.

| Exact classic OM31 graph quantity | Default q108,b2 | D2 q54,b4 |
|---|---:|---:|
| Variables | 12,670,677 | 7,645,524 |
| FIXED cells | 87,081,728 | 47,235,840 |
| MAIN cells | 293,552,384 | 159,334,656 |
| INTER cells | 599,918,592 | 348,260,352 |
| Total padded cells | 980,552,704 | 554,830,848 |
| Raw Blake G rows | 2,295,040 | 1,339,760 |
| Padded Blake G rows | 2^22 | 2^21 |
| Padded QM31 rows | 2^22 | 2^21 |

This is a43.4165% total-cell reduction on the first CPU proof of the same fixture, after both native bundles independently verified. The actual trace-only verifier graph is finalized; shared padding, preprocessed column layout and classic OM31 widths supply the exact cell count. It includes native local GKR, receipt, physical PCS and frame output. It does not instantiate an outer proof, full Ethereum source classes, fused/diet AIR or Poseidon. Same-layout D2 native LDE work doubles, so this result does not establish runtime or peak-memory improvement. The source layout report describes the dev-block memory tradeoff and planner prerequisite.

`receipt.json` pins source and test executable hashes. `census.json` carries all eleven component geometries. Raw logs preserve the executed gates; there are no synthetic timing or unmeasured proof-size entries.
