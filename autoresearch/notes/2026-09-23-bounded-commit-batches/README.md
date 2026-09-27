# Memory-bounded streaming commitment batches

The BLAKE3 execution, extension, verifier preparation and native parent paths previously requested eight columns per streaming batch. They now use the shared PCS default cap (64). PCS applies a 256 MiB source-plus-LDE staging estimate to every streaming batch, including ordinary borrowed/owned inputs; previously that byte bound applied only to retained file-backed storage. One oversized column is admitted to guarantee progress. This estimate excludes retained trees and backend scratch and is not a total-memory guarantee.

`STWO_RISCV_SMALL_COMMIT_BATCH=1` selects the old eight-column cap for research. `measure.py` compares that control with the default in the same frozen binary. Both arms include the shared byte-bound implementation. Canonical 70 queries / 26 PoW bits, 16 workers, ECDSA precompile, three measured samples per arm, no explicit warmup, fixed control/candidate order. Complete time includes execution, witness, admission, proving, encoding and fresh verification.

| Case | CPU control → candidate s | Metal control → candidate s |
| --- | ---: | ---: |
| ecdsa_secp256k1-32 | 1.137550 → 1.115520 | 1.938628 → 1.602451 |
| sha256-128 | 2.721946 → 2.704167 | 2.896569 → 2.857306 |
| sha256-2048 | 4.999730 → 4.976469 | 5.318041 → 5.304764 |
| keccak-128 | 4.810958 → 4.715889 | 4.913408 → 4.844106 |

All 48 measured proofs verified in process. All 16 retained arm artifacts freshly verified and matched preceding full-suite proof hashes. Both ReleaseFast builds passed. ReleaseSafe borrowed-streaming tests passed 3/3; retained-column tests passed 14/14, including the byte-bound helper and storage ownership coverage. Canonical base parent qualification passed (`canonical-parent.log`): child and parent both use 70 queries / 26 PoW bits and independently verify. Parent transcript replay, worker rekey, fixed-plan reuse and output lifetime checks pass; allocator peak remains 15,001,575,082 bytes under the 24 GiB cap. This is functional qualification, not a recursion latency benchmark or a repeat of every extension parent.

Metal ECDSA dispatches fell 1666 → 317 and CPU fallback events 232 → 35. Main/interaction commitment phase medians and total latency support a meaningful improvement for this case. Other three-sample timing differences are small and do not establish reliable gains. Physical process lifetime peaks were approximately stable: Metal ECDSA 1.346 → 1.335 GB; Metal Keccak 7.738 → 7.737 GB. These are process footprint measurements, not the staging estimate.

The candidate remains slower than the original CSP qualification. This targeted experiment does not replace the full suite. Proof parameters, full digest binding and protocol semantics are unchanged.

## Next bottlenecks

For candidate ECDSA, the second measured sample spent 0.255 s in Metal sampled-value evaluation versus 0.017 s on CPU, and 0.270 s in Metal FRI quotient build/commit versus 0.062 s on CPU. These are diagnostic samples, not isolated causal A/B comparisons. Investigate shared backend placement, upload/residency and batch execution for those stages; do not assume that fewer dispatches alone solves the remaining gap. Large SHA/Keccak proofs still require structural witness/constraint work.

Source snapshot contains the changed files relative to the preceding hash-plan-reuse experiment. Frozen executables and the matching Metal bundle are retained under `candidate-products`.

Further source inspection: Metal coefficient sampling uses a separate dispatch for each contiguous coefficient run and synchronizes every 128 dispatches (`runtime/polynomial_evaluation.m`). Streaming preparation detaches combined coefficient arenas into individual allocations (`pcs/tree_builders.zig`), potentially fragmenting those runs. The next experiment should measure and fix that ownership/layout interaction while keeping the strict Metal device-execution contract. Attribution remains a hypothesis until isolated.
