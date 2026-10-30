# Shared Keccak: matched complete original proof comparison

All eight runs passed fresh complete verification after producer destruction on the same source-bound binary. The8-call comparison uses an idle-host ABBAAB order with three samples per architecture;32 calls has one paired observation. ELF, statement, output, cycles, window cut, RAM events, program fetches, q70/PoW26 and memory policy match exactly. Proof identities differ by architecture.

| Calls | Baseline request | Shared request | Request speedup | Baseline DEEP/FRI | Shared DEEP/FRI | Baseline composition | Shared composition |
|---|---:|---:|---:|---:|---:|---:|---:|
| 8 | 2.568s | 1.340s | 1.92× | 1.285s | 0.042s | 0.141s | 0.263s |
| 32 | 4.095s | 2.281s | 1.80× | 1.923s | 0.486s | 0.563s | 1.111s |

The shared implementation removes much of the repeated DEEP/FRI work, but composition becomes more expensive. This is a measured tradeoff, not a uniform stage improvement. At8 calls, the full envelope shrinks from12,326,891 to4,498,292 bytes and the allocation peak from308,504,953 to257,444,283 bytes. At32 calls the envelope shrinks from16,423,428 to4,567,172 bytes and peak allocation from489,910,696 to391,652,450 bytes.

PoW must be separated from architectural attribution: at8 calls its median cost is0.464s baseline versus0.675s shared; at32 calls it is0.466s versus0.076s. The secondary per-run request-minus-PoW medians improve2.103→0.664s (3.17×) at8 and3.628→2.205s (1.65×) at32. The primary result remains complete request time, including PoW.

These are Keccak-heavy synthetic programs (38 and110 native cycles), not mixed421 or full Ethereum blocks. See `comparison.json` for exact matched authority fields and `matched-runs.csv`/`matched-stages.csv` for every measurement and report hash.
