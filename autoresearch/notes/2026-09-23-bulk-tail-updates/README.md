# Bulk absorption in the shared reused Merkle tail

After enabling bounded-prefix reuse, the tail builder still called updateLeaf once per field element. The shared reused-tail builder now gathers at most 64 M31 values into a 256-byte stack buffer and calls the existing canonical leaf encoder once per tile. Both cached native-height groups and final-height columns use the helper. Ordering, lifted indices, prefix reuse, constraints and transcript remain unchanged. There is no new compression implementation.

STWO_ZIG_SCALAR_TAIL_UPDATES=1 selects the preceding per-word behavior once per worker for a same-binary comparison. The existing tail cache receipt includes a conservative extra 256 bytes per worker. BLAKE3 focused ReleaseSafe tests pass (18 tests), including every-layer parity across state caps, chunks and workers. Both CPU and Metal ReleaseFast builds passed.

The benchmark uses 70 queries / 26 PoW bits, 16 workers, ECDSA precompile, three samples per arm, fixed order and no explicit warmup. It compares proof hashes against the preceding full suite and freshly verifies each retained artifact. Complete E2E includes admission, encoding and fresh verification; the original benchmark scope is reported separately.


## Canonical comparison

| Workload | CPU per-word → bulk s | Metal per-word → bulk s |
| --- | ---: | ---: |
| ecdsa_secp256k1-32 | 1.011363 → 0.981782 | 1.195213 → 1.130256 |
| sha256-128 | 2.371110 → 2.318434 | 2.279543 → 2.214367 |
| sha256-2048 | 4.168196 → 4.042697 | 4.029157 → 3.882486 |
| keccak-128 | 4.299384 → 4.114806 | 4.012373 → 3.833193 |

All 48 primary timed proofs passed and all 16 retained artifacts freshly verified with unchanged full-suite proof hashes. This is a targeted comparison, not a full-suite qualification or recursion latency benchmark. No compression adapter from the rejected SIMD experiment is enabled.

The commitment-stage medians support the result: CPU Keccak main falls from 0.4362 to 0.3513 s, interaction commitment from 0.4719 to 0.3904 s. Large SHA main falls from 0.4412 to 0.3637 s, interaction commitment from 0.4549 to 0.3856 s. Witness generation and hash interaction construction remain large costs and were not changed here. End-to-end changes are modest, so small differences need larger samples before strong claims.

Original-scope ECDSA (execution+witness+proving) candidate medians:
- cpu: 0.832383 s
- metal: 0.971960 s

The Metal ECDSA absolute time is higher than the preceding experiment. Inspection attributes the difference to the unchanged composition stage, not the modified leaf absorption. A separate same-session frozen-binary check (`ecdsa-recheck/results.json`) runs previous / new bulk / new scalar / previous again. The previous binary also slows in this session, so this does not establish a code-induced composition regression. Preserve these measurements rather than selecting only the fastest historical result. Recheck proof hashes match the full-suite baseline and proofs pass in process. Recheck timings are supplemental and are not mixed into the primary table.

The broader migration still has not recovered the original large SHA/Keccak performance. The persistent recursion goal and its 10× ambition remain open.
