# Shared BLAKE3 bounded-tail prefix reuse

The isolated native-hash investigation (`../2026-09-23-blake3-throughput`) found that the prior SIMD candidate missed the bounded-tail commitment builder. Canonical Keccak geometry retains log-14 prefix states for log-21 leaves. Every standard-library BLAKE3 state is 1,888 bytes; the existing 96 MiB prefix cap prevents retaining higher native-height groups. The default builder therefore replayed many lower-height columns at final-domain multiplicity.

`CommitmentSchemeProver` now defaults full-width BLAKE3 to the existing bounded-tail reuse implementation. It retains two parity states per remaining native height per worker and computes the final-height columns directly. The prefix-state cap, output layout, proof parameters, transcript, hash function and constraints are unchanged. CPU and Metal callers share the policy. Recursion already explicitly enabled this implementation; this experiment does not claim new recursion latency improvements.

`STWO_ZIG_REPLAY_BOUNDED_MERKLE_TAIL=1` selects the preceding replay behavior for same-binary research. Existing non-BLAKE3 suite defaults are unchanged. The extra cache is bounded stack storage, tracked separately in the existing geometry receipt; it is not included in the 96 MiB prefix-state cap.

ReleaseSafe focused tests passed (18 tests in the root). The BLAKE3 test compares every Merkle layer against replay across prefix caps of 2, 8, 64 and 8192 hashers and one/three workers, with heterogeneous heights and leaf payloads crossing chunk boundaries. It also checks rejection of a zero-byte cap, bounded state storage and absorption accounting. Both CPU and Metal ReleaseFast builds passed.

The benchmark uses the same frozen binary per backend for both arms, canonical 70 queries / 26 PoW bits, 16 workers and precompiled ECDSA. Three samples per arm, fixed control/candidate order, no explicit warmup. Complete E2E includes admission, artifact encoding and fresh verification. All 48 measured proofs verified in process; all 16 retained artifacts freshly verified and matched the preceding full-suite proof hashes. This is a targeted comparison, not a fresh full-suite qualification.

| Workload | CPU replay → reuse s | Metal replay → reuse s |
| --- | ---: | ---: |
| ecdsa_secp256k1-32 | 1.122576 → 0.991615 | 1.164118 → 1.024815 |
| sha256-128 | 2.477623 → 2.398359 | 2.356127 → 2.269805 |
| sha256-2048 | 4.746020 → 4.327492 | 4.503548 → 4.050913 |
| keccak-128 | 4.496416 → 4.330236 | 4.175478 → 3.996826 |

On the historical execution+witness+proving boundary, candidate ECDSA medians are CPU 0.839459 s / METAL 0.865337 s. Historical means were approximately 0.882 / 0.864 s; sampling protocols differ. ECDSA is around its original performance range, but large SHA/Keccak workloads remain substantially slower than the original suite. No overall migration speedup or 10× recursion result is claimed.

Frozen source, binaries, Metal bundle, exact commands, raw profiles, reports and retained artifacts accompany this report. The microbenchmark's limited native gains and the missed bounded-tail path explain why the preceding SIMD E2E experiment was not sufficient evidence against optimizing BLAKE3 hashing more broadly.


The follow-up one-sample canonical Keccak geometry run (diagnostic, not included in timings) matches the preceding proof hash. Every inspected commitment reports zero repeated tail absorptions, down from 52,756,480–124,452,864 per commitment in the preceding diagnostic. Prefix-state bytes remain 30,932,992 and final leaf bytes 67,108,864. The additional tail cache is 3,907,584 bytes across 16 workers; it is reported separately from the unchanged prefix-plus-leaf receipt.
