# Preserve streaming coefficient arenas

Streaming tree preparation previously detached both LDE and coefficient backing into separate column allocations. Metal sampling groups contiguous coefficient runs into dispatches, so this discarded useful batch layout and copied data already computed by the shared preparation path.

The streaming builder now detaches only LDE backing, retains coefficient buffer owners alongside the coefficient views, and transfers those buffers into the committed tree. Allocation failures clean up the original owner or builder, including failure during final tree append. Exclusive trees release coefficient backing after sampling; shared trees retain their owning storage for subsequent proofs. The research control `STWO_ZIG_DETACH_STREAMING_COEFFICIENTS=1` uses the prior detached layout.

ReleaseSafe focused ownership qualification passed 11/11 tests: real FFT/Merkle parity, value parity across mixed-height columns and batches, allocation-failure injection, borrowed caller ownership and shared tree lifetimes. The streaming fixture explicitly checks borrowed coefficient views and release of their backing. CPU and Metal ReleaseFast builds passed, with the matching 177-kernel Metal bundle.

`measure.py` uses the same frozen binary for both arms, canonical 70 queries / 26 PoW bits, 16 workers and the ECDSA precompile. It compares three samples per arm without explicit warmup, checks prior suite proof hashes and freshly verifies each retained artifact. Both arms use the previously qualified memory-bounded commitment batching policy. Results are targeted complete-transaction timings, not a replacement full CSP suite.

| Workload | CPU control → candidate s | Metal control → candidate s |
| --- | ---: | ---: |
| ecdsa_secp256k1-32 | 1.189341 → 1.174051 | 1.519465 → 1.360765 |
| sha256-128 | 2.738117 → 2.799034 | 2.722207 → 2.663813 |
| sha256-2048 | 5.021833 → 5.126343 | 4.850162 → 4.912029 |
| keccak-128 | 4.751197 → 4.773890 | 4.520814 → 4.584280 |

All 48 measured proofs verified in process; all 16 retained arm artifacts freshly verified with unchanged prior-suite proof hashes. Metal ECDSA sampled-value medians fell 0.210180 → 0.037232 s (5.65x), while complete latency fell 1.519465 → 1.360765 s (10.4%). Other small, mixed timing differences do not establish gains. CPU preparation uses in-place coefficients where supported, so the arena-preserving path is not expected to improve every backend. Original CSP performance remains unrecovered.

A separate one-sample diagnostic (`metal-ecdsa-quotient-profile.*`) verified in process and matched the canonical proof hash. It reports 238,013,312 raw quotient source bytes, 14,246 columns, 44,866 views, 1,312 source runs, zero resident sources, 25 batches and 524,288 rows on the GPU-flat path. Quotient GPU time was 195.623 ms, wall time 244.490 ms. This diagnostic is excluded from performance medians. Investigate LDE arena preservation and quotient source execution next; these counters are not an isolated causal attribution.

Native BLAKE3 parent trace commits explicitly disable coefficient retention, so this change adds no retained coefficient storage there. Focused shared-owner and streaming allocation-failure tests cover the modified ownership paths; a fresh canonical parent performance result is not claimed.

