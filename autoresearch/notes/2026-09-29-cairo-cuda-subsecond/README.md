# Cairo CUDA H200 subsecond research

Canonical benchmark: four adapted SN PIE inputs; one H200; 70 queries,
26 query PoW bits, 24 interaction PoW bits, blowup/fold 1, last degree 0,
zero channel salt, BLAKE2s. Each proof is accepted by the pinned official
Rust verifier. Timings exclude raw PIE execution and queueing. A warm proof
reuses the process and resident preprocessed material; an adapted-input to
publication interval includes ingress and proof generation.

The first paired experiment compares the retained v5 product with v6, which
uses canonical M31 reduction in the generated AIR and OODS path and
preaggregates each quotient group's constant line term. The four cold trials
followed baseline, candidate, candidate, baseline order. Uninstrumented
proof medians, with independent warm repeats of v6:

| Input | v5 cold proof | v6 cold proof | v6 warm proof | v6 warm adapted to publication | v6 sampled GPU peak |
|---|---:|---:|---:|---:|---:|
| SN PIE 1 | 1.882 s | 1.380 s | 1.299 s | 2.805 s | 101.4 GB |
| SN PIE 2 | 1.366 s | 0.984 s | 0.891 s | 1.969 s | 62.3 GB |
| SN PIE 3 | 1.877 s | 1.374 s | 1.293 s | 2.721 s | 100.2 GB |
| SN PIE 4 | 1.486 s | 1.121 s | 1.037 s | 2.457 s | 80.7 GB |

Nsight Systems PIE 1 shows quotient accumulation falling from 251 to 161 ms;
the two heaviest EC AIR kernels together fall from 323 to 138 ms. Their proof
digests match v5, the device-to-host proof transfer count is one, and the AOT
miss and CPU fallback counts are zero. Profiling runs are excluded from timing.

`summary-v6.json`, `comparison-v6.json`, and `suite-v6.json` hold the compact
receipts. The full logs, proofs and profiles are retained at
`zig-out/cairo-cuda-completion/current/hopper-v6-evidence.tar.gz`, and the exact
v6 source archive is `source-v6.tar.gz` in that directory. The source snapshot
receipt records the verifier, preprocessed coefficients and implementation
identities.

The second paired experiment compares v6 with v7. V7 changes the shared
native M31 helper and canonical Cairo witness arithmetic across the catalogue.
The complete 132-cubin source-authenticated bundle was compiled locally;
all four H200 proofs and every repeat passed the same official verifier.

| Input | v6 cold proof | v7 cold proof | v7 warm proof | v7 warm adapted to publication | v7 sampled GPU peak |
|---|---:|---:|---:|---:|---:|
| SN PIE 1 | 1.381 s | 1.341 s | 1.258 s | 2.739 s | 101.4 GB |
| SN PIE 2 | 0.978 s | 0.954 s | 0.868 s | 1.990 s | 62.3 GB |
| SN PIE 3 | 1.378 s | 1.334 s | 1.251 s | 2.728 s | 100.2 GB |
| SN PIE 4 | 1.123 s | 1.091 s | 1.007 s | 2.452 s | 80.7 GB |

The v7 kernel profile shows the main PIE 1 quotient unchanged at 161 ms;
the leading `n2b_continue` transform fell from 120 to 111 ms. The large
EC witness remained about 127 ms and the mixed BLAKE2s leaf about 88 ms.
V7 improves every measured proof but does not yet achieve subsecond across
the suite. The warm adapted-input interval remains above one second for all
four PIEs, so proof-only and end-to-end targets must remain distinct.

`summary-v7.json`, `comparison-v7.json`, and `suite-v7.json` hold the compact
receipts. The full v7 evidence is retained at
`zig-out/cairo-cuda-completion/current/hopper-v7-evidence.tar.gz`; the exact
source and SM90 cubin archives are `source.tar.gz` and
`native-cubins-v7.tar.gz` in the same directory. The H200 pod was deleted
after both evidence archives were copied locally.

The third paired experiment compares v7 with v8. V8 evaluates quotient
source terms at their native row height, then lifts each height bucket into
the group domain. It reuses the later quotient-result allocation as temporary
storage, so planned arena size and sampled GPU peak do not increase. The
new path is general across the source-height catalogue, and the native CUDA
smoke matches the independent CPU reference for mixed source heights.

| Input | v7 cold proof | v8 cold proof | v8 warm proof | v8 warm adapted to publication | v8 sampled GPU peak |
|---|---:|---:|---:|---:|---:|
| SN PIE 1 | 1.334 s | 1.193 s | 1.108 s | 2.740 s | 101.4 GB |
| SN PIE 2 | 0.948 s | 0.811 s | 0.719 s | 1.964 s | 62.3 GB |
| SN PIE 3 | 1.323 s | 1.190 s | 1.103 s | 2.708 s | 100.2 GB |
| SN PIE 4 | 1.088 s | 0.944 s | 0.858 s | 2.370 s | 80.7 GB |

These are medians of the same-host ABBA cold comparison and the last two
proofs in each three-proof warm process. All 16 paired cold proofs and all
warm repeats passed the pinned official Rust verifier at the canonical
settings above. Every v8 proof digest is byte-for-byte identical to v7. In
the PIE 1 profile, the former 159 ms quotient kernel becomes 19 ms of
native-height accumulation plus 3 ms of lifting; the paired end-to-end proof
gain is about 141 ms. PIEs 1 and 3 remain over one second, so the all-PIE
subsecond goal is not yet qualified. The warm adapted-input interval is also
still above one second for all four PIEs.

`suite-v8.json` and `comparison-v8.json` retain the canonical receipts, and
`profile-*-stats.log` records the kernel attribution. The full proof and
profile evidence is retained at
`zig-out/cairo-cuda-completion/current/hopper-v8-evidence.tar.gz`; the exact
source archive is `source-v8.tar.gz` in that directory.

The retained v9 implementation further reduces the bounded AIR-slice overhead.
The table below is one cold official-verifier-qualified proof per PIE on the
same H200; it is **proof execution and decode**, not witness generation or
adapted-input-to-publication latency.

| Input | v9 cold proof | v9 sampled device peak |
|---|---:|---:|
| SN PIE 1 | 1.183 s | 101.4 GB |
| SN PIE 2 | 0.801 s | 62.3 GB |
| SN PIE 3 | 1.178 s | 100.2 GB |
| SN PIE 4 | 0.940 s | 80.7 GB |

`suite-v9.json` records the four official-verifier receipts and proof hashes.
`hopper-v9-evidence.tar.gz` and `source-v9.tar.gz` in the ignored local
`zig-out/cairo-cuda-completion/current/` directory retain the full evidence
and exact source. PIEs 1 and 3 still exceed one second.

Several follow-up experiments were rejected. Parallel AIR slices using
per-coordinate atomics (v10) verified all four proofs but raised cold times to
1.349/0.902/1.345/1.006 s. A classification-only EC change (v11) did not
alter the actual canonical writer and performed similarly. A single-kernel
scratch reduction (v12/v13) failed OODS equality and is not in the retained
source. Routing canonical EC through the existing native composite (v14)
failed writer ingress because the native EC scratch uses 127 columns over 256
rounds while the authenticated multiplicity feed declares 16 direct words plus
252 rounds of 125 words per EC row. The canonical CUDA feed compiler actually
retains only the 16 direct counters; the native EC writer increments those
counters itself. A guarded native feed-ownership change is now in the working
tree, but it has not passed a full NVIDIA proof or performance comparison and
is not included in the v9 qualified result.

A subsequent local candidate reduces Cairo AIR launch blocks from 256 to 64
threads so the 1,024-row EC placements expose 16 blocks instead of four.
`snapshot-v16-block64.json` records the source identity. Its local compile
and source-admission checks pass, but no H200 timing exists: both a secure and
a community H200 pod failed to become reachable and were deleted. The native
EC ownership candidate also passes focused canonical feed tests locally. Both
changes remain unqualified until the four official proofs verify on NVIDIA;
neither is counted as a speedup here.

The subsequent H200 session qualified the native EC counter ownership and
64-thread AIR launch together (v17). The native EC projective writer reduced
the leading recorded EC witness kernel from 127.5 ms to about 5 ms. Reducing
the bounded AIR slice from 32 to 16 roots (v18) improved the full proofs a
little further. These are one cold proof per input, each accepted by the same
pinned official verifier and security settings listed above:

| Input | v9 | v17 | v18 | v19 (8 roots) | v20 (2-warp AIR) |
|---|---:|---:|---:|---:|---:|
| SN PIE 1 | 1.183 s | 1.049 s | 1.034 s | 1.054 s | 1.043 s |
| SN PIE 2 | 0.801 s | 0.666 s | 0.657 s | 0.671 s | 0.666 s |
| SN PIE 3 | 1.178 s | 1.045 s | 1.030 s | 1.056 s | 1.040 s |
| SN PIE 4 | 0.940 s | 0.827 s | 0.798 s | 0.813 s | 0.797 s |

The v18 source is retained as the best qualified baseline. V19 and v20
verified but regressed PIEs 1 and 3, so their source changes were reverted.
Changing AIR launch blocks alone did not reduce the two largest AIR kernel
times. A profiled two-warp AIR split raised the leading kernel from about
78 ms to 82 ms. The previously qualified transform schedule deliberately
avoids eight-stage continuation because it spills to a local stack, so no
schedule-only change was retained. `suite-v17.json` through `suite-v20.json`
are the compact verifier receipts; ignored `source-v17.tar.gz` through
`source-v20.tar.gz` retain the exact local snapshots; full proof archives are
retained for v17, v18 and v20.
These are proof execution/decode timings; cold adapted-input publication also
includes about four to five seconds of ingress and is not subsecond.

The closing H200 round qualified two more arithmetic variants against the
pinned official Rust verifier. Nine-multiply extension arithmetic (v21) gave
1.037/0.657/1.058/0.790 s for PIEs 1–4. Adding a three-multiply native CM31
formula (v22) gave 1.037/0.657/1.032/0.794 s. Both passed all four proofs
under the canonical security settings, but neither materially improved the
large PIEs over v18. The final source restores v18's arithmetic and AIR AOT;
`suite-v21.json` and `suite-v22.json` retain the rejected variants' verifier
receipts. The H200 pod was deleted after this final comparison.
