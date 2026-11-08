# Recursive basket: 9 independently accepted blocks

Nine of the fifteen blocks have fresh independent native and complete recursive-root acceptance. The native-only basket is separately15/15 accepted. Six large recursive cases remain; this is a functional checkpoint, not the completed performance basket.

All rows use the same guest/profile and the b8d7096a/60968c13 producer/runtime. Timings were observed under concurrent host work. Verifiers are independently pinned Linux x86_64 or Darwin ARM64 CPU builds; no cross-version/platform speedup is inferred. The security scope is a 128-bit target under documented assumptions, not a whole-protocol certificate.

| Block | CPU / truth proofs | Native prove s | Recursion s | Whole cold request s | Root bytes | Independent receiver |
|---:|---:|---:|---:|---:|---:|---|
| 24626900 | 12 /8 | 23.493 | 225.589 | 300.983 | 749,976 | Linux strict |
| 24628590 | 38 /18 | 79.296 | 645.961 | 891.448 | 748,984 | ARM strict |
| 24628607 | 7 /10 | 15.257 | 183.136 | 236.792 | 708,056 | Linux controls |
| 24628608 | 10 /10 | 19.788 | 219.998 | 286.895 | 757,848 | Linux strict |
| 24647140 | 6 /9 | 13.435 | 161.846 | 211.512 | 746,456 | Linux strict |
| 24697070 | 14 /17 | 28.169 | 335.774 | 429.996 | 746,264 | Linux strict |
| 24697073 | 15 /13 | 27.706 | 309.608 | 401.770 | 753,080 | Linux strict |
| 25229957 | 7 /10 | 15.871 | 189.171 | 242.312 | 706,456 | Linux strict |
| 26235156 | 4 /7 | 9.441 | 118.311 | 152.918 | 750,232 | Linux strict |

The testblock warm request was 209.915 s (native prove and recursion included); all 54 proof artifacts and the ordered tree matched cold exactly. Other rows have one fresh cold trial. Independent receiver time is separate from request wall.

Every accepted receiver used only existing proofs, restored all nodes, generated no new proof, and preserved artifacts. Original request/producer provenance stays unchanged; the ARM view explicitly records its receiver, path mapping and operational workers=4 override. The JSON receipt pins each request, input, bundle, ordered tree, root and source result.

Remaining: 26235159,26235168,25229955,25229951,24628595,24628611. Failed attempts and prefixes remain separate; their recovery/fresh runs are not silently substituted into this table.
