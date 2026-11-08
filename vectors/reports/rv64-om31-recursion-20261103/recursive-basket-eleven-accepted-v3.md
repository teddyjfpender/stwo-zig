# Recursive basket: 11 independently accepted blocks

Eleven of fifteen recursive block runs have fresh independent native and complete-root acceptance. The native-only basket is separately 15/15 accepted. Four recursive cases remain; no subset p50 or cross-version speedup is claimed.

All rows use the same guest and 128-bit target profile under documented assumptions, without a whole-protocol certificate. Timings include concurrent host work. Group A uses b8d7096a/60968c13; group B uses composition-lease client 86a285d3 and wide/prefix runtime ca537e7a. Independent Linux x86_64 and Darwin ARM64 verifiers are separately pinned.

| Block | Group | CPU / truth proofs | Native prove s | Recursion s | Whole cold request s | Root bytes |
|---:|---|---:|---:|---:|---:|---:|
| 24626900 | A | 12 / 8 | 23.493 | 225.589 | 300.983 | 749,976 |
| 24628590 | A | 38 / 18 | 79.296 | 645.961 | 891.448 | 748,984 |
| 24628595 | B | 42 / 24 | 96.247 | 850.771 | 1165.646 | 755,480 |
| 24628607 | A | 7 / 10 | 15.257 | 183.136 | 236.792 | 708,056 |
| 24628608 | A | 10 / 10 | 19.788 | 219.998 | 286.895 | 757,848 |
| 24647140 | A | 6 / 9 | 13.435 | 161.846 | 211.512 | 746,456 |
| 24697070 | A | 14 / 17 | 28.169 | 335.774 | 429.996 | 746,264 |
| 24697073 | A | 15 / 13 | 27.706 | 309.608 | 401.770 | 753,080 |
| 25229951 | B | 40 / 18 | 70.720 | 661.236 | 892.041 | 750,680 |
| 25229957 | A | 7 / 10 | 15.871 | 189.171 | 242.312 | 706,456 |
| 26235156 | A | 4 / 7 | 9.441 | 118.311 | 152.918 | 750,232 |

Each GPU run was fresh. Independent strict receivers restored existing nodes, generated no proofs and preserved physical artifacts. Only the testblock has a measured warm trial; independent receiver time is outside producer request wall.

New case 24628595: independent ARM strict receiver 292.574s, peak RSS 11.821GB; 66 leaves+65 folds restored. The compact eleventh-case receipt pins original production plan/request, producer/runtime, root/tree, actual receiver and path mappings.

Remaining: 26235159, 26235168, 25229955, 24628611. Their fresh phase-lifetime-runtime runs remain pending. Failed attempts and historical nine-/ten-case receipts remain unchanged.
