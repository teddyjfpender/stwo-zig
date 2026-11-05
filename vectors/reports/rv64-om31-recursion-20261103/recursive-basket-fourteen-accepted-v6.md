# Recursive basket: 14 independently accepted blocks

Fourteen of fifteen recursive blocks have fresh independent native and complete-root acceptance. Native-only basket acceptance is separately 15/15. One recursive case remains; no subset p50 or cross-version speedup is claimed.

All use the same guest and 128-bit target under documented assumptions, without a whole-protocol certificate. Timings include concurrent host work. Group A uses b8d7096a/60968c13; B uses composition-lease client 86a285d3/runtime ca537e7a; C uses the same client/runtime 25295868 phase-lifetime fix. Fresh receiver platform/binary and full production provenance are pinned per case.

| Block | Group | CPU / truth proofs | Native prove s | Recursion s | Whole cold request s | Root bytes |
|---:|---|---:|---:|---:|---:|---:|
| 24626900 | A | 12 / 8 | 23.493 | 225.589 | 300.983 | 749,976 |
| 24628590 | A | 38 / 18 | 79.296 | 645.961 | 891.448 | 748,984 |
| 24628595 | B | 42 / 24 | 96.247 | 850.771 | 1165.646 | 755,480 |
| 24628607 | A | 7 / 10 | 15.257 | 183.136 | 236.792 | 708,056 |
| 24628608 | A | 10 / 10 | 19.788 | 219.998 | 286.895 | 757,848 |
| 24628611 | C | 45 / 22 | 96.602 | 848.467 | 1168.823 | 742,584 |
| 24647140 | A | 6 / 9 | 13.435 | 161.846 | 211.512 | 746,456 |
| 24697070 | A | 14 / 17 | 28.169 | 335.774 | 429.996 | 746,264 |
| 24697073 | A | 15 / 13 | 27.706 | 309.608 | 401.770 | 753,080 |
| 25229951 | B | 40 / 18 | 70.720 | 661.236 | 892.041 | 750,680 |
| 25229955 | C | 30 / 19 | 58.799 | 583.459 | 774.702 | 747,640 |
| 25229957 | A | 7 / 10 | 15.871 | 189.171 | 242.312 | 706,456 |
| 26235156 | A | 4 / 7 | 9.441 | 118.311 | 152.918 | 750,232 |
| 26235159 | C | 49 / 26 | 99.497 | 928.513 | 1264.958 | 742,936 |

Every GPU production was fresh; strict CPU receivers restored all nodes without proving and preserved physical artifacts. Only the testblock has measured warm parity. Receiver time is outside producer request wall.

New case 25229955: ARM strict receiver 208.778s, 49 leaves+48 folds restored. All files unchanged.

Native counters now have one definition: CPU+truth proof count; add cells.bin and stage-one.bin for binary count; add one bundle.json for total native artifacts. These counts were checked against retained physical files whose bundle SHA matches each independently accepted case. Legacy source counts/definitions and historical receipts remain preserved.

Remaining: 26235168. Pending/failed runs are not accepted by this report.
