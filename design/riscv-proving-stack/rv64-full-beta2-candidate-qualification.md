# Complete Ethereum beta2 engineering candidate qualification

The pinned block completed under the explicit beta2 OM31 CPU-local-GKR/classic-OM-truth candidate, and a separate fresh process accepted the complete execution and expected 43-byte output. This is functional/resource qualification, not a reviewed whole-protocol 128-bit certificate or a GPU result.

Source: `7282f699de49002d154e1f5acf627df614d79635` (clean isolated worktree). Binary SHA256: `d2d558df389fb0868adee9f318932420281a787436037407c1ba199ef77a114d`. The suite is pinned q256, beta2 blowup 2, P0, fold 4; the producer cannot choose a weaker profile. The source-derived pre-key guard and the fresh receiver's hard allocation budget were enabled.

| Result | Measured value |
|---|---:|
| Retirements | 104,253,913 |
| Physical proofs | 25 CPU + 5 truth |
| Producer wall | 502.90 s |
| Capture / setup | 8.969 / 29.467 s |
| Proving | 462.639 s |
| Same-process verification | 1.490 s |
| Producer peak RSS / footprint | 44.055 / 46.505 GB |
| Fresh receiver wall | 32.77 s |
| Fresh load/setup / verification | 31.256 / 1.424 s |
| Fresh peak requested / RSS | 11.673 / 12.816 GB |
| Proof-file bytes, excluding bundle/cells/manifest | 89,022,256 |
| Swap growth during run | 0 |

Values in GB use decimal bytes. The receiver's requested-live allocation cap was 32 GiB; its 4 GiB recycler free-list cap, rounded physical backing, stacks and OS overhead are separate. The candidate fixed cache was independently rebuilt in the fresh process.

| Worker scope | Stage one | Stage two | MAIN commit | Local GKR | Native completion |
|---|---:|---:|---:|---:|---:|
| CPU | 143.724 s | 262.446 s | 55.255 s | 70.280 s | 253.231 s |
| Truth | 9.644 s | 46.604 s | 2.472 s | 0 | 46.051 s |

CPU local GKR splits into input construction 4.300 s, numerical argument 57.634 s and physical binding 7.566 s. Total spill/restore cost was 11.633/9.767 s. Recorded PCS scopes are retained as a compact per-physical summary; their inclusive/nested/parallel durations are not a disjoint wall partition.

One lane with 16 workers proved all shards, with explicit limits: GKR 32 GiB, globals 8 GiB, retained frontend 20 GiB, disk 128 GiB, immutable beta2 setup 12 GiB and scheduling admission 48 GiB. Default serial capture and natural stage-two order were preserved. A shared heavy-run lock excluded other coordinated proofs. This single run includes a diagnostic vmmap snapshot and background host conditions were not controlled, so it establishes no comparative speedup.

Parking reserved 42.648 GB of disk across the run and peaked at 2.021 GB of simultaneous mappings. Store live and mapped bytes were both zero after completion. Memory monitoring never reached the stop thresholds of sustained RSS above 56 GiB or swap growth above 1 GiB.

The real setup cost remains substantial: 29 immutable whole-key identities, 29 source validations, zero cache hits, 7.386 GB retained and 9.372 GB peak under the 12 GiB cap. Once-per-identity validation works, but geometry-specific whole keys duplicate shared fixed content. This explains much of fresh receiver startup and motivates bounded immutable-provider sharing. It is not evidence of one setup per program.

The expected output was:

```
e63d2797ca5c6f826a32d20c41ba552d25777533ab295f9d232560b014d090300101000000000000000114
```

All output bytes, execution completion and the 25/5 proof inventory were asserted against the pinned request. The accepting fresh receiver reconstructed its own source keys and beta2 authority, verified manifest/physical binding and separate RAM/KIO/Wire closure, and checked terminal output. The source guard observed 30 proofs, maximum trace log 22, 7,371 committed columns, 6,128 constraints, degree 5, 22 local instances and 26 GKR variables. Its conditional lookup budget passed; adaptive transcript, secp compression and whole-protocol qualification flags remain false.

An earlier launch failed before capture with `UnexpectedToken`: the report's shortened `lane_workers:[16]` had been copied into an input schema storing a fixed byte array. The actual run omitted this optional field and used `workers_per_lane:16`, which selects the intended identical schedule. This was an operational JSON correction, not a budget retry or profile change.

Receipts, requested resources, full worker report, fixed/source bounds, independent receiver output, memory monitor and artifact hashes are under `vectors/reports/rv64-full-candidate-20261102/`. Raw proof files and detailed stage files remain at `/tmp/stwo-rv64-om-ethereum-fullblock-candidate-v1`; hashes preserve provenance without adding large proof files to the repository.
