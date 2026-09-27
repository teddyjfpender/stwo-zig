# Current BLAKE3 recursion audit and borrowed main streaming

The original roadmap described several now-completed integration steps as future work. Current production BLAKE3 parent rows already include native query-input fusion: the canonical base-parent fixture reports 9,520 groups and 38,080 removed scalar rows, alongside 19,973 dot4 and 59,595 fma matches. Fixed commitment sharing, worker rekeying and compact retained fixed metadata also exist. Whole-tree overlap, remaining transient witness materialization, broader matched latency qualification and a separately reviewed parameter experiment remain open. See the updated audit in `design/riscv-proving-stack/recursion-architecture-comparison.md`.

## New implementation

The native parent main commitment used `scheme.commit` with borrowed main columns. Without retained file storage this prepares the full column set and uses the monolithic commitment builder. Interaction commitment already used bounded streaming. Main now uses `commitBorrowedStreaming` with the shared canonical batch policy. Prepared source columns remain owned by the parent for subsequent interaction generation; only copied descriptors belong to the streaming operation. Existing immutable fixed commitment sharing and proof parameters are unchanged.

The research control `STWO_RISCV_PARENT_MONOLITHIC_MAIN=1` selects the previous main path. The initial baseline was recorded before adding this switch; candidate/control producer source snapshots are retained. No new AIR, protocol key shape, transcript framing or constraint change is intended.

## Diagnostic evidence

Both runs use the focused canonical base-parent test with an explicitly installed two-worker CPU pool, 70 queries / 26 PoW bits for both child and parent, ReleaseFast, and stage profiling enabled. One observation per arm, sequential baseline/candidate; this is not an ABBA or production latency qualification. It excludes preparation before `proveWithWorkspace`, standalone verification and whole-tree scheduling. Do not compare these totals to historical parent benchmarks with different fixtures/workers/protocols.

| Stage | Monolithic s | Streaming s |
| --- | ---: | ---: |
| parent.validation | 0.013436 | 0.013289 |
| parent.main_setup | 5.099573 | 5.103233 |
| parent.main_commit | 18.785233 | 6.856149 |
| parent.interaction_generation | 6.291506 | 6.280878 |
| parent.interaction_commit | 7.340330 | 7.325090 |
| parent.core | 22.142115 | 21.911008 |

Sum of recorded proving stages: 59.672193 → 47.489647 s (20.4% lower in this diagnostic pair). Main commitment is 2.74× faster.

Both tests independently verify child and parent, replay the parent transcript, check rejected admissions, reuse the fixed plan after worker rekey and verify outputs after worker destruction. Parent artifact size remains 850,599 bytes; this is a size comparison, not a recorded byte-hash comparison. Peak tracked memory is 15,001,593,034 → 15,001,605,778 bytes, effectively unchanged and below the 25,769,803,776-byte cap. Core proof work still sets a large cost; inside the baseline core stage, composition is 10.829 s, sampled values 4.118 s, and FRI quotient/commit 4.164 s.

Command for each run: `STWO_RISCV_RECURSIVE_PARENT_PROFILE=1 python3 scripts/zig_serial_build.py --cwd . test-riscv-statement-codecs -Driscv-test-filter='compact range provider canonical recursive parent verifies' -Doptimize=ReleaseFast --summary all`.

The next qualification should compare the main-path switch on one frozen product, separate cold preparation from warm proof time, and cover CPU/Metal complete parents before a whole-tree speed claim. The original four-part goal remains active; the tenfold aspiration has not been achieved.
