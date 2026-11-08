# M7 sampled Blake inputs: production shadow gate [M]

The native verifier now exposes the inputs to its sampled-values Fiat–Shamir mix. A CUDA checker compares CV8, message16, the byte counter and finalization flag against the original GG witness at the matching circuit span. This first gate changes no assignment cells, circuit constraints, transcript order or proof bytes. It is opt-in with `STWO_RV64_BLAKE_SAMPLE_CHECK=1`.

Both development blocks completed cold and warm: 4/4 whole artifact sets match the M6 c1 baseline (native binaries, bundle, recursive tree and every recursive proof). The first pair passed fresh M6 CPU receivers, 2/2. All 56 leaf spans matched: 189,222 compression records / 15,137,760 GG rows checked, no mismatches. CPU observer tests passed 3/3; CUDA poison tests passed 9/9, including wrong CV/message/counter/finalization, non-u32 data, range and foreign-context refusal.

| Block | Cold request s | Warm request s | Warm native s | Warm recursion s |
|---|---:|---:|---:|---:|
| 26235156 | 27.249 | 12.731 | 3.372 | 7.309 |
| 24628607 | 35.922 | 17.715 | 4.650 | 10.679 |

These are diagnostic observations, not a latency improvement claim. Auto arena, EAGER loading, store none, root leaf tape v3 and packed fold cache; composition enqueue disabled. Peak process RSS was 23.55 GiB and sampled whole-device usage 31.51 GB; capacity targets are not met. Source is base f23633300 plus dirty overrides bound in source-sha256.json. The pod source lacked a .m3-commit marker; raw plan/receipt preserve null rather than invent provenance. build.json binds the producer and one-TU CUDA image.

The next gate can precompute only these GG outputs and omit their numerical assignment tasks, retaining the original GG AIR as authority. A checked compression output map is required; this shadow gate does not implement that optimization.

## Prefill v2: correct bytes, rejected performance candidate [M]

`STWO_RV64_BLAKE_SAMPLE_PREFILL=1` computes the original 80 GG outputs per sampled compression on GPU, then omits only those numerical GG tasks. The original AIR and witness variable addresses remain unchanged. The original GG input checker stays active. A checked one-word output-base map per compression is bounded by the existing host cache cap; these metadata are in-process only, so this option disables assignment-plan disk persistence.

Both configurations completed 4 requests each and all 8 complete artifact sets match M6. No new fresh receiver was run for this rejected candidate; the identical bytes were accepted in the earlier shadow gate. The first attempt correctly refused a fold with no native input tape (negative receipt retained); v2 limits numerical elision to leaf-owned tapes.

| Block | OFF warm s | ON warm s |
|---|---:|---:|
| 26235156 | 13.087 | 13.155 |
| 24628607 | 17.302 | 19.060 |

Median assignment callback across 76 callbacks/config improved 138.86 to 90.34 ms; numerical level time 100.663 to 58.522 ms. Median launches stayed 721. Full-request timing regressed. Diagnosis: prefill readiness incorrectly rejected fold templates, disabling 10 existing fold seed-tape preparations (39 total OFF vs29 ON; leaf tape uses29 both). This remains disabled by default. The next candidate must restore fold tape reuse and reschedule remaining dependencies from the now-ready GG outputs, rather than only deleting empty old levels. CUDA6/6 poison cases and plan-filter unit passed. Peak RSS OFF23.34 / ON23.71 GiB; auto arena, device about31.5GB. All timings are single loaded observations; no wall-time gain claimed.

## Prefill v3: byte-identical production gate passed [M]

V3 restores fold seed-tape reuse and recomputes earliest legal levels for remaining tasks with prefilled GG outputs ready at level zero. Stable counting sort preserves dependencies. All circuit gates and all proof formats remain unchanged. The largest truth class drops 146,140 to45,316 dependency levels; several CPU classes remain103k–117k, so another branch remains critical there.

Both dev blocks completed cold plus2warm requests/config:12/12 whole artifact sets match M6. A fresh M6 CPU receiver pair accepted ON's first requests,2/2 (34.3/49.9s); all remaining proof sets contain identical accepted bytes. All84 leaf input checks matched283,833 compression records. Unit tests2/2; current148c CUDA image passes input-check9/9 and prefill6/6 poison165 cases. V1/v2 failures remain preserved above.

| Block | OFF warm requests s | ON warm requests s | OFF median s | ON median s |
|---|---|---|---:|---:|
| 26235156 |13.049 /12.443|12.615 /12.465|12.746|12.540|
| 24628607 |18.161 /17.934|16.793 /17.811|18.048|17.302|

The observed headline median is4.13% lower, from only2warm observations/config in loaded ON-then-OFF order. Small-block pairs are mixed; no broad speed guarantee is established. Across114assignment callbacks/config, median total137.189→77.255ms; numerical levels100.547→47.568ms. Median assignment launches remain721. Both configurations use77seed-tape preps including57leaf preps, confirming fold reuse is restored. RSS23.407→23.560GiB; auto-arena sampled device31.508GB both. Memory, launch, native, capture and8s request targets remain unmet. Prefill remains opt-in/default-off pending final integration.

Driver197b693025c1287435e9fbb50a9251fa4e135eeee2de2dfa648373bb9ae3ea02; image148c4a1760678521d7d793a119a17b03c60ae807dd6006011429610fc50126aa. Source a365d1eb3 plus two overrides in prefill-source-v3.json, bound by prefill-build-v3.json. Disk dedup/prune receipts preserve paths/bytes or reconstruction inputs for superseded assets; current148c, root matched128 and M6 assets were retained.

## Critical-path census, then stop tuning [M]

A read-only diagnostic on26235156 retains M6 byte identity. It follows one deepest assignment path/class (input-order tie choice), not every path. CPU depth117,521 contains85,935GG tasks with indices1..381,757; that child GKR transcript ends at381,760 and its receipt hash ends565,920. CPU depth111,647 has82,355GG tasks ending367,437, before transcript boundary367,440. These long CPU paths belong to GKR Fiat–Shamir transcript, not the later receipt hash. Largest truth path after sampled prefill has45,315tasks but only20GGs; its remaining work is arithmetic/XOR. See critical-census.json for all11paths and4child ranges.

User steering now stops additional prefill/graph tuning. The qualified v3 and negative v1/v2 receipts are preserved. Next work is per-request critical-path ownership in seconds plus GPU-seconds and a single global admission planner covering native retention, recursion leases and GKR workspace with static arena budgets; no further wall-only A/B or GKR promotion before that planner.
