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
