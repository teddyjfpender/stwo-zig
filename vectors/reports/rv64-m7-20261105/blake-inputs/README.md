# M7 sampled Blake inputs: production shadow gate [M]

The native verifier now exposes the inputs to its sampled-values Fiat–Shamir mix. A CUDA checker compares CV8, message16, the byte counter and finalization flag against the original GG witness at the matching circuit span. This first gate changes no assignment cells, circuit constraints, transcript order or proof bytes. It is opt-in with `STWO_RV64_BLAKE_SAMPLE_CHECK=1`.

Both development blocks completed cold and warm: 4/4 whole artifact sets match the M6 c1 baseline (native binaries, bundle, recursive tree and every recursive proof). The first pair passed fresh M6 CPU receivers, 2/2. All 56 leaf spans matched: 189,222 compression records / 15,137,760 GG rows checked, no mismatches. CPU observer tests passed 3/3; CUDA poison tests passed 9/9, including wrong CV/message/counter/finalization, non-u32 data, range and foreign-context refusal.

| Block | Cold request s | Warm request s | Warm native s | Warm recursion s |
|---|---:|---:|---:|---:|
| 26235156 | 27.249 | 12.731 | 3.372 | 7.309 |
| 24628607 | 35.922 | 17.715 | 4.650 | 10.679 |

These are diagnostic observations, not a latency improvement claim. Auto arena, EAGER loading, store none, root leaf tape v3 and packed fold cache; composition enqueue disabled. Peak process RSS was 23.55 GiB and sampled whole-device usage 31.51 GB; capacity targets are not met. Source is base f23633300 plus dirty overrides bound in source-sha256.json. The pod source lacked a .m3-commit marker; raw plan/receipt preserve null rather than invent provenance. build.json binds the producer and one-TU CUDA image.

The next gate can precompute only these GG outputs and omit their numerical assignment tasks, retaining the original GG AIR as authority. A checked compression output map is required; this shadow gate does not implement that optimization.
