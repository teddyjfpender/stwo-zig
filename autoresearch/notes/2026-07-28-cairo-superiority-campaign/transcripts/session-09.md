# Session 09 — increment 9: preprocessed product cache (D3)

Implementation model: Claude Opus 4.5. Orchestration: Claude Fable 5.
Worktree `/private/tmp/stwo-zig-cairo-native-throughput-10x`, branch
`autoresearch/cairo-native-throughput-10x`, predecessor `3075bd8a`.
Host: Apple M5 Max, 12 performance + 6 efficiency cores, macOS.

## Reasoning trail

**The stage profile retargeted the increment before any code was written.**
The brief scoped D3 as "the deserialized preprocessed columns (table build +
materialize elimination)". One instrumented all-opcodes run on the predecessor
showed that is the wrong half. `preprocessed_materialize_and_commit` is
164.329 ms, and its own children account for 162.159 ms of it:

```
preprocessed_plan                         0.031
preprocessed_table_build                124.912
preprocessed_materialize_and_commit     164.329
  interpolate_columns                     0.501
  evaluate_extended_domain                0.268
  interpolate_columns                     0.537
  evaluate_extended_domain                1.726
  interpolate_columns                    10.759
  evaluate_extended_domain               22.221
  merkle_commit                         126.147
  (residual = materialize)                2.170
```

Materializing all 161 preprocessed columns of `canonical_small` — 10,161,776
M31 cells, 40.6 MB — costs **2.170 ms**. Caching it would buy 2 ms for a 40 MB
artifact. The whole of `preprocessed_table_build`, by contrast, is 124.912 ms
and is a 2 MB object: the window-9 Pedersen affine point table, 32,768 points
of two 252-bit coordinates. That is the entire lever, at a twentieth of the
bytes.

The remaining 162 ms is the commitment itself — interpolation, extended-domain
evaluation and 126 ms of Merkle hashing. Caching that means persisting the
committed tree state, which the brief explicitly made conditional on the format
staying simple. It does not: the state is retained for later FRI decommitment
and would be ~150-200 MB of layered hashes. Left for a successor; see the note.

**Why the Pedersen table is legitimately protocol-identity data.** It is a
pure function of the window (`small` for `canonical_small`, `standard` for
`canonical`), which is a pure function of the preprocessed variant, which comes
from the authenticated profile manifest. No program, no input, no user string.
It also feeds `base_trace.build` and `interaction_trace.build`, not only the
preprocessed columns, which is why eliminating it is worth more than
eliminating the materialize it was nominally a prerequisite for.

## Verification log

```
corrupt (byte 1000 flipped in the payload)
  sha 79ae76e1…  table_build 114.888 ms  cache_load 0.904  cache_store 1.577
truncate (file cut to 1024 bytes)
  sha 79ae76e1…  table_build 113.163 ms  cache_load 0.041  cache_store 1.558
STWO_ZIG_WORKERS=1, arithmetic-2m, warm cache
  sha 25e5719f…  prove 13,649.0 ms  table_build 1.043 ms (cache_load 1.039)
Metal arithmetic-2m, cold then warm (bundle-flagged build, identity cd1a68e4)
  run1 sha 25e5719f…  prove 1743.4 ms  table_build 109.378 (store 1.480)
  run2 sha 25e5719f…  prove 1631.9 ms  table_build   1.073 (load 1.069)
  both: metal_dispatches 74, cpu_fallbacks 0, accelerated_without_fallbacks
official verifier (stwo-cairo-official-verifier, revision 82f21252)
  all-opcodes cache-hit proof   79ae76e1…  verified:true
  arithmetic-2m cache-hit proof 25e5719f…  verified:true
  memory-7m cache-hit proof     e3317e55…  verified:true
zig build test-cairo-cpu-product test-cairo-frontend -Doptimize=ReleaseFast
  PASS (stwo-cairo-cpu closure: 332 transitive Zig sources)
```

Both corruption tests self-heal: the load rejects the artifact, the table is
computed, and the store atomically rewrites a good one.

## Per-sample raws

Every row is one cold process. `prove ms` is the product report's
`timing.prove_ns`; `preprocessed_table_build` is from the stage profile.
`pred` = pristine `3075bd8a` tree, `miss` = candidate with
`STWO_CAIRO_PREPROCESSED_CACHE=0`, `hit` = candidate with a warm cache,
`cold` = candidate with the cache directory removed immediately before the run.
One untimed warmup per arm precedes each reading; `uptime` load averages ran
between 5.7 and 11.3 across blocks.

### all-opcodes-pred-vs-miss  (A=pred, B=miss)

| block | slot | arm | prove ms | preprocessed_table_build ms | cache load ms | cache store ms |
| ---: | ---: | --- | ---: | ---: | ---: | ---: |
| 0 | 0 | pred | 1359.472 | 105.861 | — | — |
| 0 | 1 | miss | 1360.785 | 109.036 | — | — |
| 0 | 2 | miss | 1364.911 | 106.540 | — | — |
| 0 | 3 | pred | 1358.118 | 108.472 | — | — |
| 1 | 0 | pred | 1350.786 | 107.874 | — | — |
| 1 | 1 | miss | 1367.057 | 109.892 | — | — |
| 1 | 2 | miss | 1373.356 | 107.494 | — | — |
| 1 | 3 | pred | 1361.331 | 106.247 | — | — |
| 2 | 0 | pred | 1350.406 | 110.350 | — | — |
| 2 | 1 | miss | 1270.697 | 104.342 | — | — |
| 2 | 2 | miss | 1274.105 | 105.180 | — | — |
| 2 | 3 | pred | 1277.994 | 106.137 | — | — |
| 3 | 0 | pred | 1274.513 | 105.656 | — | — |
| 3 | 1 | miss | 1290.909 | 105.506 | — | — |
| 3 | 2 | miss | 1284.560 | 106.180 | — | — |
| 3 | 3 | pred | 1278.830 | 107.092 | — | — |

### all-opcodes-pred-vs-hit  (A=pred, B=hit)

| block | slot | arm | prove ms | preprocessed_table_build ms | cache load ms | cache store ms |
| ---: | ---: | --- | ---: | ---: | ---: | ---: |
| 0 | 0 | pred | 1479.588 | 113.597 | — | — |
| 0 | 1 | hit | 1361.399 | 1.108 | 1.104 | — |
| 0 | 2 | hit | 1315.013 | 1.133 | 1.129 | — |
| 0 | 3 | pred | 1402.432 | 120.543 | — | — |
| 1 | 0 | pred | 1314.482 | 109.638 | — | — |
| 1 | 1 | hit | 1198.893 | 1.143 | 1.139 | — |
| 1 | 2 | hit | 1202.887 | 1.112 | 1.108 | — |
| 1 | 3 | pred | 1310.486 | 109.898 | — | — |
| 2 | 0 | pred | 1315.418 | 109.637 | — | — |
| 2 | 1 | hit | 1232.923 | 1.143 | 1.139 | — |
| 2 | 2 | hit | 1226.979 | 1.152 | 1.148 | — |
| 2 | 3 | pred | 1337.542 | 114.466 | — | — |
| 3 | 0 | pred | 1325.500 | 108.626 | — | — |
| 3 | 1 | hit | 1292.790 | 1.150 | 1.145 | — |
| 3 | 2 | hit | 1240.353 | 1.158 | 1.154 | — |
| 3 | 3 | pred | 1328.365 | 114.077 | — | — |

### all-opcodes-pred-vs-cold  (A=pred, B=cold)

| block | slot | arm | prove ms | preprocessed_table_build ms | cache load ms | cache store ms |
| ---: | ---: | --- | ---: | ---: | ---: | ---: |
| 0 | 0 | pred | 1337.505 | 112.038 | — | — |
| 0 | 1 | cold | 1342.711 | 116.136 | 0.013 | 1.814 |
| 0 | 2 | cold | 1355.024 | 112.976 | 0.017 | 1.713 |
| 0 | 3 | pred | 1346.443 | 111.254 | — | — |
| 1 | 0 | pred | 1342.125 | 112.334 | — | — |
| 1 | 1 | cold | 1352.032 | 113.191 | 0.013 | 1.601 |
| 1 | 2 | cold | 1356.344 | 112.123 | 0.007 | 1.704 |
| 1 | 3 | pred | 1347.705 | 112.057 | — | — |
| 2 | 0 | pred | 1336.337 | 113.667 | — | — |
| 2 | 1 | cold | 1353.269 | 115.784 | 0.017 | 1.655 |
| 2 | 2 | cold | 1358.032 | 114.843 | 0.017 | 1.754 |
| 2 | 3 | pred | 1346.388 | 113.453 | — | — |
| 3 | 0 | pred | 1360.565 | 112.634 | — | — |
| 3 | 1 | cold | 1367.560 | 115.144 | 0.014 | 1.650 |
| 3 | 2 | cold | 1360.138 | 116.606 | 0.014 | 1.654 |
| 3 | 3 | pred | 1340.950 | 112.266 | — | — |

### arithmetic-2m-pred-vs-miss  (A=pred, B=miss)

| block | slot | arm | prove ms | preprocessed_table_build ms | cache load ms | cache store ms |
| ---: | ---: | --- | ---: | ---: | ---: | ---: |
| 0 | 0 | pred | 2364.131 | 101.914 | — | — |
| 0 | 1 | miss | 2377.633 | 102.351 | — | — |
| 0 | 2 | miss | 2397.507 | 101.578 | — | — |
| 0 | 3 | pred | 2389.730 | 102.262 | — | — |
| 1 | 0 | pred | 2412.153 | 102.377 | — | — |
| 1 | 1 | miss | 2433.559 | 104.661 | — | — |
| 1 | 2 | miss | 2436.775 | 102.295 | — | — |
| 1 | 3 | pred | 2438.217 | 102.865 | — | — |
| 2 | 0 | pred | 2482.666 | 102.230 | — | — |
| 2 | 1 | miss | 2455.909 | 102.183 | — | — |
| 2 | 2 | miss | 2447.664 | 102.513 | — | — |
| 2 | 3 | pred | 2477.366 | 102.115 | — | — |

### arithmetic-2m-pred-vs-hit  (A=pred, B=hit)

| block | slot | arm | prove ms | preprocessed_table_build ms | cache load ms | cache store ms |
| ---: | ---: | --- | ---: | ---: | ---: | ---: |
| 0 | 0 | pred | 2510.937 | 102.644 | — | — |
| 0 | 1 | hit | 2423.928 | 1.003 | 0.999 | — |
| 0 | 2 | hit | 2470.724 | 1.035 | 1.030 | — |
| 0 | 3 | pred | 2550.870 | 106.174 | — | — |
| 1 | 0 | pred | 2531.772 | 103.357 | — | — |
| 1 | 1 | hit | 2461.962 | 1.042 | 1.038 | — |
| 1 | 2 | hit | 2427.246 | 1.029 | 1.025 | — |
| 1 | 3 | pred | 2530.245 | 103.011 | — | — |
| 2 | 0 | pred | 2578.101 | 102.417 | — | — |
| 2 | 1 | hit | 2466.232 | 1.111 | 1.106 | — |
| 2 | 2 | hit | 2466.265 | 1.017 | 1.013 | — |
| 2 | 3 | pred | 2575.931 | 107.779 | — | — |

### arithmetic-2m-pred-vs-cold  (A=pred, B=cold)

| block | slot | arm | prove ms | preprocessed_table_build ms | cache load ms | cache store ms |
| ---: | ---: | --- | ---: | ---: | ---: | ---: |
| 0 | 0 | pred | 2595.297 | 107.091 | — | — |
| 0 | 1 | cold | 2569.944 | 104.521 | 0.012 | 1.713 |
| 0 | 2 | cold | 2592.448 | 105.384 | 0.010 | 1.668 |
| 0 | 3 | pred | 2583.969 | 102.884 | — | — |
| 1 | 0 | pred | 2594.395 | 103.959 | — | — |
| 1 | 1 | cold | 2584.189 | 108.391 | 0.010 | 1.851 |
| 1 | 2 | cold | 2586.645 | 106.083 | 0.010 | 1.907 |
| 1 | 3 | pred | 2600.015 | 102.970 | — | — |
| 2 | 0 | pred | 2591.469 | 106.459 | — | — |
| 2 | 1 | cold | 2596.439 | 107.525 | 0.009 | 1.612 |
| 2 | 2 | cold | 2606.161 | 105.757 | 0.009 | 2.012 |
| 2 | 3 | pred | 2586.498 | 107.688 | — | — |

### memory-7m-pred-vs-miss  (A=pred, B=miss)

| block | slot | arm | prove ms | preprocessed_table_build ms | cache load ms | cache store ms |
| ---: | ---: | --- | ---: | ---: | ---: | ---: |
| 0 | 0 | pred | 6151.905 | 102.204 | — | — |
| 0 | 1 | miss | 6240.890 | 104.156 | — | — |
| 0 | 2 | miss | 6226.378 | 104.008 | — | — |
| 0 | 3 | pred | 6258.169 | 109.475 | — | — |
| 1 | 0 | pred | 6237.741 | 106.062 | — | — |
| 1 | 1 | miss | 6907.435 | 106.088 | — | — |
| 1 | 2 | miss | 6932.411 | 113.165 | — | — |
| 1 | 3 | pred | 6723.554 | 115.751 | — | — |
| 2 | 0 | pred | 6725.000 | 117.551 | — | — |
| 2 | 1 | miss | 6796.678 | 114.123 | — | — |
| 2 | 2 | miss | 6720.484 | 122.738 | — | — |
| 2 | 3 | pred | 6644.211 | 114.429 | — | — |

### memory-7m-pred-vs-hit  (A=pred, B=hit)

| block | slot | arm | prove ms | preprocessed_table_build ms | cache load ms | cache store ms |
| ---: | ---: | --- | ---: | ---: | ---: | ---: |
| 0 | 0 | pred | 6500.076 | 115.285 | — | — |
| 0 | 1 | hit | 6454.574 | 1.093 | 1.088 | — |
| 0 | 2 | hit | 6437.537 | 1.105 | 1.101 | — |
| 0 | 3 | pred | 6482.933 | 115.959 | — | — |
| 1 | 0 | pred | 6471.080 | 116.415 | — | — |
| 1 | 1 | hit | 6312.223 | 1.076 | 1.072 | — |
| 1 | 2 | hit | 6372.847 | 1.203 | 1.198 | — |
| 1 | 3 | pred | 6418.254 | 109.163 | — | — |
| 2 | 0 | pred | 6386.483 | 111.943 | — | — |
| 2 | 1 | hit | 6199.905 | 1.034 | 1.029 | — |
| 2 | 2 | hit | 6239.022 | 1.078 | 1.074 | — |
| 2 | 3 | pred | 6351.783 | 115.884 | — | — |

### memory-7m-pred-vs-cold  (A=pred, B=cold)

| block | slot | arm | prove ms | preprocessed_table_build ms | cache load ms | cache store ms |
| ---: | ---: | --- | ---: | ---: | ---: | ---: |
| 0 | 0 | pred | 6294.964 | 112.879 | — | — |
| 0 | 1 | cold | 6273.730 | 114.916 | 0.013 | 1.709 |
| 0 | 2 | cold | 6249.447 | 112.376 | 0.010 | 1.817 |
| 0 | 3 | pred | 5865.072 | 103.216 | — | — |
| 1 | 0 | pred | 5846.382 | 105.219 | — | — |
| 1 | 1 | cold | 5785.554 | 107.503 | 0.009 | 1.746 |
| 1 | 2 | cold | 5827.053 | 103.957 | 0.009 | 1.711 |
| 1 | 3 | pred | 5888.756 | 105.365 | — | — |
| 2 | 0 | pred | 5813.785 | 102.175 | — | — |
| 2 | 1 | cold | 5762.399 | 103.589 | 0.010 | 1.821 |
| 2 | 2 | cold | 5824.815 | 103.791 | 0.010 | 1.845 |
| 2 | 3 | pred | 5729.271 | 101.949 | — | — |
