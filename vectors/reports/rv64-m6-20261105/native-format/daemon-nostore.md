# Resident service, no store, order 26235156, 24628607, 26235156, 24628607 (single observations [M], load 25-31)

Same binaries (715aa3f9e, driver f1b161f0, M5 CUDA library 0caf0144). The in-process SetupCache only; no persisted store
(the pod disk was at 96 %).

| request | flat control: request / setup / native / recursion s | v2-strict: request / setup / native / recursion s |
|---|---|---|
| 0: 26235156, cold | 34.80 / 9.29 / 5.74 / 17.12 | 35.85 / 7.97 / 5.43 / 19.85 |
| 1: 24628607, first visit | **45.28 / 13.25** / 7.18 / 21.37 | **38.60 / 6.33** / 7.63 / 21.12 |
| 2: 26235156, warm | 19.75 / 0.155 / 4.67 / 12.34 | 22.48 / 0.157 / 4.47 / 15.43 |
| 3: 24628607, warm | 29.73 / 0.171 / 6.28 / 20.46 | 31.22 / 0.247 / 6.97 / 21.01 |

- **Block-independent setup [M]:** under v2-strict the first 24628607 request reuses the 8 native classes it shares with
  26235156 (class-independence.json) and builds only its 5 new ones. Setup is 13.25 -> 6.33 s (x0.48) and the request
  is 45.3 -> 38.6 s. The flat format builds every class per block. With all 46 classes installed once, the first visit of
  any block would cost the warm 0.16-0.25 s [D].
- **Warm requests** pay the strict-roster and canonical-rung tax: +14 % (156) and +5 % (607) request,
  mostly in recursion (more leaf columns).
- The flat control is byte-identical to the M3/M5 default (`m3_identical: true` per request). Root proof bytes:
  v2 750,456 / 715,064 against flat 748,536 / 706,424.
- Device peak (sampled whole-device) is 31.50 GB in both; service RSS peak is 33.5 GiB (v2) against 33.6 GiB (flat).
