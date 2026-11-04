# native-gkr receipts (M5, 2026-11-04)

Protocol `rv64-m5-native-gkr/v1` — note `design/riscv-proving-stack/rv64-native-gkr.md`; interface section `native-gkr`
in `/workspace/m3/M5-INTERFACES.md`. **Reference level, off by default: no production prover, receiver or leaf
selects v1; no end-to-end request was run under v1.**

| file | what | label |
|---|---|---|
| `CENSUS.md` | per-family native INTER census of both dev blocks, v1 prediction, headline | M / D |
| `<block>-census.json` | families, totals, bits/gas, reconciliation (declared == measured tree=2 words, every proof) | M / D |
| `<block>-census-declared.json` | raw per-component census (`rv64-native-gkr-census bundle.json 18`) | D (declaration) |
| `<block>-v1-shape.json` | exact v1 roster per native proof: instances, layers, GKR facts, binding pairs, INTER cells, section bytes | D |
| `<block>-leaf-model.json` | leaf-cell delta model | E |
| `gpu-bench.json`, `raw/gpubench.log`, `raw/variables.json` | GPU GKR traversal on v1 vs today's local roster (shared kernels) | M |
| `realshape/` | CPU reference prove + fresh-process verify on real v1 rosters; tier-R corpus receipts | M |

Headline (24628607): native INTER 1,854 M cells today [M] -> 903 M under v1 [D] (x0.487); 7,796 -> 3,798 bits/gas own
height (15,592 -> 7,597 LDE b2; ZisK 28.3k LDE). GPU GKR per CPU proof +35..+53 ms [M]; truth sections new (Keccak log 18:
110 ms). Leaf cells -3.41 G per request [E]. Tests: `zig build test-riscv64-native-gkr` 10/10 (NG01 3,468/3,468 words);
tier R: every word of a real-roster section rejected in a fresh process (5,329/5,329 cases incl. honest accept), 415/415 sampled on a secp truth section; real CPU-proof roster (cpu-6, 40 instances) proved on CPU in 20.9 s and accepted by a fresh receiver.
