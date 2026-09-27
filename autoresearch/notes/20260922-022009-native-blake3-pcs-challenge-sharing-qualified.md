---
title: Native BLAKE3 PCS challenge sharing qualified
author: Teddy Pender
created_utc: 2026-09-22T02:20:09Z
---

# Native transcript challenge routes for DEEP and FRI

The native PCS challenge adapter joins semantic transcript outputs to canonical
DEEP and FRI scalar input bindings. It reuses the native composition challenge
adapter and scalar routing AIR. Each OODS coordinate is consumed once from the
transcript by composition; the composition route gains exactly one emission for
DEEP. These composition routes replace the composition-only rows. DEEP randomness
and each FRI alpha coordinate consume their own transcript exports directly.
All destination multiplicities come from the corresponding arithmetic graph.

Admission checks complete role/layer inventories, exact operation role and word
count, nonoverlapping canonical source endpoints, complete canonical graph input
coordinates and equality between operation draws and graph evaluations. The FRI
layer count comes from its validated graph profile. Missing storage is initialized
before fail-closed admission; no uninitialized coordinate value is consulted.
The native relation family stays separate from fixture universal relations.

The native integration gate checks fixed-row parity and the four extra OODS
consumptions, rejects a missing final FRI draw, and rejects a changed DEEP random
coordinate. Existing full native proof and preparation checks remain active.

Serial command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

Final terminal exit 0: 4/4 steps, 3/3 tests passed. The real capture has 88 PCS
challenge routes: four OODS, four DEEP randomness and 80 FRI alpha coordinates
across 20 layers. Compile 59 s / 4 GiB; tests 20 s / 1 GiB. Formatting and
git diff --check pass. No broad suite ran and no live build remains.

An initial compile error used the
DEEP validation method name on the FRI graph; the corrected implementation uses
FRI Evaluation.validateAgainst, which validates the graph and replays its values.
No validation was bypassed.

Scope: row construction and parity with the verified native capture. These rows
still need inclusion in the full joined native parent STARK. Public-boundary
challenge consumers, query/terminal encoding joins and authenticated paths remain.
Reusable production keys, Metal and parent-of-parent qualification remain open.
This tiny q1/PoW0 gate establishes no speedup or production security qualification.
