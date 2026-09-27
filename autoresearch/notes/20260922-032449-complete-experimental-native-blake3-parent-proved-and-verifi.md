---
title: Complete experimental native BLAKE3 parent proved and verified
author: Teddy Pender
created_utc: 2026-09-22T03:24:49Z
---

# Complete experimental native BLAKE3 parent

The native parent row assembler joins five canonical arithmetic graphs: native VM
composition, PCS/DEEP, FRI, public-boundary arithmetic, and global claim
cancellation. It uses the existing lowering plan and eighteen typed AIR
components. There is no fallback that turns an unconnected private graph input
into a public constant. An exact producer inventory checks source identity and
value, rejects duplicates, and requires every arithmetic input to have a source.

Assembly selects the final versions of shared claim/sample/challenge producers
once. It preserves all transcript encodings, path/opening adapters, query and
terminal routes, fixed preprocessing root, private roots/nonces, boundary sums,
and arithmetic constant/output terms. Detailed physical claims remain private
and feed the existing aggregate/composition constraints. VM, DEEP and FRI
activation selectors are explicitly fixed to one. An initial inventory failure
identified the missing DEEP/FRI selector producers before proving began; those
bindings were added explicitly.

The real native child capture produces:

| Inventory | Count |
| --- | ---: |
| Arithmetic inputs, each covered exactly once | 8,376 |
| BLAKE3 G rows | 86,464 |
| Scalar producer/route rows | 7,093 |
| Multiply, inverse and linear arithmetic rows | 29,488 |

The gate first tests duplicate and missing opening producers. It then checks
fixed/live preprocessing equality and global LogUp cancellation, generates a
complete parent STARK, independently commits trusted preprocessing, rejects a
changed key/root, and verifies the proof with the core verifier. Final transcript
states also agree. The log records `V2_BLAKE3_NATIVE_PARENT verified`.

The shared proof harness now accepts an explicit backend type, allowing native
integration gates to use it without introducing a CPU dependency into the
frontend module. Existing standalone gates retain their default API. The shared
combined-FRI gate was rerun because this harness changed.

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment test-blake3-combined-fri -Doptimize=ReleaseSafe --summary all
```

Final terminal exit 0: 8/8 steps, 4/4 tests. Native gate: 3 tests / 34 s / 1 GiB,
compile 1 min / 5 GiB. Combined-FRI gate: 1 test / 32 s / 7 GiB, compile 42 s /
2 GiB. Formatting and git diff --check pass. No build remains live.

Earlier terminal logs preserve compiler integration failures, the missing-input
failure and its direct-binary diagnostic. They are not passing evidence. The
final log is the acceptance result. No broad suite or speed benchmark ran.

Limits: the native child uses q1/PoW0; the outer parent uses q8/PoW0 with the
standalone test transcript and statement-specialized preprocessing. This proves
the assembled verifier relations work for a real native child at diagnostic
parameters. It does not qualify production security parameters, a reusable
parent key/artifact, binary aggregation, Metal or parent-of-parent recursion.
Those admission/integration gates remain before switching production defaults.
There is no measured end-to-end speedup claim.
