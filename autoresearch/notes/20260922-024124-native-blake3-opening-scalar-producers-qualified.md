---
title: Native BLAKE3 opening scalar producers qualified
author: Teddy Pender
created_utc: 2026-09-22T02:41:24Z
---

# Native BLAKE3 authenticated opening scalar producers

Native opening-source preparation now derives the exact eligible input inventory
from validated DEEP queried_value and FRI authenticated_value_word bindings. Each
path source must consume one eligible node exactly once, match its evaluated
base-field value, and belong to the correct lane. Complete inventory coverage is
required; arbitrary input nodes, missing sources, duplicate nodes and mismatched
values reject. All memory belongs to one returned arena, with rollback on failure.

Trace scalar emissions equal arithmetic use counts plus two consumers: canonical
leaf encoding and the read-only lifted-column consistency adapter. FRI emissions
equal arithmetic use counts plus one QM31 packing consumer. Existing typed AIRs
and graph use-count computation remain the only arithmetic/relation authorities.
No new AIR, hash primitive or protocol framing was introduced.

The native gate checks producer value/fixed-row parity against all path sources
and rejects omitted, duplicated and changed-value source entries. Existing path,
transcript, composition, PCS/DEEP, FRI and sharing checks remain active.

Serial command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

Final terminal exit 0: 4/4 build steps and 3/3 tests passed. All 781 native
opening sources have scalar producer rows. Compile 1 min / 4 GiB; tests 20 s /
1 GiB. Formatting and git diff --check pass. No broad suite ran and no live
build remains. Tiny q1/PoW0 diagnostics establish
no production speedup or canonical CSP result.

Remaining: include these rows together with path encodings, packing, readonly
consistency and arithmetic in the complete native parent; join root/nonce sources
and public-boundary authority. Statement-independent keys, production artifact
admission, Metal and parent-of-parent qualification remain unfinished.
