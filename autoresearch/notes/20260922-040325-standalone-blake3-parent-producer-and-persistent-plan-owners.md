---
title: Standalone BLAKE3 parent producer and persistent plan ownership qualified
author: Teddy Pender
created_utc: 2026-09-22T04:03:25Z
---

# Standalone native BLAKE3 parent producer

Parent proving now runs through a backend-injected API rather than the shared
proof-test harness. `blake3_native_parent_producer.Plan(Backend)` retains one
independently pinned key's authenticated AIR definitions, relation plans,
compiled component templates, expected row metadata and fixed columns. Its heap
address is stable. Requests use separate scratch arenas and PCS schemes; the
output owns its proof through the caller's allocator.

Plan admission reconstructs and commits fixed columns and checks the pinned
preprocessing root. Request admission checks exact row counts and all fixed
metadata before proving. Main witness values remain private and are handled by
the canonical typed AIRs. Compiled component templates are copied per request;
only relation references, claims and claim shifts change. Fixed columns are
reused as host columns, but their commitment is still computed per proof.
Commitment-tree reuse and scheduler integration are not claimed.

Canonical projection, lookup registration and table-column helpers were
extracted to `blake3_row_columns`. Existing fixtures delegate to these helpers,
so the standalone producer does not maintain a second row-generation path.
The producer contains no test assertions or fixture imports.

The real native-parent gate now:

- Builds a persistent plan against the independently reconstructed key.
- Rejects changed fixed row metadata before proving.
- Produces an owned proof through the standalone API.
- Checks the plan arena's end index did not grow during that request.
- Destroys the plan before using the returned proof.
- Encodes/decodes, checks canonical roundtrip and malformed inputs, tests rejected
  proof ownership, and independently verifies the resulting artifact/capture.

Output remains 111,428 bytes under diagnostic key
`f76d51b30dce850ad74060c42808bed2f4dd5bee6cc5705673f00b4754d3c976`.
The gate uses the testing allocator for the standalone plan/proof and subsequent
transport/verification ownership; no leaks were reported.

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment test-blake3-combined-fri -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

The first batch passed combined-FRI (32 s / 7 GiB) and found a native compile
error: the temporary roots owner had to be mutable for deinitialization. After
that cleanup fix, the final native gate reached terminal exit 0: 4/4 steps and
3/3 tests, 33 s / 2 GiB, compile 1 min / 5 GiB. No unchanged broad suite was
repeated. Formatting and git diff --check pass. No build remains live.

Current scope is diagnostic q1/PoW0 child and q8/PoW0 parent. Remaining: a
canonical capture-to-preparation coordinator, commitment reuse and bounded
scheduling, production-security-profile qualification, statement-independent
keys, Metal, binary aggregation and parent-of-parent qualification. This is
implementation/ownership evidence, not a speedup benchmark. Defaults are unchanged.
