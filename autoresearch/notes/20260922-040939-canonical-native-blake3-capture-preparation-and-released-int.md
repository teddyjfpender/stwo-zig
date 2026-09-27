---
title: Canonical native BLAKE3 capture preparation and released intermediates qualified
author: Teddy Pender
created_utc: 2026-09-22T04:09:39Z
---

# Canonical verified-native-capture preparation

`blake3_native_parent_preparation.prepare` now owns the complete ordered path
from a verified native BLAKE3 segment capture to parent rows and key context.
It reuses the existing transcript, VM, DEEP, FRI, path, query, public-boundary,
claim and scalar/byte adapters. Path/projection read multiplicities are finalized
before row assembly. Partial construction uses reverse-order cleanup.

The normal API returns only owned final rows and pointer-free key context. It
releases all intermediate graphs, evaluations, transcript and routing owners
before returning. A stable diagnostic `State` exposes those same components for
the mutation fleet; it is not a second preparation implementation.

The native integration test now obtains its component owners from this State,
removing its local preparation sequence. Existing source/claim/nonce/path/query
mutation checks still exercise the individual validated adapters. Duplicate and
missing producer tests use the State's canonical source mapping.

The test also calls the normal compact API, compares every live/fixed row and
key-context field against State.finish, and proves from the compact result.
That result then traverses the standalone persistent plan, artifact codec and
witness-independent verifier. Thus normal preparation releases intermediate
owners, and proving releases its plan, before the final artifact verification.

Evidence remains: 8,376 covered arithmetic inputs, a 111,428-byte canonical
artifact, and diagnostic key
`f76d51b30dce850ad74060c42808bed2f4dd5bee6cc5705673f00b4754d3c976`.

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

Terminal exit 0: 4/4 steps and 3/3 tests, 35 s / 2 GiB; compile 1 min / 5 GiB.
No allocator leaks reported. Formatting and git diff --check pass. No build
remains live. No broad suite or performance benchmark ran.

Remaining: commitment-tree reuse and bounded scheduling, production security
profile, statement-independent keys, Metal, binary aggregation and
parent-of-parent qualification. The child remains q1/PoW0 and the outer parent
q8/PoW0. This completes the experimental native-child preparation/proving/
transport/verification path, not the production BLAKE3 migration or speed goal.
