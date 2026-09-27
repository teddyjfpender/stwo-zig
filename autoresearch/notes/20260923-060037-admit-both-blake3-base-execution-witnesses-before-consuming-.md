---
title: Admit both BLAKE3 base execution witnesses before consuming either child
author: Teddy Pender
created_utc: 2026-09-23T06:00:37Z
---

# Admit both base execution witnesses before consuming either

Status: implemented, format check passed; focused four-leaf tree gate queued.

Base paired aggregation previously checked verifier identity and custody for both
children, but deferred witness-phase and hash-plan checks to each child's proving
call. A consumed or mismatched second witness could therefore fail after the first
child had generated interactions. Ethereum already used non-consuming admission.

Base execution now shares its non-consuming phase/hash-plan validation between
one-shot proving and segment admission. The existing four-leaf tree fixture checks
that a consumed or mismatched second child rejects while leaving the first child
unconsumed, then proves the ordinary tree. This fixture also exercises the new
parent coefficient-retention/streaming policy across multiple aggregate levels.

Command:

```sh
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-aggregation '-Driscv-test-filter=BLAKE3 adjacent segments form a four-leaf tree' -Doptimize=ReleaseSafe --summary all
```

The shared lock serializes this behind active validation. No passing runtime
result is claimed yet.
