---
title: Native public challenge sharing and aggregate cancellation qualified
author: Teddy Pender
created_utc: 2026-09-22T02:59:33Z
---

# Native public-boundary challenges and aggregate cancellation

The public-boundary graph now shares 32 relation challenge coordinates with the
native composition graph. Typed relation/coordinate bindings determine every
source node; values alone cannot authorize swapping identities. The composition
challenge rows gain one public-boundary consumer and replace the earlier rows,
retaining the existing OODS fanout unchanged.

A canonical arithmetic Builder graph checks the native verifier's global LogUp
cancellation equation: sum of the 28 component aggregates plus the public total
is zero. It has 116 scalar inputs and four separate zero outputs, one per QM31
coordinate. Claim scalar producers gain one consumer beyond arithmetic and
transcript encoding. Public-total scalar producers feed both boundary arithmetic
and the aggregate graph. Input routes bind all 116 coordinates to these sources;
no aggregate value is treated as a public preprocessing constant.

Public-boundary admission now validates input count and typed source schema,
arithmetic structure, graph mirror nodes/outputs, and a complete replay against
stored evaluation values. This rejects mutated metadata/evaluations before their
ports are used. The native public-sum formula remains the existing authority.

The real native gate checks producer multiplicities, unchanged OODS sharing and
fixed-route parity; changes an aggregate input and requires cancellation failure;
changes a relation source node and requires rejection; and changes the stored
public-boundary evaluation and requires replay rejection.

Serial command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

Both initial and strengthened gates reached terminal exit 0. Final: 4/4 steps,
3/3 tests passed; compile 1 min / 4 GiB, tests 23 s / 1 GiB. Formatting and
git diff --check pass. No broad suite ran and no live build remains. Tiny q1/PoW0
qualification establishes no production speedup.

Remaining: public wire/register-byte/memory-byte/selector source closure and
private published-sum producers; include all graphs and prepared AIR rows in the
complete native parent STARK. Statement-independent keys, production artifacts,
Metal and parent-of-parent qualification remain outstanding. Replacement rows
must not be included alongside the producers they supersede.
