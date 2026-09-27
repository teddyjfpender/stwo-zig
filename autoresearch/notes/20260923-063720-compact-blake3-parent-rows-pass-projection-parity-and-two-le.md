---
title: Compact BLAKE3 parent rows pass projection parity and two-level tree with overlapping plan reuse
author: Teddy Pender
created_utc: 2026-09-23T06:37:20Z
---

# Compact fixed parent rows at assembly

Status: focused projection parity and diagnostic two-level tree qualification passed; canonical aggregation pending.

Canonical Ethereum preparation retained 10,150,562,296 bytes outside the worker
cap. Its fixed row storage included every main-column placeholder although main
values were already retained in separate committed columns. G-call rows have
124 main columns and 16 fixed columns; XOR rows have 12 main and 6 fixed columns.

The builder now retains only the typed fixed schedule plus any proof-kind
parameters, immediately on append. Parent rows use that representation throughout
joining, namespace validation, rebasing, transactional append, key derivation and
persistent plan admission. Fixed projection reuses the existing column writer
through a layout view with no main prefix. Main values remain independently owned.
Wire formats, hash inputs, proof parameters and logical row counts are unchanged.

The new differential test compares compact and full-row preprocessing for every
parent cohort, including padding and parameter tails. Existing append/join and
rebase fixtures were updated to construct independent main values. The queued
four-leaf test will exercise compact preparation across aggregate levels. The
currently running Metal v4 binary and the previous canonical CPU success predate
this representation change; they do not qualify it. No byte reduction is claimed
until a completed preparation reports its retained size.

Focused command:

```sh
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-memory-update '-Driscv-test-filter=BLAKE3 memory update proves compact' -Doptimize=ReleaseSafe --summary all
```

Canonical Ethereum two-segment aggregation is queued after the tree/parity gates:

```sh
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-ethereum-canonical-aggregation -Doptimize=ReleaseSafe --summary all
```

This fixture uses 70 queries and 26 PoW bits for both leaves and their parent,
checks independent child admission and full-memory custody, and verifies the root
after witness/worker destruction. Its existing worker cap is 48 GiB, unlike the
36 GiB single-child parent fixture. Source rows and allocator/backend overhead are
outside that worker cap. No completed result is claimed yet.

## Qualification result

The four-leaf/two-level CPU tree gate passed with compact fixed rows and the
non-consuming base paired-admission checks. It verified two height-one nodes and
an independently verified root; retained root rows were 669,671,752 bytes.
The two-job bounded pipeline reused its plan, overlapped preparation/proving
(10,780,157,791 ns measured overlap), and verified outputs after worker destruction.
Tracked worker peak: 3,862,465,628 bytes under an 8 GiB cap. Root artifact: 131,497
bytes. Wrapper: 5 minutes, 6 GiB MaxRSS including compilation. This remains the
diagnostic q8/PoW0 tree, not canonical-parameter aggregation or a speed benchmark.

Compact/full preprocessing parity for every cohort and compact interaction parity passed (7 seconds build/run, 608 MiB build MaxRSS).
The first root canonical-aggregation command stopped before compilation because its catalog entry was missing; that entry is now added and the command requeued.
