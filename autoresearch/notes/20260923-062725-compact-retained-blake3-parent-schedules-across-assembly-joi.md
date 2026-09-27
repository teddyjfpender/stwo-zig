---
title: Compact retained BLAKE3 parent schedules across assembly join and namespace rebasing
author: Teddy Pender
created_utc: 2026-09-23T06:27:25Z
---

# Compact fixed parent rows at assembly

Status: implemented; projection parity and complete tree qualification pending.

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
