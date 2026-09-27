---
title: Measure frame encoding allocation-order regression
author: Teddy Pender
created_utc: 2026-09-22T07:26:41Z
---

# Restore frame encoding order around direct destinations

The direct frame destination change moved live encoded bytes after G/XOR row
allocation. Earlier owned frames encoded before allocating rows. With arenas this
can change chunk growth despite identical output ownership. The overall tracked
preparation peak rose by 21,848,700 bytes; frame receipt lifetime separation alone
did not change that peak.

Mechanical experiment: restore encoding before row allocation for live frames,
keeping direct destinations and fixed-row writers intact. No algorithm/protocol
change. Byte storage remains frame-arena-owned; borrowed destinations are validated
first. Falsifier: full native tracked preparation peak does not fall. Validate
frame failure/parity and native proof; do not claim the cause without measurement.
