---
title: Checked private draw counter advancement
author: Teddy Pender
created_utc: 2026-09-22T00:24:06Z
---

# Checked private draw counters

Task: authenticate counter_next = counter + pending, with pending boolean, exact
u64 bytes, and no wrapping. Byte ripple-carry is the exact canonical addition
circuit: eight byte equations, seven boolean carries, one boolean increment;
range-check input/output bytes. O(8) work, fixed shape independent of values.
Reuse existing byte-pair lookup tables and wire tuples; no external code copied.
Pair this with first-acceptance control: pending is one through the accepted
attempt, then zero, so padded slots preserve the selected native counter.

Expose draw-index words through canonical frame callbacks, preserving protocol
bytes. Build a bounded draw fragment from existing hash/challenge/frame providers,
retry control, and the checked counter. Its capacity is explicit and trusted;
exhaustion is an admission error, not permission to skip acceptance. Initial
counter/state and final challenge/counter are authenticated external ports.
This is not yet a complete reusable transcript or production key family.

Verify typed identity/export, every byte carry boundary, u64 maximum and overflow,
nonboolean carry/increment mutations, input/output range requests, native frame
parity, native genuine rejection plus padding, and a complete fragment proof.
Final transcript integration and capacity-family admission remain separate work.
