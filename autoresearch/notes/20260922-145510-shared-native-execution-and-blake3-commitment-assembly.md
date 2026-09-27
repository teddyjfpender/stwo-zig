---
title: Shared native execution and BLAKE3 commitment assembly
author: Teddy Pender
created_utc: 2026-09-22T14:55:10Z
---

# Shared native execution and BLAKE3 commitment assembly

The existing execution-statement implementation now provides a full-width
BLAKE3 execution shape. Its admission rejects legacy program, memory, Merkle
and Poseidon infrastructure, bounds PC coordinates to the program-tree domain,
and requires execution headers to agree with public state. Legacy statement
layout and transcript namespace remain unchanged.

The same base assembly walk now constructs native opcode/clock/lookup adapters
for the new shape. A stable owner binds both proving and verification adapters
to native relations projected from the same universal challenge draw as the
BLAKE3 components. Full public roots are checked against the admitted commitment
plan. Commitment manifest origins place their columns and constraints after
native execution; placement arithmetic is checked for overflow.

Validation: test-riscv-statement-codecs passed before the heavy check was split
out (1 min, 4 GiB). The new test-riscv-blake3-execution-commitments gate passes
with a minimum of one test (51 s, 3 GiB). It exercises a native base-ALU-immediate
component shape with supplied claims alongside the program/memory preparation
fixture, shared challenge binding, offset placement, public compensation and
legacy-provider/overflow rejection. It retains column/interaction/reuse checks.
The ordinary codec gate now excludes this heavier engine-integration branch.

This is component assembly, not a proof of that instruction execution. Native
execution witness/lookup-table assembly, the complete joined STARK, PCS key and
artifact admission, continuation and multi-level recursion remain unfinished.
No default promotion or end-to-end speedup is claimed.
