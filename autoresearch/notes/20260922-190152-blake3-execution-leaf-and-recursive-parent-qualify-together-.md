---
title: BLAKE3 execution leaf and recursive parent qualify together at q70 PoW26
author: Teddy Pender
created_utc: 2026-09-22T19:01:52Z
---

# BLAKE3 execution leaf and recursive parent at q70/PoW26

A dedicated focused gate uses the canonical segment owner and caller-pinned
segment-to-parent pipeline for a real six-instruction program publishing a
nonzero output byte. Both the execution leaf and its parent select exactly
70 queries, 26 PoW bits, log blowup 1, last-layer bound 0 and fold step 1.
The job/Span protocol identity binds the leaf configuration and full program,
initial/final memory and public-I/O identities. The parent context records and
checks the same admitted child configuration.

The fixture releases the runner, execution owner, child verifier and conversion
witnesses before parent proving. Parent proving uses the shared persistent worker
with four CPU workers and a 24 GiB routed-allocation cap. It then destroys both
the worker and prepared columns before verifying the original artifact and an
independently decoded copy. Root coverage and the parent's 70 actual raw queries
are checked; the original verified capture retains its allocator lease.

## Qualification command

`python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-canonical-chain -Doptimize=ReleaseSafe --summary all`

Passed: 4 minutes build/test, 25 GiB peak RSS. Preparation contains 81,132
inputs and retains 4,214,454,616 bytes. The independently verified parent artifact
is 860,503 bytes. Worker peak routed allocations are 23,106,927,066 bytes under
the 25,769,803,776-byte cap. Both original and decoded proofs pass root coverage
after proving plans and witnesses are released. These are qualification/resource
figures, not isolated proof latency or an end-to-end speedup measurement.

The separate target keeps this higher-memory case out of the ordinary diagnostic
iteration gate. This is a single execution leaf plus one recursive parent, not
a canonical multi-segment tree or an additional parent-of-parent level. It also
does not establish production key authority, extension/precompile integration,
Metal parity, default replacement or an end-to-end speedup. Those requirements
and the complete original performance objective remain active.
