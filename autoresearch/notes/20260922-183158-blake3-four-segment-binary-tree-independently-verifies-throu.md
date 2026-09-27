---
title: BLAKE3 four-segment binary tree independently verifies through owning nodes
author: Teddy Pender
created_utc: 2026-09-22T18:31:58Z
---

# Owning BLAKE3 tree nodes and four-segment binary aggregation

`prover.blake3_execution_parent.tree.Node.verifyOwned` consumes an unverified
artifact under an independently pinned parent admission and authenticates the
supplied Span against that key. It owns its verified capture and copies the
admission and Span, with no borrowing from proving plans or witness rows.
Wrong-key admission consumes rejected artifacts as well. Node validation checks
both the statement identity and the capture seal; root admission additionally
requires complete execution coverage.

`tree.preparePair` borrows two verified nodes. It rejects aliasing, unrelated jobs,
wrong heights, gaps and reversed order before witness allocation. It prepares
the two verifier witnesses, carries each child Span/custody identity through its
admitted aggregate key, relocates the two namespaces and joins final columns.
Temporary child preparations are consumed on success or failure. No earlier
execution or aggregate witness is required. Output remains an unproved fold and
requires a caller-admitted parent key; it never selects verification authority
from a received proof.

The four-leaf test uses a real leaf-local runner with segment sizes 1, 1, 1 and 3.
It checks all adjacent full-memory/CPU boundaries and a nonzero final output,
proves two intermediate aggregates and then a root that recursively verifies
both aggregates. Each plan is destroyed before artifact roundtrip and independent
verification. Intermediate pair witnesses are released before preparing the next
pair/root. Aliased/reversed children reject, both root child-key bindings match,
wrong expected keys consume their rejected artifacts, complete root admission
succeeds, and the borrowed intermediate nodes remain valid afterward.

The integration boundary deliberately keeps admission separate from execution:

1. The caller admits the parent key and expected identity.
2. `Node.verifyOwned` verifies the artifact and its Span under that admission.
3. `preparePair` prepares a folded witness from two verified nodes.
4. The caller derives/adopts the next trusted key from that preparation, uses the
   shared persistent `ForBackend(Backend).Plan` to prove it, and repeats step 2.

The existing bounded overlap scheduler remains tied to the older native-child
preparation/worker protocol. Adapting that shared scheduler is the next scheduling
integration; this change does not introduce a competing queue or worker pool.

## Qualification command

`python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-aggregation -Driscv-test-filter=four-leaf -Doptimize=ReleaseSafe --summary all`

Passed: 5 minutes build/test, 6 GiB peak RSS. The two intermediate artifacts
are 130,994 and 132,374 bytes; the root is 131,497 bytes. Root preparation
retains 1,077,529,688 bytes. All three nodes independently verify and complete
root admission succeeds. These are diagnostic qualification measurements,
not canonical end-to-end proving latency or speedup evidence.

This focused command covers the new four-leaf case. The unfiltered aggregation
gate now requires both the existing two-segment case and the four-leaf case.

This is diagnostic q8/PoW0 CPU work with specialized caller-admitted keys. It does
not complete a production scheduler, padding/non-power-of-two orchestration,
precompile integration, canonical recursion qualification, Metal parity, default
promotion or active Poseidon removal. No recursion speedup is claimed. The
persistent-plan/bounded-scheduling and other original performance goals remain
active.
