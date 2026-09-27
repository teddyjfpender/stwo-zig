---
title: BLAKE3 continuation memory conversion and public custody qualification
author: Teddy Pender
created_utc: 2026-09-22T17:27:18Z
---

# BLAKE3 continuation memory custody

Ordinary execution memory roots exclude words whose memory-access custody is
handled by public I/O. Continuation roots commit the full retained snapshot.
These are different commitments and cannot be directly equated by aggregation.

The new conversion reuses the typed single-byte update with shared private
siblings. A canonical sorted edit chain owns its intermediate full-width roots,
uses disjoint path namespaces, and binds both endpoints and every edit in its
plan identity. Fixed columns reconstruct from caller-pinned plans independently
of private paths. A separate witness planner computes intermediate roots without
conferring admission authority. Partial preparation failures release earlier
path allocations.

Public-custody admission derives the exact allowed edits from admitted public
inputs, output words, completion and ordinary memory schedules. Snapshot role
flags do not authorize edits. All four bytes of each excluded public word are
checked, including zero bytes. Inputs already covered by a final memory boundary
are not reinserted. Conflicting schedules and duplicate custody are rejected.
Execution proof authentication remains a caller obligation: commitment-plan
admission alone is not evidence of a valid execution.

The ordinary commitment witness exposes `prepareContinuation`, taking a
caller-supplied full-memory root and checking the ordinary endpoint against its
admitted commitment plan. It returns owned conversion rows and a plan suitable
for subsequent parent integration. The span protocol must authenticate the full
endpoint and include these rows in the parent proof; this change does not yet
perform that integration or prove distinct-child aggregation.

## Validation scope

The focused memory-update gate includes five named tests:

- Existing single-byte update STARK and altered-root rejection.
- Chained insertion/deletion STARK preserving an unrelated byte, with altered
  intermediate-root preprocessing rejected. Diagnostic q8/PoW0.
- Plan/witness rejection for wrong pins/endpoints/intermediate roots, changed
  before bytes, duplicate addresses, colliding namespaces and unrelated memory
  changes; empty transition and partial-allocation cleanup.
- Public custody derivation, exact little-endian bytes including zero bytes,
  touched/untouched input distinction, mutated public values, stale admission,
  conflicting schedules and owned conversion preparation.
- Real runner input with high bytes: entry and exit conversions match separately
  constructed full snapshot roots; substituted full roots reject. This tests
  snapshot conversion, not a new execution proof with this input.

The runner fixture initially rejected nonempty input because its ELF declared
no input capacity. The corrected fixture declares input start/end symbols.

Command:
`python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-memory-update -Doptimize=ReleaseSafe --summary all`

The focused ReleaseSafe gate passed (36 seconds build/test, 1 GiB peak RSS).
The suite guard requires all five named tests. The terminal result is retained
in `qualification.log`. No whole-repository suite,
canonical-security recursion benchmark, Metal gate or speed comparison ran.
Production defaults and prover-owned Poseidon removal remain unfinished.
