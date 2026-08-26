# 2026-08-13 — row-19 composition-control proof

## Question

Can the verifier-owned AIR-composition control slice enter the captured-leaf
outer proof without adding a second schedule authority or material overhead to
the arithmetic hot path?

## Implementation

Row 19 now uses `control_slice_witness.CompositionPreprocessed` built from the
same authenticated VM and recursion `verifier_schedule.Plan` values already
used by the Merkle and FRI-control rows. The manifest admits it before row 20,
and named log indices replace numeric offsets throughout the outer assembly.
The component has nine preprocessing columns, zero main columns, four
interaction columns, one generated direct constraint, and one LogUp batch.

Its absence of main columns permits a stronger verifier boundary. After
drawing its own universal relation challenges, the verifier recomputes the
entire row-19 claimed sum from canonical preprocessing and the fixed segment
proof kind. A mismatched claim rejects before the proof object is consumed.
This adds a fourth outer mutation in addition to public-boundary, wire-closure,
and preprocessing-root mutations.

## Evidence

Both runs use ReleaseSafe and four outer workers.

| Measure | Frozen V1, 2x/193 | Frontier candidate, 4x/97 |
| --- | ---: | ---: |
| Honest proof union | 17/36 | 17/36 |
| Covered contiguous rows | 19--34 | 19--34 |
| Columns, preprocessing/main/interaction | 316/758/256 | 316/758/256 |
| Constraints | 850 | 850 |
| Proof estimate | 66,360 B | 64,760 B |
| Prove | 55.499 s | 28.137 s |
| Assembly | 46.241 s | 23.438 s |
| STARK body | 9.248 s | 4.691 s |
| Independent verify | 18.161 s | 9.251 s |
| Outer mutations rejected | 4/4 | 4/4 |

The PCS graph and multiply/inverse/linear row counts are identical to the
row-24 checkpoint. Timings are slightly favorable but remain within normal
single-run noise; no speedup is claimed. The added proof-size cost is 1,884
bytes on frozen V1 and 1,852 bytes on 4x/97.

## What this does not establish

The row consumes authenticated `recursion_step` tuples, but their complete
producer/global cancellation is not yet in this partial proof. Row 18 still
needs a production VM AIR-composition graph; rows 1--17, row 35, full relation
closure, child-proof binding, and the canonical proved `2 -> 1` node remain
open.

## Decisions/tasks affected

- R-012 honest proof coverage advances from 16/36 to 17/36.
- The next contiguous boundary is row 18's production composition graph.
- Fixed-only component claims should be verifier-recomputed before proof
  consumption whenever their cost is bounded.
