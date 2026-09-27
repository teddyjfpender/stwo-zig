# Canonical fusion census without parent witness emission

`test-blake3-planning-census` independently proves/verifies the existing canonical
compact RISC-V child at 70 queries and 26 PoW bits, authenticates its capture, and
constructs the ordinary deferred parent plan. It inspects arithmetic graph shapes
without emitting parent hash columns, assembling the parent rows, or proving a
parent. This reduces the development loop needed to choose fusion experiments.

`Planned.fusionCensus` uses only initialized planning state. The shared graph census
accepts explicit graph/deep inputs, and the existing full-source census delegates to
it. There is no duplicate matching implementation. The diagnostic retains the plan
and capture pointers, does not consume the plan, rejects a consumed plan, and uses
the testing allocator for cleanup checks. Production proof behavior is unchanged.

The output explicitly distinguishes a verified canonical child from an un-emitted,
unproved parent. This diagnostic is not parent correctness, speed or recursive-tree
qualification. Counts from this child are not evidence for a parent-of-parent shape.

The first build failed because the new harness lacked its direct postcard import;
`census-initial.log` records that failure. The corrected harness imports postcard and
prover API explicitly. Final qualification is recorded in `census.log`.

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-blake3-planning-census -Doptimize=ReleaseSafe --summary all
```

The host remains on low battery, so no performance timing conclusion is drawn.
The earlier shared-leaf end-to-end comparison still requires external power.

## Qualified results and next action

Final focused gate: **8/8 checks pass**, ten seconds testing, cached compilation
76 ms, 341 MB reported maximum RSS. These low-battery timings describe the completed
development gate only, not an accepted prover speed benchmark. `census-roster.log`
retains the preceding run where all eight checks passed but the guard expected only
one. The final exact roster includes the named check and seven imported anonymous
tests; no test was removed to satisfy the guard.

The current canonical child contains 6,800 subtraction-input products, 27 addition
cases and only two negations after existing dot4/FMA reservations. There are no
products with two removable operands. Negation-only fusion is therefore not the
next implementation priority for this fixture. A degree-two subtraction-product
component is the concrete candidate to implement and compare at the next level.

`analyze.py` reads the qualified census and produces `analysis.json`. Its conditional
static estimate for a 17-main/7-fixed/8-interaction subtraction-product component:
linear rows 22,923 -> 16,123 (padded 32,768 -> 16,384), multiply/FMA rows
126,358 -> 119,558 (padded height unchanged), and a new 8,192-row domain. Net base-field
column storage falls by an estimated 2,818,048 bytes. That is not a measured peak
reduction or speedup: the component is not implemented, and the estimate excludes
LDE/FRI, composition, Merkle trees and next-level verification/hash costs. The narrow
261-row margin below the linear height boundary must also be checked on recursive
parent captures before promoting the candidate.
