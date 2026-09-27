# Residual arithmetic fusion census — 2026-09-24

The previous goal turn was progress: bounded compression-call emission was
implemented and measured faster with canonical independent verification. This
checkpoint investigates priority 2 of the active objective: fusion beyond existing
dot4/FMA, using the current typed execution fixture rather than historical graphs.

## Implemented diagnostic

The existing authenticated arithmetic census now reports unreserved multiply,
linear and inverse rows after the canonical dot4/FMA matchers. It also counts:

- Inverses with exactly one use, feeding an existing FMA multiply. These are
  quotient-accumulation candidates; one inverse row could disappear into a new AIR.
- Single-use add/subtract/negate nodes feeding unreserved multiplies. These are
  candidates to absorb linear work into a multiplication row.

Graph outputs and explicit cross-circuit exports participate in use counts. The
focused test confirms that exported intermediates cease to be candidates. Neither
candidate set changes lowering, security parameters, proof shape or the AIR roster.
`STWO_RISCV_PARENT_FUSION_CENSUS=1` opts the typed execution preparation path into
this existing read-only census. It is off by default and also applies when preparing
a native parent capture. The caller still owns authenticated graph provenance.

## Current canonical fixture

M5 Max, ReleaseFast, SMP allocator, eight proving workers; both CPU child and Metal
parent use q70/PoW26. This is the tiny typed execution fixture, not a full tree.

| Lane | Remaining multiply | Remaining linear | Inverse | Quotient candidates | Products with linear inputs | Hidden linear candidates |
|---|---:|---:|---:|---:|---:|---:|
| Composition (1500) | 2,224 | 837 | 52 | 0 | 151 | 151 |
| DEEP (1502) | 12,778 | 8,722 | 842 | 210 | 3,203 | 3,203 |
| FRI (1504) | 52,168 | 13,581 | 1,260 | 0 | 3,501 | 3,501 |

Existing lowering already removes 196,842 of 368,470 arithmetic rows, leaving
171,628, including 19,613 dot4 and 59,551 FMA rows. Existing native query fusion
also replaces 9,170 dot4 groups and removes 36,680 scalar rows. These are existing
savings, not newly achieved speedups from this census.

The 210 quotient candidates are only 0.12% of remaining arithmetic rows, but if
all are admitted, inverse rows fall 2,154 to 1,944: padded height 4,096 to 2,048.
The 6,855 linear candidates could reduce linear rows 23,140 to 16,285: padded
height 32,768 to 16,384. These are **conditional geometry calculations**, not
qualified new circuits or measured runtime improvements. New component domains,
columns, constraints, lookup events and the next-level verifier cost must be included.

For scale, the existing inverse cohort has 14 main, 15 preprocessing and four
interaction base columns. Halving its current domain removes only 67,584 field
cells before accounting for the replacement component. The linear cohort has
21 + 27 + 8 columns; halving its domain removes 917,504 field cells before replacement.
These are not whole-process memory savings or LDE/commitment traffic estimates.
Neither candidate alone plausibly establishes an order-of-magnitude total win.

## Constraint requirements for the next implementation

A quotient accumulator must retain an explicit nonzero-denominator check. For the
positive-add case, witness the reciprocal and constrain both:

```
denominator * reciprocal = 1
denominator * (output - accumulator) = numerator
```

The second equation alone is unsound at denominator = numerator = 0. The external
lookup multiset must retain every denominator, numerator and accumulator occurrence
and the output's original multiplicity. Other signed FMA modes need their own exact
mapping; the census includes them and does not admit any particular component.

Linear-input fusion similarly needs exact add/subtract/negate semantics, protected
shared/exported intermediates, and accounting for preprocessing-selector degree.
Count reductions alone do not authorize deleting graph constraints or wire uses.

Next implementation should compare actual domain/column cost for these candidates,
then qualify constraint mutations, exact lookup closure, independent key derivation
and canonical proofs. The larger scheduling, full-tree, direct-layout, CSP recovery
and separately reviewed parameter requirements remain open.

## Verification and evidence

Focused ReleaseSafe target: **12/12 tests pass**, including the new export-safety
census check and the existing PCS fusion constraint/lookup/admission tests.
Canonical Metal target: **7/7 tests pass**, with independent verification, fresh
codec verification, transcript replay, worker rekey, plan reuse and output lifetime
checks; parent size remains 857,591 bytes. This run does not record an artifact SHA,
so it is not additional evidence of byte identity with the previous checkpoint.

The initial focused run executed 13 passing tests but failed its exact-count guard:
an unnecessary anonymous root test had been added. Its import moved into the existing
comptime block; the final run passes the 12-test guard. Both logs are retained.

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-recursive-fused-pcs-opening -Doptimize=ReleaseSafe --summary all
STWO_RISCV_PARENT_FUSION_CENSUS=1 STWO_RISCV_PARENT_BENCH_ALLOCATOR=smp STWO_RISCV_PARENT_BENCH_WORKERS=8 python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal test-blake3-native-parent-aot -Dmetal-core-aot-bundle="$PWD/zig-out/share/stwo-zig/metal/core" -Doptimize=ReleaseFast --summary all
```

`canonical.log`, `census.json`, focused logs, frozen executable and changed-source
snapshots are retained. `binary.json` pins the executable and identifies the previously
archived authenticated bundle. These changed files are not a complete clean-checkout
reproduction of the dirty workspace. No new speed or memory benchmark is claimed.
