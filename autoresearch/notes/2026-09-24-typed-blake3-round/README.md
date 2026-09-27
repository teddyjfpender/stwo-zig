# Typed BLAKE3 round precompile qualification

Status: rejected candidate, archived outside the live proving path. The commands
below describe the archived source checkpoint, not current build targets. The user
requested efficient, fully constrained hash precompiles as the default. Promotion
requires CPU/Metal and next-level qualification, not just fewer arithmetic rows.

The component fuses eight canonical G operations into one round. It reuses the
existing typed arithmetic author and witness operations, shares internal SSA
values, and retains explicit caller input/output wire bindings. All seven round
positions use the same normalized arithmetic with different authenticated schedules.
Hash framing, native compression outputs, query count and PoW policy are unchanged.

| Per compression, excluding final XOR/boundary components | Existing G | Round |
| --- | ---: | ---: |
| Rows | 56 | 7 |
| Main columns | 112 | 832 |
| Main cells before padding | 6,272 | 5,824 |
| Relation events before padding | 3,472 | 3,024 |

The 7.1% cell and 12.9% event reductions are structural counts, not measured
end-to-end speedups. Wider commitments can increase the next recursion level's work.

Implementation also removes two narrow runtime capacity assumptions. Interaction
event/batch ordinals now use u16, with internal plan format version 2. The direct
constraint compiler specializes capacity per AIR; existing components keep their
512-node/192-constraint storage. The round explicitly admits 4,096 nodes and 768
constraints. Polynomial export and component scratch use those same capacities.
This is an internal authenticated plan format change, not a hash framing change.

## Qualification

- `typed-and-compiler-safe.log`: 21/21 ReleaseSafe tests. Includes all seven round
  positions over randomized compression inputs, mutations of every one of 898
  main/fixed coordinates, original packed G checks, partition closure and original
  compiler base/extension-field equivalence and semantic-seal tests.
- `proof-safe.log`: four exact guarded tests pass. A real complete compression
  STARK uses seven round rows, sixteen feedforward XOR rows and public boundaries;
  independent verification rejects substituted preprocessing. The original G/XOR
  compression proof also passes. This gate uses diagnostic q8/PoW0.
- `test-blake3-round-cost`: matched q70/PoW26 CPU compression proof comparison.
  `canonical-cost-fast.log`: 1/1 guarded test passes; both proofs independently
  verify at q70/PoW26. The same public compression inputs are used in both arms.

The initial compile/guard failures are retained: the wider component exposed the
old event and direct-program limits; the focused root initially omitted the old
compression regression import; an anonymous compiler test then violated the exact
test-count guard. These were fixed rather than bypassing the guard.

Commands, from the repository root:

```sh
/opt/homebrew/opt/zig@0.15/bin/zig test -O ReleaseSafe --dep stwo_core -Mroot=src/frontends/riscv/blake3_round_test_root.zig -Mstwo_core=src/core/mod.zig
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-round-precompile -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-round-cost -Doptimize=ReleaseFast --summary all
```

Remaining: measure the width tradeoff, then integrate a beneficial design with
canonical native hash scheduling, compact trusted metadata and direct column
emission; qualify Metal and complete parent/parent-of-parent proofs. Full CSP
CPU/Metal recovery and default promotion are not established by these tests.

## Canonical comparison and decision

| Verified single-compression fixture | G | Round |
| --- | ---: | ---: |
| Committed columns, all trees | 328 | 1,838 |
| Committed cells, all trees | 10,521,152 | 10,517,088 |
| Next-level path G rows | 1,978,928 | 2,374,848 |
| Next-level path XOR rows | 565,408 | 678,528 |
| Next-level padded G domain log | 21 | 22 |
| Complete fixture wall time, one cold run | 17.324 s | 11.159 s |

**Do not promote round fusion to the default.** The verified next-level path census
increases 20.0% and crosses a power-of-two domain boundary. These are computed
requirements from a verified child capture, not an executed parent proof. Universal
lookup tables dominate this tiny fixture's committed cells; wall time includes
setup, PoW search, independent verification and negative checks. One unbalanced
sample per arm is not evidence of a runtime speedup. No CSP claim follows.

The next candidate should reduce the existing narrow G component: ZisK's equivalent
ROTR7 = ROTL1(ROTR8) construction can be adapted to two bounded 16-bit limbs in M31.
Boolean inter-limb carries and range-checked output bytes keep every equality below
2^17, avoiding the unsound direct 32-bit-field equations. This targets fewer columns
and lookups without the wide-round opening penalty. The present round remains a
qualified experimental comparison, not the default hash implementation.

The live round modules and their larger compiler/runtime capacities were removed
after the comparison. The canonical narrow G precompile is being optimized instead;
see [bounded rotations](../2026-09-24-blake3-rotate7-limbs/README.md). The archived
source retains the exact wide experiment and its original arithmetic for review.
