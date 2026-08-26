# 2026-08-12 — BRANCH_EQ production SSOT

## Status

BEQ/BNE are live production typed authorities. One authenticated fixed
capability owns architectural retirement, witness projection, direct roots,
ordered relation events, and formal extraction. The generated-retirement
registry owns both decoded opcodes, the legacy executor fails closed without
mutation, and the old handwritten semantic evaluator is now an explicitly
named test-only oracle.

## Fixed authority

`typed_branch_eq_authority.zig` binds the complete typed BRANCH_EQ graph and
physical witness recipe to this pointer-free production geometry:

```text
main columns:       30
direct roots:       18 (17 family roots plus placement)
ordered relations: 9
lookup batch size:  2
protocol opcodes:   BEQ=27, BNE=28
authority digest:   afa781f9d1a02f5906706554bcc694f39658998470b6da79ee85717e4b0232f4
```

The capability pins equality and inequality witnesses, BEQ/BNE condition
selection, every signed even B immediate, four-byte zkVM target alignment, the
30-bit program-address domain, x0 and same-source aliases, two ordered
read-only register accesses, state transition, and the subtle distinction
between a logically taken `+4` branch and the physical `branch_taken` marker.

Production direct and lookup facades use statically selected BRANCH_EQ seams
after their family admission check. This removes repeated dynamic dispatch
from a frequent, lookup-light control family while retaining the generic
family entry points and exact typed authority underneath.

## Failure-atomic retirement

The fixed retirement transaction authenticates the complete encoded B-type
word, including both source register fields, every immediate bit, and the
decoder's trace-visible diagnostic `rd` field. It stages source values, raw and
effective predecessor clocks, gap counts, target, and branch marker before
capacity growth or logical publication.

Source one publishes before source two. When the registers alias, source two's
authenticated predecessor is source one's newly emitted event. Allocation
failure and every stale CPU, trace, plan, or tracker mutation expose no partial
retirement. The hot fused route allocates nothing. Exact compiled sizes are 72
bytes for the compact transaction, 80 bytes for the plan, and 16 bytes for the
single-use prepared token.

The encoding gate exhausts both opcodes, all 4,096 representable even B
immediates, and all 32 × 32 source-register encodings. Boundary, x0, alias,
misalignment, stale-state, forged-word, allocation-failure, and clock-gap
tests are independently covered.

## Production evidence

The canonical AIR root passes 686/686 tests in Debug and ReleaseSafe. The
runner root passes 346/346 in Debug, ReleaseSafe, and ReleaseFast. Formal
production extraction agrees for all 17 families across 32 deterministic
trials. The exhaustive BRANCH_EQ rigidity lane performs 6,918 admissibility
evaluations within its 8,000-evaluation budget.

Final focused ReleaseFast medians, each consuming the complete result to
prevent dead-code elimination, were:

| Route | Typed/production | Retired legacy | Legacy / typed |
| --- | ---: | ---: | ---: |
| production direct AIR | 11,465,875 ns | 13,033,459 ns | 1.1367x |
| production lookup construction | 3,915,083 ns | 3,909,833 ns | 0.9987x |
| runner retirement | 192,250 ns | 318,375 ns | 1.6560x |

The two preceding focused evaluator samples measured 1.1365x/1.1256x direct
and 0.9962x/0.9986x lookup throughput. The independent witness scaling gate measured 1.1018x,
1.1389x, and 1.1291x at 1,024, 16,384, and 262,144 rows in the final complete
ReleaseFast run. Every BRANCH_EQ route retains the strict 0.97x throughput
floor without a waiver.

The full ReleaseFast AIR root reached and passed every BRANCH_EQ correctness
test. Its aggregate performance run remained noisy: an earlier pre-final
lookup implementation sampled at 0.9675x, and complete reruns also stopped on
unrelated BASE_ALU_REG, FENCE, LT_REG, and MULH local microbenchmark samples.
The final implementation then passed two isolated ReleaseFast admissions at
0.9962x and 0.9986x; no threshold was weakened and unrelated failures are not
reported as BRANCH_EQ evidence.

The complete Debug package audit compiled 1,820 tests and reached 1,816 passes,
one skip, and three pre-existing failures before an unrelated BASE_ALU_REG
fixture assertion terminated the runner. Its inventory diagnostics name only
concurrent private-family and recursion files; no BRANCH_EQ production file is
missing. The other failures are the already-open compatibility artifact and
unreviewed-effect validation drift. They remain visible and were not changed
to promote this family.

Generated and retained-legacy arms produced identical statements,
interaction claims, terminal transcript state, and serialized proof bytes,
and each proof was independently verified. The pinned Sail oracle was required
to answer on the same guest:

```text
proof bytes: 57073
proof sha256: 1188c212cf160b7e4b77294e6f4b94d75b4ad8915db674f96a3349370df8b7d2
transcript:   79f12b629a0be20d86df373b302fee35e701922e819cca5f75ee87b5359e1537
draws:        1
Sail:         required and answered; exact retirement stream agreed
```

## Closed promotion checklist

- Generated retirement owns BEQ/BNE, and the legacy executor rejects both
  without mutation.
- Witness generation, direct roots, relations, and formal extraction route
  through the same pinned typed authority.
- The handwritten semantic evaluator is absent from production and explicitly
  named as a retained test oracle.
- Canonical roots and inventory include authority and retirement gates; the
  private root has been removed.
- Exact polynomial/ordered-relation parity, exhaustive encoded-word coverage,
  allocation and stale-state negatives, formal extraction, exhaustive witness
  rigidity, proof A/B, independent verification, required-live Sail, and
  performance gates are closed.

The compatibility artifact is intentionally not regenerated while other
family identities are concurrently migrating. That repository-level source
closure remains an explicit final coordinated admission task, not a reason to
retain duplicate BRANCH_EQ production authority.
