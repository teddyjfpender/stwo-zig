# 2026-08-12 — JAL production SSOT

## Status

JAL is a live production typed authority. The fixed capability now owns
architectural retirement, witness construction, direct constraints, ordered
relations, and formal extraction. The legacy executor fails closed, and the
retired semantic source survives only as an explicitly named independent test
oracle. Exact proof A/B, independent verification, and required-live Sail have
all passed on the same retirement stream.

## Fixed authority

`typed_jal_authority.zig` binds one pointer-free executable capability to the
already authenticated typed JAL definition and witness recipe:

```text
main columns:       20
direct roots:       10 (nine family roots plus placement)
ordered relations: 8
lookup batch size:  2
protocol opcode:    33
authority digest:   5bbec19054a41de222c3e7bbad2e4ee900b5f7fe1fd62804b80aedff9bbe4aea
```

The relation order remains program fetch, state consume/emit, middle-byte
range, outer-byte range, destination consume/emit, and destination clock gap.
This preserves the existing physical AIR and transcript geometry; the cutover
is an authority consolidation, not an AIR-size or degree change.

The capability also pins the control-flow refinement which physical columns
alone do not express: a signed 21-bit J immediate with one encoded low zero
bit; a wrapping RV32 `pc + immediate` architectural target; four-byte zkVM
instruction alignment; and a 30-bit program-commitment address domain. Both
source and target are admitted against the program-word profile before a row
can retire. Accepted executions therefore cannot exploit field/u32 or
uncommitted-program-address aliases.

## Failure-atomic retirement

`jal_retirement.zig` compiles one exact decoded-word-bound retirement into a
compact fixed transaction. It owns link generation, x0 discard, target and
branch metadata, the destination predecessor, synthetic clock gaps, CPU
publication, and the canonical trace row.

All fallible capacity work occurs before logical mutation. A cold allocator
return revalidates the complete CPU, trace, and state-chain snapshot; the warm
path allocates nothing. The common no-gap publication writes the already
authenticated event directly, while the uncommon path retains the generic
gap publisher. A closed-form gap derivation replaces two scans and is checked
against the generic state-chain algorithms at every threshold plus 16,384
deterministic samples across the proof clock domain.

The adversarial gate covers malformed words, all representable J displacements,
misaligned and out-of-program targets, source-PC bounds, x0, encoding-field
aliases, forged plan fields, stale CPU/trace/tracker state, allocation failure,
and exact compact-vs-generic transaction equivalence. Direct roots and every
ordered relation are also compared against an independent retained polynomial
oracle over random QM31 rows.

## Production evidence

The production AIR and runner roots pass in Debug and ReleaseSafe. The runner
root passes in ReleaseFast, and the focused ReleaseFast JAL AIR gate passes
65/65 tests. The formal production-extraction differential passes all 17
families over 32 trials, and the exhaustive JAL witness-rigidity corpus passes
6,918 admissibility evaluations within its 8,000-evaluation budget.

The full ReleaseFast AIR root was also attempted. Every JAL test passed, but
the aggregate gate stopped on unrelated noisy LT_REG and MULH witness
performance thresholds; their failures are not relabelled as JAL evidence and
their thresholds were not weakened.

The ReleaseFast retirement admission uses nine paired samples over 16,384 rows
with mixed fallthrough, forward, and backward aligned targets. It compares the
typed path with the exact pre-cutover execution/trace/access work and enforces a
1.20x ceiling. Three consecutive medians after the final benchmark broadening
were:

| Run | Typed | Legacy | Typed / legacy |
| ---: | ---: | ---: | ---: |
| 1 | 209,084 ns | 264,542 ns | 0.7904 |
| 2 | 209,000 ns | 226,375 ns | 0.9232 |
| 3 | 209,500 ns | 228,042 ns | 0.9187 |

An unchecked assume-capacity implementation is printed separately as a
diagnostic lower bound (1.51–1.56x faster than the fully checked typed path in
these samples). It deliberately omits word, clock, target, and atomicity checks
and is not used as the regression baseline.

These are local runner measurements, not proof-speed claims. The typed witness
retains its independent scaling/performance gate. The production constraint
and relation routes also have a paired ReleaseFast admission against the exact
retired evaluators. Three consecutive fixed-path medians were:

| Run | Direct speed | Lookup speed |
| ---: | ---: | ---: |
| 1 | 1.1129x | 1.0314x |
| 2 | 1.0787x | 1.0066x |
| 3 | 1.0847x | 1.0032x |

Both routes enforce at least 0.97x retained throughput. The production runner
root measured 192,875 ns typed versus 222,250 ns legacy, a typed/legacy time
ratio of 0.8678. These receipts establish local non-regression; they do not
claim a whole-proof speedup.

The generated and retained-legacy witness arms produced identical statements,
interaction claims, terminal transcript state, and serialized proof bytes,
then independently verified. With the pinned Sail oracle required on that
exact proven stream, the receipt was:

```text
proof bytes: 54850
proof sha256: ef797c33718909bece536409c81d39fd4b064500f3c1fe85649e3ddd197163ba
transcript:   39367abaaddac2755434c66518fb3bbd36586ed73c559c0d53580b9fa673c431
draws:        1
Sail:         required and answered; exact retirement stream agreed
```

## Closed promotion checklist

- JAL routes through the generated-retirement registry, and the legacy
  executor rejects it without mutation.
- Witness generation, direct roots, lookups, and formal extraction route
  through the fixed capability.
- The handwritten semantic module is removed from production; the independent
  legacy polynomial oracle is explicitly test-owned.
- Singular-source guards and canonical test-root coverage are live.
- All relevant all-mode and focused performance gates above are recorded.
- Proof A/B, independent verification, byte/transcript equality, and
  required-live Sail are closed.

The compatibility manifest check is intentionally not regenerated while other
authority migrations are concurrent. Its exact audit reports only the
concurrent BASE_ALU_REG formal-export digest mismatch; JAL introduces no
artifact mismatch. The full package gate additionally reports unrelated live
branch inventory/performance failures. The coordinated BASE_ALU_REG artifact
pass remains a repository-level task rather than a reason to preserve duplicate
JAL source.
