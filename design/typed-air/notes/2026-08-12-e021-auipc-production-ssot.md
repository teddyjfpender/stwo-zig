# 2026-08-12 — AUIPC production SSOT

## Scope

AUIPC is the fourth live execution/AIR single-source family. One immutable,
pointer-free typed authority owns its PC-relative architectural result and x0
visibility, exact 29-column witness recipe, 17 direct roots, 12 ordered
relations, and formal/runtime identity.

Production now routes AUIPC through the generated retirement registry. The
legacy executor fails closed with `GeneratedRetirementRequired`; the retired
Stark-V-shaped semantic evaluator is named and rooted only as a test oracle.

## Runner boundary

The fixed 64-byte plan authenticates the complete U-type word (including the
trace-visible diagnostic `rs1`/`rs2` decode bits), pre-retirement PC, register
value, predecessor access clock, gap geometry, expected trace position, typed
result, and sequential next PC. Trace/access capacity is reserved before the
first logical write. A cold allocator return revalidates the complete live
snapshot; a warm retirement allocates nothing. The prepared token is 16 bytes
and single-use.

Tests cover every destination register, x0, U-immediate sign boundaries,
diagnostic-field aliases, forged plans/words, stale PC/register/trace/tracker
state, induced allocation failures, and allocation-free warm execution.

## Independent evidence

- The fixed evaluator is symbolically node-identical to the retained legacy
  direct and lookup formulas.
- The architectural corpus agrees with the required live pinned Sail oracle;
  oracle absence was configured as a hard failure.
- The serial proof A/B gate independently regenerates the final family witness
  with the retired writer, requires identical statement, claim, transcript,
  and proof bytes, and independently verifies both arms.
- Debug AIR and runner gates pass after production wiring; ReleaseSafe runner
  plus required Sail passes.

Pinned proof evidence:

```text
proof bytes:  57468
proof SHA256: 65d47cdf783470a0833d548d38e655abf0a939ec3f7989e8a8eae9574b9399d7
transcript:   6cab10fa3ee9bebdc43a6b3949faf125066ef20f4f330fbdd90691eb91bf972a
draws:        1
```

Representative paired performance:

```text
retirement:       129292 ns typed / 141667 ns legacy = 1.0957x
witness 2^10:     104375 ns typed / 104125 ns legacy = 0.9976x
witness 2^14:    1675750 ns typed / 1680167 ns legacy = 1.0026x
witness 2^18:   26963792 ns typed / 26925625 ns legacy = 0.9986x
direct Debug:       approximately 1.04x to 1.06x
```

The ReleaseFast aggregate reported two unrelated existing microbenchmark
failures in BASE_ALU_REG and LT_REG. AUIPC's own witness and retirement gates
were green. A separate audit found BASE_ALU_IMM's runner assertion did not
encode its documented 0.97x floor; that admission is explicitly reopened and
is not attributed to AUIPC.

## Residual boundary

The compatibility manifest is intentionally not regenerated while adjacent
family source-closure identities and the combined formal receipt are in
flight. No AIR geometry, relation order, batch size, or proof protocol changed.
The combined artifact update must follow the live formal gate, not precede it.
