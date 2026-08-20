# 2026-08-12 — E-020 BASE_ALU_REG production SSOT

Status: production cutover complete; authenticated-manifest regeneration is
deferred to the coordinated artifact pass.

## Fixed authority

`typed_base_alu_reg_authority.zig` is a fixed, pointer-free authority over the
existing native typed BASE_ALU_REG graph. Its authenticated binding owns:

- protocol opcode ids `0, 1, 5, 8, 9` for ADD, SUB, XOR, OR, AND;
- all 35 physical columns and the existing witness binding;
- 22 direct constraints, including active placement;
- all 18 ordered lookup events, their roles and access ordinals;
- the two-event LogUp batch geometry; and
- architectural result and x0-discard behavior.

The frozen authority receipt is:

```text
ab6f594fea12f5d296126f074f05d3540ca689df30367435ac775123b60302df
```

The evaluator is a direct fixed replay, with no graph walk, allocation,
strings, function pointers, or runtime recipe dispatch. Symbolic admission
proves node-identity equality against the independent legacy polynomials for
all direct roots and lookup fields.

## Retirement geometry

`base_alu_reg_retirement.zig` compiles the exact three-access transaction:

```text
rs1 read @ phase 1 -> rs2 read @ phase 2 -> rd write @ phase 3
```

Alias resolution always selects the latest earlier physical phase. In
particular, for `rd == rs1 == rs2`, the destination consumes the phase-2 rs2
event, not the phase-1 rs1 event. The compiler is differentially checked
against the generic access compiler across every opcode and alias partition.

Staging is allocation-free and mutation-free. Preparation reserves the trace,
access log, and every possible synthetic register-clock row before publishing
anything. The warm commit is allocation-free. Cold allocation failure, forged
plans, CPU changes, tracker changes, and double commit all reject without a
logical trace, CPU, or access-chain prefix.

The compact transaction and plan are compile-time stack-budgeted at 112 and
128 bytes respectively.

## Evidence

Pre-promotion focused Debug root:

```text
214/214 tests passed
```

Five consecutive ReleaseFast direct-evaluator paired medians:

```text
1.2872x  1.2824x  1.2946x  1.2899x  1.2979x
```

Five consecutive ReleaseFast retirement paired medians:

```text
1.6984x  1.7737x  1.7217x  1.7565x  1.7373x
```

Both performance tests enforce the strict lower bound
`typed_median * 97 <= legacy_median * 100`.

## Production promotion receipt

All runtime promotion work is closed:

1. `.base_alu_reg` direct roots, lookup events, formal extraction, and witness
   generation route through the fixed authority;
2. ADD, SUB, XOR, OR, and AND are dense entries in generated failure-atomic
   retirement dispatch;
3. the legacy executor fails closed for every migrated opcode;
4. the retired semantic evaluator is absent from the production registry and
   remains rooted only as an independent differential oracle;
5. canonical test roots and source-level singular-authority guards cover the
   authority and transaction; and
6. live Sail covers all five operations, x0 discard, and the
   `rd == rs1 == rs2` alias partition.

Canonical admission evidence:

```text
Debug AIR:                  668/668 passed
Debug runner:              319/319 passed
ReleaseSafe AIR:           668/668 passed
ReleaseSafe runner:        319/319 passed
ReleaseFast AIR:           668/668 passed
ReleaseFast runner:        319/319 passed
Required-live Sail runner: 319/319 passed

ReleaseFast fixed direct evaluator: 1.3249x
ReleaseFast witness medians:         0.9961x  0.9973x  0.9888x
ReleaseFast atomic retirement:       1.1830x

Exact proof bytes:       55171
Exact proof SHA-256:     e95dff718cf31f6cce4ade9ea8dce269437bb73e914e25e8d1fc3296af56ce50
Exact transcript digest: 659a61c4c45bf996f91f8029457364e6231258179e06249bc88d89d410a8e4f8
```

The proof generated from the production authority is byte-identical to the
proof generated with the retained legacy witness oracle. Compatibility
artifacts are intentionally not regenerated here; that remains one
coordinated review boundary across all concurrently promoted families.
