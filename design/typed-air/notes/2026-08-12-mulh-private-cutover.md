# MULH private fixed-authority cutover

Status: family-private implementation complete; shared production wiring intentionally deferred to the serialized integration owner.

## Scope

This slice closes the executable typed authority and failure-atomic retirement boundary for the shared RV32 high-word multiply family:

- `MULH`: signed × signed, high 32 bits;
- `MULHSU`: signed × unsigned, high 32 bits;
- `MULHU`: unsigned × unsigned, high 32 bits.

The retained authority is pointer-free and authenticated by
`cdd4adafaac33832e7e8797021ea1b5e0073cbce33933a942968c3387c6262a5`.
It owns the operation algorithms, all physical witness slots, all direct-root
recipes, all ordered relation recipes, and batch size. The legacy semantic
module remains a test oracle only.

## Protocol geometry and hot-path contract

- 47 main columns.
- 24 direct roots: the 23 legacy semantic roots plus placement.
- 22 ordered lookups in one-entry batches.
- Eight `range_check_8_11` product/carry requests.
- Two `range_check_m31` sign-bit requests.
- Zero new symbolic DAG nodes when replaying direct roots, placement, and all
  lookups against the native typed graph.

Carry derivation is deliberately absent from main-trace materialization and
retirement. The scalar writer emits the low and high product halves directly;
the eight schoolbook carries are derived only by interaction construction,
where the protocol consumes them.

The fixed direct evaluator uses explicit root assignment. This preserves the
exact symbolic root identities while avoiding temporary helper arrays and
their copy traffic in the hot evaluator.

## Admission and retirement invariants

- Exact R-type encoding checks for `funct7 = 1`, opcode field `0x33`, and
  `funct3` values `001`, `010`, and `011` only.
- All 98,304 legal opcode/register encodings are accepted.
- All 131,072 `opcode_field × funct7 × funct3` selector combinations are
  exhaustively checked fail closed.
- Source-source, destination-source, and all-register alias orders are exact.
- `x0` reads as zero and discards writes without weakening the attempted result.
- Stage/prepare/commit uses capacity preflight followed by state revalidation;
  OOM and allocator-triggered reentrancy cannot partially publish a retirement.
- A prepared token is single-use and rejects stale CPU, trace, or access-chain
  state.
- The pre-reserved warm path performs zero allocations.

Exact retained footprints are compile-time contracts:

- compact transaction: 80 bytes;
- plan: 96 bytes;
- prepared token: 16 bytes.

## Soundness gates

- Source-location-independent authority identity and full binding mutation
  rejection.
- Native typed-definition root and range-refinement forgery rejection.
- Exact symbolic parity with the legacy oracle, including zero new nodes.
- 768 signedness/boundary rows spanning all three operations, aliases, and
  `x0`, with byte-identical witness output and zero direct roots.
- 65,536 exhaustive byte × byte carry tuples.
- High-word/M31 field-alias product forgeries and signed-witness forgeries.
- Malformed-row validation before the first output write.
- Exhaustive allocation-failure cleanup.
- Cold OOM atomicity, reserve-time reentrancy detection, prepared-token stale
  rejection, and warm zero-allocation retirement.

## Performance receipt

Apple Silicon, Zig 0.15.2, `ReleaseFast`, paired alternating samples with median
selection:

- fixed direct evaluator: 2.5026×–2.5171× versus the legacy evaluator in three
  focused repeats (full-suite sample: 2.5316×);
- fixed retirement: 1.6957×–1.7025× versus the legacy retirement oracle in
  three focused repeats (full-suite sample: 1.7598×).

These gates reject a regression below 1.0309× (`fixed * 97 <= legacy * 100`),
while the recorded results leave substantial margin.

## Reproduction

```sh
zig test --dep stwo_core \
  -Mroot=src/frontends/riscv/mulh_private_test_root.zig \
  -Mstwo_core=src/core/mod.zig

zig test -OReleaseSafe --dep stwo_core \
  -Mroot=src/frontends/riscv/mulh_private_test_root.zig \
  -Mstwo_core=src/core/mod.zig

zig test -OReleaseFast --dep stwo_core \
  -Mroot=src/frontends/riscv/mulh_private_test_root.zig \
  -Mstwo_core=src/core/mod.zig
```

Receipts at closure: Debug 223/223, ReleaseSafe 223/223, ReleaseFast 226/226.

## Shared integration boundary

The integration owner may wire the private authority and retirement module
into the shared family registry, runner dispatch, and test inventory. No shared
production file was changed in this slice. The private focused root remains the
canonical pre-integration gate.
