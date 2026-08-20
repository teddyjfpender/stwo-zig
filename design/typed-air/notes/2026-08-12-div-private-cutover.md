# DIV private fixed-authority cutover

Status: family-private implementation complete; shared production wiring intentionally deferred to the serialized integration owner.

## Scope

This slice closes the executable typed authority and failure-atomic retirement
boundary for the complete RV32 divide/remainder family:

- `DIV`: signed quotient truncated toward zero;
- `DIVU`: unsigned quotient;
- `REM`: signed remainder with the dividend's sign;
- `REMU`: unsigned remainder.

The architectural exceptional cases are part of the authority, not caller
policy: a zero divisor produces the ISA-mandated all-one quotient and unchanged
remainder, while `INT_MIN / -1` produces `INT_MIN` with zero remainder.

The retained authority is pointer-free and authenticated by
`65ea8c40383f799fe8526eaf44cf763953fd61c5e56c19c7b79562ff789b934b`.
It binds opcode IDs 41 through 44, semantic digest
`a33fd73890a391f954566eac75c54111c3ab5da54f20554ce095f7083b9e3ec2`,
witness digest
`1310f45968fb0e8336e1cfed92ee27eea614d7dbfd9e48f6441ffe5d87919040`,
the execution recipe, every physical witness slot, every direct-root recipe,
every ordered lookup descriptor, and lookup batch size. The legacy semantic
module and writer remain test oracles only.

## Protocol geometry and hot-path contract

- 67 main columns.
- 79 direct roots: the 78 legacy semantic roots plus placement.
- 25 ordered lookups in one-entry batches.
- 14 range refinements and 11 fixed-table requests.
- Two `range_check_8_8` divisor requests.
- Eight `range_check_8_11` quotient/remainder carry requests.
- One `range_check_m31` quotient-sign request, one `range_check_8_8`
  operand-sign request, and one `range_check_20` positive-remainder bound.
- Zero new symbolic DAG nodes when replaying direct roots, placement, and all
  lookups against the native typed graph.

The hot authority is a small authenticated value. Direct evaluation uses fixed
root assignment and lookup construction writes into fixed-capacity storage;
neither path traverses the authored arena, performs textual lookup, dispatches
callbacks, interprets recipes, or allocates.

## Admission and retirement invariants

- Exact R-type encoding checks for `funct7 = 1`, opcode field `0x33`, and
  `funct3` values `100`, `101`, `110`, and `111` only.
- All 131,072 legal opcode/register encodings are accepted.
- All 131,072 `opcode_field × funct7 × funct3` selector combinations are
  exhaustively checked fail closed.
- Source-source, destination-source, and all-register alias orders are exact.
- `x0` reads as zero and discards writes without weakening the attempted result.
- Stage/prepare/commit uses capacity preflight followed by state revalidation;
  OOM and allocator-triggered reentrancy cannot partially publish retirement.
- A prepared token is single-use and rejects stale CPU, trace, or access-chain
  state.
- The pre-reserved warm path performs zero allocations.

Exact retained footprints are compile-time contracts:

- compact transaction: 80 bytes;
- plan: 96 bytes;
- prepared token: 16 bytes.

## Soundness gates

- Source-location-independent authority identity and mutation rejection across
  every authenticated binding dimension.
- Native typed-definition root, effect, range-refinement, and fixed-request
  forgery rejection.
- Exact symbolic parity with the legacy oracle, including zero new nodes.
- The exact 292-row operand-class corpus across all four operations, with
  aliases and `x0`, byte-identical legacy witness output, zero direct roots,
  and accepted fixed-table range evidence.
- 262,144 exhaustive byte-pair/operation arithmetic comparisons plus the full
  12 × 12 × 4 signed-boundary cross product and explicit exceptional cases.
- An adversarial quotient, remainder, carry, sign, inverse, bound, and
  destination mutation matrix. This includes a forged quotient that leaves all
  direct roots zero and is rejected by the range interaction.
- Malformed-row validation before the first output write and exhaustive
  allocation-failure cleanup.
- Cold OOM atomicity, reserve-time reentrancy detection, prepared-token stale
  rejection, and warm zero-allocation retirement.

## Performance receipt

Apple Silicon, Zig 0.15.2, `ReleaseFast`, paired alternating samples with median
selection:

- fixed direct evaluator: 1.1172×–1.1204× versus the legacy evaluator in three
  focused repeats (full-suite sample: 1.1175×);
- fixed retirement: 1.7332×–1.7548× versus the legacy retirement oracle in
  three focused repeats (full-suite sample: 1.8242×).

Both performance gates reject a regression below 1.0309×
(`fixed * 97 <= legacy * 100`). The direct evaluator's smaller gain than simpler
families is expected: DIV's algebra is dominated by the same quotient-product,
sign, inverse, and bound arithmetic on both sides of the comparison, while the
fixed path removes authority interpretation and root collection overhead.

## Reproduction

```sh
zig test --dep stwo_core \
  -Mroot=src/frontends/riscv/div_private_test_root.zig \
  -Mstwo_core=src/core/mod.zig

zig test -OReleaseSafe --dep stwo_core \
  -Mroot=src/frontends/riscv/div_private_test_root.zig \
  -Mstwo_core=src/core/mod.zig

zig test -OReleaseFast --dep stwo_core \
  -Mroot=src/frontends/riscv/div_private_test_root.zig \
  -Mstwo_core=src/core/mod.zig
```

Receipts at closure: Debug 223/223, ReleaseSafe 223/223, ReleaseFast 226/226.

## Shared integration boundary

The integration owner may wire the private authority and retirement module
into the shared family registry, runner dispatch, and test inventory. No shared
production file was changed in this slice. The private focused root remains the
canonical pre-integration gate.
