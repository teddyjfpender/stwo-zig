# Packed native AIR evaluation

`NativeAirProgram` now retains each OM31 IR value in one `bytes32`, with eight
canonical 31-bit coordinates in 32-bit slots. Previously it retained eight EVM
words per value and allocated additional arrays for arithmetic. This changes
only internal memory: the authorized AIR1 program, native little-endian field
wire, quotient result, OODS authority and transcript are unchanged.

`NativeOm31Packed` requires canonical operands. The AIR decoder validates all
constant, input and parameter coordinates before reading them. The accumulator
challenge is also checked. Packed addition/subtraction use each slot's spare
bit to reduce modulo `2^31-1`; canonical operands prevent carries or borrows
crossing slots. A whole-word byte swap translates the native wire into slots.

Multiplication reuses `NativeFriFold.multiplyInto` and its existing 27-product
quadratic tower. Eight-word operands and output are temporary. Only the packed
result escapes; the free-memory pointer is restored after the operation. The
saved pointer precedes all temporary allocations, and multiplication scratch
starts after live inputs/output. No caller-owned value or returned memory
pointer aliases the reclaimed region. This holds for nested AIR operations
because stored DAG values and arithmetic arguments are words, not references
to that scratch. A future change returning a scratch pointer would invalidate
this design and must not be added.

## Qualification and gas

Solc 0.8.30, via-IR, optimizer 100,000 runs, Shanghai, Anvil 1.7.1. Gas includes
transaction intrinsic/calldata costs. The control substitutes the unchanged
`NativeAirProgram.sol` from `9c94ad76e` into the same compiler input and uses the
same test harness, fields, expected values and programs.

| Program | Nodes | Prior gas | Packed gas | Ratio |
| --- | ---: | ---: | ---: | ---: |
| Real native initial-state AIR | 177 | 1,221,972 | 1,067,981 | 1.14x |
| Mixed-operation diagnostic | 17 | 149,502 | 125,090 | 1.20x |
| Mixed-operation diagnostic | 257 | 1,387,443 | 905,387 | 1.53x |
| Mixed-operation diagnostic | 2,048 | 15,983,119 | 6,764,679 | 2.36x |

These are AIR evaluation components, **not complete checkpoint verification**.
Memory expansion remains quadratic in retained program size, even after the
8x storage reduction. Native GKR, complete authority routing, recursive proof
verification and checkpoint integration still require their own implementation
and qualification before an OP settlement claim.

The default suite passes 24 tests with three optional external-fixture tests
skipped. Field tests compare all 64 basis products, 25 edge pairs and 64 random
pairs with independent formal polynomial reduction, including all add/sub
coordinates. Wire byte order, noncanonical coordinates, forward references,
invalid opcodes/roots, code identity and vanishing inverse mutations reject.
Repeated multiplication at 0, 1, 2, 64 and 256 iterations leaves the free-memory
pointer unchanged and preserves a live memory guard. Mixed-operation DAGs
exercise add, subtract, multiply, negate and ordered residual accumulation.

```sh
cd settlement
npm ci
npm test
```

Raw measured counters are in
[`fixtures/packed-air-gas.json`](fixtures/packed-air-gas.json).
