# Compact typed BLAKE3 G — 2026-09-21

The preceding turn made progress by adding the shared compression schedule and
bit-reference constraints. This turn replaces the prospective production
arithmetic layout with byte limbs and exact canonical lookup requests, while
retaining the bit reference as an independent representation oracle.

Final component: `blake3_g_packed.zig`, semantic digest
`4d97d2df517a07b5dc1b59659734f81e9ab4eaa34651e31648fba9df2921c5f2`.

| Per G | Bit reference | Compact component |
| --- | ---: | ---: |
| Witness columns | 704 | 124 |
| Direct equations | 1024 | 80 |
| Maximum degree | 2 | 2 |
| Lookup requests | 0 | 56 |

These are arithmetic-layout counts, not complete proof cost or speedups.
Interaction columns, wire/call binding, providers and domain padding are not
included. There is no new complete recursive proof or performance claim.

The final design uses only the existing `bitwise` and `range_check_8_8` schemas.
Each addition is base-256 with constrained binary carries and bounded bytes.
XOR uses operation ID 2. Rotations 8/16 permute bytes. Rotations 12/7 split bytes
and reassemble them with bounded pieces. To bound an n-bit piece, request
`(piece, scaled)` in the byte-pair table and constrain
`scaled = piece * 2^(8-n)`. Both quantities are byte-bounded, so the field
equality cannot hide a modular alias. Do not rely on a declared typed bound as
an implicit constraint.

An earlier local draft used `range_check_8_8_4` and `range_check_m31` for split
pieces (112 columns, 68 constraints). It was replaced before final qualification:
that would expand the provider roster and potentially introduce a 2^20-row
generic table. The final 124/80 design trades 12 extra witness columns/equations
for reuse of the existing byte-pair provider. The original recorded problem
brief has a revision describing this choice.

Validation: three focused guarded tests. 128 edge/random cases match the typed
bit reference; all 124 coordinates are tested with +1 and replacement by 256;
all 56 calls of a seven-round compression agree with the native trace. A crafted
negative-field witness passes all algebraic equations while failing lookup
membership, proving the test actually exercises required bounds. Typed schema,
request role, multiplicity-one and degree checks are included.

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-packed -Doptimize=ReleaseSafe --summary all
```

Boundary: tests check exact table membership of emitted requests. They do not
establish cryptographic LogUp closure or authenticate inter-call connections.
Next is binding the six input/four output byte words to the canonical compression
schedule, initialization/feedforward and live table providers, then complete
hash framing and recursive protocol/key/device migration. Production proofs
remain Poseidon; the original broader goal stays active.

Final gate: 3/3 tests pass in 466 ms, compilation 4 seconds. Source conformance
retains 103 existing finding identities; it is not green. Formatting and
`git diff --check` pass.
