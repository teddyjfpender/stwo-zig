# Closed OP Miller-line provider

This directory has two physical correctness references for the same OP-only
640-byte packet (`0x00040001`). Neither opens OP proof admission. The existing
Ethereum profiles, 424-byte legacy curve capture, and legacy service roster are
unchanged.

`spec.zig` uses one wide row per call. It is useful as an independently checked
reference, but its 20,832 main plus OM31 interaction columns would make recursive
openings expensive. The narrow provider therefore uses two independently sized
components in **one proof**, rather than one proof for each micro-operation:

| Component | Active rows per call | Main | OM31 interaction base columns |
| --- | ---: | ---: | ---: |
| Input frontier | 20 | 33 | 16 |
| Arithmetic DAG | 32 | 370 | 560 |

For 22,185 calls, these components use logs 19 and 20. Their 979 combined main
and interaction columns are 21 times narrower than the wide reference. Their
1,000,865,792 padded native cells are 1.47 times the wide reference's cells.
This is an explicit tradeoff, **not a measured proving speedup**. The physical
toy proof is 101,072 bytes including its four-claim frame, versus 931,648 bytes
for the wide reference. Whole-block and recursive timings remain necessary.

## Authority and organization

- `dag.zig`: immutable 32-step program, 52 SSA values, fixed read fanouts, and a
  compile-time unique-writer/topological-edge audit. No incoming packet selects
  instructions, edges, signs, or weights.
- `micro.zig`: exact integer arithmetic, source-derived carry offset and strict
  positive/negative M31 residual bounds. Carries use one U15 limb, reducing the
  arithmetic row from 399 to 368 columns before two multiplicity columns.
- `narrow_source.zig`: receiver-reconstructible periodic ROM, complete 20/32-row
  call spans, global Wire35 expressions, and local BYTE/U15/SSA expressions.
- `narrow_equations.zig`: degree-three AIR and paired classic lookup chains.
  SSA and global Wire35 have separate claims. Arithmetic/frontier SSA claims
  must sum to zero; their Wire35 claims must match the authenticated packet.
- `narrow_trace.zig`: native witness advice in column-major storage. Arithmetic
  is evaluated once per call before rows are written. Its retained input advice
  is bounded independently of the committed witness.
- `narrow_component.zig`: packed 16-row domain evaluator and scalar OODS evaluator
  for each independently sized component.
- `schedule.zig`: source-owned mass bounds and a 64-row control cost model. This
  uniform control schedule is not the chosen independently sized layout.

Inputs can be arbitrary 256-bit representatives. Their byte range comes from the
packet frontier's global Wire35 authority. Every arithmetic output is locally
byte ranged and constrained below the BN254 modulus. Exact local SSA closure
then supplies range authority to later reads. Constant zero/nine operands are
constrained to source-owned literals; exempting them from SSA creates no free
values. Absolute relation masses include both positive and negative sides and
must remain strictly below the M31 characteristic.

## Qualification and next gates

Focused tests check independent tower algebra, arbitrary representatives,
every 32-step carry/output/quotient/distance/borrow forgery, exact SSA closure,
self-consistent orphan operands, whole-call geometry, characteristic bounds,
and degree three including fixed ROM columns. A fresh physical receiver rebuilds
the fixed root and rejects wrong call IDs, outputs, OODS samples and SSA claims.
The fixture uses 12 queries and no PoW for correctness; it does not qualify the
production 128-bit target.

Before production admission: join actual CPU call ownership and all 80 packet RAM
transitions; add durable service framing, manifest/source bounds and fresh
receiver authority; connect the typed recursive catalog; qualify native-to-root
proofs on real OP calls; then benchmark the complete heavy block. Local GKR may
replace classic BYTE/U15/SSA interaction traces using the same typed source
expressions. It must bind both independently sized components on the lifted
domain and preserve cross-instance SSA closure. The request whitelist remains
closed until these gates pass.
