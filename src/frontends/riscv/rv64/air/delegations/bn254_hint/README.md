# Canonical private BN254 hint writer

Shared source foundation for subgroup/residue experiments. No physical proof,
BYTE/SSA binding, VM operation or production admission is implemented here.
A hint is free witness data; this chip proves canonicality only. Consumers must
separately constrain inverse/product/final-result predicates and literal outputs.

Stable interface is `source.zig`: MAIN95 =32 output bytes +32 distance bytes +
31 carries; FIXED3 =source-owned active, writerID and fanout. `emitCanonical(F,v,
sink)` emits127 constraints. `byteQuery(F,v,i)` supplies64 BYTE lookups (output
and distance); their multiplicity is the source-owned active bit. `ssaTuple(F,v,
namespace,call)` returns `[namespace,call,writerID,bytes32]`, and `ssaWeight` returns
active×fanout. Namespace/call, all IDs/fanout/active bits and any extra must-zero
predicate are the caller's immutable/public authority, never proof-selected flags.
There is no global/ISA tag or trusted `isValid` bit.

Let c0=active, c32=0. The32 byte equations are
`output[i]+distance[i]+c[i]−active*p[i]−256*c[i+1]=0`.
Each stored carry satisfies `c*(c−active)=0`; inactive output/distance are zero.
With independent BYTE checks and source-fixed active∈{0,1}, integer residual
magnitude is≤511, below M31 p. Telescoping gives output+distance+1=BN254p on an
active row, hence output<p without an additional trusted comparison. A coherent
output+p with wrapped distance fails the last carry equation. This uses **31
carry bits**; it is not the15-borrow16-bit representation in the initial subgroup
source-contract note. Consumers replacing that older hypothetical hint contract
must bind this exact new layout/source identity explicitly.

Constraints have degree≤2, including arbitrary sampled FIXED values in the degree
test. Actual source keys must independently bind Boolean active and immutable
IDs/fanout. Source digest binds the exact BN254 modulus and source code. Arithmetic
consumers may inherit bytes only after physical BYTE/SSA and this canonical gate
are qualified together. No self-referential SSA read is needed: this is one
canonical producer, with no input operand bus.

`witness.fill(value)` rejects noncanonical values and computes exact distance and
carries; `padding()` returns the unique disabled all-zero row. Numeric `valid`
checks the byte/carry/equation system itself. The raw alias helper is only a
witness-construction aid and conveys no acceptance authority.

Focused qualification:

```sh
zig test -O ReleaseSafe --dep stwo_core \
  -Mroot=src/frontends/riscv/rv64_bn254_hint_test_root.zig \
  -O ReleaseSafe -Mstwo_core=src/core/mod.zig \
  --test-filter 'BN254 canonical private hint'
```

Tests cover zero/p−1 and byte/limb boundaries,64 random canonical fields,
noncanonical constructor rejection, source-level wrapped alias rejection, every
MAIN-column mutation, inactive/non-Boolean controls, exact SSA tuple/weight/64
BYTE-query exposure and full constraint degree-two finite differences. Physical
subgroup/residue proof integration remains a separate gate.
