# Word16 native services: recursion readiness

Reviewed source is `4a4a9e31e`, with CPU50/LS71 and the optional native Fold4
suite. This is not the later CPU47 authority. The diagnostic below verifies
native proofs and describes their static openings; it never constructs or
verifies a recursive circuit. Existing authenticated RV64 recursion does not
qualify Word16 execution.

## What can be reused

`src/frontends/circuit/native_verifier/{shape,verify,proof,fri,deep}.zig` already
handles native composition split1 and split2 and the existing larger FRI fold
schedule. `Shape.SamplePlan` derives periodicity entries and DEEP batches from
actual column logs and masks. Its fold schedule and serialized native work
sizes are useful diagnostics, not circuit gate or security estimates.

`rv64_recursion/{circuit_lane,native_fixed_root}.zig` supplies arithmetic wires
and an independently derived fixed-root equality. The legacy `native_capture`,
`leaf_statement`, `transcript_walk` and `rv64_point_{evaluation,lift,layout}`
are specialized to authenticated RV64 `ReceiverKey`/`Public` and its roster.
They are not adapters for the Word16 services protocol.

The new CPU, ROM and JALR components in `rv64/air/word16_execution` expose
`ComponentFor(C)` and `evaluateQuotientsAtPointFor`, with dynamic public inputs,
claims and challenges supplied through arithmetic lanes. Degree3 DIV/MUL and
Keccak/secp truth components have equivalent generic point authorities. Their
native component order, degree-bound weights and composition split must be
preserved exactly; heterogeneous truth proofs do not inherit CPU split1.

## Arithmetic seams still required

These are integration gaps, not known failures of native acceptance:

- `word16_v1/{alu_component,binary_component}` and the packed SHIFT component
  retain Q-valued component owners and native point callbacks. Their lookup
  authorities already have `ClaimsFor(C)`/`ChallengesFor(C)` and direct Circuit
  tests. They still need a concrete lifted component/point adapter using drawn
  wires; making native challenges circuit constants is not an adapter.
- `word16_cpu/component.zig` remains concrete Q for local register-boundary,
  U16 and byte-table roles. Its public register endpoints and lookup challenges
  must become wires in the composition evaluator.
- `memory/load_store_v2/equations.zig:emitLsFor` already accepts typed dynamic
  claims/challenges and reuses the exact LS71 projection and arithmetic. The
  top-level dispatcher and component remain Q-valued. Scalable boundary and
  selection paths call legacy Q-valued helpers. `closed_ram/equations.rangesFor`
  and the paired selection branch of `load_store_v1/authority.emitFor` are the
  smallest shared arithmetic seams to generalize without copying equations.
  Existing `closed_ram.types.RamChallengesFor` and v2 `ClaimsFor/ChallengesFor`
  should remain their single tuple authority.
- Keccak/secp `word16_bridge/{types,equations,component}` still carry Q-valued
  OWNER/RAM/truth/range claims and challenge structures. Generic local arithmetic
  alone does not connect these public scalars to the recursive transcript.
- `word16_execution/components.zig` and services `air_components.zig` assemble
  concrete Q rosters. A Word16 point lift must visit their actual shape-selected
  roles and tails in identical order. Optional/absent-role claims stay forced0.

First bounded engineering slice: typed LS/boundary/selection arithmetic and point
adapters, preserving every native residual, mask, default Q API and proof byte.
Tests must use independent challenge/claim wires, arbitrary Q masks and points,
all component kinds, mutated claim/challenge wires, and actual fresh native
controls. This alone would not create a recursive accepting receiver.

## Missing statement and aggregate authority

The native reference is services `execution.verify` plus `protocol` and
`statement.CpuClaims`. A future recursive statement must reproduce all of:

1. Independently expected program/image/policy, geometry and PCS suite; fixed
   commitment0 is constrained against the admitted key, not merely host-captured.
2. `beginCpu`/`beginTruth` public serialization, actual stage1 roots and the
   complete ordered manifest. `shared` derives typed RAM14/KIO11/Wire35 challenges
   only after all CPU and truth roots exist; each leaf's own actual roots must
   equal its manifest entry. A producer-selected hash or supplied alpha is not
   authority. Local draws retain proof ordinal/family separation.
3. All physical claims enter the transcript before interaction commitment and
   constraint coefficients. `CpuClaims.local`, absent-role guards and the final
   separate RAM, Keccak-IO and secp-Wire sums need circuit/public-root binding.
   Merged-prefix ledger fields are additive shares, not independently certified
   relation balances. Never assert stronger independent balances than the AIR.
4. Native admission enforces exact service-ID spans, unit stateful owners,
   characteristic-mass caps, canonical public values and resource limits. Those
   checks must be constrained or independently checked on root-bound public
   data; host construction of a valid witness is insufficient.
5. Ethereum `receiver.expected` pins genesis, epoch order, batch schedule,
   PC/all32 register-value adjacency and final-PC completion. Local register
   clocks reset to0 per shard; final clocks are bounded locally, not copied into
   the next shard. A recursive fold currently has no Word16 adjacency statement.
6. INIT/TERM lists are canonical sorted unique native public cells. Their exact
   RAM claims are recomputed in services `execution.verify`; the pristine image
   and `ethereum/terminal.require` independently anchor initialization and the
   43-byte result. A compact recursive root needs an explicit equivalent
   authority. A native list hash or unconstrained expected rational claim alone
   does not prove its relation to the guest image/output. Keeping public lists
   at an independently checking final receiver is possible but not compact.
7. Root admission must pin expected topology/layout/circuit identities and the
   root-bound complete statement, never adopt hashes from untrusted leaf JSON.
   Existing legacy topology hardening is a pattern, not Word16 qualification.

## Executable bounded diagnostic

Build `zig build rv64-word16-recursion-shape -Doptimize=ReleaseFast`. Invoke:

```
rv64-word16-recursion-shape TRUSTED_CONFIG BUNDLE_DIR full f1
rv64-word16-recursion-shape TRUSTED_CONFIG BUNDLE_DIR prefix f4
```

Completion mode and suite come from the receiver's command. The tool loads the
independently pinned image, applies cheap receiver schedule admission, derives
keys, runs the ordinary full/prefix native receiver, then reconstructs actual
FS draws and component handles. It reports per-column logs/offsets, composition
geometry, DEEP batch shifts/sizes, native FRI steps and serialized witnesses.
Every derived sampled-value count/column length is checked against the actual
proof. No recursion circuit is built and no gate counts are inferred.

Limits precede expensive keys: at most32 CPU and32 truth declarations,64 physical
proofs,4MiB metadata,256MiB total native proof bytes,64MiB per proof and2^28
aggregate native rows. Existing transport, geometry, image and mass admissions
remain active. Per-proof decoding uses reclaimable native storage; only bounded
report metadata survives. Native verifier proof capture and real builder gate
counts remain a future diagnostic, after the typed Word16 statement exists.

The pinned full30 CPU50 bundle reports25 split1 CPU proofs and5 split2 truth
proofs:93,365 sampled QM31 values,97,411 DEEP entries including periodicity,
633 FRI steps, and80,752 row-residual expressions across the30 rosters. These
are exact native shape counts, not numbers of recursive gates. The compact
receipt records per-proof counts and the hash of the full per-column artifact.
