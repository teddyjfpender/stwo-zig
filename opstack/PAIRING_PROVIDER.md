# Fused pairing provider: qualified scope and next gates

The current work replaces a long sequence of guest field operations with one
source-owned pairing computation. It is an experimental, finite, four-pair,
positive-certificate construction. It has no new VM tag, production admission,
Wire/RAM integration or recursive acceptance yet. Existing qualified OP routes
remain available.

## Source authority

The [composite DAG](../src/frontends/riscv/rv64/air/delegations/bn254_pairing/spec.zig)
owns all of the following in one scalar-ID namespace:

- Canonical public P/Q inputs and immutable field/tower constants.
- G1 curve equations and four exact G2 curve/subgroup checks.
- All G2 preparation steps and 348 chronological line consumptions.
- Shared Miller accumulation: 63 real squares and 347 sparse products after
  folding constant ONE operations.
- A positive residue certificate whose input z aliases the actual Miller output.
  Its private scale has only six free coordinates; the upper six alias ZERO.
- All 1,460 zero/one obligations, including all twelve coordinates of each
  inverse-check and final-ONE endpoint.

Subgroup Q aliases preparation Q directly. Residue z aliases Miller z directly.
Standalone acceptance or matching host digests would not establish these joins.
Tests coherently substitute a different valid subgroup Q and a standalone z=ONE
certificate: their individual computations remain valid, but the composite
source rejects them. Infinity inputs are explicitly outside this conditional
construction; general EVM pairing semantics still require that case and false
results to be handled before admitting a replacement service.

## Engineering layers

| Layer | Location | Qualification |
| --- | --- | --- |
| Homogeneous transition and all preparation lines | `bn254_g2/`, `bn254_g2/preparation/`; integration `op_g2*` | Physical BYTE/SSA proofs, fresh authority and adversaries |
| Exact G2 subgroup | `bn254_g2/subgroup/`; integration `op_g2_subgroup/` | Conditional physical proof and canonical-hint attacks |
| Positive residue | `bn254_residue/`; integration `op_residue/` | Conditional physical proof and off-subfield inverse-scale rejection |
| Whole shared Miller | `bn254_miller/` | Source/oracle and chronology gates |
| Connected pairing | `bn254_pairing/` | Complete source DAG and substitution gates; physical composite pending |
| Arithmetic layout | `bn254_mac6/`, `bn254_mac12/`; integration `op_mac12/` | Numeric/cost controls and bounded physical integer/BYTE gate; composite SSA join pending |

Frontend paths in this table are below
`src/frontends/riscv/rv64/air/delegations/`; integration paths are below
`src/integrations/riscv_cpu/delegations/`. Qualified older banks are independent
controls. Their source fingerprints include code files, so even cosmetic source
edits require identity review and requalification. Explanatory changes belong in
documents outside those fingerprints.

## Coupled layout choice

The complete source contains 31,996 arithmetic writers and 1,438 private
canonical hint writers. A concrete twelve-product row is the next physical
experiment: source normalization needs 32,543 arithmetic rows, fitting log15.
Six products need 36,751 rows, forcing log16. Including independently sized
hint/frontier/BYTE roles, the model is 39.04M native cells and 17.96M padded
lookup facts for twelve products, versus 51.30M and 34.74M for six.

The twelve-product choice has wider openings: 1,410 committed columns in the
model versus 1,008 for six. These are column counts, not OODS sample counts or
recursive gates. A native cell saving does not establish a root-prover saving.
The experiment requires independently bounded 22-bit carries, signed quotient
handling, complete canonical-input inheritance and physical terminal bindings.
See the [coupled cost review](../design/riscv-proving-stack/op-bn254-universal-mac-source-cost-20261110.md).

A follow-up [independent-geometry model](../vectors/reports/rv64-opstack-cpu-20261110/pairing-independent-geometry-model-v1.json)
also records the competing design rather than assuming one universal bank is
optimal. Folding only trusted literal IDs removes ten stages, leaving 16,381
non-subgroup and 16,152 subgroup rows. Separately sizing a narrow subgroup bank
would put both at log14: 29.49M native cells versus 39.04M, but 2,005 opening
columns versus 1,410. Its uniform-height leaf-payload model is 28.9% smaller;
this is not measured hashing traffic or a root speedup. It adds GKR instances
and must remap the existing subgroup equations into the same canonical source.
The first complete physical gate remains the universal MAC12 construction.

## Advice and packet compatibility

The existing guest residue hint has thirty fields in the order seed12,
seed-inverse12, scale6. The new source's private witness uses seed12, scale6,
and inverse(seed^p²)12. These are different interfaces. The current source
fixtures supply private advice directly and do not reinterpret an existing VM
packet. A future service must bind its actual public P/Q inputs and result;
private advice remains checked by source equations. Any conversion from the
old guest packet needs an explicit authenticated conversion or new version,
not reuse of a tag with changed meaning. The host positive-certificate generator
already exists in `opstack/kona/src/precompiles/pairing_residue.rs`.

## Remaining acceptance gates

1. Lower the complete immutable source into one concrete physical arithmetic
   bank, private-hint bank and frontier, preserving all IDs, fanout and endpoints.
2. Close BYTE and SSA separately, bind every GKR terminal to committed MAIN,
   and independently reconstruct source/FIXED authority in a fresh receiver.
3. Reject physical canonicality, signed-quotient, disconnected Q/z, missing
   obligation, changed-source and balanced lookup attacks.
4. Establish the concrete production security profile and resource bounds;
   the existing small physical fixtures use q12 correctness settings.
5. Bind variable VM inputs and outputs through authenticated Wire/RAM, handle
   the complete accepted input semantics, and qualify recursive reception.
6. Benchmark the same real workload through its complete root. Neither source
   counts nor toy proof times close the heavy-block tenfold target.

## Focused development gates

```sh
zig build test-riscv64-op-g2-preparation-source \
  test-riscv64-op-g2-subgroup-source test-riscv64-op-residue-source \
  test-riscv64-op-miller-source test-riscv64-op-pairing-source \
  test-riscv64-op-mac-source test-riscv64-op-mac12-source \
  -Doptimize=ReleaseSafe -j1
zig build test-riscv64-op-g2-subgroup-proof \
  test-riscv64-op-residue-proof -Doptimize=ReleaseSafe -j1
```

These targets retain test-count guards. Run the bounded gates while iterating;
complete OP production and recursion qualification is an integration step.
