# Fused pairing provider: qualified scope and next gates

The current work replaces a long sequence of guest field operations with one
source-owned pairing computation. It is an experimental, finite, four-pair,
positive-certificate construction. It has a complete experimental physical arithmetic proof, but no new VM tag,
production admission, Wire/RAM integration or recursive acceptance yet. Existing qualified OP routes
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
| Connected pairing | `bn254_pairing/`; integration `op_pairing_mac12/` | Complete four-role physical BYTE/SSA proof; VM and recursion pending |
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
See the [coupled cost review](../design/riscv/op-bn254-universal-mac-source-cost-20261110.md).

A follow-up [independent-geometry model](../vectors/reports/rv64-opstack-cpu-20261110/pairing-independent-geometry-model-v1.json)
also records the competing design rather than assuming one universal bank is
optimal. Folding only trusted literal IDs removes ten stages, leaving 16,381
non-subgroup and 16,152 subgroup rows. Separately sizing a narrow subgroup bank
would put both at log14: 29.49M native cells versus 39.04M, but 2,005 opening
columns versus 1,410. Its uniform-height leaf-payload model is 28.9% smaller;
this is not measured hashing traffic or a root speedup. It adds GKR instances
and must remap the existing subgroup equations into the same canonical source.
The first complete physical gate remains the universal MAC12 construction.

The complete universal MAC12 physical gate now passes at q12/B2 correctness
settings: 175,544-byte PCS plus 48,604-byte GKR child, with 995,747,973-byte
requested peak under 2 GiB. BYTE and SSA close independently, and all six
terminal instances bind committed MAIN. Thirteen independently reconstructed
source/mask controls reject. A coherent hint+p attack changes actual committed
read ports, recomputes quotient/carries and rebuilds the actual BYTE histogram;
its GKR child closes, but fresh physical verification rejects OODS. All four
role constraint systems have degree at most three. This is not a production
security, speed or VM-admission claim. [Receipt](../vectors/reports/opstack-cpu-20261110/pairing-mac12-whole-physical-v1.json).

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

## Acceptance gates

1. Lower the complete immutable source into one concrete physical arithmetic
   bank, private-hint bank and frontier, preserving all IDs, fanout and endpoints
   (q12 correctness gate established).
2. Close BYTE and SSA separately, bind every GKR terminal to committed MAIN,
   and independently reconstruct source/FIXED authority in a fresh receiver
   (q12 gate and witness-free authority requalification established).
3. Reject physical canonicality, signed-quotient, disconnected Q/z, missing
   obligation, changed-source and balanced lookup attacks
   (q12 retained-forgery and source controls established).
4. Establish the concrete production security profile and resource bounds;
   the existing small physical fixtures use q12 correctness settings.
5. Bind variable VM inputs and outputs through authenticated Wire/RAM, handle
   the complete accepted input semantics, and qualify recursive reception.
6. Benchmark the same real workload through its complete root. Neither source
   counts nor toy proof times close the heavy-block tenfold target.

## Focused development gates

```sh
zig build check-riscv64-op-pairing -Doptimize=ReleaseSafe -j1
zig build test-riscv64-op-g2-preparation-source \
  test-riscv64-op-g2-subgroup-source test-riscv64-op-residue-source \
  test-riscv64-op-miller-source test-riscv64-op-pairing-source \
  test-riscv64-op-mac-source test-riscv64-op-mac12-source \
  -Doptimize=ReleaseSafe -j1
zig build test-riscv64-op-g2-subgroup-proof \
  test-riscv64-op-residue-proof test-riscv64-op-pairing-proof \
  -Doptimize=ReleaseSafe -j1
```

These targets retain test-count guards. Run the bounded gates while iterating;
complete OP production and recursion qualification is an integration step.

## Target-parameter control

The [caller-pinned q72 control](../vectors/reports/opstack-cpu-20261110/pairing-mac12-target-profile-v2.json)
uses OM31, Blake2s PCS, B4/q72/fold4/PoW0. These are existing OP FRI parameters,
not the OP lane's Poseidon2 hash/profile identity. Both profile substitutions
reject. A fresh receiver derives only immutable plan plus expected public
fields; no private certificate or normalized witness is needed. Its source
authority revision is explicit and the earlier receiver/artifacts are retained.

One-worker qualified producer phases total 14.854 s including 0.122 s of
diagnostic checks; an additional fresh receiver takes 0.556 s. GKR 8.251 s and
terminal bindings 2.084 s dominate; column materialization is 1.463 s and native
STARK production is 1.171 s. These single observations identify work, not a
quiet speed comparison. The next execution gate combines a bounded worker pool
with packed base-field bindings and measured witness encoding. Typed full
36-byte Poseidon2 transport is required before entering the existing OP lane.

## Current native P2 qualification

Revision4 uses native Poseidon2 M31 Om31V2 PCS with all nine root coordinates
bound directly in scope, receipt, codec and native verification. Cross-suite,
wrong-profile and ninth-coordinate controls reject. The complete provider
proves in1.869s inReleaseFast on16CPUworkers; fresh reception is additional
0.150s and requested peak1.007GB. ReleaseSafe is2.306s plus0.168s. All nine
gates pass, and all twelve Safe/Fast binary artifacts match exactly. These
are given-certificate arithmetic-provider observations, not arbitrary hint
generation, VM, OP block or recursive-root results.

Bounded physical-row generation preserves all FIXED/MAIN fields under a poison
allocator; partial worker and allocation failures join and clear borrowed views
before freeing. Parallel/scalar full native proof and GKR child match exactly.
[Safe receipt](../vectors/reports/opstack-cpu-20261110/pairing-mac12-columns-v4.json) ·
[Fast receipt](../vectors/reports/opstack-cpu-20261110/pairing-mac12-columns-v4-fast.json).

## Recursion preparation

Two isolated source gates prepare the real R7 integration, without changing
its current authority or claiming recursive proof timings.

- [Typed terminal parameters](../design/riscv/rv64-whole-pairing-r7-typed-projection.md)
  carry dynamic beta, SSA coefficients, weights, eta and targets in external
  lanes. All six native projections and packed16 cases agree. Circuit-verified
  GKR outputs still need to supply those parameters; caller values alone do not
  prove that provenance.
- [Same-residual convolution factorization](../design/riscv/rv64-mac12-horner-convolution-prototype.md)
  evaluates the unchanged65-convolution block with1,099generic multiplications
  rather than14,871, including arbitrary full-extension masks andalpha0/1.
  This is an algebraic operation count, not lowered IR or proving speed. It has
  not changed the live evaluator, sink or protocol.

The [exact OP/P2/R7 integration checklist](../design/riscv/rv64-whole-pairing-op-p2-r7-integration.md)
identifies the VM/session/tape, global Wire/RAM, immutable input authority and
source-emission work. Moving24input fields into canonical writers fits existing
heights, but global I/O authority and actual circuit transcript provenance must
be established before admitting that replacement.

The [final integrated receipt](../vectors/reports/opstack-cpu-20261110/pairing-main-integrated-v4.json)
repeats all nine gates in both optimization modes on the PR branch and checks
all twelve binary files exactly. Native P2 proof678,856B plus48,604B local child.
An earlier derived-count/explicit-enum cleanup gives this tree a different
code-byte source fingerprint from the agent control; identical proof bytes are
claimed only within each cohort. The retained complete OP small root also
freshly verifies on the integrated tree, reading zero native proof bytes.
