# Receive an anchored OP Mainnet transition

The OP execution guest publishes the existing `OP` transport, which binds a
canonical payload range and the ordered computed L2 block hashes. The anchored
derivation guest publishes the `OD` transport after deriving the payload from
authenticated L1 and L2 histories, executing it, and checking the claimed next
output root and L1 origin. For a one-block transition, both transports commit
to the same payload commitment and computed block hash. The derivation proof
also binds the public L1 anchor and the two L2 checkpoints.

Use the CPU linked recursion product to wrap a complete native bundle with
`recurse-candidate CONFIG PROOF_DIRECTORY FIXED_SETUP_BYTES [RECEIVER_BYTES]`.
For GPU production, keep the established `produce-and-recurse-candidate`
configuration and use the same native and outer profile when receiving. The
native-only binary does not build or verify the recursive tree.
Run the linked product from the repository root so it can read its
pinned AIR recording under `vectors/circuit/official`. It checks this
recording before preparing native keys or constructing the graph.
Standalone CPU wrapping caps its freed-block recycler at 64 MiB. The
requested live allocation limit is separate. The native OM31 CPU leaf
path also releases the builder gate arrays and scratch arena once the
preprocessed columns own the topology. It keeps the assignments for trace
generation. Topology diagnostics keep the graph available for inspection.
GPU production and the strict receiver retain their existing recycler
policies.

```sh
zig build rv64-word16-ethereum-gkr-recursion -Doptimize=ReleaseFast -j1

python3 opstack/recursive_transition.py \
  --runner zig-out/bin/rv64-word16-ethereum-gkr-recursion \
  --statement statement.json \
  --derivation-request derivation-config.json --derivation-proof derivation-proof \
  --execution-request execution-config.json --execution-proof execution-proof \
  --outer-profile r1_b2_q108_p20_fold4 \
  --fixed-setup-bytes 1073741824 --receiver-bytes 6442450944
```

For CPU performance qualification on the retained execution fixture, the
existing D2 native profile and M6 outer profile reduce openings and use one
three-child fold instead of two binary folds:

```sh
export STWO_RV64_OUTER_PROFILE=m6_outer_diet_k4_cap3_r1_b2_q108_p20_fold4_v1
zig-out/bin/rv64-word16-ethereum-gkr-recursion \
  --security-profile d2_native_b4_q54_p20_fold4 \
  recurse-candidate REQUEST_JSON D2_NATIVE_PROOF_DIRECTORY 2147483648 42949672960
```

The directory must contain a complete native D2 bundle. Its independently
pinned request may select `workers: 16`; this changes scheduling, not the
statement or transcript. Use `verify-recursion-candidate` with the same explicit
native/outer profiles and independent request for fresh reception. The actual
measured fixture needs 40 GiB requested-live production admission; this is not
a universal RSS bound or a recommended budget for arbitrary transitions.

Set `STWO_CIRCUIT_OM31_PROFILE_DIR` to an external artifact directory for
per-proof CPU stage JSON. It records MAIN witness/commit, interaction
generation/commit, and the engine's composition, quotient, FRI and opening
stages, including whole-process counters. Each proof owns its recorder; no
profile enters the transcript or receiver authority. Nested or overlapping
counter intervals must not be added. Profiling is off by default.

The explicitly selected outer profile
`m7_outer_gkr_k4_cap3_r1_b2_q108_p20_fold4_v1` also has a complete CPU
producer. Its hybrid lookup section, MAIN binding and fresh native/in-circuit
receivers use the same pinned construction as the device path. It remains an
experiment: M6 still has the best measured complete-root CPU result. M7 stage
profiles separate lookup projection, GKR, native admission and binding witness;
`components/hybrid-*.json` additionally splits public auxiliary construction,
row preparation and constraint evaluation. These files are observations only.

On AArch64, `STWO_RV64_OUTER_GKR_NATIVE=1` opts into M7's generated
coordinate kernels; `STWO_RV64_OUTER_GKR_INTERPRETER=1` forces the control.
Build-time lowering verifies the original bundle hash and keys the registry by
full program identity. Scalar OODS and receiver authority are unchanged. The
focused `test-riscv64-outer-gkr-cpu-lowering` and
`test-riscv64-outer-gkr-cpu-native` targets exercise independent scalar parity,
all eleven kernels, input/output validation and allocation failure cleanup.
Current evidence establishes composition savings, with only a modest and noisy
whole-root change; this route is not enabled by default.

Use `zig build test-riscv64-outer-gkr-cpu-polynomial -Doptimize=ReleaseFast`
for the fast scalar/packed, cyclic binding, pool and auxiliary FFT checks.
The full `test-riscv64-outer-gkr` suite additionally checks physical proofs,
in-circuit child verification and adversarial transcripts. Changes to a CPU
implementation must retain exact same-profile proof bytes and independent
fresh reception; a new proof construction needs separate qualification.

For complete native rosters of at most four workers, the explicit CPU modes
`recurse-grouped-candidate REQUEST OUT FIXED_SETUP_BYTES [LIVE_BYTES]` and
`verify-grouped-recursion-candidate REQUEST OUT FIXED_SETUP_BYTES [LIVE_BYTES]`
compose the original native verifiers into one circuit before producing an
outer proof. Select the same native/outer profiles independently on both sides.
The transport is `OUT/recursion-group-v1/root.proof`; it is separate from the
existing leaf/fold tree. The current qualified M7 fixture used 48 GiB requested
live production admission and 24 GiB reception, with 39.16 GiB measured RSS.
This is not a universal memory budget. Larger rosters fail explicitly, with no
partial-execution acceptance. Run `zig build test-riscv64-native-group
-Doptimize=ReleaseFast` for focused graph, physical proof and admission checks.
The [bounded review](../design/riscv-proving-stack/rv64-native-verifier-groups.md)
explains computed-wire digest binding, native closure and remaining limitations.

`STWO_RV64_GROUP_ARITHMETIC=structural-v1` separately opts into GROUP2
for the grouped modes. Both producer and receiver must choose it independently;
the transport becomes `recursion-group-v2/root.proof`. It removes operations on
immutable zero wires and uses the circuit's cheaper seven-row OM31 product.
Guessed zeros are still unknown wires and retain their constraints. The original
GROUP1 and leaf/fold authorities remain available when the flag is absent.
Current active-row savings do not reduce the real fixture's padded arithmetic
height, so no further whole-root speedup is claimed. The fast qualification
command is `zig build test-riscv64-structural-arithmetic -Doptimize=ReleaseFast`.

The receiver operator supplies the canonical L1 anchor, previously admitted L2
checkpoint and next claim, the trusted runner and the request files with the
independent ELF and input hashes. Choose the outer profile used by both proof
trees with `--outer-profile` (default `r1_b2_q108_p20_fold4`). The receiver
requires the exact domain for that selection on both branches.
The native construction is independently selected with `--native-profile`.
The default remains `conjectured128_b2_q108_p20_fold4`; the existing
`d2_native_b4_q54_p20_fold4` construction is available for qualification. It
trades a larger native commitment domain for fewer openings in each recursive
leaf. The receiver requires its explicit selection on both branches; a
producer's profile declaration cannot select the receiver's policy. Exposing
this option does not establish an OP performance improvement or change the
documented security assumptions.
Keep this authority outside the producer's
proof directories, and use absolute `elf` and `input` paths in the request files.
In particular, check the derivation ELF against the guest
build which pins both Mainnet chain configurations; do not accept program
identities selected by the producer. Both request files carry the exact
independently expected 43-byte terminal output in `expected_output`.

The `stwo.opstack.anchored-transition.v1` JSON object carries numeric `chain_id`
(10), `l1_chain_id` (1), `anchor_number`, `previous_number`, `next_number`,
`next_origin_number`, and lowercase 32-byte hex `anchor_hash`, `previous_root`,
`next_root`, `next_origin_hash`, `payload_commitment`, `block_hash`. Only the
statement schema and these fields are admitted. Numbers are encoded as little
endian 64-bit values in the two transports. See `TransitionStatement` for the
domain and field order.

The join invokes the actual strict receiver twice. That receiver independently
rebuilds native authority, verifies the CPU and service proofs and their closure,
replays verifier graphs for each saved recursive leaf and fold, and requires the
published root proof to equal the authenticated final proof bytes. The join
checks both terminal outputs against the same statement and emits a receipt
only after both runs accept. It does not read producer reports as proof evidence.

This is a receiver-side join of two complete trees. It does not produce one
in-circuit proof of the join, certify the profile, select a canonical L1 anchor,
or supply an on-chain verifier. A positive receipt needs real saved derivation
and execution proof trees for the same transition; a native replay or unit test
of the statement encoding does not supply those trees.

The experimental public binary fold can expose both authenticated child
outputs in order after its normal fold digest. Its receiver checks the digest
against the pinned child authorities and expected output words, then checks
the two public output sequences against the transition statement. Run
`zig build test-riscv64-op-public-fold -Doptimize=ReleaseFast -j1` for the
synthetic OD/OP proof fixture and fresh receiver. It can be bounded with
`STWO_OP_FOLD_MAX_BYTES`. The fixture exercises actual OM31 proof generation
and verification over fixed transport values. It does not prove Kona or EVM
semantics. Existing execution roots expose a digest rather than those raw
output words, so the public binary fold is not wired into Mainnet production.

Run the expensive child and parent proof fixture with an explicit host budget:

```sh
STWO_OP_FOLD_MAX_BYTES=34359738368 zig build test-riscv64-op-public-fold -Doptimize=ReleaseFast -j1
```

The budget is an admission cap, not a measured fit. With no explicit budget the
same target runs the public output admission test and skips the full proof trial.


## CPU builder lifetimes

Explicit disposable CPU graph calls release gate arrays and scratch after PP
owns the topology, and release the builder assignment after MAIN and copied
public outputs own all needed values. This applies to both classic and hybrid
outer CPU proofs. Reusable borrowed entry points retain their old behavior;
disposable contexts are only safe to deinitialize after the call, including
errors. Device factories retain their original lifetime contract.

The [ownership qualification](../vectors/reports/rv64-opstack-cpu-20261108/recursion-consumed-assignment.json)
preserves the exact GROUP2 root bytes, accepts fresh receivers and earlier
GROUP1/M7 tree proofs, and covers assignment consumption on early errors.
Cold ABBA peak RSS falls 39.16 → 37.90 GiB. Wall medians 20.44 → 20.71 s do
not establish a speed gain. The large M7 four-child fold still refuses at the
same node under its live cap; this change does not solve that shape's memory
requirement. The separately qualified M6 ternary heavy root remains available.
