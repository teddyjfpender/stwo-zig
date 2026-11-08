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

```sh
zig build rv64-word16-ethereum-gkr-recursion -Doptimize=ReleaseFast -j1

python3 opstack/recursive_transition.py \
  --runner zig-out/bin/rv64-word16-ethereum-gkr-recursion \
  --statement statement.json \
  --derivation-request derivation-config.json --derivation-proof derivation-proof \
  --execution-request execution-config.json --execution-proof execution-proof \
  --fixed-setup-bytes 1073741824 --receiver-bytes 6442450944
```

The receiver operator supplies the canonical L1 anchor, previously admitted L2
checkpoint and next claim, the trusted runner and the request files with the
independent ELF and input hashes. Keep this authority outside the producer's
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
