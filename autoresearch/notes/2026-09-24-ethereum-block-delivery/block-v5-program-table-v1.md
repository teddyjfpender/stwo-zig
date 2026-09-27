# Block-v5 global decoded-ROM program table, first proof slice

`block_v5_program_table_v1.zig` accepts the complete decoded ELF ROM leaves
only when their BLAKE3 program root matches an independently pinned job root.
It groups four consecutive words per program tuple, checks address order and
canonical M31 words, then checks the **u64** multiplicities sum to the exact
fetch census. The sum must be below the M31 modulus. Blocks above that cap need
explicit shards; reducing a large count into one field element is forbidden.

`block_v5_program_table_proof_v1.zig` commits the existing typed
`blake3_public_program` fixed rows, including counts, before deriving the
shared 47-relation challenge bundle. It proves the interaction columns in a
separate STARK, fresh-verifies the fixed root against the full authenticated
ROM and exact counts, and returns a scoped table receipt. The v5 seal binds
source and native first-round roster digests, the table plan, program root,
and table first roots before challenge draw. The integrated fixture derives
that program seal from `block_v5_source_seal_v1`, whose ordered roster includes
the native execution and program-request roots. The structural closure requires
the same seal digest, exact integer fetch census, and cancellation of the
program relation sum from freshly verified native request receipts. A native
unretired completion fetch has no opcode row; the receiver must derive its
one consuming request from the freshly verified native public statement under
the same universal challenges. Halt-flag completion contributes zero.

This slice does not change the current B3SK/B3CK native route. Its table proof
does **not** authorize dropping native program rows yet: the complete block
receiver must fresh-verify every native-v5 request proof under these exact
shared challenges, derive its request receipt without trusting prover metadata,
and call closure in that same verification call. The native v5 first-round
roster must itself be pinned independently before this seal is accepted.

The current `RiscVInteractionClaim` cannot supply that request receipt by
itself. Opcode batch claims combine program access with register, memory, and
range events, while precompile caller claims also combine domains. The next
native-v5 slice therefore needs a program-only LogUp adapter over the **same
PCS-committed native main columns**: replay `opcode_entries.Entries(S).fromMain`
for each admitted opcode family and select its unique `program_access` entry;
add SHA, Keccak, and signer caller program requests from their committed
extension main columns. Prove the request interaction and exact active-row
census under this table's shared challenge channel, then return the request
receipt only after fresh verification and same-root checks. A host replay or
the old mixed claim is not sufficient proof authority. The block receiver
must derive expected fetch count from the independently pinned component row
counts plus precompile call counts and any unretired public terminal fetch,
and require equality with this table's
exact u64 census before closing the relation.

The scoped `block_v5_program_batch_receiver_v1` accepts serialized native,
request, and table proofs; it reconstructs the B5SS seal from independent
pins and ordered first-round entries, checks canonical program/request IDs,
fresh-verifies all three PCS proofs under the pinned roots, derives the
terminal boundary claim from the verified native public statement, then
closes the program sum and exact integer fetch census internally. The
`block_v5_program_first_round_v1` adapter streams native plans into exact
ROM counters, releases first-round PCS state, and checks table/request roots
again on deterministic proving replay. Its family entries are inputs to the
larger block roster, not receiver authority.

The adapter now takes the native template/key ID separately from the native
instance ID: execution family entries use the latter, while opcode request IDs
bind the former and the execution ordinal. Every segment must explicitly
record its SHA/Keccak/signer fetch partition before `finish`. Native plans
already include those fetches; the partition validates exact counts and
per-address inclusion without incrementing ROM multiplicities again. Its
family12 entry binds the independently prepared precompile instance, native
execution instance, actual execution ordinal, caller slots, and root pair.
The exact count-partition tightening passed the focused 13/13 gate.

The family12 companion uses separate family11 precompile roots with zero
native/hash column prefix. `extension_slots.fromProfile` derives placements
from the independently supplied extension shape and requires exact column
log geometry. Its PCS transcript binds both the precompile and native
execution instance IDs; relation challenges remain the common B5SS bundle.
Its narrow three-caller quotient/common-seal ROM closure gate passed 3/3.
This uses committed caller columns, not a fresh family11 arithmetic proof;
that separate arithmetic admission remains required for production authority.
The follow-up `block_v5_program_precompile_root_test` now closes that scope:
standalone family11 SHA/Keccak arithmetic is freshly verified, family12 opens
the exact extension-only fixed/main root pair, and a complete-ROM table with
three exact caller fetches closes their program relation under one B5SS seal.
The focused root passed 6/6, including fresh rejection of changed fetch count
and a swapped execution instance. Its native execution/retirement roster is
still scaffolding; this does not verify the native caller link or full block.

The q8 gates cover nonzero table multiplicities, fresh serialized proof
verification, same-root native admission, shared program/memory challenge
parity, exact-count mismatch, decoded-ROM mutation, canonical-ID/root and seal
tampering, and strict empty-main-tree preflight. They remain scoped: the
native proof still carries per-leaf program custody, SHA/Keccak/signer caller
fetches need separate fresh family11 arithmetic admission, and the complete block
receiver must also close memory, initial-state, and recursive relations.

The two-pass adapter focused ReleaseFast rerun passed 13/13 on 2026-09-26.
This includes old-native root replay, separated execution instance/key IDs,
explicit zero-call partition and duplicate partition rejection. It is not
native-v5 catalog admission: the scoped receiver still verifies B3SHART1.
The default adapter request ID additionally binds the native-v5 execution
instance; only the explicitly named `addLegacy` keeps the old request ID.

`block_v5_program_native_batch_receiver_v1` is the source-ready replacement
seam: independently supplied native-v5 shapes/plans/templates/catalog, a
one-proof-at-a-time loader, fresh `verifyOwnedWithCatalog`, request same-root
checks, terminal requests, and global ROM closure. It returns an OPEN native
residual rather than complete block authority, and refuses family11/12 until
fresh extension arithmetic/request verification is connected. This new seam
has passed AST checking but not its real-native integrated proof gate yet.
