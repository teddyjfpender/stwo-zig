# Direct RISC-V leaf wrapper proof

**Status:** This 47-row roster is now a real q193 diagnostic witness, not the
proof-complete target. Its closure exposes missing native identity producers,
ProgramV2 word authority, range/frame multiplicities, and a public LAS2
boundary. The [versioned 50-row target](direct-leaf-wrapper-v5.md) records the
required additions. The architectural decision to avoid the 49-row/PFD1
commitment cycle below remains valid.

## Decision

The production leaf wrapper must prove the native SegmentV2 verifier and the
V3 global-position relation in **one** STARK transaction. Rows 0–38 of the
existing detached leaf cohort already verify the native proof. A separately
proved 39-row local outer STARK therefore repeats the same verifier and is
not a recursively authenticated child merely because the host freshly checks
it. The strong q193 native-to-outer gate remains a useful diagnostic, not a
required step or soundness premise for the direct wrapper.

The staged 49-row wrapper is not a production candidate. Its provider field
digest (PFD1) is derived from the 39-row outer proof's claims, relation draws
and Poseidon partial sums. Those values are available only after the outer
interaction transcript. Replacing that proof with the wrapper's own 39 rows
would require main-tree rows 39/40 and 45 to commit a digest of *this same*
wrapper's future challenges and sums. That is a commitment-order cycle.
Host validation of a previously proved outer PFD1 does not fix it: the 49-row
AIR does not verify that outer proof. No PFD1 field may be treated as
pre-challenge proof authority in the direct wrapper.

## V4 direct diagnostic roster

The next versioned roster has 47 components. Rows 0–33 and 35–38 retain the
native-verifier owners; row 34 is rebuilt as the single enlarged Poseidon
provider for the entire transaction. New rows are:

| Row | Component | Input available before main commitment? |
| --- | --- | --- |
| 39 | V3 metadata/link source | Yes: canonical global statement and native verifier inputs |
| 40 | V3 source projection | Yes: row-39 values, local wire, pinned constants |
| 41 | 64-bit position/completion arithmetic | Yes: local count and global span |
| 42 | native transcript ProgramV2 field words | Yes: native child proof and fixed verifier plan |
| 43 | ProgramV2 field hash | Yes: row-42 words |
| 44 | native Tree0 field link | Yes: native verifier input and captured fixed root |
| 45 | V3 metadata hash | Yes: canonical metadata preimage |
| 46 | V3 link hash | Yes: canonical link preimage |

The row-34 call roster has four ordered ranges: existing native-verifier
calls, metadata hash, link hash and ProgramV2 hash. Its exact calls, not just
their count, determine the provider main trace. The AIR must close every
relation domain across all 47 rows, including the enlarged Poseidon caller
bus. The first 39 rows cannot be copied from an already committed proof:
their row-34 trace, manifest, claimed sums and interaction tree all belong to
the new 47-row transaction.

The direct ProgramV3 source schedule must omit the old provider-digest
emitter and its projection/hash consumers. Its public verifier-input shape is
exactly 24 field limbs: link identity, native ProgramV2 digest and native
Tree0/preprocessed root. The old 56-limb authority scope must be rejected so
no provider digest survives as an unconstrained public word. Each consumed
digest tuple needs the exact emission multiplicity; the Tree0 root also needs
an AIR equality bridge to the native verifier's commitment input, rather than
only a host-side equality check. Its immutable schedule ID, typed
AIR geometry, relation registry, q193/PCS-PoW16/fold4 and 10-bit interaction
PoW belong in a new protocol and verification-key namespace. The verifier
recomputes the preprocessed root and admits only an independently pinned
native Tree0/program key; a prover-supplied root or mutable host snapshot is
not a key. The native transcript ProgramV2 includes the local wire and
statement-authority identities, so its preprocessed words and the direct
wrapper key may vary per leaf. The detached parent must authenticate the
child key through an admitted program/statement or registered key family;
accepting the key carried in a child artifact would let a prover select an
arbitrary circuit.

### Native program authority that is still missing

The current row-42 word AIR checks a main word against a preprocessed word,
then row 43 hashes that word. Nothing in rows 0–38 produces the same indexed
word tuple. Thus these two rows authenticate a self-consistent preimage, not
the program that actually drove the native verifier. This is a soundness
blocker even if host code reconstructs both objects from the same input.

The intended versioned bridge uses a distinct `NPV2` lookup tuple
`(scope, index, value)` emitted by the native verifier program source and
consumed by row 42. Row 42 then emits the existing `PV2W` tuple consumed by
row 43. The native producer must derive every canonical ProgramV2 header,
PCS, statement and instruction word from the corresponding verifier-owned
source that rows 0–38 actually use; a second independently supplied word
table would merely move the gap. Active/index preprocessing may be fixed by
shape, while word values remain main data. The proof must reject a missing,
duplicated, reordered, or changed word through exact lookup closure and the
ProgramV2 hash.
The typed `transcript_program_v2_field_bridge_v4` AIR and an adversarial
missing-producer/changed-word gate now exist. The current PlanV4 row 42 still
uses the older self-consistent source; switching it to the bridge and adding
the native producer are required before a direct proof can be qualified.

An independent detached verifier may require an expected native identity and
recompute the 47-row Tree0 root before checking proof bytes. That protects a
local transaction from artifact-selected keys, but if it also needs the full
native proof and ProgramV2 for every child, it is not yet succinct recursive
admission. A production parent must prove its own membership/identity policy
for any leaf-dependent key. Neither the expected identity nor a root copied
from a child artifact may become an unchecked public input.

## Transcript and proof boundary

1. Admit the native proof under its pinned q193 profile/key. Derive the V3
   local-to-global witness and the 47-row fixed schedule from verifier-owned
   data. All pre-main inputs must be independent of this wrapper's future
   relation draws.
2. Commit the pinned preprocessed tree and the complete main tree. Mix the
   direct wrapper program/statement, grind the 10-bit interaction nonce, then
   draw relations. Generate all 47 interaction components and their exact
   claimed sums. Commit the interaction tree and prove at q193/PCS-PoW16.
3. Serialize, destroy producer state, decode and freshly verify with a
   separately reconstructed cohort, fixed key and preprocessed root. Publish
   a V3 leaf only after all 47 rows and relation domains have verified. The
   transaction and detached loader must reject changed proof bytes, key,
   local proof identity, metadata, call order, claim or completion.

This path still requires the public-I/O byte binding in issue #228. Without
it, even a verified direct wrapper cannot claim that the guest processed the
published application input or produced its output bytes. The temporal
parent is a separate proof after direct leaf publication; its mixed-family
child verifier and sparse-memory/finality joins remain open.

## Qualification

The first gate is a real two-leaf ELF: two independently pinned q193 native
proofs, two freshly verified direct wrappers and one freshly verified temporal
parent. Mutations must cover child order, proof/key/root, native transcript
claim count, row-34 call omission/reorder, global cycle/segment arithmetic,
CPU and sparse-memory boundary, completion and public I/O. A second gate
crosses 2^24 total retired instructions with each local leaf under its cap.
Measure native proof, wrapper preparation/proving/verification, parent proof,
canonical proof bytes and peak memory separately. Compare the direct wrapper
against the diagnostic native-plus-outer chain to quantify the removed work.

All direct-wrapper publication flags remain false until these proof gates
pass. The existing 49-row/PFD1 prototype stays labeled diagnostic and must
not be used as an accepted recursive leaf.
