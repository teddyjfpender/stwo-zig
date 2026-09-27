# BLAKE3 prover migration

Status, 2026-09-21: priority work; native CPU protocol foundation, a complete
compression proof and fixed-length full BLAKE3 hash proofs are implemented and tested. Production RISC-V leaf/parent proofs still use their
existing Poseidon suite. No BLAKE3 recursion, Metal proof or new production key is
qualified yet. The fused PCS prototype and prior scheduling work are retained.

## Evidence and upstream scope

The inspected [ZisK alpha release](https://github.com/0xPolygonHermez/zisk/releases/tag/v1.3.0-alpha)
is commit `02d2ae7b711454ce4574d852f8bfbddbfcbb1d67`. Its release notes describe an
optional BLAKE3 recursive configuration and a seven-round compression precompile.
They also describe scheduling and witness-generation changes. This is evidence
for the architecture, not a controlled measurement of the hash change alone.
The earlier research checkout's tag resolved to
`5c5f81c96929abed88894473ec6060b1b545b5c5`; preserve both identities rather than
silently attributing earlier source inspection to the later release.

Release Cargo.lock uses `proofman-fields` 1.3.0-alpha, checksum
`eb8d460b2e0e01f448eb78bd5486877239130674572be8f5c334bc86948cd65b`.
Inspected reference implementation: Proofman
`d485fac207679076958b502554fb595568c2f954`,
`fields/src/blake3_core.rs` and `fields/src/blake3_transcript.rs`.
That commit is not asserted identical to the published crate. The transferable
idea is using the full BLAKE3 construction with a compression backend, rather
than replacing a Poseidon permutation inside its existing sponge. Goldilocks
transcript word reduction is not directly reusable over M31.

## Implemented reference protocol

`src/core/channel/blake3.zig` and
`src/core/vcs_lifted/blake3_merkle.zig` export an explicit experimental suite.
They reuse the existing std-backed `Blake3Hasher`; no new production dependency
or default-suite change. Protocol identifier: `stwo.blake3.experimental.v1`.
Every hash starts with that exact ASCII string and one operation byte:

| Tag | Encoding after protocol prefix and tag |
| --- | --- |
| 0, initial state | empty |
| 1, mix words | previous digest, u64 word count, u32 words |
| 2, mix QM31 | previous digest, u64 QM31 count, four u32 coordinates per value |
| 3, mix integer | previous digest, u64 value |
| 4, mix root | previous digest, full 32-byte root |
| 5, draw | current digest, u64 draw index |
| 6, PoW | current digest, u32 difficulty, u64 nonce |
| 7, leaf | concatenated canonical M31 values, each encoded as u32 |
| 8, node | full left digest, full right digest |

`src/core/channel/blake3_frame.zig` is now the sole protocol-byte author. Native
channel/Merkle hashing and recursive witness messages share its streaming writer;
materializing a frame is optional and is not done by the native hot path. The
original independent protocol-vector pins still pass. A complete CPU STARK also
verifies a canonically framed Merkle node against the native hasher, with public
child digests. See [framing evidence](../../autoresearch/notes/2026-09-21-blake3-framing/README.md).

All integers are little endian. Absorption updates the digest and resets the
draw index. Draws increment a checked counter without updating the digest.
For base-field sampling, reject an eight-word draw if any word is >= 2p,
then reduce each accepted word modulo p = 2^31-1. Each output has exactly two
preimages. Single-QM31 draws consume one block and use its first four words;
bulk draws consume up to two QM31 per block, matching the existing PCS API's
consumption convention. PoW checks trailing zero bits in the first little-endian
u32 and rejects difficulty above 32. The initial state is pinned against an
independent oracle because Zig 0.15.2's BLAKE3 implementation fails to evaluate
this short input at comptime; runtime hashing is tested.

Digests remain `[32]u8`. There is no M31 digest reduction and no device-family ID
advertised by this new hasher. This protocol has not received cryptographic
review; the identifier deliberately says experimental. The primitive's digest
size alone does not establish 128-bit soundness for the entire M31/QM31 proof.

## Migration boundaries and implementation order

| Boundary | Existing implementation | Required migration |
| --- | --- | --- |
| Native commitments/channel | Core BLAKE2 paths; recursion `poseidon2_channel.zig` | BLAKE3 suite is now a CPU oracle; qualify generic proving and serialization before selecting it |
| Scheduled Fiat–Shamir | `native_scheduled_channel.zig`, transcript witness and verifier schedule | Constrain identical byte framing, draw indices, field rejection, roots and PoW |
| Recursive hash provider | Typed Poseidon components, `detached_parent_catalog_v1.zig` | Typed BLAKE3 compression plus framing/chaining constraints; exact lookup closure |
| Trace/FRI authentication | Merkle witness components and `fixed_wire_adapter.zig` | Lossless digest limbs, BLAKE3 path verification, all child roots authenticated |
| Program/memory statements | `air/memory_commitment`, segment statement wire | New commitment suite and statement version, recomputed roots and empty-tree hashes |
| Keys/proof identities | `engine_protocol.zig`, protocol identities, canonical proof identity, trusted artifacts | Bind family and full protocol definition into trusted key and wire admission; reject mismatches before interpretation |
| Metal | `hash_domain.zig`, runtime ABI, commitment/FRI kernels, typed AOT | New explicit family, BLAKE3 kernels and generated recursive evaluator, CPU parity and actual dispatch evidence |
| Product defaults | RISC-V leaf, parent, CSP scripts and docs | Switch together after end-to-end qualification; retire old prover selection and redundant code |

The shared seven-round compression schedule and typed degree-two G arithmetic
reference are now implemented; see
[compression evidence](../../autoresearch/notes/2026-09-21-blake3-compression/README.md).
Four focused tests pass, including complete witness-coordinate mutation and
standard hash parity across chunk boundaries. This is not a qualified recursive
provider: the reference has 704 Boolean columns per G and no authenticated
inter-call relations. A compact typed G now uses 124 columns, 80 degree-two
equations and 56 requests to existing byte-pair/bitwise schemas. Its three
focused tests cover equivalence, mutation and table membership; see
[compact component evidence](../../autoresearch/notes/2026-09-21-blake3-packed/README.md).
Typed G and feedforward XOR call components now compile through the canonical
relation binding, with a fixed 272-wire compression plan and a writer for all
72 rows. Exact signed multiset tests close both wires and canonical production
lookup-counter rows; see [wiring evidence](../../autoresearch/notes/2026-09-21-blake3-wiring/README.md).
A standalone CPU compression STARK now commits the G, XOR and public-boundary
components together with the production bitwise and byte-pair tables. The core
verifier accepts it using independently reconstructed preprocessing and matching
BLAKE3 transcript draws. Substituted preprocessing roots and changed public
outputs fail root admission. The test uses eight queries and zero PoW solely to
keep integration checks short; it is not a production-security performance result.
See [committed proof evidence](../../autoresearch/notes/2026-09-21-blake3-committed/README.md).

A canonical full-hash DAG now expands fixed public message lengths into the same
G/XOR wire circuit. It handles empty input, zero-padded partial blocks, chunk
counters, CHUNK_START/END, left-complete chunk trees, PARENT and ROOT. Chaining
values share wires across compression calls; they are private intermediates,
not additional public claims or values recomputed by the verifier. The first
eight words of the root output form the ordinary 32-byte digest. Keyed hashing
and XOF are outside the current unkeyed protocol suite.

`test-blake3-hash` checks standard-library parity across 18 lengths up to 8193
bytes, exact global wire closure, mutations and allocation failures.
`test-blake3-proof` now verifies full hash STARKs for 0, 65 and 2049 bytes, covering
empty/partial blocks and an unbalanced three-chunk tree. It rebuilds fixed
columns from public message/digest and length-owned topology without computing
the private rounds. See [full-hash evidence](../../autoresearch/notes/2026-09-21-blake3-full-hash/README.md).

These are public-message hash proof gates. A typed private-input bridge now
copies complete caller word tuples into the hash graph and constrains unused
partial-word bytes to zero. Its trusted preprocessing receives length and caller
wire range, never message bytes. Compiler/export and exact global wire tests pass,
including rejection of missing caller emissions and changed endpoints. See
[private-input evidence](../../autoresearch/notes/2026-09-21-blake3-private-input/README.md).
The bridge now also passes a complete CPU STARK for H(H(message)): the first
hash's digest is omitted from the public statement and its output wires feed the
second hash through the bridge. Trusted preprocessing uses only original message,
final digest and canonical schedules. This is witness-only composition, not a
zero-knowledge claim. See [private composition evidence](../../autoresearch/notes/2026-09-21-blake3-private-proof/README.md).
Production child-proof source admission remains unfinished. Recursion also needs
exact scheduled transcript byte framing and rejection sampling, and Merkle path
composition.
Follow with new trusted protocol/key/artifact identities and CPU/Metal end-to-end
qualification. Preserve old identities until the replacement can produce and
verify a parent-of-parent. New proof bytes must never be interpreted under an
old key because their digest happens to have the same byte length.

The compact provider uses four bounded bytes per 32-bit word, preserving every
bit. Additions use bounded byte carries; XOR and rotations use canonical bitwise
and byte-pair tables. The shared typed arithmetic and relation compiler remain
the only constraint authors. Full construction reference:
[BLAKE3 specification](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf).

Retain guest-visible Poseidon precompile semantics when a program explicitly
requests Poseidon. Ethereum Keccak and structural SHA-256 artifact pins are
separate obligations. Migrating the prover's commitments does not authorize
changing the guest's program or making existing artifact identifiers ambiguous.

## Qualification and performance

The focused gate is `test-blake3-protocol` in the RISC-V CPU integration build.
It covers official primitive vectors across block/chunk boundaries, streaming,
independent protocol vectors, rejection boundaries, domain separation, a
nonconstant CPU PCS/FRI proof, tampered sampled-value rejection, every root byte's
high-bit mutation, wrong BLAKE2 family rejection, and matching final transcripts.
This target is PCS/FRI qualification. `test-blake3-framework` adds typed boundary,
export and padded interaction checks; `test-blake3-proof` produces and verifies a
compression and full-hash STARKs. None is a complete RISC-V or recursive parent proof.

Native diagnostic on M5 Max / 64 GiB, Zig 0.15.2 ReleaseSafe, six alternating
pairs, 2048 hashes per sample:

| Operation | Poseidon median ns/hash | BLAKE3 median ns/hash | Median paired speedup |
| --- | ---: | ---: | ---: |
| Leaf, 16 M31 words | 1786.45 | 204.56 | 8.76x |
| Leaf, 256 M31 words | 19687.54 | 1826.48 | 10.79x |
| Leaf, 4096 M31 words | 305724.42 | 27860.52 | 10.99x |
| Internal node | 595.38 | 160.38 | 3.70x |

These are single-message native API timings, not optimized batch/device paths,
not a profile-weighted workload, and not proof speedups. They include each
suite's own domain framing. Both use the same M31 leaf inputs; repeated nodes
use each suite's own digest chain. No build/proof work ran concurrently.
Samples and source pins are in
[`../../autoresearch/notes/2026-09-21-blake3-migration/README.md`](../../autoresearch/notes/2026-09-21-blake3-migration/README.md).

The next performance acceptance measure is complete same-statement,
same-security-profile leaf/parent/tree wall time with independently verified
outputs, including recursive witness generation, interaction work, commitments,
PoW, admission and bounded scheduling. Native savings must exceed the added
recursive bitwise constraints and lookup traffic. Do not claim the earlier
5.54-second Poseidon parent timing is now a BLAKE3 result.

Security parameter changes remain a separate experiment. Keep original
q193/16+10 recursive measurements distinct from canonical CSP 70-query/26-bit
results. No query or PoW reduction accompanies this foundation.
