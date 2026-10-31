# Word16 Keccak global-RAM prefix

This is a separately tagged concrete service protocol. The existing closed and
RAM-only execution constructors/receivers keep their service rejection and local
closure checks. It is not a full Ethereum block, halt/output certificate, secp
service receiver, or recursion proof.

Each shard commits the existing seventeen-role CPU/RAM roster, the existing
triple-batched Keccak permutation, its exact chi/xor providers, and the new
Word16 lane bridge in one PCS. Its fixed key depends on the independently
expected program and native geometries, never call counts or call inputs.
Setup owns rootless CPU material and one combined committed fixed tree; it does
not construct or retain a redundant legacy fixed tree. Existing setup-based
transcript/admission APIs delegate to the same material-based authority.
All shard fixed and MAIN roots, request digests, ordinals, coverage and geometries
enter the complete ordered manifest before RAM randomness. Per-shard CPU OWNER
and Keccak IO randomness are then derived from that shard's retained transcript
and the manifest; no caller-supplied lookup challenge is accepted.

The bridge has six fixed, 66 MAIN and 116 INTER columns. It uses 25 rows/call,
plus at least one inactive padding row. It shares the checked epoch16/tick24
RAM14 transition equations and strict pair inverse/prefix equations. All 167
residuals have degree at most three and the native quotient uses 2n points.
The Keccak permutation retains its existing degree-four/4n authority.

One active group emits exactly one negative OWNER19 ECALL fact with raw opcode,
full64 a0 pointer, zero immediate, a7=0x10001, zero result, public epoch and CPU
slot-four tick. All 25 rows repeat that header. Call IDs are constrained local
IDs 1..count and each fixed lane0..24 appears exactly once; captured global
native call IDs are transport metadata and are not truncated into this bus.
Each row consumes both Keccak IO11 directions, reconstructs four RAM u16 limbs
from eight before/after bytes, and emits one before-minus-after RAM14 update.
Full64 pointer+8*lane addition has Boolean carries and prohibits wrap. Eight-byte
alignment is constrained. Both read and write permissions must hold for every
word, and the same rights are preserved. Earlier epochs or strictly earlier
same-epoch ticks are range constrained by the existing transition authority.

The constructor interleaves ordinary LS records and services in instruction
order without VM replay. A service touches25 distinct words at one CPU tick;
each word has its own predecessor. The ledger supplies hints only. Sole first
INIT values/permissions are independently queried from the pristine expected
image; sole last TERM is physically RAM-authenticated and transcript-bound.
All words occur in sorted identical INIT/TERM address sets. Before accepting,
the receiver checks actual proof roots against every manifest entry, verifies
every STARK, closes all per-shard non-RAM debts including OWNER/IO/ranges, and
then closes aggregate RAM. All41 physical claims are transcript-bound.

Bridge ranges are unconditional: 22 U16 and19 U8 queries per padded physical
row. RAM positive/negative absolute mass adds50*call_count to ordinary LS and
boundary masses. Each family's positive/absolute mass is admitted below M31's
characteristic. Keccak's existing chi/xor mass limits remain mandatory. Fixed
chi/xor values are key material; their MAIN multiplicities are request-specific.
No table interaction or multiplicity is reused merely because a fixed key is
cached.

Security parameters match the existing q70/P26, blowup-one configuration
(nominal configuration96). This is not a whole-protocol96-bit or128-bit claim;
lookup rational degree/mass and unions require separate accounting.

The convenience producer currently retains bounded worker PCS owners in one
process. It is a qualification harness, not an unbounded distributed scheduler
or a demonstrated full-block memory budget. The receiver never uses the native
ledger or captured service outputs as truth.
