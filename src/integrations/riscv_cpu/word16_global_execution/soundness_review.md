# Global execution: soundness obligations and qualification ledger

This source review is an engineering record, not a formal security proof.
The canonical Ethereum route is `services/{protocol,execution,roster,wire}.zig`
with `ethereum/{capture,keys,receiver,terminal}.zig`. The base, Keccak-only,
shared-Keccak and secp routes are retained controls/qualification tools; their
prefix acceptance does not certify Ethereum completion. The earlier base-only
review did not cover services. The obligations below now include their joins.

The completed block receipt is
`vectors/reports/rv64-word16-execution-20261101/ethereum-full-current-foundation-v1.json`:
104,253,913 instructions,25 CPU STARKs and five independently sized crypto truth
STARKs, plus a separate fresh receiver. It pins the precise source/binary and
layout (CPU50/40, LS71/48, ALU52/32, SHIFT53/28). It qualifies the joined
services route at source f4f9cc5ab, including physical closure and the separate
fresh completed receiver; it does not qualify every later layout automatically.
The 21,530,255,168 native cells are 3.0445 times fewer than the pinned wide RV64
route for the same ELF, input, retirements, calls, final registers and output.
This is an exact representation comparison, not a controlled wall-time claim.

## Independent authority and geometry

The receiver loads and hashes the independently pinned ELF/input, validates
symbols, immutable code/policy and absorbing terminal PC, and derives native
program/materials from that image. No packet, transport hash, producer key or
native VM result grants proof authority. The fresh Ethereum receiver consumes
no work packets or execution tape and performs no native replay.

Producer geometry is deliberately an untrusted admissible cost parameter.
Wire admission bounds logs, CPU/truth counts, proof bytes, total steps, rows,
call spans and lookup masses before large allocations. Ethereum admission then
checks genesis, batch schedule, epochs, PC/all32-register adjacency, budget and
completed endpoint before keys are built. Every admitted geometry must describe
a sound AIR; rebuilding a key alone is not sufficient acceptance.

`beginCpu` binds the compiled core layout/encoding identities and every shape,
bridge geometry and request into its spec digest. `beginTruth` binds family,
program, geometry and exact call span. The complete manifest checks reconstructed
specs and actual fixed/MAIN root pairs. Receivers compare actual proof roots
against independently reconstructed keys and that manifest, then verify every
physical proof. Real serialized declaration changes to admissible CPU and truth
geometries are rejected as `GlobalExecutionInventoryMismatch`; a changed epoch
is rejected during wire admission. Consistently resealed declaration/root attacks
must additionally fail the actual-root/physical-verification boundary.

## Two-phase transcript and closure

All CPU and truth fixed/MAIN roots are sealed before any shared RAM14, KIO11 or
Wire35 challenge is derived. The ordered inventory binds each worker ordinal,
expected image/program identity, total/budget and endpoint. A worker must recheck
its actual retained roots before stage2. An execution cannot start an early
shard's stage2 while a later shard's stage1 is still uncommitted. Each phase may
run workers concurrently with the complete-manifest barrier between them.

Every physical core and bridge claim enters the local transcript before INTER
commitment and constraint coefficients. Local CPU closure excludes precisely
shared RAM and typed crypto truth debts. Merged local lookup claims are additive
ledger shares authenticated by their combined physical prefix; they are not
independent certificates for each subrelation. No local provider debt may escape
through an omitted role or cancel against an unrelated global relation.

The receiver verifies every CPU/truth STARK, every absent-role zero-claim guard,
all local closures, then the complete global RAM/KIO/Wire sums. Shared positive
or absolute masses are bounded below the characteristic. Per-request R16/R8
relations remain local, avoiding an unjustified block-wide range-query mass.

Shared protocol revision 1 (WSRD) draws the manifest-derived RAM relation
without first drawing and discarding a local RAM relation. The protocol identity
changes explicitly, and prover and receiver use the same draw authority. Closed
and genesis controls retain their original local relation and transcript. The
completed-block receipt above includes the revised shared transcript.

## Memory, canonicality and state connection

Epoch is ordinal+1; after-tick is4*CPUrow+4. PC and all32 register values connect
across shards, while local register clocks reset and close inside each CPU proof.
OWNER19 has Boolean unit weights on both CPU and memory/service sides. This is
not a weighted dictionary and cannot authorize duplicate memory transitions.

Only the first shard supplies INIT and only the last supplies TEARDOWN. Native
public-list admission enforces sorted unique aligned addresses and canonical
integer state fields. INIT values/rights come from the pristine expected image.
EVERY physical boundary RAM claim is compared to `expectedClaim`, including
empty-side zero claims, before the final RAM sum. A balanced noncanonical tuple
encoding can pass a bare polynomial proof and total sum yet must fail this
per-boundary authority check. Native constructor validation is not the verifier.

Strict bounded lexicographic epoch/tick gaps, canonical after-clocks, unique
unit owners and INIT stamp0 rule out forked/orphan memory histories. Read
preservation, store selection and permissions are constrained. Every writer
produces canonical after-values: ordinary LS retains after-value and load-result
anchors; Keccak and secp bridge values are ranged and authenticated by the
corresponding truth program. Pointer alignment, coordinate ordering, bounded
addition and final carry0 prohibit wraparound accesses.

The LS48 interaction encoding removes only ranges implied by independent write anchors, REG/ROM binding
and the closed RAM DAG. The precise noncircular induction, retained query list,
caller assumptions and counterexamples are in
`design/riscv-proving-stack/rv64-ls-canonical-range-induction.md`. All gap ranges,
after-clock limbs and load-result/write-value anchors remain. A bare LS proof
without OWNER/RAM closure does not establish those inherited facts. The later
LS79-to-LS71 MAIN projection removes eight affine copies by exact substitution;
it keeps the same 48 interaction columns, canonical anchors and physical buses.
CPU53-to-CPU50 similarly derives zero-register flags as 1-enabled; ROM binding
and padding constraints authenticate that identity. A repaired forged witness
can pass bare physical verification but is rejected by closed REG/ROM checks.

## Services and independently sized truths

The ROM admits exactly the named LE-word service tags. CPU OWNER tuples bind
pointer, epoch and tick; bridges authenticate each RAM word's predecessor and
after-state. Keccak covers25 words; ADD covers24 and DOUBLE12. Call IDs are
contiguous per family across CPU shards and exactly covered by bounded truth
spans. Wire35 includes the program kind, preventing ADD/DOUBLE substitution.
KIO11 binds Keccak input/output lanes. Truth claims cannot cancel across an
unrelated typed bus or missing provider.

Crypto truths have their own PCS and geometry. Their current4n kernels do not
lift the CPU's native2n composition. Secp truths certify the specified modular
RCB programs, not standalone ECDSA validity; the complete guest execution proves
the surrounding recovery/validation and Ethereum behavior.

### arith256_mod (v3 family 4)

`ethereum_services_v3` admits `0x0003_0021`: r = (a*b + c) mod m, r = 0 when
m = 0, on a 32-byte aligned 20-word packet (only r written). The Word16 bridge
kind 4 binds five coordinates to RAM exactly as for secp/SHA-256; the truth
(`air/delegations/arith256`, one row per call, degree 3, own PCS) proves
`(1-z)(a*b+c) = q*m + r` over byte limbs with 48 two-coefficient groups and
carries in [-2^14, 2^14), whose field residuals stay below 1.61e9 < p and are
therefore integer equations; r < m is `m - r - 1 = d` with canonical d bytes
and no final borrow; z = [m = 0] is forced by `z*Σm = 0`, `Σm*inv = active-z`.
Operand and result bytes inherit U8 range from the bridge through Wire35; q, d
and carry bytes use a local BYTE table whose challenge is drawn after the
truth MAIN root and whose chain must close to zero (mass 237n < p). The truth
also consumes the before-value of the r slot (wire 4) so that every bridge
input tuple is matched. Adversarial tests cover wrong r, r >= m, wrapped q,
m = 0 forgeries, non-canonical limbs, carry forgery, forged Wire35/RAM/OWNER
data in real proofs, and absent/foreign bridges at a fresh receiver; the v2
fixture bundle is byte-identical to the pre-v3 base. Not established: a
block-scale proof with a guest using the tag, and recursion support. Details:
`design/riscv-proving-stack/rv64-arith256-service.md`.
## Admitted bulk memory (ethereum_services_v3)

Tags 0x30001 (memcpy) and 0x30002 (memset) are admitted by three bridge
components inside the issuing CPU proof (`desc`, `copy`, `set`;
`src/frontends/riscv/rv64/air/delegations/bulk_memory`). Full argument, layout,
masses and tests: `design/riscv-proving-stack/rv64-bulk-memory-service.md`.
Obligations this receiver relies on:

- The desc row consumes the CPU OWNER19 ECALL tuple (Boolean `active`), binding
  `a0`, `a7`, epoch and the after tick `4r+4`; it emits one OWNER19 token whose
  slot 0 (`0x424D0001/2`) is outside the opcode range. Body runs consume tokens
  on Boolean start rows; local OWNER closure therefore pairs every bulk ECALL
  with exactly one body run of exactly `len/8` rows (chain-end constraint).
- Every packet read, source read and destination write is a RAM14 transition at
  the ECALL's clock with ranged gaps. Strict predecessor order makes any alias
  among packet, source and destination words unprovable (the executor refuses
  it), and makes every read observe the latest earlier write.
- Alignment and no-wrap follow from canonical aligned INIT addresses and the
  absence of a top-limb carry; `len` limbs 2, 3 are constants 0.
- Canonical limbs: memset writes `257*fill` with a ranged byte (anchored);
  memcpy writes the consumed source token's limbs (new strictly decreasing edge
  in the joint REG/RAM write induction). Bulk after ticks are `4r+4`.
- Masses: RAM14 `6*calls + 4*copy_words + 2*set_words`, U16 per physical row,
  bulk ECALLs counted as CPU steps; admitted in `services/protocol.zig::admitBulk`
  and `services/wire.zig`.
- v2 rosters mix, commit and serialize nothing new (bulk block present iff the
  key has bulk components). The Ethereum driver's v3 work-packet route is not
  yet qualified; the services fixture (`services/bulk_test.zig`) is the
  accepting evidence.
- Extension (2026-11-02): memcpy with any source alignment (`ucopy` body rows,
  one lead row reading source word 0 then one row per destination word built
  from two source words at a one-hot byte shift) and memcmp 0x30003 (`cdesc`
  descriptor writing the -1/0/1 result word, `cmp` rows up to the first
  differing word with a strict first-difference byte argument). Zero-length
  calls are excluded (`cdesc` length inverse, no lead-only ucopy run). The
  extension block is mixed, committed and serialized only when present
  (`bulk_ext` claims, extension request counts omitted when zero), so
  aligned-only bundles are unchanged. Arguments B8-B11 in the bulk design
  doc; canonical writes in `rv64-ls-joint-write-induction.md` section 11.
  Evidence: `services/bulk_ext_fixture.zig` (real STARKs, fresh receiver).

## Ownership, storage and resource scope

The canonical services coordinator transfers both CPU and crypto truth
MAIN/INTER buffers into owned streaming commitments. Historical borrowed control
APIs still exist; their presence is not evidence that the production route uses
them.
All descriptor/allocator/shape/alias validation precedes ownership changes;
allocation failures preserve retryable original owners. Narrow relation metadata
survives MAIN retirement. Completed sources retire only after encoded claims
and request boundaries own every receiver obligation.

Retained MAIN mappings hold already committed native coefficients, not replayed
witnesses. Their roots and values do not change. Allocations are bounded, scratch
files are unlinked, and the PCS owns teardown. The store/allocator outlive every
lease. Success, first-spill refusal, later-truth refusal and allocation failures
are qualified for cleanup. This is same-process storage, not a durable restart
checkpoint or proof of arbitrary concurrent fanout memory bounds.

The streaming collector is producer advice. A partially failed append poisons
its ledger; it must be discarded. Successful advice copies permit tape and
capture-record retirement, while owned LS metadata preserves all obligations.
Explicit event consumption frees copied advice only after that ownership exists.
Its full-block control preserves all30 proofs, manifest and RAM sidecar exactly.

## Completion, evidence and remaining boundaries

Prefix mode proves a producer-claimed prefix endpoint within the trusted image
and budget. It returns `accepted:true`, `completed_ethereum_block:false`, and no
output. Endpoint coverage is intentionally not an independently requested block
completion statement. Downstream consumers requiring a block certificate must
require the completed flag and independently expected image/output authority.

Completed mode first verifies ALL physical proofs and global obligations, then
requires the independently pinned absorbing final PC, halt=1, output length43
and the expected43 bytes from authenticated terminal RAM. Missing words cannot
fall back to a VM image. Actual valid prefix proofs with false halt/length/output
and an early endpoint are rejected as completed blocks.

Tests include locally valid wrong predecessor/service-output proofs rejected by
full closure; foreign epochs/pointers/kinds; swapped/missing roots; balanced local
or RAM claims; omitted-role ghosts; permission/image/program substitutions;
repeated INIT/premature TERM; invalid chronology; strict-inverse poles; and actual
noncanonical witness proofs accepted by a bare PCS but rejected by the closed
receiver. Declared-geometry mutation tests invoke the fresh receiver on durable
real-block artifacts, not just native constructors.

A small recursive root is not yet qualified for this lane. Native verification
still reconstructs statement-specific fixed keys and consumes the public RAM
sidecar. Compact recursion needs explicit initializer/image and terminal-output
authority; hashing that sidecar is not a substitute for proving its meaning.
GPU qualification and same-AIR Rust verification are also open.

q70/P26/log-blowup1 has a nominal96-bit parameter score, not a formal whole-
protocol96-bit or128-bit guarantee. Lookup degree, actual masses, adaptive
statement selection and unions across all relations/proofs require separate
security analysis. Epoch16/tick24 and the characteristic guard remain explicit
finite limits, not unbounded-execution claims.

## SHA-256 compression (`ethereum_services_v3`)

Design and evidence: `design/riscv-proving-stack/rv64-sha256-service.md`.

SHA-256 is Wire35 program kind 3 and services `Family.sha256 = 3`, appended
after the v2 roster. A v2 bundle is byte-identical with or without this code.

- **Bridge.** The shared Word16 Wire35 bridge with kind `.sha256` binds:
  - OWNER19 (ECALL, full64 `a0`, `a7 = 0x30010`, epoch, CPU tick);
  - 32-byte alignment and non-wrapping word addresses;
  - an authenticated RAM14 predecessor for each of the 12 words, all readable;
  - write rights for words 0..3; words 4..11 are read-only, so their after
    value equals the before value.

  RAM adds 24 terms per call.
- **Truth.** One compression per row, degree 3, native 2n, in its own PCS.
  - Boolean registers for `W_0..63`, `A_{-4..63}` and `E_{-4..63}`, plus
    exact carried 16-bit-half sums.
  - Every half-sum is below `8·2^16 < p`, so each field equation is an integer
    equation.
  - Padding rows are honest zero-state compressions.
  - Activity is a strict prefix of exactly `calls` rows, enforced through the
    previous-row ACTIVE mask, FIRST/LAST and the public `calls`.
- **Joins.** The truth consumes wires 0..2 (state and both message halves) and
  produces wire 3, keyed by kind, call ID (`first_id + ROW`) and wire ID. The
  bridge produces its BEFORE tuples and consumes coordinate 0's AFTER tuple.
  Input bytes are linear forms over truth bits (the big-endian swap is in the
  form). Output bytes inherit U8 canonicality from the bridge through Wire35
  closure. The receiver adds every bridge and truth Wire35 claim into the one
  global sum.
- **Transcript.** The CPU spec mixes the SHA block only when the bridge is
  present, and the CPU claim vector then grows by five claims. The truth
  spec mixes its geometry and constraint count. Unused truth-claim slots must
  be zero.
- **Admission.**
  - The ROM and CPU AIR are unchanged: a SHA tag closes OWNER only in a shard
    whose admitted roster contains a SHA bridge.
  - The Ethereum receiver rejects any SHA declaration unless the request's
    `execution_profile` is v3.
- **Tests** (beyond the unit/AIR suites): locally valid false new state →
  Wire35 unclosed; forged block word consistent between bridge and truth →
  RAM unclosed; wrong pointer → CPU local OWNER unclosed; missing-bridge
  receiver → presence mismatch; a 4-shard real-block prefix accepted by a
  fresh receiver.
- **Open.**
  - recursion support;
  - a complete-block v3 qualification;
  - binding the profile into the program identity rather than receiver policy;
  - whole-protocol security accounting.

## Keccak-256 sponge (`ethereum_services_v3`, tag 0x30130)

Full argument: `design/riscv-proving-stack/rv64-keccak-sponge-service.md` §4.

- **Shape.** Two bridge components in the issuing CPU proof (`call`: one row
  per ECALL; `perm`: one row per permutation, a contiguous run per call). The
  permutations are proven by the unchanged Keccak-f truth over the shared
  IO11 bus. Not a `Family`: a roster block after bulk memory.
- **IDs.** Sponge permutations take IO11 IDs after every Keccak-f call, shard
  by shard. Each request carries `sponge.first_id`; `admit` checks every
  first ID and requires Keccak truth spans to cover `1 .. K + S` exactly.
  A permutation row's ID is `first_id + fixed row index`.
- **Joins.** Call row: OWNER ECALL consume, token emit, 4 packet reads and 25
  state read+writes (RAM14, R = W = 1 constants), IO11 link `(id, 2, l, old)`
  emit (weight `active − fresh`) and last-output `(id + q + fin − 1, 1, l, new)`
  consume. Perm row: token consume on the first row, message word reads
  (RAM14, read-flag thermometer continued across rows, exactly `W` words),
  input `(id, 0, l, pre ⊕ msg)` and previous output / link consume, XOR via
  the core byte-AND table (`pre + msg − 2·and`). Direction 2 is never produced
  by the truth, so links only meet links.
- **Length and padding.** `len = 136q + r` (ranged), `rb` counter per row,
  thermometer mask; the finalizing last row carries `Σ mask = r`, `0x01` at
  the first masked position and `0x80` at byte 135; non-final rows are full.
  This fixes the run length to `q + fin` over the integers.
- **Canonicality.** Even window bytes of in-mask positions are AND-checked
  through `msg`, odd bytes U8-checked, so every limb that feeds an absorbed
  byte decomposes canonically. Truth bytes are bit sums; call-row old/new
  bytes inherit canonicality through the IO11 tuples they meet. Writes are the
  25 state words with truth-anchored values: no new circular edge in the joint
  write induction.
- **Transcript.** A sponge block in `beginCpu` and twelve CPU claims, both
  only when present; the receiver adds sponge IO11 claims to the global IO
  sum. v2, SHA-only, arith-only and bulk transcripts are unchanged.
- **Admission.** Executor and AIR agree: len < 2^20, no empty non-final call,
  state rights 3, packet/state/message words disjoint, flags < 4. The
  Ethereum receiver rejects sponge declarations unless the request is v3.
- **Tests.** AIR: honest scenario and 23 lengths × 8 alignments close against
  an honest truth; wrong XOR, wrong byte, skipped/reordered blocks, forged
  final state, length mismatch, forged padding, nonzero fresh state and a
  non-canonical tail split are rejected; degree ≤ 3. Services: real STARKs,
  fresh receiver over the wire, split truth spans; wrong truth input → IO11
  unclosed; forged and stale message words → RAM unclosed.
- **Open.**
  - recursion support (no om31/circuit role for the sponge components);
  - a real-block v3 qualification with an admitted sponge guest;
  - whole-protocol security accounting.
