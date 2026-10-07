# S31 SHA256d chip integration contract

Status: a one-header private circuit-plus-SHA proof has now been generated and
natively verified with the committed caller AIR and both lookup closures.
Its current matched cost is recorded below; it is slower than the generic
circuit. Existing
Bitcoin fold proofs still use `sha256d.zig` in the generic circuit. The
earlier six-call SHA STARK uses public boundary rows and is not a proof of a
private S31 header.

## The statement and the minimum private boundary

An S31 80-byte header has 40 little-endian `u16` limbs, and its SHA256d digest
has 16 little-endian `u16` limbs. A fast caller should bind only those 56
circuit values to the chip. The two intermediate compression states belong to
the SHA chip and caller AIR; copying SHA's whole round trace into the circuit
would keep the generic circuit's dominant cost.

For one header, the packed SHA graph has three compression calls. Each call
uses 24 input words (eight state plus 16 message words) and eight output
words. A `recursion_wire` tuple has six M31 coordinates:

```text
(call_id, wire_id, byte0, byte1, byte2, byte3)
```

The bytes are ordered from least significant to most significant **within
the SHA word**. SHA loads four serialized header bytes as a big-endian word.
For header bytes `h0 h1 h2 h3`, its tuple is `(h3,h2,h1,h0)`.
Call IDs are verifier-assigned `1..3` for one header, `1..6` for two. Source
boundary wire IDs are `4096..4119`; output wire IDs are the fixed graph's
`264..271`. The tuple convention is implemented in
[`sha_chip_plan.zig`](../../src/frontends/s31/sha_chip_plan.zig) and tested
against the packed SHA AIR's actual lookup events for both batch sizes.

## Caller polynomial equations

[`sha_caller_equations.zig`](../../src/frontends/s31/sha_caller_equations.zig)
specifies one caller row with 56 circuit limb values and 96 four-byte SHA
boundary words. Its **264 degree-one equations** apply over both M31 prover
rows and QM31 verifier openings. The first header limb is constrained by

```text
L0 − (call0.block0.byte3 + 256 × call0.block0.byte2) = 0.
```

The next limb uses bytes 1 and 0 of that same word. The other 38 input limbs
use the rest of the first block and the first four words of the second. The
16 digest limbs use the final call's eight output words in the same pattern.
The caller also constrains both initial SHA states, the second call's state to
the first call's output, the third call's first eight message words to the
second call's output, both `0x80` pad bytes, all zero pad bytes, and the exact
big-endian bit lengths 640 and 256. The caller code emits the 56 fixed-address
Gate tuples and 96 SHA word tuples that a joined component must use.

The limb equation is integer-sound **only if each byte is range checked**.
The packed source AIR requests two `range_check_8_8` table lookups per input
word. Packed SHA arithmetic's `word()` constructor requests the same lookups
for produced words, including the eight feed-forward outputs. The shared
`recursion_wire` lookup then makes the caller coordinates equal to those
byte-constrained SHA words. Tests intentionally replace `7 + 256×3` with
`263 + 256×2`: the local limb equation still holds over M31, while the SHA
wire multiset no longer closes. The range tables and every lookup sum are
therefore mandatory parts of the verifier, not optional witness checks.

## The committed caller AIR, by hand

[`sha_caller_air.zig`](../../src/frontends/s31/sha_caller_air.zig) places one
header in a 16-row circle trace, the minimum size supported by the current
component. Every honest row repeats the same 440 M31 values: 56 circuit `u16`
limbs plus `3 × (8 state + 16 block + 8 output) × 4 = 384` SHA byte
coordinates. Those are **main trace columns**, committed before the Gate and
SHA lookup challenges are sampled. The verifier never reads the private
header from a public input.

At every row, the AIR evaluates all 264 equations from
`sha_caller_equations.zig` over the committed columns. For example, if the
first two serialized bytes are `0x07` and `0x03`, the first circuit limb must
be `7 + 256 × 3 = 775`. The SHA input tuple for the first big-endian word
holds these as `byte3 = 7` and `byte2 = 3`; the AIR checks
`limb0 − byte3 − 256 × byte2 = 0`. At a verifier opening, the **same**
polynomial is evaluated over QM31. The other equations tie the remaining
header and digest limbs, the initial states, the two inter-call links, every
padding byte, and both bit lengths.

The caller makes 152 signed lookup uses per header:

| Bus | Caller use per header | Matching use elsewhere |
| --- | ---: | --- |
| Circuit Gate | 56 positive `(Gate,address,limb,0,0,0)` tuples | 56 negative uses at verifier-fixed addresses in circuit preprocessing |
| SHA `recursion_wire` | 72 positive input tuples: three calls × 24 words | SHA source/schedule/round/feed-forward consume them |
| SHA `recursion_wire` | 24 negative output tuples: three calls × 8 words | SHA source/schedule/round/feed-forward emit them |

Each tuple has a denominator `d = Σ alpha^i × tuple[i] − z`. The caller uses
**separate transcript-drawn** `(z, alpha)` pairs for Gate and SHA wires. It
contributes `(+1/16)/d` or `(−1/16)/d` on each of its 16 rows. Repeating a
tuple across all rows therefore contributes exactly `+1/d` or `−1/d`, which
cancels the matching circuit or SHA use. Two independent LogUp chains keep
the Gate and SHA claims separate. Pairing two uses per interaction batch gives
28 Gate batches and 48 SHA batches, represented by `76 × 4 = 304` M31
interaction columns. The component imposes 76 LogUp recurrence equations in
addition to the 264 caller equations, for **340 constraints** in all. The
largest expression has degree three, from a running sum times two affine
tuple denominators.

The security dependency is exact: a relying party must pin the 56 distinct
Gate addresses, call IDs, component shape, source and AIR identities, and
preprocessed root before commitments. The circuit AIR must prove one
producer for each Gate value; the packed SHA AIR and its bitwise/range tables
must prove that every joined wire byte is a byte and that each compression is
correct. The common verifier must enforce **both** Gate and SHA lookup
closures and verify all AIR constraints and FRI openings. The prover rejects
a zero lookup denominator; soundness at verification uses the usual
Fiat–Shamir random-challenge bound against denominator zeros and compressed
tuple collisions. The caller equations or a host SHA computation alone do not
establish the hash.

For the current Bitcoin PoW profile, the public statement is exactly eight
M31 words: the Poseidon leaf commitment to the 32-byte SHA256d digest. The
native verifier rejects any other output count. Its verification key is
derived from the value-free compiled topology **before proving**, including
the 56 Gate addresses and the root of the canonical fixed circuit, SHA, and
table columns. The verifier also hashes and parses the pinned official circuit
AIR bundle and checks the sparse-wide fixed-column layout against the sealed
profile. A proof's own metadata is never authority for that key.

The one-header roster includes the `bitwise` and `range_check_8_8` tables.
Its four fixed SHA AIR builders emit no `range_check_8_8_4` or
`range_check_20` requests: source rows range-check each input byte pair;
arithmetic `word()` range-checks produced byte pairs; bitwise operations
request the bitwise table. Relation domains are fixed when each AIR definition
is built and checked against its semantic digest, so a private header cannot
select a different lookup table. The full RISC-V SHA memory-caller profile
still retains the larger table roster it needs.

## One-proof construction and admission

The joined profile uses one Fiat–Shamir transcript, one base/main commitment
sequence, one interaction commitment, and one PCS/FRI proof for:

1. The S31 circuit AIR, with one additional authenticated Gate producer use
   at each of the 56 fixed private limb addresses.
2. A committed caller AIR evaluating the 264 equations above and consuming
   the corresponding Gate tuples. It emits the 24 input and consumes the
   eight output SHA tuples for each compression call.
3. SHA source, schedule, round, and feed-forward AIRs, plus their bitwise and
   range lookup tables. Their signed `recursion_wire` sums must cancel the
   caller's sums. Every table relation must also close.

The verifier reconstructs fixed call IDs, wire IDs, component order,
semantic digests, row logs, table identities, challenge order, and the
fixed Gate addresses from a sealed key **before the first witness
commitment**. It checks the Gate sum separately from the aggregate SHA-wire
and table sum. The table relations have independent transcript challenges,
so a nonzero relation imbalance can cancel another only with the usual
random-challenge failure probability. The existing `direct_arithmetic`
private bridge proves this pattern for eight
repeated-step endpoints in one proof, but it is fixed to that chip and its
direct-M31 circuit profile. The SHA caller has 56 Gate limbs and 96 word
tuples in a separate sparse-wide profile. Bitcoin fold adoption still needs
the dedicated SHA path wired into that fold's proof API. RISC-V SHA uses
per-relation challenge elements, whereas the S31 circuit uses one Gate
challenge pair; the joined proof authenticates their complete draw schedule.

No prover-side equality check, matching host SHA computation, separate SHA
proof, or public-boundary row substitutes for those commitments and lookup
closures.

## Matched local cost

The [machine-readable measurement](measurements/bitcoin-sha-joint-v1-2026-10-07.json)
uses the genesis 80-byte private header, the same normalized PoW program,
assignment, and eight-word public Poseidon root in both paths. Both use
26-bit FRI proof of work, blowup log 1, 70 queries, and fold step 1. The
generic run uses `sparse-wide-gate`; the joined run uses the circuit, three
packed SHA compression calls, committed caller, and two live lookup tables
in **one** STARK proof. Both native verifiers accepted the honest proof and
rejected a changed public root. The joined verifier's key was independently
derived from value-free topology before proving.

| Three-run local median | Generic circuit | Joined SHA chip |
| --- | ---: | ---: |
| Internal proving time | 378 ms | 2,567 ms |
| Proving time excluding FRI PoW | 154 ms, also excludes interaction PoW | 689 ms, includes interaction PoW |
| Proof bytes | 338,282 | 721,880 |

The joined profile is currently about **4.5× slower outside FRI PoW** and
its proof is about **2.13× larger**. The joined proof's final STARK stage
took 2,245 ms in the last run, of which 1,886 ms was transcript-dependent
PoW; composition evaluation took 111 ms and FRI quotient construction
took 133 ms. The chip saves generic SHA circuit operations, but the
log-18 bitwise table and its openings still impose a larger proof and
more non-PoW work. These are one-header local measurements, not a
throughput or recursive-light-client result. Generic verifier timings
were measured in separate processes; joined verifier timings were measured
in process, so the two verifier numbers are not directly comparable.
