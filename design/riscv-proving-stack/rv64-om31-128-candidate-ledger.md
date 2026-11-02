# OM31 native/local-GKR 128-target candidate: pinned policy and open proof obligations

This is a receiver-owned candidate and a conditional accountant, not a security
certificate. The native q70/P26 control and the small engineering proof profile
remain unchanged. `om 31_security_candidate.zig` adds a concrete parameter identity,
typed authority admission, pre-challenge scope binding and explicit refusal to
promote an unreviewed construction. It never changes existing proof acceptance.

## Concrete construction and cost

|Item|Candidate|Reason/limit|
|---|---|---|
|Secure challenges|OM31, eight coordinates|Every weak local/global/PCS argument must use it; wider GKR alone is insufficient.|
|Sampling|Existing tagged raw-Blake-u32 modulo M31 authority|Native/circuit same map, including rare words; coordinate max probability 3/2^32.|
|Merkle|Existing prefixed unreduced Blake2s-256|No reduced Merkle roots are assumed.|
|FRI blowup|4× (`log_blowup=2`)|Johnson-regime audit point, supports AIR degree≤5; this needs new immutable fixed keys.|
|FRI queries/fold|256 /4|Exact query calculation below; no q-only certificate.|
|Query PoW|0|No grinding is credited to earlier algebraic draws.|
|Trace/roster caps|log≤22, native proofs≤256, columns≤16384, constraints≤65536, samples/column≤8, local instances≤128, GKR variables≤30|All from admitted receiver geometry, not producer declarations.|
|Multiplicity/mass|Each individual and each±integer mass per relation/challenge group<p|Extension degree does not change characteristic.|
|RO round/work audit|rounds≤2^20, work T≤2^120|Only a declared conditional audit range; it is not a complete 128-work range certificate.|

The identity hashes all fixed caps, sampler identity and protocol version.
`admitNative` rejects a Q field, other channel/hasher, β1, q70, changed PoW,
changed identity or excessive source-derived geometry/mass. `begin` binds admitted
facts and identity before dependent draws. The current services path retains a
β1 immutable fixed tree and validates its blowup: it **cannot** use this candidate
until new β2 setup generation, retention, admission and fresh verification are
qualified. The explicit promotion gate records that as a separate blocker.

This is a security-cost anchor, not a recommended production default. Against
β1/q70, β2 doubles native committed evaluation lengths and requires separate
fixed setup; q256 increases raw query count 3.66×. Wider secure planes and their
recursive arithmetic have their own costs. Folding changes the tree geometry,
not the required number of independent queries. No speed/RSS estimate is claimed.

## Source authority and multiplicities

The raw fraction enum in `services/gkr_local/fractions.zig` has nine local
relations; the test checks this enum rather than a hand-written inventory. REG,
ROM, FUNCTION, OWNER, U16/U8, AND, SHIFT and selection remain separate debts.
CPU emits 15 fractions (including six REG terms and padded unit-range queries).
Weighted ALU/BINARY/SHIFT facts emit their committed base multiplicity; zero
weights do not authorize dropping a pole. `Inputs.RowSink` checks that N and
all tuple coordinates really lie in M31; it does not establish their ordinary
integer total mass. That latter fact needs receiver geometry plus the source
Boolean/count/canonical-writer induction, explicitly marked unreviewed here.

`services/protocol.zig:admit` enforces characteristic-related request/range/wire
mass checks. Global RAM14, KIO11 and Wire35 remain classic LogUp obligations
under a shared manifest; local GKR closure does not close them. The candidate
requires all three to use OM31 and to be included in the global argument and
final receiver before promotion. Maximum local mass is per challenge group;
independent native-proof groups are explicitly unioned by the proof count.

## Conditional numerical ledger

For each relation, use the positive and negative source-admitted integer masses.
With massM their sum, arityA andP native proofs, tuple fingerprinting is bounded
conditionally by `(9P+3) A M²` bad roots across independent groups. This is a
conservative pairwise union, not the tighter final LogUp theorem. Rational
identity and pole terms countM for each participating relation/group. These
require a nonzero rational numerator, correct signed multiplicities and no
characteristic aliasing; they are not established by a producer's numeric label.

GKR sumcheck counts three degrees per round and at mostV(V−1)/2 rounds per
instance. Instance mixing counts alpha/lambda degree envelopes, and late N/D
binding counts one eta combination per instance. The terminal checks must bind
the MLE of actual row expressions, not products of their MLE evaluations. The
physical Eq/prefix AIR, lifted circle point and suffix/lane conventions need the
specific univariate-to-multilinear theorem instantiated for this implementation.

The OODS/DEEP terms use explicit 32N×samples×columns×proofs envelopes conditional
on the appropriate circle-PCS reduction. FRI folding has an **unreviewed**
engineering envelope containing list≤16, fold≤4, domain, columns and round losses.
The enum `Basis` exposes these distinctions in code; an arithmetic pass is not
a theorem. In particular, the arbitrary 65536 FRI envelope cannot be cited as a
proven bound. It must be replaced by the instantiated theorem before promotion.

The raw modulo map has maximum point mass 3^8/2^256. Integer arithmetic tests
`degree_weight ×3^8×2^bits ≤2^256`; it never substitutes a uniform 1/p^8 claim.
The exact coordinate min-entropy is `32−log2(3)` (about30.415 bits),
and the eight-coordinate maximum point mass has min-entropy
`256−8log2(3)` (about243.320 bits), rather than approximately248 uniform-field bits.
The density relative to uniform OM31 is exactly `(3p)^8/2^256`, strictly
less than `(3/2)^8` (about25.629), a loss below4.680 bits. The integer ledger
already includes this loss; no new correction factor is missing. Tests now pin
both the243/244-bit single-root threshold and the exact128-bit union-weight
boundary, including a weight incorrectly accepted by a uniform-field model.

This is conditional distribution arithmetic, not a proof that Blake outputs are
independent. One fresh ideal-RO256 block has independent uniform raw32-bit words;
residue reduction gives the stated product bound. Across adaptive rounds, each
bad-polynomial event needs the conditional bound after earlier messages are
fixed. Apply a union over the admitted degree weights, not a claim that all
transcript outputs are jointly uniform or a density exponent for every round.

`drawU32s` hashes `digest || little_endian_counter || 0` (37 bytes); absorption
hashes the previous digest and a whole number of32-bit words (length divisible
by4), so these two encodings are distinct. The draw counter increments modulo
2^32 and resets when the digest is updated. Conditional freshness therefore
needs distinct counter inputs before wrap, and a reduction accounting for
adaptive digest states, repeated RO queries/collisions and Fiat–Shamir work.
The current source-bound report explicitly leaves
`transcript_round_bound_qualified=false`, and `adaptive_raw_mod_rom_theorem`
is not established. Counter-parity tests do not close either proof obligation.
Whole-protocol promotion remains unconditionally fail-closed, even if all
caller review flags are set true.

At the full admitted cap, the generated budget report records every term and
its conditional integer-bit bound. Tuple collisions dominate the current
conditional ledger. Neither PoW nor unreviewed repetition appears in it.

For a Johnson audit point, choose rate 1/4, theta 3/8, agreement 5/8. Then the
query-only bound is exactly `P×(5/8)^256`, checked with 1024-bit integers. At P=256
this is at most 2^-165. This remains conditional on the theorem's applicability
to the implemented multi-domain query projection and quotient reduction.

## Fiat–Shamir, hashing and the meaning of 128

The [official Stwo whitepaper summary](https://raw.githubusercontent.com/starkware-libs/stwo/dev/.agents/papers/llm/Stwo_Whitepaper.llm.md)
reports the NIROP error form `(T+R)max(eps_i)+3(T²+1)/2^lambda`, with λ256.
It also flags incomplete theorem coverage for the implemented query/quotient
variant. We have not independently filled that proof gap. Native queries in
`core/queries.zig` mask raw u32 words; the core's lifted/mixed-height implementation
must be matched to the specific theorem, rather than inferred from test success.

Our bounded arithmetic audit reserves two union bits and 21 bits for `(T+R)/T`
under the explicit round cap, requiring conditional algebraic and query errors
at most 2^-151. Both pass the cap model. For 1≤T≤2^120, the remaining collision
contribution per work is bounded by `6×2^120/2^256`; this passes the reserved
2^-130 budget. These are necessary conditional calculations, not a reviewed
adaptive-RO reduction for GKR and all dependent commitments.

AtT2^128, the literal conservative bound's collision term alone exceeds the
exact 2^-128-per-work target by a constant factor. `requireConditionalRomBudget`
therefore rejects that unreviewed range. This is not a demonstrated attack or
a demand to replace Blake; it makes the security convention explicit. A final
certificate must state its success-probability/work definition and range, obtain
a tighter applicable bound, or adopt a separately reviewed wider hash profile.
Calling the bounded 120-range audit “whole-protocol 128 complete” would be wrong.

All outer leaf/fold/root proofs remain outside this candidate's numerical
ledger. Existing Q arithmetic/reduced internal Fiat–Shamir state cannot simply
inherit OM31 native security. A whole-protocol claim needs their own wide
construction, transcript analysis and union across the full recursive topology.
Both native and actual circuit Merkle roots are raw 256-bit Blake, so reduced
internal FS state is not evidence of reduced Merkle binding.

## Explicit remaining gates

- β2 immutable setup/key authority, separate from legacy β1 suite validation.
- Complete native/global OM31 coverage and full execution receiver closure.
- Source count/weight/range/characteristic proof, including weighted facts.
- Exact GKR binding and adaptive raw-modulo transcript reductions.
- Applicable circle-FRI query layout and quotient/degree-correction theorem;
  replace engineering envelopes with its actual list/round error constants.
- Every recursive layer's field/channel, outer error and statement/topology binding.
- Reviewed classical-work definition and receiver-owned final certificate registry.

Even setting every review boolean true returns
`NoReviewedWholeProtocol 128Certificate`. There is no producer-supplied certificate
or parameter field that bypasses this boundary. The current benchmark and tiny
engineering profile still work under their existing identities.

Primary context: [LogUp](https://eprint.iacr.org/2022/1530),
[LogUp-GKR](https://eprint.iacr.org/2023/1284),
[Circle STARKs](https://eprint.iacr.org/2024/278), and the official summary above.
The ePrint PDFs returned 403 during this pass; their landing pages and official
summary were checked. This document does not claim a fresh full-paper proof audit.
