# Table-free SHA-256 AIR: implementation gate

## Decision and measured reason

The current joined SHA profile proves correct byte-exact SHA256d, but its
per-operation bus and two large lookup tables cost more than the generic
circuit. In the [matched two-header record](measurements/bitcoin-sha-joint-batch2-v1-2026-10-07.json),
one shared SHA chip took 646 ms excluding FRI proof of work and 889,412 proof
bytes; the generic lowering took 323 ms excluding both proof-of-work grinds and
382,425 bytes. The shared chip is therefore an opt-in experiment. This plan
replaces its operation graph with one row per SHA round and small direct
constraints. Local AIRs and their lookup arguments now have native proof
tests. A digest-public private-header SHA-only join passes native verification.
The direct SHA chips and sparse-wide Bitcoin circuit also pass a one-header,
one-STARK native proof test, closing both Gate and word-bus claims. A
production-config speed measurement is recorded below.

The reference semantics are [NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).
Stwo supports distinct component table heights and multiset bus consistency,
as described in the [Stwo whitepaper](https://github.com/starkware-libs/stwo/blob/dev/.agents/papers/llm/Stwo_Whitepaper.llm.md).

## Implemented components and pending join

| Component | Live rows per compression | Witness purpose |
| --- | ---: | --- |
| Schedule | 64 | Sixteen padded message words, then 48 computed words |
| Round | 65 | Initial state, 64 round transitions, terminal state |
| Feed-forward | 8 | Add final state to the incoming chaining state |
| Private caller | 80 per 80-byte header | Bind header limbs, digest limbs, padding, IVs, and chaining across three calls |

The current one-header SHA-only layout has three calls, each with 128 padded
schedule rows, 128 padded round rows, and eight feed-forward rows; the caller
has 128 padded rows. The circuit AIR remains present and the private caller consumes its
40 header limbs and 16 digest limbs through Gate lookups. A second word bus
connects caller, schedule, round, and feed-forward. Every bus use needs a
verifier-pinned address/call ID and a matching producer multiplicity. A local
row equation alone does not establish cross-component custody.

The round component has eight fixed, 270 main, and 36 word-lookup interaction
columns, with 340 round constraints and nine LogUp constraints. The schedule
component has five fixed and 36 main columns; feed-forward has seven fixed
and 40 main; caller has eight fixed and 38 main. Each has a native serialized
proof test. Public modes pin local inputs in fixed columns. Private modes use
canonical fixed columns without header-derived words, while boundary values
sit in committed main columns. Those private boundary values gain authority
only after all word claims close in one proof. The isolated tests use 12 FRI
queries and zero proof-of-work bits; they are not a Bitcoin speed comparison.

## Round relation

For each round `t`, the row contains the eight 32-bit state words
`a,b,c,d,e,f,g,h` and schedule word `W[t]`. Every bit of the state is Boolean.
Boolean polynomials compute the functions
directly, with `0/1` inputs:

```text
xor3(x,y,z) = x+y+z-2(xy+xz+yz)+4xyz
Ch(e,f,g)  = ef + (1-e)g
Maj(a,b,c) = ab + ac + bc - 2abc

A = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]  (mod 2^32)
next.a = A + Σ0(a) + Maj(a,b,c)         (mod 2^32)
next.e = d + A                          (mod 2^32)
next.b,c,d,f,g,h = a,b,c,e,f,g
```

`Σ0` and `Σ1` select rotated bit positions; no 32-bit rotation is a free
field operation. `A` is not stored in the trace. Instead the AIR expands its
five addends into both `next.a` and `next.e` limb equations, saving 32 Boolean
columns. Split each output sum into low/high 16-bit limbs, with one three-bit
Boolean carry per limb. The largest side has seven 16-bit addends plus a
carry, below `2^19` and far below the M31 modulus. State words are Boolean
reconstructions; `W` is range-constrained by the schedule chip through the
closed word lookup, and `K` is verifier-fixed. Field wrap cannot imitate an
integer carry in the joined proof.
Fixed columns pin `K[t]`, round index, and first/last-row selectors. The
private schedule word sits in the main trace. The caller-bus configuration
pins call identity. Transition constraints copy/rotate the state into the next row, and
first/last selectors prevent a transition crossing a compression boundary.
The terminal row exposes the final state to feed-forward.

The schedule component enforces FIPS small-sigma bit functions and
16-bit carried addition of `W[t-16]`, `σ0(W[t-15])`, `W[t-7]`, and
`σ1(W[t-2])`. Those four inputs are opened from earlier rows of the same
schedule trace. The first sixteen words must come from
the caller's exact 512-bit padded block. Feed-forward uses carried addition
and must connect both the incoming and terminal states to the same call.
The caller must bind the first hash's two blocks and the second hash's one
block, including bit lengths 640 and 256, the exact IV and chaining, and
digest byte order. Distinct call IDs prevent cross-header substitution.

The [direct schedule AIR](../../src/frontends/s31/sha_schedule_direct_air.zig)
constrains that relation. Each of 64 active rows has 32
Boolean word bits and two 2-bit carries. For `t >= 16`, the two limb equations
are, with `L` and `H` denoting 16-bit halves:

```text
L(x0)+L(x1)+L(x2)+L(x3)           = L(W[t]) + 65536*c0
H(x0)+H(x1)+H(x2)+H(x3)+c0        = H(W[t]) + 65536*c1
(x0,x1,x2,x3) = (W[t-16], σ0(W[t-15]), W[t-7], σ1(W[t-2]))
```

Here `c0,c1` are each constrained to `0..3`. The largest side before the
equality is `4×65535+3 = 262143`, below the M31 modulus, so these field
equations implement integer addition. The small-sigma bits are XOR
polynomials on already-Boolean word bits. For the padded one-block `abc`
message, `W[0]=0x61626380` and `W[15]=24`; hand substitution gives
`W[16]=0x61626380`, `W[17]=0x000f0000`, `W[18]=0x7da86405`, and
`W[19]=0x600003c6`. Those constants are checked in the unit test. The AIR
opens its four predecessors directly from committed trace columns and has
native proof tests in public and private fixed-column modes. A joined proof
must authenticate the first sixteen words against the caller.

The [streamed caller equations](../../src/frontends/s31/sha_caller_stream_equations.zig)
are another executable piece. Eighty fixed-role rows cover exactly 20 header
words, eight final digest words, sixteen chaining pairs, and 36 IV or padding
constants. Together they emit all 56 Gate uses and all 96 SHA boundary word
uses for three compression calls. A header/digest row contains two circuit
`u16` limbs, the low/high halves of its SHA word, and 32 Boolean bits of the
serialized four bytes. The bits constrain both the little-endian circuit
limbs and the byte-reversed SHA word. This extra bit decomposition is
necessary: linear byte-swap equations alone admit field-valued byte witnesses
that connect an arbitrary Gate limb to a different 16-bit SHA word. The unit
test constructs such an alias with all packing equations satisfied and shows
that only Boolean bit constraints reject it. The remaining caller rows
constrain chaining equality and exact IV/padding constants. The
[caller AIR](../../src/frontends/s31/sha_caller_stream_air.zig) and
[caller bus](../../src/frontends/s31/sha_caller_stream_bus.zig) natively prove
the local equations and Gate/word LogUps over the same committed main trace.
The two claims remain open until the circuit and SHA chips close them in one
proof.

The [feed-forward AIR](../../src/frontends/s31/sha_feed_direct_air.zig)
add the incoming and terminal state words in eight rows. The output has 32
Boolean bits; each 16-bit half uses one Boolean carry. The exact equation is
`initial_lo + terminal_lo = output_lo + 65536·c0`, then
`initial_hi + terminal_hi + c0 = output_hi + 65536·c1`. Local tests agree with
complete SHA compression and reject output, carry, and input mutations. Its
three-slot word LogUp natively proves events from the committed main trace.
The global closure must bind both inputs to caller and round; their range is
a global fact, not established by this local AIR alone.

The [word-bus roster](../../src/frontends/s31/sha_direct_word_bus.zig)
uses the six-field tuple `(relation_id, call_id, address, lo16, hi16, 0)`. Within each
compression call, addresses `0..7` carry incoming state, `8..23` carry block
words, `24..31` carry output state, `1024..1087` carry schedule words, and
`2048..2055` carry terminal state. Call IDs are distinct for all three
compressions per header. The caller emits an incoming state word with weight
`+2`: both round and feed-forward consume it. Schedule consumes a block word
and emits each `W[t]`; round consumes each `W[t]` and emits terminal state;
feed-forward consumes incoming and terminal state and emits output for the
caller to consume. That gives 216 signed events per compression, or 648 per
header. Host tests close the exact multiset and reject altered word, call ID,
or multiplicity. The local AIR components now constrain every event from
their committed rows. The joined proof derives addresses and call IDs from
verifier-fixed positions, enforces all ten word claims sum to zero, and closes
the separate Gate claim with the circuit. Host balance and local proofs by
themselves do not authenticate private data across components.

## Cost hypothesis and acceptance gates

The implemented one-header SHA-only layout totals 79 fixed, 1076 main, and
184 interaction columns: one caller plus three schedule/round/feed groups.
The earlier 52/485/76 estimate was too low because the round AIR stores
Boolean state bits. The existing joined profile measured 57/739/780 columns
including circuit and table components, so raw widths alone are not
comparable. The direct AIR removes large bitwise and byte-range tables but
increases Boolean main width. Degree, quotient work, FRI domains, and the
circuit component determine whether this is faster.

1. Prove and natively verify the isolated round AIR against independent SHA
   vectors. Mutate `K`, `W`, IV, state transition, terminal state, each Boolean
   function, and carried sums. Check all row selectors and padding rows.
2. Add the schedule and feed-forward AIRs; compare their words with an
   independent SHA-256 implementation over random and boundary messages.
3. Add the streamed private caller and both Gate/word lookup closures. Derive
   the verifier key from value-free source topology, fixed AIR identities,
   component roster, PCS configuration, and public-output ABI. Never accept
   proof-supplied key parameters.
4. Prove the exact one-header and two-header S31 relations. Check altered
   public roots, addresses, message bytes, padding, call IDs, digests, and
   proof bytes. Audit field bounds, masking degree and multiset collision
   probability before sealing a package.
5. Retain the same FRI configuration and benchmark the same witness/source as
   the generic lowering. One-header adoption requires beating **154 ms
   excluding proof of work and 338,282 proof bytes** in the recorded matched
   local baseline. Two-header adoption requires beating **323 ms and 382,425
   bytes**. Publish repeated stage times and proof sizes even if the design
   fails this gate.

All four direct AIRs and their local LogUps are implemented and natively
verified. The three-call SHA-only join closes all ten word claims in one
serialized native proof. One q2 ReleaseSafe functional run after removing the
`T1` bit columns took 138 ms proving, 77 ms verifying, and 141,016 bytes with
zero proof-of-work bits and 12 FRI queries. The circuit-plus-SHA join closes
the Gate claim and ten word claims in one serialized STARK proof. Its v2
statement publishes only the Poseidon root, matching the existing S31 Bitcoin
source ABI; the digest stays private in the caller and circuit, joined by the
Gate lookup. Two ReleaseSafe production-config v2 runs took 429–454 ms
proving excluding FRI proof-of-work, 149–152 ms verifying, and 731,280 proof
bytes, with 93 fixed, 1097 main, and 212 interaction columns. The
[measurement record](measurements/bitcoin-sha-direct-circuit-v2-private-digest-2026-10-07.json)
includes total time, stage times, and the production FRI configuration.
The comparable generic reference measured 154 ms excluding both proof-of-work
grinds and 338,282 bytes; those runs used a different command path and the
direct timing still includes its smaller interaction grind. The direct AIR is
currently slower and larger. A soundness review and substantial width and
prover-cost reduction remain acceptance gates. The proposed
[shift-register round layout](SHA_SHIFT_REGISTER_AIR.md) targets the largest
remaining committed trace cost.
