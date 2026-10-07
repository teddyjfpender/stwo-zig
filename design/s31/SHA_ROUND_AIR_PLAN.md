# Table-free SHA-256 AIR: implementation gate

## Decision and measured reason

The current joined SHA profile proves correct byte-exact SHA256d, but its
per-operation bus and two large lookup tables cost more than the generic
circuit. In the [matched two-header record](measurements/bitcoin-sha-joint-batch2-v1-2026-10-07.json),
one shared SHA chip took 646 ms excluding FRI proof of work and 889,412 proof
bytes; the generic lowering took 323 ms excluding both proof-of-work grinds and
382,425 bytes. The shared chip is therefore an opt-in experiment. This plan
replaces its operation graph with one row per SHA round and small direct
constraints. All geometry and speed estimates below are design targets until
native proofs and matched measurements exist.

The reference semantics are [NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).
Stwo supports distinct component table heights and multiset bus consistency,
as described in the [Stwo whitepaper](https://github.com/starkware-libs/stwo/blob/dev/.agents/papers/llm/Stwo_Whitepaper.llm.md).

## Proposed components

| Component | Live rows per compression | Witness purpose |
| --- | ---: | --- |
| Schedule | 64 | Sixteen padded message words, then 48 computed words |
| Round | 65 | Initial state, 64 round transitions, terminal state |
| Feed-forward | 8 | Add final state to the incoming chaining state |
| Private caller | 80 per 80-byte header | Bind header limbs, digest limbs, padding, IVs, and chaining across three calls |

For one header, the planned padded heights are 256 schedule, 256 round, 32
feed-forward, and 128 caller rows. For two headers they are 512, 512, 64, and
256. The circuit AIR remains present and the private caller still consumes its
40 header limbs and 16 digest limbs through Gate lookups. A second word bus
connects caller, schedule, round, and feed-forward. Every bus use needs a
verifier-pinned address/call ID and a matching producer multiplicity. A local
row equation alone does not establish cross-component custody.

The first native implementation is the **round component**. Its harness
supplies the 64 schedule words and IV as verifier-fixed inputs, then proves
all 368 round constraints and verifies serialized proof bytes. This is an
isolated test profile, not a private-header proof. The joint profile must
replace those trusted inputs with authenticated schedule and caller bus events.
Its 128-row layout has seven fixed and 294 main columns. Functional local
runs used 12 FRI queries and zero proof-of-work bits; they produced roughly
39 KB proofs in roughly 22 ms of core proving time. These settings and inputs
do not match the Bitcoin benchmark, so these times cannot establish an end-to-end
speedup.

## Round relation

For each round `t`, the row contains the eight 32-bit state words
`a,b,c,d,e,f,g,h`, schedule word `W[t]`, and intermediate `T1`. Every bit of
the state and `T1` is Boolean. Boolean polynomials compute the functions
directly, with `0/1` inputs:

```text
xor3(x,y,z) = x+y+z-2(xy+xz+yz)+4xyz
Ch(e,f,g)  = ef + (1-e)g
Maj(a,b,c) = ab + ac + bc - 2abc

T1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]  (mod 2^32)
T2 = Σ0(a) + Maj(a,b,c)                    (mod 2^32)
next = (T1+T2, a, b, c, d+T1, e, f, g)  (wordwise mod 2^32)
```

`Σ0` and `Σ1` select rotated bit positions; no 32-bit rotation is a free
field operation. Split each word sum into low/high 16-bit limbs. Constrain
each limb with an explicit small carry and constrain carries to their integer
range. All input words are reconstructed from Boolean bits, so each limb sum
is far below the M31 modulus; field wrap cannot imitate an integer carry.
The fixed column pins `K[t]`, round index, first/last-row selectors and call
identity. Transition constraints copy/rotate the state into the next row, and
first/last selectors prevent a transition crossing a compression boundary.
The terminal row exposes the final state to feed-forward.

The schedule component will enforce FIPS small-sigma bit functions and
16-bit carried addition of `W[t-16]`, `σ0(W[t-15])`, `W[t-7]`, and
`σ1(W[t-2])`. Those four inputs must come from already-produced schedule
words via a call-and-index-bound bus. The first sixteen words must come from
the caller's exact 512-bit padded block. Feed-forward uses carried addition
and must connect both the incoming and terminal states to the same call.
The caller must bind the first hash's two blocks and the second hash's one
block, including bit lengths 640 and 256, the exact IV and chaining, and
digest byte order. Distinct call IDs prevent cross-header substitution.

The [direct schedule equations](../../src/frontends/s31/sha_schedule_direct_equations.zig)
are an executable first piece of that relation. Each of 64 rows has 32
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
`W[19]=0x600003c6`. Those constants are checked in the unit test. The current
equation module has field-parity and mutation tests; it is **not yet** a
native AIR proof. A joined proof must authenticate the first sixteen words
and enforce every referenced row opening.

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
constrain chaining equality and exact IV/padding constants. This is a local
equation and roster test, not yet a committed AIR or closed word bus.

The [feed-forward equations](../../src/frontends/s31/sha_feed_direct_equations.zig)
add the incoming and terminal state words in eight rows. The output has 32
Boolean bits; each 16-bit half uses one Boolean carry. The exact equation is
`initial_lo + terminal_lo = output_lo + 65536·c0`, then
`initial_hi + terminal_hi + c0 = output_hi + 65536·c1`. Local tests agree with
complete SHA compression and reject output, carry, and input mutations. A
future word bus must bind both input half-words to the round component; their
range is an assumption of this local module, not yet a proved joint fact.

The [candidate word-bus roster](../../src/frontends/s31/sha_direct_word_bus.zig)
uses the tuple `(relation_id, call_id, address, lo16, hi16)`. Within each
compression call, addresses `0..7` carry incoming state, `8..23` carry block
words, `24..31` carry output state, `1024..1087` carry schedule words, and
`2048..2055` carry terminal state. Call IDs are distinct for all three
compressions per header. The caller emits an incoming state word with weight
`+2`: both round and feed-forward consume it. Schedule consumes a block word
and emits each `W[t]`; round consumes each `W[t]` and emits terminal state;
feed-forward consumes incoming and terminal state and emits output for the
caller to consume. That gives 216 signed events per compression, or 648 per
header. Host tests close the exact multiset and reject altered word, call ID,
or multiplicity. The eventual joint proof must constrain every event in its
component AIR, derive its addresses and call IDs from verifier-fixed row
positions, and prove one challenge-derived LogUp closure. Host balance alone
does not authenticate private data.

## Cost hypothesis and acceptance gates

An early column budget was about 52 fixed, 485 main, and 76 interaction
columns for one header, compared with the measured 57/739/780 in the
existing joined profile. The caller's newly explicit Boolean byte binding
raises that main-column estimate by at least 28 to about 513, before
component integration and degree review. The current bitwise and byte-range tables alone
commit roughly 2.82 million M31 cells. Removing them is the main expected
gain. Column counts do **not** predict proof time by themselves; degree,
quotient work, FRI domains, and the circuit component still matter.

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

The round AIR is implemented and natively verified in isolation. Schedule,
feed-forward, and caller remain local equations without a joined native AIR or
word-bus proof. The two-header proof and retarget proof remain the current
experimental artifacts; the generic lowering remains the measured faster
choice for byte-exact SHA256d.
