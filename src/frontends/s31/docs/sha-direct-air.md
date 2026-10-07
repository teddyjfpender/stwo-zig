# A SHA-256 word crossing four AIRs

The direct SHA design turns one Bitcoin header's double SHA-256 into three
compression calls. Each call uses a message-schedule AIR, a round AIR, and a
feed-forward AIR. An 80-row caller AIR describes the header bytes, SHA padding,
chaining between calls, and final digest. These are separate tables of field
values in one proof. The three-call SHA-only proof passes native verification
with a public digest. The v2 joined proof adds the sparse-wide Bitcoin circuit,
keeps the SHA digest private, and closes the Gate claim in that same proof.

## One word by hand

Imagine the first four bytes of a padded message block are ASCII `abc` followed
by the SHA padding bit. They form the SHA word `W[0] = 0x61626380`.
The word is represented by two 16-bit field elements: low `0x6380` and high
`0x6162`. In the first compression call, with call ID `1`:

| Table | Role | Word-bus tuple | Weight |
| --- | --- | --- | ---: |
| Caller | Supplies block word 0 | `(SHA_WORD, 1, 8, 0x6380, 0x6162, 0)` | +1 |
| Schedule | Receives block word 0 | `(SHA_WORD, 1, 8, 0x6380, 0x6162, 0)` | −1 |
| Schedule | Supplies `W[0]` | `(SHA_WORD, 1, 1024, 0x6380, 0x6162, 0)` | +1 |
| Round | Receives `W[0]` | `(SHA_WORD, 1, 1024, 0x6380, 0x6162, 0)` | −1 |

`SHA_WORD` is the field constant `0x53333103`. The first address is
`8 + block_word_index`; the second is `1024 + schedule_index`. The address and
call ID prevent a word from being borrowed from another position or call. A
different value on one side leaves an unmatched tuple.

The incoming state word `H[0] = 0x6a09e667` has low half `0xe667` and high
half `0x6a09`. The caller supplies it with weight `+2` at address `0` because
both round and feed-forward need it. Each chip consumes it with weight `−1`.
The round's terminal word travels at address `2048`; feed-forward returns the
sum at address `24`, which the caller consumes. That is how one word is traced
from header or IV to digest without publishing the private header.

“Private” here means absent from the public statement. This proof path does
not currently provide zero-knowledge confidentiality: its unmasked trace
openings may reveal information about the header or digest.

## What each AIR equation checks

The schedule stores 32 Boolean bits for each word. A bit `b` is constrained by
`b(b−1)=0` in the M31 field. For rounds 16–63, the schedule computes the two
16-bit halves of
`W[t] = W[t−16] + σ0(W[t−15]) + W[t−7] + σ1(W[t−2]) mod 2³²`.
Its five row openings are current, `t−2`, `t−7`, `t−15`, and `t−16` from the
*same committed trace*. It constrains low and high carries to `0..3`.
For the padded `abc` block, a handwritten check gives `W[16]=0x61626380` and
`W[17]=0x000f0000`; see the [full schedule derivation](../../../../design/s31/sha/SHA_ROUND_AIR_PLAN.md).

The round AIR stores eight 32-bit state words as Boolean bits, four three-bit
carries, and the two halves of `W[t]`. It computes `T1` as an expression but
does not store its 32 bits. At round `t`, its main equations include:

```text
T1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]  mod 2^32
next.a = T1 + Σ0(a) + Maj(a,b,c)         mod 2^32
next.e = d + T1                         mod 2^32
next.b,c,d,f,g,h = a,b,c,e,f,g
```

The low and high 16-bit equations directly constrain `next.a` and `next.e`
using the same `T1` expression. This removes 32 committed columns per SHA
call. Each integer limb sum is below the M31 modulus, and Boolean state bits
range constrain the result limbs. The fixed columns pin the round constant
`K[t]` and row selectors. The first
state and `W[t]` are private main values. The round's word lookup reads those
*same* committed columns; it cannot substitute a different host-side value
for its bus event. The feed-forward AIR uses two carried 16-bit additions per
state word and Boolean output bits to prove `output = incoming + terminal mod
2³²`.

The caller AIR checks exact byte order. A header byte pair becomes a
little-endian circuit `u16`, while four serialized bytes become a big-endian
SHA word. Thirty-two Boolean bits per row bind both views. The caller's Gate
lookup reads its committed circuit limbs; its word lookup reads the committed
SHA halves. This avoids accepting a field-valued fake byte decomposition.
For the private-digest joined proof, the eight digest rows still enforce this
byte packing, but their digest selector and digest constant columns are zero.
The digest bytes live in the committed caller main trace. Its Gate events
pair them with the circuit's private digest `u16` wires; its word events pair
them with the third SHA compression output. The circuit computes the public
Poseidon root from those same private wires. A native verifier derives the
canonical fixed root from the source topology and the zero-digest statement.

## Why the lookup sum matters

After all main columns are committed, the transcript draws independent Gate
and word lookup challenges. Each event contributes its signed weight divided
by a challenge-compressed tuple. Matching `+1` and `−1` events cancel. The
verifier must check these global equalities:

```text
circuit Gate claim + caller Gate claim = 0
caller word claim + Σ(schedule, round, feed word claims for calls 1..3) = 0
```

The second sum has ten claims. The joined prover checks it before the
interaction commitment, and its native verifier checks it again. The local
AIRs alone establish that each table follows its own equations. The two zero
sums establish that the tables agree on the *same* private values. A canonical fixed-column commitment pins
role selectors, addresses, call IDs, multiplicities, SHA constants, and row
indices. Header-derived words stay in main columns.

Stwo interpolates each committed column as a low-degree circle-domain
polynomial. It checks the AIR equations through quotient evaluations and
sampled openings, and checks the lookup recurrence through interaction
polynomials. In the joined v2 profile, the verifier sees commitments, claims,
and the public Poseidon root; it does not read the private header or SHA
digest. See [AIR and polynomials](air.md) for a
small complete trace and the quotient calculation.

## Current evidence and limit

The schedule, round, feed-forward, and caller AIRs, plus their word or Gate
LogUps, pass isolated proof tests. The SHA-only join proves all three calls in
one serialized proof and closes the ten word claims. The v2 one-header circuit
join proves those SHA chips and the sparse-wide Bitcoin circuit in one STARK;
its native verifier checks both global lookup sums. The proof publishes the
same eight-element Poseidon root as the S31 Bitcoin source and no SHA digest.
The [v1 measurement](../../../../design/s31/measurements/sha/bitcoin-sha-direct-circuit-v1-2026-10-07.json)
used a public digest and is retained as a historical reference. The
[v2 measurement](../../../../design/s31/measurements/sha/bitcoin-sha-direct-circuit-v2-private-digest-2026-10-07.json)
records the matched public-output ABI and the 32-column-per-call round-width
reduction. In two local runs under production FRI settings, proving took
429–454 ms excluding FRI proof-of-work, native verification took 149–152 ms,
and the proof was 731,280 bytes. The generic circuit reference took a 153.626 ms
median excluding both grinds and produced a 338,282-byte proof. The direct
result therefore still needs significant cost work; its reported non-FRI-PoW
time includes the smaller interaction grind. A soundness review and further
performance work remain.
