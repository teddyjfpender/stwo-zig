# Bitcoin fold: proof-bound median time past

The genesis-anchored fold now carries the last eleven header timestamps in
its recursive state. The array is newest first. Its public statement has
eight BLAKE2s digest words, and that digest commits to the array together
with the fold AIR root, full step number, checkpoint root, and current block
hash root. The timestamps themselves appear in the statement JSON so a
native verifier can recompute the exact eight public words.

## The consensus rule

Bitcoin Core gathers up to eleven ancestors of the preceding block, sorts
their `nTime` values, and selects index `floor(count / 2)`. It rejects a new
header when `new.nTime <= median` ([`GetMedianTimePast`, pinned Bitcoin Core
source](https://github.com/bitcoin/bitcoin/blob/aef8a04966d7ab6c04edc5d19b733e78205405de/src/chain.h#L1459-L1479),
[`ContextualCheckBlockHeader` rejection](https://github.com/bitcoin/bitcoin/blob/aef8a04966d7ab6c04edc5d19b733e78205405de/src/validation.cpp#L4100-L4101)).
The first post-genesis block has one ancestor: the pinned mainnet genesis
timestamp `1231006505` ([Bitcoin Core chain parameters](https://github.com/bitcoin/bitcoin/blob/aef8a04966d7ab6c04edc5d19b733e78205405de/src/kernel/chainparams.cpp#L154-L159)).

For a hand example, suppose the newest three predecessor times are
`[200, 500, 100]`. Sorting gives `[100, 200, 500]`; index `floor(3/2)=1`
is `200`. A new time of `200` fails and `201` passes. With only two
predecessors `[200, 500]`, Core selects index one, or `500`. The fold does
the same rather than averaging the two values. At eleven predecessors it
selects sorted index five.

## How the circuit authenticates the window

The base proof publishes the genesis block-hash root. At fold step zero,
the circuit forces the private predecessor window to
`[1231006505, 0xffffffff, ..., 0xffffffff]`. The ten `0xffffffff` values
mark absent ancestors. At every later step, the child proof's verified
public digest must equal `S31BFD2!` over the *opened* predecessor hash root
and full predecessor timestamp array. After checking the new header, the
next array is `[header.nTime, prior[0], ..., prior[9]]`. Thus a prover cannot
invent a favorable older timestamp without changing a verified child claim
or breaking the digest binding.

The digest preimage is 144 bytes: 32 bytes of fold AIR root, four bytes of
little-endian step, 32 bytes of canonical M31 checkpoint root, 32 bytes of
canonical M31 current hash root, then eleven little-endian `u32` times.
The eight digest words are the only STARK public output. The key and
statement schemas were bumped to v3 and v2 respectively, so older proofs
cannot be interpreted under this timestamp policy.

## Integer constraints

Each timestamp is split into two range-checked `u16` limbs. A strict
comparison subtracts low and high limbs with Boolean borrows. For one limb,

```text
a + 65536 * borrow_out = b + borrow_in + digit
0 <= digit < 65536; borrow_out in {0,1}
```

Because the equation is below the M31 modulus, it is the intended integer
subtraction, not a wrapped field relation. The final borrow equals the
predicate `a < b`. A fixed insertion sorting network applies 55 comparisons
and Boolean-controlled swaps to the eleven predecessor words. Step-bound
selectors choose sorted index `floor(min(step + 1, 11) / 2)`: for step 0
index zero, step 1 index one, and from step 10 onward index five. The
selectors compare against the constrained packed `u32` counter, so choosing
an incorrect early-height count makes the circuit unsatisfied. A final
strict comparison constrains `median < header.nTime`.

The source-level test covers one, two, three, ten, and eleven ancestors,
the saturated window, and a high counter. For each case it accepts
`median + 1` and rejects both equality and `median - 1`. The native
genesis-to-block-two proof test also checks public timestamp-window
tampering after the proof is generated.

## Scope

The key still restricts the fold to the first difficulty epoch through
height 2015, and the circuit enforces `nBits = 0x1d00ffff` on each header.
The first retarget, checked chainwork and best-chain selection, contextual
future-time policy, and transaction validity remain outside this statement.
The current Poseidon2 root and recursive proof system also need independent
cryptographic review and a concrete depth bound before light-client use.
