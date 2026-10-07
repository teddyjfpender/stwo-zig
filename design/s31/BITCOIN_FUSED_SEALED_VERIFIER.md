# Sealed verifier for one fused Bitcoin header

`S31FCF01` proves one Bitcoin mainnet header after the genesis checkpoint. Its
11 circuit components verify a generic checkpoint anchor, enforce the header
link, PoW, timestamp and chain-state transition; its 10 SHA components compute
byte-exact SHA256d. One Gate lookup joins the 40 private header limbs and 16
private digest limbs to their exact circuit producer wires. The outer proof has
one native verifier in
[`bitcoin_fused_chain_verifier.zig`](../../src/frontends/s31/bitcoin_fused_chain_verifier.zig).

## Trusted inputs and key derivation

The application pins the SHA256 of the **entire verification-key JSON**. The
verifier parses that JSON and independently rebuilds a value-free anchor and
fused fold topology. It derives the anchor root, all 56 SHA Gate addresses,
the combined fixed-column root, and the native fused key digest. It requires
the exact mainnet genesis display hash, step 0, the circuit's padded component
sizes, child FRI `(PoW 26, blowup 1, 70 queries, fold 4)`, and outer FRI
`(PoW 26, blowup 1, 70 queries, fold 1)`. The JSON also records the trusted
source, AIR bundle and projection digests so audits can identify the code and
constraints behind the commitment. Proof bytes never choose a root, Gate
address, component list or FRI policy.

```zig
const encoded_key = try fused_chain.generateKeyJson(allocator, fused_chain.genesis_display_hash);
const pinned_digest = chain.sha256(encoded_key); // Store this through a trusted channel.
const key = try fused_chain.validateKey(allocator, encoded_key, pinned_digest);
```

The wrapper re-exports the canonical genesis display hash from
`bitcoin_chain_verifier.zig`. Key generation is a deployment step and is
expensive because it constructs the full circuit and commits canonical fixed
columns. Cache the resulting verified key for repeated proof checks.

## Named Bitcoin statement

The statement schema contains `current_block_hash` in canonical lowercase
Bitcoin display order, `current_block_timestamp`, the newest-first
`last_timestamps` array, and eight raw `u32` public words. At step 0, the time
array must be `[current_block_timestamp, 1231006505, 0xffffffff, ...]`: the
last nine entries are missing-ancestor sentinels. The verifier reverses the
display hash bytes, splits the digest into 16 little-endian `u16` limbs,
computes the Poseidon leaf root, and recomputes the eight words as

```text
Blake2s-256(personalization="S31BFD2!",
  fused_fixed_root || LE32(step=0) ||
  LE32[8](genesis_checkpoint_root) || LE32[8](current_hash_root) ||
  LE32[11](last_timestamps))
```

Each result word is packed as two `u16` limbs into one QM31 public output.
`verifyProof` first checks the key-bound statement, then passes these eight
outputs and the independently derived native key to the `S31FCF01` verifier.

```zig
const statement = try fused_chain.generateStatementJson(
    allocator, key,
    "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
    1231469665,
);
try fused_chain.verifyProof(allocator, key, statement, proof_bytes);
```

Applications that do not cache `VerifiedKey` can call `verifyPinned` with the
key bytes and independently pinned SHA256 digest. The on-chain header is a
private *witness input* to the combined AIR; this proof format does not claim
zero knowledge because some trace openings are unmasked.

The example hash and timestamp are Bitcoin block 1. Changing either named
field without the matching public words is rejected before STARK decoding.
Changing the proof's public words, fixed key, or private SHA boundary is
rejected by the native verifier and Gate lookup closure.

This key authenticates **exactly one** header after genesis. A second fused
fold cannot currently use an `S31FCF01` proof as its in-circuit child: that
child verifier still implements the generic circuit proof format. The sealed
API rejects any step other than zero and does not assert full Bitcoin consensus
or a recursive light client.

Run the focused key and statement tests with:

```sh
zig build --build-file src/frontends/s31/build.zig test-bitcoin-fused-chain-verifier -Doptimize=ReleaseFast
```

The opt-in proof test reuses a production-parameter `S31FCF01` proof through
the sealed API, and rejects a changed named timestamp:

```sh
S31_FUSED_FOLD_PRODUCTION=1 zig build --build-file src/frontends/s31/build.zig test-sha-fused-fold-proof -Doptimize=ReleaseFast -j1
```
