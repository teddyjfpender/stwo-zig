# 5. Hashes and Merkle paths

S31 currently offers two different hash families. `Digest<Poseidon2>` is eight
canonical M31 words produced by the pinned field permutation. A
`Digest<Blake2sReduced>` is eight M31 words obtained by reducing each word of
a BLAKE2s-256 digest. These families have different roots, constraints, and
security assumptions; the text type checker will not pair them.

| Text call | Normalized node | Inputs | Result |
| --- | --- | --- | --- |
| `poseidon2_leaf(x)` | `hash_poseidon2_leaf` | 4, 8, 12, or 16 M31 words | Eight M31 words. |
| `poseidon2_pair(a,b)` | `hash_poseidon2_pair` | Ordered pair of eight-word digests | Eight M31 words. |
| `blake2s_leaf(x)` | `hash_blake2s_leaf` | 4, 8, 12, or 16 M31 words | Eight reduced M31 words. |
| `blake2s_pair(a,b)` | `hash_blake2s_pair` | Ordered pair of eight-word digests | Eight reduced M31 words. |

The normalized-only `hash_blake2s` hashes 4/8/12/16 words with zero
personalization. Leaf and pair personalization are distinct. All input words
must be canonical (`0 <= word < p`, `p=2147483647`).

## Check hash values without building a proof

`s31 oracle` evaluates every current hash relation node as a separate Python
value check. For BLAKE2s raw, leaf, and pair nodes, it serializes the M31
words as four little-endian bytes each, calls Python's standard-library
`hashlib.blake2s` with the framing below, then reduces each digest word
modulo $p$. For Poseidon2 leaf and pair nodes, it uses a separate Python
field-arithmetic implementation in [`poseidon2_oracle.py`](../python/poseidon2_oracle.py).
That implementation reads the pinned round constants from this repository;
it does not call the Zig circuit evaluator. Both paths compare their
computed digest with the claimed public output.

```sh
python3 src/frontends/s31/python/s31.py oracle src/frontends/s31/examples/hashes/hash4.s31.json src/frontends/s31/examples/hashes/hash4.valid.json
python3 src/frontends/s31/python/s31.py oracle src/frontends/s31/examples/hashes/merkle_path1_poseidon.s31 src/frontends/s31/examples/hashes/merkle_path1_poseidon.valid.json
```

Both checked-in assignments report `status: passed`. The Merkle example
computes the eight-word root printed below. A changed claimed root fails
this value check. `s31 trial` includes the same check in its
`independent_value_oracle` report field alongside the native proof result.
The value check helps catch a mismatch between the stated relation and
an assignment; it does not prove that Zig compiled that relation correctly
or that the STARK verifier is sound. For a `.s31` text source, the common
text frontend still produces the normalized relation first. Unknown future
operations fail explicitly instead of being reported as checked.

## Poseidon2-M31, completely specified for this frontend

The permutation works on 16 M31 words. Its full pinned constants are included
in [poseidon2-constants.json](poseidon2-constants.json), so the round function
below can be implemented without fetching another file. The JSON has eight
arrays of 16 external-round constants, 14 internal-round constants, and a
16-word internal diagonal. Its `source_sha256` identifies the exact constants
file used by the compiler.

All arithmetic below is modulo `p`. Define `M4(a,b,c,d)` by:

```text
t0 = a+b       t1 = c+d
t2 = 2b+t1     t3 = 2d+t0
t4 = 4t1+t3    t5 = 4t0+t2
M4(a,b,c,d) = (t3+t5, t5, t2+t4, t4)
```

The external layer applies `M4` independently to each consecutive four-word
block. Call the intermediate words `u[0..16]`. For each lane `j=0..3`, let
`sum[j] = u[j]+u[4+j]+u[8+j]+u[12+j]`. The final external-layer word at
`4b+j` is `u[4b+j]+sum[j]` for block `b=0..3`.

The permutation is:

```text
state = external_layer(state)
for each of external_round[0..4]:
    state[i] = (state[i] + round[i])^5, all i=0..15
    state = external_layer(state)
for each of internal_round[0..14]:
    state[0] = (state[0] + round)^5
    total = sum(state[0..16])
    state[i] = internal_matrix[i] * state[i] + total, all i=0..15
for each of external_round[4..8]:
    state[i] = (state[i] + round[i])^5, all i=0..15
    state = external_layer(state)
```

The slice ends above are exclusive: four full rounds, fourteen partial
rounds, then four full rounds. An `x^5` S-box becomes `x²`, `x⁴`, `x⁵`: three
multiplication gates. This is currently a **generic arithmetic circuit**,
not a dedicated Poseidon AIR chip.

A **leaf** starts with 16 zeros and sets `state[15]=1`. It adds input words
into rate positions `state[0]..state[7]`, permuting immediately after every
eight words. It then adds an end-marker `1` at the next rate position and
permutes if any words are pending. The digest is `state[0]..state[7]`.
Thus an eight-word leaf performs two permutations: one after the eight words
and one after the marker. A **parent** starts from `left[0..8] ||
right[0..8]`, performs one permutation, and returns the first eight words.
Child order matters.

For an independent check, a leaf of `[1,2,3,4,5,6,7,8]` is:

```text
[1028419626, 840344419, 441147974, 1658139767,
 1562726555, 572367908, 1125001664, 1414944824]
```

## BLAKE2s-256 and the reduced digest

S31 serializes each input M31 word as **four little-endian bytes**, concatenated
in source order. A leaf uses the eight-byte BLAKE2s personalization
`S31LEAF1`; a parent uses `S31PAIR1` and serializes the left eight words
before the right eight. The normalized-only raw node uses eight zero bytes.
These messages are 16, 32, 48, or 64 bytes, so the current operations use a
single 64-byte compression block with zero padding. The BLAKE2s digest length
is 32 bytes, with no key and no salt.

For completeness, the one-block BLAKE2s computation used here has IV words:

```text
6A09E667 BB67AE85 3C6EF372 A54FF53A
510E527F 9B05688C 1F83D9AB 5BE0CD19
```

Initialize `h=IV`; XOR `0x01010020` into `h[0]`, and XOR the first and
second little-endian `u32` words of the eight personalization bytes into
`h[6]` and `h[7]`. Set `v[0..8]=h`, `v[8..16]=IV`, XOR the message byte length
into `v[12]`, and XOR `0xffffffff` into `v[14]` for the final block.
Interpret the padded message as 16 little-endian `u32` words `m[0..16]`.
All additions in the compression function are modulo `2^32`.

The mixing operation `G(a,b,c,d,x,y)` updates four `u32` state words:

```text
a = a+b+x;  d = rotr32(d xor a,16)
c = c+d;    b = rotr32(b xor c,12)
a = a+b+y;  d = rotr32(d xor a, 8)
c = c+d;    b = rotr32(b xor c, 7)
```

Each of ten rounds applies `G` to state index quadruples
`(0,4,8,12)`, `(1,5,9,13)`, `(2,6,10,14)`, `(3,7,11,15)`, then
`(0,5,10,15)`, `(1,6,11,12)`, `(2,7,8,13)`, `(3,4,9,14)`.
The two message words for `G` number `g` are
`m[sigma[round][2g]]` and `m[sigma[round][2g+1]]`. The ten `sigma` rows are:

```text
 0:  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
 1: 14 10  4  8  9 15 13  6  1 12  0  2 11  7  5  3
 2: 11  8 12  0  5  2 15 13 10 14  3  6  7  1  9  4
 3:  7  9  3  1 13 12 11 14  2  6  5 10  4  0 15  8
 4:  9  0  5  7  2  4 10 15 14  1 11 12  6  8  3 13
 5:  2 12  6 10  0 11  8  3  4 13  7  5 15 14  1  9
 6: 12  5  1 15 14 13  4 10  0  7  6  3  9  2  8 11
 7: 13 11  7 14 12  1  3  9  5  0 15  4  8  6  2 10
 8:  6 15 14  9 11  3  0  8 12  2 13  7  1  4 10  5
 9: 10  2  8  4  7  6  1  5 15 11  9 14  3 12 13  0
```

After round ten, output words are `h[i] xor v[i] xor v[i+8]`. Read the
32 output bytes as eight little-endian `u32` words and reduce **each word
separately modulo `p`**. These eight M31 values are S31's reduced digest.
They are not the original 256 digest bits, and the reduction is many-to-one.
The circuit constrains this computation with M31-to-`u32`, Blake-G, XOR,
range, and arithmetic components, so BLAKE2s sources currently use the full
`gate` profile.

## A one-level Merkle opening, by hand

```s31
circuit merkle_path1_poseidon(
    private leaf: [m31; 8],
    private sibling: Digest<Poseidon2>,
    private direction: bit
) -> public Digest<Poseidon2> {
    let digest = poseidon2_leaf(leaf);
    let left  = select(direction, digest, sibling);
    let right = select(direction, sibling, digest);
    poseidon2_pair(left, right)
}
```

The implemented [example](../examples/hashes/merkle_path1_poseidon.s31) uses a
small `parent` helper but has the same graph. Direction zero places the
leaf on the left; direction one places it on the right:

```text
direction=0:  leaf ──▶ [left ] ─┐
              sibling ─▶ [right] ─┴─▶ pair ─▶ public root
direction=1:  sibling ─▶ [left ] ─┐
              leaf ─────▶ [right] ─┴─▶ pair ─▶ public root
```

For each digest word, a select proves
`selected=(1-direction)*a+direction*b`; the bit is constrained by
`direction²-direction=0`. Two selects precede the pair hash. The
[private-choice walkthrough](worked-choice.md) fills the selector wires
with small numbers and shows why the Boolean equation rules out a third
answer. For `leaf=[1..8]`, `sibling=[100,200,...,800]`, and
`direction=1`, the
public root is:

```text
[1670055224, 23919780, 1989297705, 2052259550,
 1137029259, 319747347, 1744170436, 1858156544]
```

Changing `direction` to zero gives a different root. A path helper repeats
the two-select/one-pair pattern for a statically known depth of 1..16.
Poseidon2 and BLAKE2s path roots cannot be interchanged.

Next: [what the proof package and verifier bind](proofs.md).
