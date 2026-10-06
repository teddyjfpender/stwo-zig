# Recursing over the sparse-wide proof profile

This chapter follows a `sparse-wide-gate` proof through two real wrapper
proofs. It uses [`wide_order.s31`](../examples/wide_order.s31), a small
256-bit arithmetic program. The same proof profile is used by the Bitcoin
header examples. This is a proof of **one program execution** and then a
proof that its STARK verifier accepted it. A recursive Bitcoin header-chain
transition still needs a constrained header-state update and a repeatable
fold key.

## The computation before recursion

The source converts two 32-byte values to little-endian `UInt256`, asserts
that `digest + increment = target`, checks `digest <= target`, and publishes
an eight-word Poseidon2 commitment. The private bytes are never part of the
public statement. For each of the sixteen `u16` limbs, the addition circuit
enforces the integer equation

```text
digest[i] + increment[i] + carry[i]
    = target[i] + 65536 * carry[i+1]
```

with constrained bits for the carries. The comparison similarly uses a
borrow bit per limb. The output commitment and the final two assertions are
also circuit constraints. See the [hand-filled limb table](wide-values.md)
for concrete values and the resulting gate rows.

The child prover turns those circuit gates into four AIR components, in this
exact order:

| Component | What its trace helps establish |
| --- | --- |
| `eq` | Asserted equalities, including the final 256-bit checks. |
| `qm31_ops` | Field additions, subtractions, products, and packed word operations. |
| `m_31_to_u_32` | Range and word conversion witnesses. |
| `range_check_16` | The fixed 16-bit range table used by the conversions. |

The first three row counts come from the sealed preprocessed layout; the
range table has log size 16. The resulting child proof is `S31NAT5W`. Its
native verifier checks the lookup closure, AIR evaluations at the sampled
point, Merkle openings, FRI, and proof of work. It does not receive the
private assignment.

## What the first wrapper circuit computes

Let `K0` be the **exact bytes** of `verification-key.json`, `P0` the child
proof, and `W0` its eight public `u32` words. The wrapper circuit takes the
expanded proof openings and `W0` as witness values. It performs the STARK
verification algorithm as constraints. That includes recomputing the
Fiat–Shamir transcript, checking the four component claims, evaluating the
AIR composition polynomial, checking all sampled Merkle paths and FRI
folds, and checking both proof-of-work steps. A malicious prover can supply
different openings, but the outer AIR then fails unless those openings
satisfy the verifier circuit.

The wrapper fixes the child preprocessed root, sparse component sizes,
source digest, and circuit identity as constants from `K0`. The identity is
the sparse-wide SHA-256 hash of source digest, root, component log sizes and
blowup factor. These are **not** chosen by the child proof witness. The
profile-specific transcript starts with three separate mixing operations:

```text
mix_u64(0x5333315350573501)    // S31 sparse-wide-v5 tag
mix_u32s(LE32(SHA256(source.s31.json))[0..8])
mix_u32s([0, 0, 0])
```

Then come channel salt zero, the key's FRI configuration, preprocessed
commitment, circuit identity, `W0`, trace commitment, interaction nonce,
lookup challenges, and the remaining STARK transcript. The circuit uses the
same three separate hash updates. Combining those words into one hash would
produce different challenges and reject a valid proof.

After verifying `P0`, the circuit outputs

```text
D1 = Blake2s-256(person="S31RCV2!",
     SHA256(exact bytes of K0) || LE32(W0[0]) || ... || LE32(W0[7]))
```

This is one 64-byte Blake2s input. `SHA256(K0)` is embedded as eight fixed
`u32` constants. `W0` is constrained by the in-circuit verifier, and its
32-bit words retain all bits, including values at or above the M31 modulus.
The native verifier for the outer proof checks the sealed outer key `K1`,
the digest equation above, and the outer STARK. It needs the public
statement and the **outer** proof; it does not need `P0` or its private
assignment.

The second wrapper verifies that gate-profile outer proof inside another
circuit and outputs

```text
D2 = Blake2s-256(person="S31RCV2!", SHA256(K1) || LE32(D1[0..8]))
```

The top verifier checks a chain statement containing `W0`, `D1`, and `D2`;
it requires `head.child_public_words == leaf.outer_public_words`. A correct
top proof establishes that a valid first wrapper proof and a valid
sparse-wide child proof exist for the chained claims, under the two sealed
keys. It does not prove that the published child words have a Bitcoin
consensus meaning beyond the compiled S31 relation and its public ABI.

## Where polynomials enter

The wrapper verifier is an ordinary S31 circuit. For example, a circuit
equality gate constrains two wires `a` and `b` with `a-b=0`; a multiply gate
constrains `c-a*b=0`. The gate lists become preprocessed AIR columns. The
wrapper prover places the circuit's wire values in trace columns, interpolates
them into trace polynomials, and commits to their evaluations. Composition
checks combine the AIR equations; FRI argues that the committed evaluations
have the required low-degree structure. Thus the **outer proof** attests to
the verifier circuit's computation, including its check of the **inner
proof**. The outer native verifier checks the outer AIR; it does not just run
the inner native verifier again.

## Run the full chain

From the repository root:

```sh
python3 src/frontends/s31/s31.py build \
  src/frontends/s31/examples/wide_order.s31 \
  --lowering sparse-wide-gate --out zig-out/s31/wide-recursive
python3 src/frontends/s31/s31.py prove \
  zig-out/s31/wide-recursive \
  src/frontends/s31/examples/wide_order.valid.json \
  zig-out/s31/wide-recursive/child.proof
python3 src/frontends/s31/s31.py audit-recursive \
  zig-out/s31/wide-recursive zig-out/s31/wide-recursive/child.proof
python3 src/frontends/s31/s31.py wrap \
  zig-out/s31/wide-recursive zig-out/s31/wide-recursive/child.proof \
  zig-out/s31/wide-recursive/first.proof --low-memory
python3 src/frontends/s31/s31.py wrap-next \
  zig-out/s31/wide-recursive zig-out/s31/wide-recursive/first.proof \
  zig-out/s31/wide-recursive/second.proof --low-memory
python3 src/frontends/s31/s31.py verify-recursive-next \
  zig-out/s31/wide-recursive zig-out/s31/wide-recursive/second.proof
```

`audit-recursive` checks the valid in-circuit witness and challenges ten
independent fields after native proof authentication, including the profile
prefix, circuit identity, public word, LogUp sum, Merkle paths, FRI witness,
and FRI last layer. `audit-recursive-next` challenges seven fields of the
second-level gate verifier. The
[acceptance fixture](../acceptance_sparse_wide_recursion.py) also changes
proof bytes, key bytes, public claims, and both chain statements.
The [cross-key fixture](../acceptance_sparse_wide_key_binding.py) rebuilds
the same arithmetic under a different source name. The preprocessed AIR
root stays the same, but the sparse-wide profile identity and wrapper AIR
roots change. Each leaf proof is rejected by the other source's native
verifier. The original outer proof is rejected under the clone's key even
after its public digest and statement roots are repaired for that key.

In [one local acceptance run](../../../../design/s31/measurements/sparse-wide-recursion-v1-2026-10-07.json),
the leaf, first wrapper, and second wrapper proofs were 238,047, 507,885,
and 554,779 bytes. The first verifier circuit had 6,972,423 raw variables.
Measured command wall times were about 1.09 s, 2.21 s, and 4.25 s for the
three proof commands. These are single local observations; package setup and
the native verification inside each command are included. The package build
took about 61 s, primarily to construct and seal two verifier topologies.

The outer keys are generated from witness-free topologies and embedded in
the installed native verifier. The value-bearing circuit must match the
sealed topology gate for gate before proving. The package manifest detects
edits to artifacts but is not a signature; obtain verifier binaries and
keys through a trusted distribution path. Current sparse-wide recursion
covers the four-component gate profile and two depth-specific wrappers.
It does not yet provide a homogeneous fold for a Bitcoin header chain, nor
does it move SHA256d from the generic circuit to a proof-bound dedicated SHA
AIR chip.

The [two-header Bitcoin acceptance run](../../../../design/s31/measurements/bitcoin-sparse-wide-recursion-v1-2026-10-07.json)
uses [`bitcoin_header_pair.s31`](../examples/bitcoin_header_pair.s31), which
constrains two byte-exact SHA256d hashes, both mainnet proof-of-work checks,
their previous-hash link, a genesis checkpoint, equal compact bits, and the
strict first-step timestamp rule. It also passed two wrappers and the same
mutation suite. Its verifier circuit had 9,733,516 raw variables; proof sizes
were 372,904, 521,838, and 560,419 bytes. The first and second wrap commands
took about 2.51 s and 4.80 s wall time in that local run. This is a fixed
two-header relation, not an indefinitely extensible Bitcoin light client.
