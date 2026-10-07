# Stable Bitcoin recursion with a fused SHA leaf

Status: engineering design, not an implemented recursive proof profile.
The sealed `sha-fused-v4` package proves one header natively. The existing
Bitcoin fold recursively verifies **generic circuit** proofs and computes
SHA256d with generic gates. Neither path currently verifies a fused proof
inside a circuit.

## Reuse boundary

The [in-circuit STARK verifier](../../src/frontends/circuit/stark_verifier/verify.zig)
accepts a statement duck type and a shape-driven
[`ProofConfig`](../../src/frontends/circuit/stark_verifier/proof.zig). Its Merkle,
OODS and FRI checks can handle a different component count and fold schedule
when the AIR uses the wire format's one OODS opening per trace column.
The [proof conversion](../../src/integrations/circuit_cpu/verifier_proof.zig)
accepts verified captures for that format. Fused SHA uses shifted openings
at five points for some trace columns, so its capture cannot yet be converted
without extending the wire format and OODS replay. The
[joined transport inventory](JOINED_SHA_RECURSION_TRANSPORT.md) records the
exact mismatch. These are useful transport and cryptographic subroutines,
not an in-circuit verifier for fused v4.

The current [generic statement](../../src/frontends/circuit/statements/circuit_statement.zig)
has exactly 11 circuit evaluators. The [sparse-wide statement](../../src/frontends/circuit/statements/sparse_wide_statement.zig)
has four. Fused v4 has 14 components and a different transcript: its key
profile and canonical fixed root, identity root, eight canonical-M31 public
outputs, 20-bit interaction nonce, **two** challenge pairs (Gate and SHA
word), ten claimed sums, then production FRI26/70/fold1. The generic verifier
currently mixes public claims as `u32` words and gives one lookup pair to all
components. The fused caller bus can use both pairs in the same component.
The ten SHA-side AIR evaluators also exist as native code, not in the circuit
evaluator table. Changing the component shapes alone would prove neither the
SHA equations nor the word-bus closure.

The first safe reusable primitive is now
[`addToRelationWithElements`](../../src/frontends/circuit/stark_verifier/constraint_eval.zig):
one LogUp accumulator can append a term under an explicitly chosen challenge
pair while retaining the old common-pair API. The SHA AIR evaluators and the
joined statement remain to be implemented and proved equivalent to the native
v4 verifier.

The in-circuit channel now also has native-parity `mixU64`, `mixFelts`,
`mixChannelSalt`, and `drawLookupElements` operations. A regression test
compares a profile tag, reduced salt, field claims, and two consecutive lookup
draws against the native Blake2sM31 channel. The generic verifier accepts
optional statement hooks for the profile prelude, public claims, challenge
draws, and interaction-claim mixing. These hooks preserve existing generic
statements, but a fused statement must still implement them and translate
every SHA component equation before a recursive fused proof can be accepted.

## Chosen stable topology: a generic outer fold with two child proofs

Use a *generic circuit* proof as the top fold at every height. At each step
its circuit verifies two private child proofs:

1. The prior **generic** chain proof, or the generic genesis anchor when
   `step = 0`. The current child verifier and base selector can be reused.
2. One **fused** proof of the current 80-byte header, under a fixed leaf key
   derived from a new S31 source and a value-free circuit topology.

The outer circuit opens the prior block hash and timestamp window from the
verified prior state, and opens the current header and its SHA256d digest from
the fused leaf's public commitment. It checks previous-hash linkage,
difficulty and time policy, the step counter, and the next-state digest.
The leaf proves the byte-exact SHA256d and mainnet PoW inequality. The outer
fold may recheck the inequality as defense in depth, but it must not recompute
SHA256d merely to bind the leaf. The resulting top proof remains a generic
11-component circuit proof, so the next step's prior-child verifier accepts
it under the same outer topology. The native top verifier needs only the
newest generic proof, trusted outer key, and public state statement. Both
child proofs are witnesses inside that top proof.

The current leaf is insufficient: its eight public words commit only to the
SHA digest. An outer circuit could then choose unrelated header fields while
reusing that digest claim. Introduce a **versioned header-and-digest
commitment** as the leaf's sole eight-M31 public output:

```text
L = Commit_v1("S31-BTC-HEADER-DIGEST" || header_bytes[80]
              || sha256d_bytes[32])
```

Its encoding, chunk lengths, domain separation and hash assumption must be
specified once and implemented identically in S31 and the outer circuit.
A fixed-shape Poseidon2 tree is a candidate, subject to review of the exact
commitment construction. The outer circuit witnesses all 80 header bytes and
32 digest bytes, recomputes `L`, and equates it to the verified leaf output.
This equality binds every `nBits`, timestamp, previous-hash and hash byte
used by policy checks. The leaf still has one private `Bytes80` input, one
SHA256d operation, and one eight-M31 output, but its source digest and sealed
key are new. The current source library does not expose a `Bytes80`-to-field
commitment helper, so this operation and its byte-order-preserving lowering
must be added and tested. The SHA digest remains private to both statements.

### Keys, bootstrap and self-reference

Let `K_L` be the independently rebuilt fused leaf key, `R_A` the trusted
generic anchor root, and `R_F` the independently rebuilt generic outer-fold
root. The outer value-free topology fixes `K_L`'s complete profile and key
digest, the commitment version, checkpoint/network rules, its generic child
proof geometry, and the outer FRI policy. At `step = 0`, the prior-child
verifier checks the anchor under `R_A`; at later steps it checks a fold proof
under `R_F`. The selector is constrained by the public step counter, not a
free witness. The fused leaf verifier runs on **every** step, so no dummy or
conditionally skipped fused proof is needed at the base.

As in the existing generic chain fold, the circuit can witness its own root
to avoid embedding a circular root constant. Its public state digest includes
that root. The native top verifier recomputes `R_F` from value-free topology
and recomputes the public digest with `R_F`; a different witnessed root would
require a digest collision. The key/schema must change from the current
generic fold and reject old-fold, stand-alone v4, and alternate leaf-source
proofs. The leaf key is constant in the outer topology, not supplied by a
witness or by an unchecked external JSON field.

### Proof transport and transcript requirements

The accepted leaf file is the sealed `S31FCJ04` envelope. A host adapter
checks its exact magic, length, key digest, claims and PCS geometry, runs the
native verifier, and obtains a verified capture. It then expands the
postcard STARK into the circuit verifier's query-order witness format using
the frozen 14-component shape, including duplicate query openings and FRI
cosets. Native verification makes conversion safe to perform; the *outer
circuit* must still re-verify every cryptographic condition so that the top
proof stands alone. The circuit does not need to parse the file envelope,
but its constants and witness must reproduce the accepted envelope's v4
statement and transcript exactly.

That in-circuit v4 verifier needs profile/semantic/air/source-key mixing in
the native order; fixed-root and identity binding; `mixFelts` for the eight
public values; the exact interaction nonce; both lookup challenge draws;
Gate closure including circuit public outputs; zero sum of the five word
claims; all 14 component equations and cumulative-sum constraints; Merkle,
OODS, composition, and FRI26/70/fold1 checks. The generic prior verifier has
its own root, transcript, shape, and FRI fold4. No proof-format or schedule
downgrade is implicit.

### Cost and acceptance

The leaf verifier is likely expensive: the current v4 proof has 291 main and
92 interaction columns, so 70 queries alone expose at least
`70 × (291 + 92) = 26,810` M31 trace/interaction samples before fixed
columns, Merkle paths, FRI witnesses, and the generic prior verifier. FRI
fold1 also creates more layers than fold4. A separate generic wrapper around
each leaf would still need the same fused in-circuit verifier and would add
another proof and another generic child verification; it does not remove this
cost. Measure rows, memory, proof bytes and full wall time against the
existing direct-SHA chain fold before adopting the design. The larger circuit
must also fit the supported trace-domain limit and fixed-key padded geometry;
the current chain-fold row targets cannot be assumed to fit it.

Acceptance must first compare the in-circuit fused transcript, OODS
evaluation, and lookup closures against the native v4 verifier on the same
proof. Then prove anchor → block one → block two → block three under one
outer key, verifying only the newest proof natively. Reject mutations of
the leaf source/key/root/profile, commitment domain or one header/digest byte,
Gate address/call ID/word coordinate, each claim sum, either challenge,
Merkle/FRI opening, prior generic proof/root/output, step or base selector,
checkpoint/network, previous hash, `nBits`, timestamp window, and public
state digest. Also reject a valid leaf for a different header and a valid
generic child under a different fold key. Host-only verification of either
child is not a substitute for these circuit constraints.

## Alternative: a fused outer proof

A fused outer fold could move the current header's SHA calls into the outer
STARK and eliminate the separate leaf proof. Its own proof would then have a
new component roster, so stable recursion requires an in-circuit verifier
for that *joined outer profile* and a sound anchor/recursive child switch.
The existing generic child verifier cannot authenticate a joined outer proof
at block two. This alternative may prove faster, but the verifier and base
case are a larger unsolved project. A one-step joined proof is useful for
benchmarking; it is not a recursive light client.
