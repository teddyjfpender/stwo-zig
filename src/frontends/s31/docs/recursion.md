# One-level S31 proof recursion

S31 now proves that a proof of an S31 program verified. The first wrapper
supports the full eleven-component `circuit-v1` (`gate`) profile. It converts
the child proof into the repository's in-circuit STARK verifier format,
constrains verification, and proves that verifier circuit. The generated S31
native verifier independently checks the outer proof through `recurse-verify`.

This is **one level**, not yet a repeatable chain fold. The Bitcoin header
example uses `sparse-wide-gate`; its different AIR roster is rejected by this
adapter. An exact sparse-wide recursive verifier and a homogeneous wrapper
key are needed before header proofs can be folded repeatedly.

## What the outer proof establishes

For `arith4_m31`, the eight child public M31 words are four inputs followed
by four outputs:

```text
[1, 2, 3, 65535, 1381993681, 1163620247, 833240539, 2139095920]
```

The child key fixes the normalized source, circuit topology, preprocessed
root, AIR bundle, eleven component shapes, PCS/FRI settings and transcript
profile. The outer circuit guesses a child proof and runs the STARK verifier
**inside its constraints**. It also fixes the eight child-root words by
equality constraints against constants from the child key. Its public output
is exactly:

```text
Blake2s-256(person="S31RCV2!",
  SHA256(exact_child_key_bytes) || LE32(child_public_words[0..8]))
```

The preimage remains one 64-byte Blake2s block. The key digest is eight
**fixed circuit constants**, not witness values. The child root equality
prevents a valid proof for a different AIR from being paired with that key.
For root word `i`, the circuit adds the equality gate
`guessed_root[i] = key.preprocessed_root[i]`; the in-circuit verifier also
checks the child proof's first commitment against `guessed_root`. The eight
key-digest constants enter the Blake2s message as its first eight `u32`
words, followed by the eight constrained child output words. Both the
value-bearing prover graph and the witness-free graph must have the same
gate list and constant table before the outer AIR is accepted.
For this fixture the outer digest, interpreted as eight little-endian `u32`
words, is:

```text
[1165332741, 1691151829, 1726621965, 1268399239,
 691784874, 833490328, 1935791649, 1134705563]
```

The outer verifier embeds the child key and a sealed recursive key generated
from that key's fixed proof geometry during package build. The recursive key
contains the outer AIR component sizes, preprocessed root and circuit hash,
and the SHA-256 of the exact child key. At verification time, the native
verifier checks those bindings, recomputes the outer circuit hash from the
cached root and layout, checks the statement digest, and verifies the outer
STARK. It does not need the child proof
file: the outer proof attests that a valid child proof exists for those
public words. The caller must still interpret the words using the embedded
S31 program's public ABI.

`recurse-keygen` rebuilds the outer topology and creates
`recursive-verification-key.json` once at package build. The key is embedded
in the native verifier and hashed in the package manifest. The acceptance
suite regenerates it and compares every field. A trusted build of that
binary and key is part of the soundness assumption; a supplied JSON file
cannot authorize a different outer circuit at verification time.
The recursive prover independently rebuilds the outer topology and checks
its layout, root and hash against the package's sealed recursive key before
proving. A mismatched or altered package fails before an outer proof is made.

## Computation and soundness checks

```text
S31 source + private assignment
    │ compile, constrain, prove
    ▼
S31NAT1 child proof ── native verification
    │ convert proof and expanded Merkle/FRI openings
    ▼
CircuitStatement over all 11 child AIR components
    │ constrain roots, Fiat–Shamir, LogUp, composition, FRI and PoW
    ▼
Verifier circuit root = fixed child-key root
    │ 8 word equalities
    ▼
Verifier circuit output = Blake2s(person="S31RCV2!", key digest || public words)
    │ prove with the full circuit AIR
    ▼
S31NAT1 outer proof ── separately built native verifier
```

Expanded opening data is a witness, not an admission decision: the circuit
checks it. For a saved child proof, the native verifier reconstructs these
openings while checking the exact child key and public statement. Conversion
occurs only after that check succeeds; it does not trust a prover-supplied
opening sidecar. The one-shot `recurse-prove` command now uses the same
native-verifier capture from its serialized child proof. The prover also
builds a witness-independent `NoValue` topology,
compares every gate with the value circuit before and after padding, checks
circuit satisfaction, and natively verifies the outer proof before writing
it. `recurse-check` runs a separate audit: it serializes the in-circuit proof
input from both the prover's metadata and the native verifier's authenticated
opening capture, then requires the bytes to match exactly. It also requires
rejection for a changed public word, preprocessed root, trace commitment, claimed LogUp sum,
channel salt, FRI opening witness, and FRI last-layer coefficient.
`recurse-prove` avoids those extra audit builds.
`audit-recursive` accepts a saved child proof and public statement, replays
native verification, and tests the same seven in-circuit mutations on the
verifier-captured witness without needing the private assignment.
For the documented fixture, the prover-side and verifier-captured in-circuit
inputs serialized to the same 799,464 bytes. This equality checks conversion
parity; it does not replace verification of either proof.

The public outer statement contains the child key digest, eight child words,
the outer digest, and the outer circuit's root and hash. The native outer
verifier checks the last two against its embedded recursive key; the statement
cannot choose them. It rejects unsupported profiles before decoding.
The v2 outer AIR itself contains the key digest as constants and fixes the
child root, so an outer proof for one compiled child key cannot be replayed
under a different compiled key even if both keys describe the same gate
topology. `recurse-check` takes the child key path so this binding is also
tested by its audit circuit.
The [cross-key acceptance fixture](../acceptance_recursion_key_binding.py)
builds two differently named programs with identical child AIR roots. It
shows that the child proof verifies under either key, while the outer AIR
roots differ and an attempted outer-proof replay is rejected.

The security claim is conditional on the soundness of the child and outer
STARKs, the collision resistance of BLAKE2s and SHA-256, and the correctness
of the circuit verifier and its native proof conversion. The key is compiled
into the verifier binary; users must obtain that binary from a trusted build.
The SHA-256 key identifier in the JSON detects a statement/key mismatch but
does not make an untrusted verifier binary trustworthy. This implementation
has executable adversarial checks, not a formal soundness proof or an
independent cryptographic audit.

## A private-witness child

The [preimage example](../examples/preimage4.s31) has a different circuit
shape and a private four-word `u16` witness:

~~~s31
circuit preimage4(public target: [m31; 4], private secret: [u16; 4])
    -> public [m31; 4] {
    let secret_field = m31_from_u16(secret);
    let square = secret_field .* secret_field;
    let offset = square + splat<4>(7_m31);
    assert_eq(offset, target);
    square
}
~~~

For the checked assignment, `secret = [1,2,3,42]`, `square =
[1,4,9,1764]`, and `target = [8,11,16,1771]`. The child circuit proves
each `secret[j]` is in the `u16` range and satisfies
`secret[j]² + 7 = target[j]` in M31; `assert_eq` becomes a circuit equality
constraint. The outer circuit verifies that child
STARK. Its statement contains the eight public `target || square` words
and the digest binding those words to the exact child key. It contains no
private `secret` value or child proof. The [second acceptance fixture](../acceptance_recursion_private.py)
proves and audits this route, and rejects changed public claims and an
incorrect private assignment. This shows proof-of-proof composition for a
private witness; it does not yet implement a many-step fold.

## Reproduce

From the repository root, first prove the child as an ordinary S31 program,
then wrap its saved proof:

```sh
python3 src/frontends/s31/s31.py build \
  src/frontends/s31/examples/arith4_m31.s31 \
  --lowering gate --out zig-out/s31/recursive-arith4

python3 src/frontends/s31/s31.py prove \
  zig-out/s31/recursive-arith4 \
  src/frontends/s31/examples/arith4.valid.json \
  zig-out/s31/recursive-arith4/child.proof

python3 src/frontends/s31/s31.py wrap \
  zig-out/s31/recursive-arith4 \
  zig-out/s31/recursive-arith4/child.proof \
  zig-out/s31/recursive-arith4/outer.proof

python3 src/frontends/s31/s31.py audit-recursive \
  zig-out/s31/recursive-arith4 \
  zig-out/s31/recursive-arith4/child.proof

python3 src/frontends/s31/s31.py verify-recursive \
  zig-out/s31/recursive-arith4 \
  zig-out/s31/recursive-arith4/outer.proof

python3 src/frontends/s31/acceptance_recursion_gate.py \
  --package zig-out/s31/recursive-arith4

python3 src/frontends/s31/acceptance_recursion_key_binding.py \
  --package zig-out/s31/recursive-arith4
```

`recurse-prove ASSIGNMENT CHILD-PROOF OUTER-PROOF CHILD-KEY` remains a one-shot
prover command. The acceptance run checks both one-shot and saved-proof
wrappers, rejects changed leaf and outer statements, altered proofs and
keys, and runs both audits to exercise the seven direct in-circuit
corruptions above using both prover metadata and authenticated capture.

A `ReleaseFast` v2 acceptance run produced a 438,157-byte child proof and a
541,609-byte outer proof. The earlier v1 wrapper had 10,277,308 verifier
variables and 1,139,003 arithmetic gates. Its outer proving took 2.644
seconds and produced a 547,655-byte proof; the full command took 4.27
seconds and peaked at 9.39 GB resident memory (`/usr/bin/time -l`, macOS).
These are single observations, not controlled benchmark distributions or a
Bitcoin-specific cost claim. The v1 timing is historical and should not be
used as a v2 benchmark. The verifier circuit still dominates memory;
reducing its gate count and the prover's trace storage are required for
practical folding.

`s31.py wrap ... --low-memory` retains committed evaluations without a
second coefficient copy during outer proving. Three local runs of the same
`arith4_m31` witness with the earlier v1 wrapper and `/usr/bin/time -l`
gave these ranges:

| Outer proving policy | Wall time | Peak resident memory | Outer proof |
| --- | ---: | ---: | ---: |
| Default, faster | 3.57–4.13 s | 9.31 GB | 547,655 bytes |
| `--low-memory` | 4.38–4.54 s | 7.00–7.10 GB | 547,655 bytes |

Both policies produced byte-identical proofs. These are local runs rather
than controlled cross-machine benchmarks. The default favors speed; the
explicit flag trades roughly 10% more wall time for about 2.3 GB less peak
memory in this case. The low-level `recurse-prove` and `recurse-wrap`
commands also accept `--low-memory` as their final argument. The
[raw sample record](../../../../design/s31/measurements/recursion-memory-policy-v1-2026-10-06.json)
contains the six wall-time and peak-memory observations and common proof hash.
Before the sealed recursive key, a standalone outer verifier rebuilt the
topology and took 0.55 seconds with 1.45 GB peak resident memory in one
`time -l` run. With the key embedded, one run took 0.07 seconds and peaked
at 205 MB; key generation during package build took 0.52 seconds and peaked
at 1.60 GB. These are single observations on the same `arith4_m31` outer
proof, not a controlled distribution. The key moves topology construction
out of routine verification; it does not shrink the outer proof or its prover.

The saved `S31NAT1` file lacks the expanded opening witness, so `wrap`
replays full native verification and captures the authenticated paths before
conversion. It does not need the private assignment. The final
`verify-recursive` command only needs the outer proof and its statement.

## Next boundary

The eight-word child ABI does not yet carry a typed Bitcoin state with
height, chainwork, network, checkpoint and header hash. That needs a
reviewed state commitment or wider ABI. The wrapper also needs an
in-circuit verifier for the exact `sparse-wide-v5` roster and transcript,
native/circuit parity on malformed proofs, and one canonical padded wrapper
shape that can verify proofs of its own shape. Only then can a base case and
step relation produce a bounded many-header fold.
