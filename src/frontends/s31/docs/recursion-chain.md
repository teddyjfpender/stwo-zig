# A proof of a proof of a proof

The first [recursion chapter](recursion.md) wraps a leaf S31 proof once. S31
can now wrap that **first wrapper proof** again. This chapter follows a
private-witness `preimage4` example through two wrappers. It also states
the key boundary: the two wrapper AIRs have distinct sealed keys. The
[fixed-key fold](recursion-fold.md) now supplies one AIR for repeated steps.

## The three statements

The leaf program proves that a private four-word `u16` value satisfies
`secret[i]² + 7 = target[i]` in M31. The checked assignment has `secret =
[1,2,3,42]`, so `square = [1,4,9,1764]` and `target = [8,11,16,1771]`.
Its eight public words are:

```text
W0 = [8, 11, 16, 1771, 1, 4, 9, 1764]
```

Let `K0` be the exact bytes of `verification-key.json`. The first wrapper
verifies the leaf STARK inside a circuit. It fixes the leaf AIR root by eight
equality gates and embeds `SHA256(K0)` as circuit constants. Its public
output is eight raw `u32` words:

```text
D1 = Blake2s-256(person="S31RCV2!", SHA256(K0) || LE32(W0))
```

For the compiled `preimage4` package in the acceptance fixture, this is:

```text
D1 = [114393851, 3697851308, 811829754, 1234097880,
      1149239534, 237789166, 2377151022, 2124025211]
```

Let `K1` be the exact bytes of `recursive-verification-key.json`. The
second wrapper verifies the **first wrapper STARK** inside another circuit.
It fixes the first wrapper's AIR root and embeds `SHA256(K1)` as constants.
Its public output is:

```text
D2 = Blake2s-256(person="S31RCV2!", SHA256(K1) || LE32(D1))
```

The same fixture produces:

```text
D2 = [3261532993, 4216833817, 3540888548, 444438926,
      1344647726, 3496049993, 1965291402, 1057682655]
```

The [worked-value record](../../../../design/s31/measurements/hash/preimage-chain-hand-example-2026-10-07.json)
pins the source and exact key hashes used for these numbers.

Each preimage is exactly 64 bytes, so each binding uses one Blake2s block.
`D1` and `D2` are raw hash words. A word may be greater than the M31
modulus; the second wrapper must accept the full `u32` range. Only the
original leaf `W0` has the S31 program's canonical-M31 public ABI.

| Proof | Private witness inside its relation | Public words | Sealed key |
| --- | --- | --- | --- |
| Leaf `P0` | `secret` and leaf trace | `W0` | `K0` |
| First wrapper `P1` | Expanded openings of `P0` | `D1` | `K1` |
| Second wrapper `P2` | Expanded openings of `P1` | `D2` | `K2` |

The `P2` verifier receives one chain statement containing `W0`, `D1`,
`D2` and the corresponding sealed roots and hashes. It checks both digest
equations and verifies only `P2`. The lower proof files can be deleted
after `P2` is made. The chain statement still carries the leaf words so a
caller can interpret them using the leaf program's public ABI.

The on-disk statement nests the two ordinary recursive statements:

```json
{
  "schema": "s31-recursive-chain-statement-v1",
  "leaf": {
    "schema": "s31-recursive-gate-statement-v2",
    "child_key_sha256": "SHA256(K0), as 64 hex characters",
    "child_public_words": "W0, eight u32 values",
    "outer_public_words": "D1, eight u32 values",
    "outer_preprocessed_root": "root of K1",
    "outer_circuit_hash": "hash of K1"
  },
  "head": {
    "schema": "s31-recursive-gate-statement-v2",
    "child_key_sha256": "SHA256(K1), as 64 hex characters",
    "child_public_words": "D1, eight u32 values",
    "outer_public_words": "D2, eight u32 values",
    "outer_preprocessed_root": "root of K2",
    "outer_circuit_hash": "hash of K2"
  }
}
```

The strings in this teaching sketch stand for the actual arrays and hex
strings in the generated file. In particular, `head.child_public_words`
must equal `leaf.outer_public_words` byte for byte.

The security argument has two finite steps. If the native verifier accepts
`P2`, outer-STARK soundness says its verifier AIR was satisfied. That AIR
checks a `P1` proof against `K1` and `D1`. If that in-circuit verifier is
correct and the child STARK is sound, `P1` attests to a `P0` proof against
`K0` and `W0`. The argument also needs the build-time keys to describe the
actual circuits, the proof conversion to preserve native-verifier data, and
collision resistance for the two public digests. The adversarial fixtures
exercise these boundaries; they are not a formal cryptographic audit.

## What is constrained in the second AIR?

The second circuit takes the native verifier's authenticated opening
capture from `P1`. It guesses those values as witness wires and enforces
the child STARK verifier: commitment roots, Fiat–Shamir channel, LogUp
sums, composition checks, FRI layers and proof of work. It checks each
guessed preprocessed-root word against the matching constant from `K1`.
It then computes `D2` from fixed `SHA256(K1)` words and the eight `D1`
output wires. A witness-bearing graph and a separate witness-free graph
must have identical gates before the second AIR is committed. The prover
checks that AIR's root and hash against build-time sealed `K2`, verifies
the new proof natively, and writes it.

The native top verifier embeds `K0`, `K1` and `K2`. It checks the nested
chain statement, including `P2`'s child words equalling `P1`'s output
words. Altering the original leaf claim and recomputing **both** public
digests still causes the top proof to fail. The
[acceptance fixture](../tests/acceptance/acceptance_recursion_chain.py) checks that attack,
corrupted proofs and keys, and the low-memory proof policy. It also audits
seven direct mutations inside the second-level verifier circuit.
The packaged prover embeds the same three exact key byte strings and
rejects substituted key files. `K1` is rebuilt and checked once when `K2`
is generated during package build; routine wrapping checks the sealed
bytes and rebuilds only the second verifier topology needed for its proof.

## Reproduce

```sh
python3 src/frontends/s31/python/s31.py build \
  src/frontends/s31/examples/preimage4.s31 \
  --lowering gate --out zig-out/s31/preimage-chain

python3 src/frontends/s31/python/s31.py prove \
  zig-out/s31/preimage-chain \
  src/frontends/s31/examples/preimage4.valid.json \
  zig-out/s31/preimage-chain/leaf.proof

python3 src/frontends/s31/python/s31.py wrap \
  zig-out/s31/preimage-chain \
  zig-out/s31/preimage-chain/leaf.proof \
  zig-out/s31/preimage-chain/first.proof

python3 src/frontends/s31/python/s31.py audit-recursive-next \
  zig-out/s31/preimage-chain \
  zig-out/s31/preimage-chain/first.proof

python3 src/frontends/s31/python/s31.py wrap-next \
  zig-out/s31/preimage-chain \
  zig-out/s31/preimage-chain/first.proof \
  zig-out/s31/preimage-chain/second.proof

python3 src/frontends/s31/python/s31.py verify-recursive-next \
  zig-out/s31/preimage-chain \
  zig-out/s31/preimage-chain/second.proof

python3 src/frontends/s31/tests/acceptance/acceptance_recursion_chain.py \
  --package zig-out/s31/preimage-chain
```

`wrap-next --low-memory` uses the same lower-memory proving policy as the
first wrapper. The acceptance fixture checks that both policies produce
byte-identical top proofs. A second-level proof for the `arith4_m31`
fixture was 555,050 bytes; its optimized wrapping command took 3.89 seconds
wall time and peaked at 9.31 GB on one local macOS `ReleaseFast` run.
The `--low-memory` run took 4.38 seconds and peaked at 7.00 GB, producing
the same proof bytes. The
private-witness fixture produced a 560,563-byte top proof. These are
single-machine observations, not stable cross-machine benchmarks. The
[raw record](../../../../design/s31/measurements/recursion/recursion-chain-v1-2026-10-07.json)
also reports 0.07 seconds and 205 MB for the standalone native top verifier
on that `arith4_m31` proof.

## Current limit

`K2` is sealed at package build by rebuilding the first wrapper AIR and
then deriving the second. The two wrapper layouts happened to have the
same padded component sizes for the `arith4_m31` fixture, but their
preprocessed roots differ because their embedded child identities differ.
This depth-specific chain supports the full eleven-component `circuit-v1`
child profile. The [fixed-key fold](recursion-fold.md) repeats the same
leaf claim under one key with a `u32` step counter. A
[sparse-wide variant](recursion-wide-fold.md) accepts a Bitcoin two-header
leaf proof after two wrappers. Neither fold updates Bitcoin chain state.
