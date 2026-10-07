# A repeatable proof fold under one key

The [one-level wrapper](recursion.md) proves that an S31 proof verified. The
[two-level chain](recursion-chain.md) proves that the first wrapper verified,
but its key changes at each depth. This chapter shows the fixed-key fold: a
base proof and any number of later fold proofs are all produced under the
same `fixed-fold-verification-key.json` (`KF`). The counter is two constrained
`u16` limbs forming a `u32`, so the implemented range is steps 0 through
4,294,967,295.
The new counter changes the fold AIR. Gate fold keys and statements use schema
v3; sparse-wide fold keys and statements use v4. Older proofs must be
verified with their matching older package.
The limit is an encoding bound, not a measured practical depth or a concrete
security guarantee at that depth. Each step costs another proof run, and a
security analysis must account for the number of recursive verifications.

## What the proof says

Use this S31 function as a concrete leaf:

```s31
fn step(v: [m31; 4]) -> [m31; 4] {
    v .* v + splat<4>(7_m31)
}

circuit arith4_m31(public x: [m31; 4]) -> public [m31; 4] {
    let result = iterate<256>(step, x);
    result
}
```

`P0` proves the 256 constrained recurrence steps and exposes eight canonical
M31 public words `W0`: four inputs and four outputs. `P1` is the earlier
wrapper proof under key `K1`. It verifies `P0` in a circuit, and exposes the
eight raw `u32` words

```text
D1 = Blake2s-256(person="S31RCV2!", SHA256(exact K0 bytes) || LE32(W0))
```

For the saved `arith4_m31` fixture,
`D1 = [3093557552,2965838155,2753976554,486232688,3300667518,3444298827,547066196,2739038157]`.
Some words exceed the M31 modulus; recursive hash words are full `u32`s.

The fold's public output is another eight-word hash. Let `RF` be the actual
preprocessed root sealed in `KF`, `n` the step, and `D1` those base words:

```text
F(RF,n,D1) = Blake2s-256(person="S31FOL2!",
    RF[32 bytes] || LE32(n) || LE32(D1[0..8]))
```

This is 68 bytes and two BLAKE2s blocks. The step occupies its own `u32`
slot, so changing it cannot be canceled by changing a private root word.
An earlier one-block draft had exactly that alias and was rejected during
soundness review. In the current `u32` fixture, `RF` is
`5682495391e4b8d187470b4042244f2aa81ec1b4e70bafe2adc780068c20b305`.
The first word of `F` at steps 0, 1, 2 and 3 is respectively
`1101848050`, `1955705351`, `2532963129`, and `2945726935`. The first
word at step 65,536 is `2301011972`, showing the high counter limb enters
the digest. Every proved step's eight words are in its generated
`.statement.json`. The [worked-value record](../../../../design/s31/measurements/fixed-fold-u32-hand-example-2026-10-07.json)
pins the source and key hashes, gives all eight output words at these steps,
and records a natively verified step-0 proof.

| Proof | Child verified inside the fold AIR | Public words | Proof key |
| --- | --- | --- | --- |
| `F0` | `P1` under `K1`, with output `D1` | `F(RF,0,D1)` | `KF` |
| `F1` | `F0` under `KF`, with output `F(RF,0,D1)` | `F(RF,1,D1)` | `KF` |
| `F2` | `F1` under `KF`, with output `F(RF,1,D1)` | `F(RF,2,D1)` | `KF` |
| `F3` | `F2` under `KF`, with output `F(RF,2,D1)` | `F(RF,3,D1)` | `KF` |

The native verifier needs only the final proof, its statement, and its
compiled sealed keys. It recomputes `D1` from the original `W0`, computes
`F(RF,n,D1)`, and verifies the top STARK. Earlier proof files can be removed.
Its conclusion relies on the fold AIR actually checking its child proof;
that is why the in-circuit verifier is a constraint, not a host shortcut.

## The selector and counter, by hand

The fold circuit has one STARK verifier gadget. A private Boolean `base`
selects which root and output that gadget must verify:

```text
lo,hi,prev_lo,prev_hi ∈ u16
n = lo + 65536·hi; previous = prev_lo + 65536·prev_hi
base,borrow ∈ {0,1}
(lo + hi) · base = 0
(lo + hi + base) · inverse = 1
recurse = 1 - base
prev_lo = lo - recurse + 65536·borrow
prev_hi = hi - borrow

child_root   = base ? root(K1) : RF
child_output = base ? D1 : F(RF,previous,D1)
verify_STARK(child_proof, child_root, child_output)
public_output = F(RF,n,D1)
```

The equations force the base branch exactly at zero. The limb sum is below
the M31 modulus, so it vanishes exactly when both limbs are zero. Then the
inverse forces `base=1`. At every positive step `base=0`, and the constrained
limbs and Boolean borrow make `previous=n-1` as an integer. For `n=65536`,
`(lo,hi)=(0,1)`, `borrow=1`, and `(prev_lo,prev_hi)=(65535,0)`.
At `n=0`, `borrow=1` would require a negative high limb and is impossible.
At `n=4294967295`, the predecessor is `4294967294`; the host refuses another
step because it cannot fit a `u32`. For `n=2`, a satisfying assignment is
`base=0`, `inverse=1/2` in M31 (`1073741824`), and `previous=1`.
Changing the branch bit, inverse, borrow, or previous counter after witness creation
fails the circuit's gate checks in the acceptance audit.

The selector itself is a small arithmetic circuit. For each word it computes
`left + recurse·(right-left)`. A `base=1` row chooses the base root and `D1`;
a `base=0` row chooses the fold root and previous digest. Those selected
words enter the full child STARK verifier circuit: commitments, transcript,
LogUp, FRI, and proof of work. The BLAKE2s output gadgets and the counter
gates then become circuit AIR rows. Their column polynomials are interpolated
from the trace values and committed by the outer STARK, as described in
[circuit lowering](circuits.md) and [AIR and polynomials](air.md).

## Why the AIR can verify itself

Putting `RF` as a literal constant in its own circuit would create a
cryptographic fixed-point equation: the AIR root would depend on itself.
The circuit guesses a `u32[8]` root `R`. Its public output includes
`F(R,n,D1)`, while the native verifier insists on `F(RF,n,D1)` using its
**sealed actual** root. BLAKE2s collision resistance binds the guessed `R`
to `RF` at the top. In a recursive step, the circuit uses that same `R` to
verify the child proof and compute the previous output. The decreasing
counter leads to the `K1` base case.

Key generation independently constructs the witness-free fold topology,
pads it, and rejects it unless its child-proof column layout exactly matches
`K1`'s. The installed prover embeds `K0`, `K1`, and `KF`; it rejects supplied
key bytes that differ from those sealed artifacts. Every proof run compares
the value circuit with the witness-free gate lists before and after padding,
checks circuit satisfaction, checks the resulting root against `KF`, and
natively verifies its own output before writing it. The package manifest
hashes the keys and binaries. This is a computational soundness argument
under the STARK and hash assumptions, not a formal proof or independent
cryptographic audit.

## Reproduce the chain

```sh
python3 src/frontends/s31/s31.py build \
  src/frontends/s31/examples/arith4_m31.s31 --out zig-out/s31/arith4-fold
python3 src/frontends/s31/s31.py prove zig-out/s31/arith4-fold \
  src/frontends/s31/examples/arith4.valid.json zig-out/s31/leaf.proof
python3 src/frontends/s31/s31.py wrap zig-out/s31/arith4-fold \
  zig-out/s31/leaf.proof zig-out/s31/base.proof
python3 src/frontends/s31/s31.py fold-base zig-out/s31/arith4-fold \
  zig-out/s31/base.proof zig-out/s31/fold0.proof
python3 src/frontends/s31/s31.py fold-next zig-out/s31/arith4-fold \
  zig-out/s31/fold0.proof zig-out/s31/fold1.proof
python3 src/frontends/s31/s31.py verify-fold zig-out/s31/arith4-fold \
  zig-out/s31/fold1.proof --max-step 1
python3 src/frontends/s31/acceptance_fixed_fold.py
```

`fold-next` may be repeated until step 4,294,967,295. `--low-memory` applies to
`fold-base` and `fold-next`; it produced byte-identical proof bytes in the
acceptance run. `--max-step` is a relying-party limit on the accepted top
counter. The native verifier checks it after validating the sealed statement
and before reading proof bytes; it is not a cryptographic security estimate.
`audit-fold-base` tests a first wrapper proof against altered
leaf words, base root, step, branch selector, inverse, and previous counter.
`audit-fold-next` applies the same checks to a saved fold proof, including
its selected recursive root.
`fold-advance PACKAGE CHILD-PROOF OUT-PROOF --steps N` runs multiple steps
in one process and caches the sealed AIR, commitment, and padded topology.
An optional `--checkpoint-dir DIR` keeps intermediate proofs for resume.
Every step still checks the complete value-bearing gate list and natively
verifies its child. The acceptance fixture compares batch output byte for
byte against separate proof commands.
The [claim inspector](../inspect_recursive_claim.py) verifies a saved top
proof and prints the exact sealed key hashes, original leaf words, base
digest, counter, and previous/current public fold digests as JSON.
`inspect-fold PACKAGE` rebuilds the fold topology from the sealed keys and
prints its raw rows, padded rows, available headroom, and cumulative
`verifier_stages` as JSON. Subtract adjacent stage counts to see which
verifier phases add variables and gates; inspection does not alter the AIR.
The earlier u16 fold's `arith4_m31` fixture had raw/padded `triple_xor` rows
`243880/262144`. Its recorded geometry remains historical because the u32
counter changes the AIR root and several raw row counts. This matters when
designing a stateful fold: a small gadget can double one trace component.

In one local sample of the earlier u16 `arith4_m31` step-3 fold, proving took 3.65 s wall time and
9.31 GB peak resident memory; `--low-memory` took 3.91 s and 7.00 GB. The
proof was 560,468 bytes. Native top verification took 0.45 s and 205 MB.
These are single local measurements, not comparative benchmarks or promised
performance across machines. The [raw measurement record](../../../../design/s31/measurements/fixed-fold-v2-2026-10-07.json)
contains the key geometry, four proof sizes, and the tested negative cases.

This fold repeats the **same leaf claim**. The
[sparse-wide variant](recursion-wide-fold.md) now accepts a wide-integer or
two-header Bitcoin leaf proof after two wrappers, under a separate fold key.
Neither variant updates Bitcoin chain state or adds another header per step;
that requires a constrained state-transition relation.
The [state-transition fold](state-fold.md) implements the first such relation
for an S31 four-lane M31 recurrence while retaining one verification key.
