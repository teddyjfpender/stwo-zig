# Source-derived recursive state fold

Status: implemented for the recognized four-lane M31 recurrence on the
`gate` profile, 2026-10-07. See the [worked language chapter](../../src/frontends/s31/docs/state-fold.md)
and [acceptance fixture](../../src/frontends/s31/acceptance_state_fold.py).

## Relation and public statement

S31's normalized source must satisfy `Program.repeatedStepChip()`: one public
four-lane input; an optional `u16` to M31 cast; one static `repeat` node with
`square` then `add_const`; a power-of-two base count from 16 through 32,768;
no assertions; and one public four-lane output.
The extractor returns the base round count `r` and constant `c`. A normal
leaf proof establishes `S0 = f^r(x)` for `f(v)=v²+c` lane by lane. The first
wrapper proof attests to that leaf proof and exposes digest `D1`.

The state-fold key `KS` includes the exact SHA-256 digest of `K1`, the
source-extracted `r` and `c`, pinned AIR asset identities, its component
layout, preprocessed root and circuit hash. A package only generates `KS`
when the compiler reports a matching source shape. It rejects a geometry
mismatch between its own proof layout and `K1`'s; both branches of the
in-circuit verifier then use the same proof shape and PCS configuration.

The fold statement contains `n:u16`, the original eight canonical public
words `W0`, `D1`, `S0: M31[4]`, `Sn: M31[4]`, the key digest, root, hash,
and output words. The native verifier requires `S0=W0[4..8]`, computes
`D1=Blake2s(person="S31RCV2!",SHA256(K0)||W0)`, and computes:

```text
G(R,n,D1,S0,Sn) = Blake2s-256(person="S31STF1!",
    R[32] || LE32(n) || LE32(D1[8]) || LE32(S0[4]) || LE32(Sn[4]))
```

The preimage is 100 bytes. All five fields have disjoint fixed-width
slots. In particular, the counter cannot be canceled by changing a private
root word. The top verifier uses the actual root sealed in `KS` and verifies
only the top STARK. Its public statement remains enough to identify the
original leaf claim and final state.

## Circuit invariant

The circuit guesses the root, counter, base selector, initial/current/
previous states, child proof and digest. Its constraints enforce:

```text
base∈{0,1}; n·base=0; (n+base)·inv=1
recurse=1-base; predecessor=n-recurse∈u16
Sn[i] = S0[i] + recurse·(Previous[i]²+c-S0[i]) in M31
child_root = base ? root(K1) : R
child_public = base ? D1 : G(R,predecessor,D1,S0,Previous)
verify_stark(child_proof, child_root, child_public)
output = G(R,n,D1,S0,Sn)
```

At `n=0`, the equations force `base=1`, `Sn=S0`, and verification of a `K1`
proof with output `D1`. That proof verifies the leaf and its `W0`. At
`n>0`, the equations force `base=0`, prove `Sn=f(Previous)`, and verify a
child proof whose statement commits to the same `S0` and `Previous` at
counter `n-1`. The counter decreases in the well-founded `u16` range.
At the top, `G` binds the root, step and states to their public values under
BLAKE2s collision resistance. Induction gives `Sn=f^n(S0)=f^(r+n)(x)`.

This reasoning assumes STARK soundness, correctness of the in-circuit
verifier, proof capture that preserves the native-verifier data, the sealed
build artifacts, and BLAKE2s binding. It is not a formal proof or
independent cryptographic audit.

## Enforcement and tests

- The source extractor, not a supplied step constant, selects `c` and `r`.
- Native verification rejects noncanonical leaf or state words, a changed
  initial state, a changed key digest/root/hash, and a recomputed but false
  top digest once the proof is checked.
- The prover first verifies and captures the serialized child proof natively,
  then verifies that proof in the value circuit. It compares that circuit's
  gate lists against a witness-free topology before and after padding,
  checks circuit satisfaction and the sealed root, proves, and natively
  verifies its own result before writing it.
- Base and recursive audits mutate leaf words, state, step, selected root,
  branch selector, inverse and predecessor counter inside the circuit.
  The recursive audit also mutates the previous state. The acceptance suite
  checks four successive states against an independent Python M31 recurrence,
  low-memory proof equality, hostile rehashed statements, corrupted proofs,
  key substitution and verification after lower files are removed.
- The same-AIR, different-key fixture repairs all public hashes under a
  second package and still rejects cross-key replay.

The current fixed step is deliberately narrow. A general source-level fold
needs a typed, statically bounded step compiler that lowers an S31 function
against previous and current state variables, then binds that function's
canonical IR and public ABI into `KS`. Bitcoin needs byte-exact SHA256d,
target and linkage constraints, wide work arithmetic, and an in-circuit
verifier for the sparse-wide header proof profile. Those changes must retain
the fixed-key geometry condition or use a dedicated chip/adapter with its
own sound cross-AIR boundary.

The [geometry record](measurements/state-fold-v1-2026-10-07.json) shows that
the four-lane transition adds 48 raw variables, 4 equality rows, 32 QM31
operation rows and 16 M31-to-u32 conversion rows over the claim-only fold,
without crossing a padded component boundary. The measured step-3 proof was
550,173 bytes and took 3.62 s wall/9.31 GB peak RSS, or 3.82 s/7.00 GB
with the low-memory policy; the proof bytes matched. These are isolated
local samples, not a general performance guarantee.
