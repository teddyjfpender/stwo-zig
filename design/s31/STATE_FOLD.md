# Source-derived recursive state fold

Status: implemented for the recognized four-lane M31 recurrence on the
`gate` profile, 2026-10-07. See the [worked language chapter](../../src/frontends/s31/docs/state-fold.md)
and [acceptance fixture](../../src/frontends/s31/acceptance_state_fold.py).

## Relation and public statement

S31's normalized source must satisfy `Program.stateFoldStep()`: one public
four-lane input; an optional `u16` to M31 cast; one static `repeat` node with
1–32,768 base rounds; a body of 1–16 ordered `square`, `add_const`, or
`mul_const` operations; no assertions; and one public four-lane output.
The extractor returns the base round count `r` and exact body `b`. A normal
leaf proof establishes `S0 = f_b^r(x)` lane by lane. The first
wrapper proof attests to that leaf proof and exposes digest `D1`.

The state-fold key `KS` includes the exact SHA-256 digest of `K1`, the
source-extracted `r` and ordered body `b`, `counter_bits=32`, pinned AIR asset identities, its component
layout, preprocessed root and circuit hash. A package only generates `KS`
when the compiler reports a matching source shape. It rejects a geometry
mismatch between its own proof layout and `K1`'s; both branches of the
in-circuit verifier then use the same proof shape and PCS configuration.

The fold statement contains `n:u32`, the original eight canonical public
words `W0`, `D1`, `S0: M31[4]`, `Sn: M31[4]`, the key digest, root, hash,
and output words. The native verifier requires `S0=W0[4..8]`, computes
`D1=Blake2s(person="S31RCV2!",SHA256(K0)||W0)`, and computes:

```text
G(R,n,D1,S0,Sn) = Blake2s-256(person="S31STF2!",
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
lo,hi∈u16; n=lo+65536·hi as an integer; z=lo+hi
base∈{0,1}; z·base=0; (z+base)·inv=1
recurse=1-base; borrow∈{0,1}
prev_lo=lo-recurse+65536·borrow∈u16
prev_hi=hi-borrow∈u16
predecessor=prev_lo+65536·prev_hi
Sn[i] = S0[i] + recurse·(f_b(Previous[i])-S0[i]) in M31
child_root = base ? root(K1) : R
child_public = base ? D1 : G(R,predecessor,D1,S0,Previous)
verify_stark(child_proof, child_root, child_public)
output = G(R,n,D1,S0,Sn)
```

At `n=0`, the equations force `base=1`, `Sn=S0`, and verification of a `K1`
proof with output `D1`. That proof verifies the leaf and its `W0`. At
`n>0`, the equations force `base=0`, prove `Sn=f_b(Previous)`, and verify a
child proof whose statement commits to the same `S0` and `Previous` at
counter `n-1`. Since `z≤131070<p`, the branch equations cannot wrap in M31.
The limb range checks force the unique borrow at every 16-bit carry boundary
and reject underflow. The counter decreases in the well-founded `u32` range.
At the top, `G` binds the root, step and states to their public values under
BLAKE2s collision resistance. Induction gives `Sn=f_b^n(S0)=f_b^(r+n)(x)`.

This reasoning assumes STARK soundness, correctness of the in-circuit
verifier, proof capture that preserves the native-verifier data, the sealed
build artifacts, and BLAKE2s binding. It is not a formal proof or
independent cryptographic audit.

## Enforcement and tests

- The source extractor, not supplied witness metadata, selects `b` and `r`.
- Native verification rejects noncanonical leaf or state words, a changed
  initial state, a changed key digest/root/hash, and a recomputed but false
  top digest once the proof is checked.
- The prover first verifies and captures the serialized child proof natively,
  then verifies that proof in the value circuit. A single-step wrap compares
  its gate lists against a witness-free topology before and after padding;
  batch wraps compare each padded value circuit against the retained sealed
  topology. Both check circuit satisfaction and the sealed root, prove, and natively
  verifies its own result before writing it.
- Base and recursive audits mutate leaf words, state, step, selected root,
  branch selector, inverse, predecessor counter and borrow inside the circuit.
  They also mutate the captured child trace root, claimed sum, channel salt,
  sampled trace value, trace and FRI Merkle authentication paths, FRI witness
  and last layer after native proof authentication. The recursive
  audit also mutates the previous state. The acceptance suite
  checks four successive states against an independent Python M31 recurrence,
  low-memory proof equality, hostile rehashed statements, corrupted proofs,
  key substitution and verification after lower files are removed.
- The same-AIR, different-key fixture repairs all public hashes under a
  second package and still rejects cross-key replay.

The current typed step is deliberately bounded to four lanes and three
operation kinds. The [affine-square example](../../src/frontends/s31/examples/affine_square4.s31)
proves `f(x)=3x²+5` from a three-round base program and two more recursive
steps; its independent [acceptance fixture](../../src/frontends/s31/acceptance_state_fold_general.py)
checks the source-derived operation list, state values, and hostile key edits.
The state-fold key schema is v3, its statement schema is v2, and its digest
domain is `S31STF2!`. Existing v1/v2 packages remain readable through the
Python package verifier and use their sealed binaries.
`state-fold-advance` validates a package once and uses a native batch
prover that reuses the preprocessed circuit, commitment and padded topology
across steps.
It keeps optional intermediate checkpoints and verifies the top proof.
Every step still checks child proof validity and compares the value circuit
with a fresh witness-free topology. Resuming from a checkpoint gives the
same proof bytes; the acceptance fixture compares batch proofs with separate
one-step commands and checks both normal and low-memory resume.
The counter circuit is tested at 0, 1, 65,535, 65,536, 2³¹, and 2³²−1, with
wrong borrow, branch and predecessor witnesses rejected. The v3 transition
adds only 13 raw variables, two equality rows, 11 arithmetic rows and two
M31-to-u32 rows over v2, with no change in padded AIR sizes.
An isolated in-circuit BLAKE2s check matches the host statement digest at
steps 0, 65,536, 2³¹ and 2³²−1, so the upper counter bits are exercised.

An arbitrary S31 function fold still needs typed state beyond four lanes and
lowering for other operations with a sound circuit boundary. Bitcoin needs byte-exact SHA256d,
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
local v1 samples, not a general performance guarantee. The
[v3 counter record](measurements/state-fold-u32-v3-2026-10-07.json) gives the
current key and raw/padded geometry without a timing claim.
The [FRI schedule record](measurements/fri-fold-step-v1-2026-10-07.json)
compares the same v3 counter under two separately keyed proof schedules.
Four folds per FRI commitment halves the padded recursive AIR and reduced
median three-step wall time by 40.3% in four local runs per schedule. The
PoW, blowup and query counts stay fixed; this is not an independent FRI
soundness analysis.
