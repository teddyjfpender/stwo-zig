# Recursion that computes one more source step

The [fixed-key fold](recursion-fold.md) repeats verification of one S31
claim. This chapter adds a state transition: each new proof verifies its
predecessor **and** proves one more step of a function extracted from the
S31 source. All proofs use one state-fold AIR and one sealed key `KS`.

## The source and the claim

```s31
fn step(v: [m31; 4]) -> [m31; 4] {
    v .* v + splat<4>(7_m31)
}

circuit arith4_m31(public x: [m31; 4]) -> public [m31; 4] {
    let result = iterate<256>(step, x);
    result
}
```

The text frontend specializes `step` and lowers `iterate<256>` to a static
`repeat` node. The state-fold compiler accepts a public four-lane recurrence
with 1–32,768 base rounds and a static step body of 1–16 ordered operations:
square, add a field constant, or multiply by a field constant. It accepts no
private input, side assertion, or extra node in this profile. The ordered
body, including constant 7 here, and the 256-round base length are copied
into the versioned state-fold key and checked against the sealed source.
The dedicated hybrid chip still has its narrower power-of-two `square` then
`add_const` profile. A different supported step can use the generic gate
leaf and the same state-fold mechanism.

The ordinary leaf proof `P0` proves the first 256 steps. Its eight public
M31 words are the four inputs and four outputs. The latter become the
initial state of the state fold:

```text
W0 = [1,2,3,65535, 1381993681,1163620247,833240539,2139095920]
S0 = [1381993681,1163620247,833240539,2139095920]
```

The first wrapper `P1` proves that `P0` verified and exposes `D1`, the
personalized BLAKE2s digest of `SHA256(K0)` and `W0`. The state fold begins
with proof `SProof0`, which checks `P1` inside its circuit and binds `S0`.
`SProof1` checks `SProof0` and proves one more `step`; `SProof2` checks
`SProof1` and proves another. Thus `SProof3` attests to **259** recurrence
steps from the original public `x`, assuming the soundness conditions below.

| Fold step | State after original source program plus fold steps | First lane |
| --- | --- | ---: |
| 0 | `[1381993681,1163620247,833240539,2139095920]` | 1381993681 |
| 1 | `[1771435623,294854840,521360168,252467169]` | 1771435623 |
| 2 | `[371774827,166216213,712922489,990353809]` | 371774827 |
| 3 | `[1261523235,1373840506,29423616,860202541]` | 1261523235 |

For the first lane, the step-1 arithmetic is ordinary M31 arithmetic:

```text
1381993681² + 7 = 1909906534323929768
                 = 889369535 · 2147483647 + 1771435623
```

The checked Python acceptance fixture independently repeats that calculation
for all four lanes and compares every generated statement.

## Exactly what the AIR constrains

Let `R` be the fold root guessed by the circuit, `n` the guessed `u32`
step, `S0` the initial four M31 words, `S` the current state, and `P` the
previous state. Let `base` be a private Boolean and `recurse=1-base`:

```text
lo,hi ∈ u16; n = lo + 65536·hi as an ordinary integer
base · (base - 1) = 0
z = lo + hi
z · base = 0
(z + base) · inverse = 1
recurse = 1 - base
borrow · (borrow - 1) = 0
prev_lo = lo - recurse + 65536·borrow, with prev_lo ∈ u16
prev_hi = hi - borrow, with prev_hi ∈ u16
previous_step = prev_lo + 65536·prev_hi

for each lane i:
    next_i = step(P_i) = P_i · P_i + 7 mod (2³¹ - 1)
    S_i = S0_i + recurse · (next_i - S0_i)

child_root   = base ? root(K1) : R
child_output = base ? D1 : G(R,previous_step,D1,S0,P)
verify_STARK(child_proof, child_root, child_output)
public_output = G(R,n,D1,S0,S)
```

`S0`, `S`, and `P` are individually range constrained to M31. Since
`z≤131070<p`, the product and inverse equations force the base branch at
step zero and the recursive branch at every positive step. The two range
checks force `borrow=1` exactly when a positive step crosses a zero low
limb: at `n=65536`, the predecessor is `lo=65535, hi=0`. At zero the base
branch is forced, so the `u32` predecessor always decreases by one and a
valid recursive proof must eventually reach the base case. At
step zero the lane equation reduces to `S=S0`; at a positive step it reduces
to `S=step(P)`. The child verifier constrains its commitments, transcript,
LogUp, FRI and proof-of-work inputs, just as in the [recursion chapter](recursion.md).
The hash gadget packs the constrained low and high limbs as an exact `u32`
word; it does not reduce the counter modulo M31 before hashing.

Here are actual counter witnesses at the carry boundary. The circuit checks
each column's equations and `u16` ranges; the numbers are integers before
they are embedded in M31.

| Public step `n` | `lo` | `hi` | `base` | `recurse` | `borrow` | `prev_lo` | `prev_hi` | Proved previous step |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | base proof |
| 65,535 | 65,535 | 0 | 0 | 1 | 0 | 65,534 | 0 | 65,534 |
| 65,536 | 0 | 1 | 0 | 1 | 1 | 65,535 | 0 | 65,535 |
| 65,537 | 1 | 1 | 0 | 1 | 0 | 0 | 1 | 65,536 |

For `n=65,536`, `prev_lo=0-1+65,536·1=65,535` and
`prev_hi=1-1=0`. Choosing `borrow=0` would require `prev_lo=-1`, outside
`u16`; choosing `borrow=1` at `n=65,537` would require `prev_lo=65,536`,
also outside `u16`. At `n=0`, the base branch makes `recurse=0` and
`borrow=0`. These range checks rule out wrapping the counter while moving
to the child proof.

Each scalar equality, multiplication, range check and hash gate is lowered
to the circuit AIR components. For one lane, the transition constraint
polynomial is

```text
C = S - S0 - recurse · (step(P) - S0).
```

On a valid trace row, `C=0` in M31. The prover interpolates the trace
columns into polynomials, commits to their evaluations, and proves the AIR
identities using the same machinery explained in [AIR and polynomials](air.md).
For this example, `step(P)=P²+7`. Each body operation becomes an addition
or multiplication gate before this equality. The transition is genuinely
inside that proof; the host's independently
computed `nextState` is only a witness-generation and cross-check step.

## A different function by hand

The [second source file](../examples/affine_square4.s31) defines
`step(v)=3v²+5` and `iterate<3>(step,x)`. The source step is the ordered
list `[square, mul_const(3), add_const(5)]`. Its first lane starts at 1:

```text
base round 1: 3·1²+5       = 8
base round 2: 3·8²+5       = 197
base round 3: 3·197²+5     = 116432
fold step 1:  3·116432²+5  = 40669231877
                             = 18·2147483647 + 2014526231
```

A fifth application is carried by the next proof. In the
general circuit, the per-lane transition is
`C=S-S0-recurse·(3P²+5-S0)=0`. The base proof certifies three rounds;
fold step 2 certifies five rounds in total. See the
[general acceptance fixture](../acceptance_state_fold_general.py) for all
four lanes and adversarial claims. The [current u32 geometry record](../../../../design/s31/measurements/state-fold-u32-v3-2026-10-07.json)
shows that this three-operation step stays within the original padded AIR
sizes; the extra raw arithmetic rows are small compared with the embedded
STARK verifier.

## Public binding and the self-key

The fold digest includes every item in a fixed-width slot:

```text
G(R,n,D1,S0,S) = Blake2s-256(person="S31STF2!",
    R[32 bytes] || LE32(n) || LE32(D1[0..8]) ||
    LE32(S0[0..4]) || LE32(S[0..4]))
```

That is a 100-byte message over two BLAKE2s blocks. The circuit guesses
`R` to avoid putting its own preprocessed root into its own AIR. The native
verifier uses the **actual sealed** root of `KS` when recomputing `G`.
The statement also carries `W0`; the native verifier requires
`S0=W0[4..8]`, recomputes `D1` from exact `K0` bytes and `W0`, and checks
`G` before verifying the top STARK. In a recursive branch, the AIR binds
the same `S0` into the previous proof's expected digest. This prevents a
prover from swapping the initial state mid-chain under the hash assumption.

The installed prover rejects supplied `K0`, `K1`, or `KS` bytes that differ
from its sealed package. Key generation rederives `K1`, constructs the
state-fold AIR, and checks that its padded child-proof geometry equals
`K1`'s. A single-step wrap compares value-bearing and witness-free gate
lists before and after padding; a batch reuses the first sealed padded
topology and compares every later padded value circuit gate by gate. Both
paths check circuit satisfaction and the key root, then natively verify the
newly produced proof. The native top verifier needs
only that proof and statement; earlier proof files can be deleted. The
[acceptance fixture](../acceptance_state_fold.py) challenges repaired false
state, step, leaf and initial-state claims; corrupt proof bytes; a changed
step key; and 18 or 19 direct in-circuit mutations per branch, including
child transcript roots, sampled trace values, Merkle paths, claimed sums
and FRI data. This is
an engineering argument under STARK and BLAKE2s assumptions, not a formal
cryptographic audit.

## Reproduce it

```sh
python3 src/frontends/s31/s31.py build \
  src/frontends/s31/examples/arith4_m31.s31 --out zig-out/s31/arith4-state-fold
python3 src/frontends/s31/s31.py prove zig-out/s31/arith4-state-fold \
  src/frontends/s31/examples/arith4.valid.json zig-out/s31/state-leaf.proof
python3 src/frontends/s31/s31.py wrap zig-out/s31/arith4-state-fold \
  zig-out/s31/state-leaf.proof zig-out/s31/state-base.proof
python3 src/frontends/s31/s31.py state-fold-base zig-out/s31/arith4-state-fold \
  zig-out/s31/state-base.proof zig-out/s31/state0.proof
python3 src/frontends/s31/s31.py state-fold-next zig-out/s31/arith4-state-fold \
  zig-out/s31/state0.proof zig-out/s31/state1.proof
python3 src/frontends/s31/s31.py verify-state-fold zig-out/s31/arith4-state-fold \
  zig-out/s31/state1.proof
python3 src/frontends/s31/s31.py state-fold-advance zig-out/s31/arith4-state-fold \
  zig-out/s31/state1.proof zig-out/s31/state4.proof --steps 3 \
  --checkpoint-dir zig-out/s31/state-checkpoints
python3 src/frontends/s31/acceptance_state_fold.py
python3 src/frontends/s31/acceptance_state_fold_general.py
```

`state-fold-advance` validates the package once. Its native batch path
reuses the preprocessed circuit, commitment and sealed padded topology.
It checks each child proof and compares each fresh value circuit gate by gate
against that topology. It
natively verifies the final proof. With `--checkpoint-dir`, each
intermediate proof and statement is kept as `state-00002.proof` and so on;
passing one of those proofs as the next input resumes from that step. The
command checks the `u32` counter bound before starting, limits one batch to
65,536 proofs, and refuses to
overwrite an existing proof or statement.

## Choose the FRI schedule

The default gate package uses one FRI fold per commitment. Build a separate
package with four folds per commitment when recursively proving many steps:

```sh
python3 src/frontends/s31/s31.py build \
  src/frontends/s31/examples/affine_square4.s31 \
  --out zig-out/s31/affine-square4-fri4 --fri-fold-step 4
```

The four-fold setting keeps 26 proof-of-work bits, blowup factor 2, and 70
queries. It changes the FRI transcript and proof shape, so it is sealed into
the package manifest and verification key. A proof from one schedule cannot
be verified under the other. The leaf AIR can have the same preprocessed root
in both packages, while the recursive AIR and all recursive keys differ.
This is a protocol choice made at build time, not an optimization a verifier
may silently apply to an existing proof. The [FRI schedule acceptance
fixture](../acceptance_fri_fold_step.py) checks both leaf verifiers,
cross-schedule rejection, and the manifest binding.

For the affine-square source, the four-fold verifier circuit has 5,589,622
raw variables and 9,811,780 padded variables, versus 11,823,705 and
19,642,180 with one fold. The exact [cost map](../../../../design/s31/RECURSION_PERFORMANCE.md)
shows which verifier phase shrinks. These are circuit sizes; the local timing
and memory comparison is in the [measurement record](../../../../design/s31/measurements/fri-fold-step-v1-2026-10-07.json):
the three-step batch's local median wall time fell from 10.819 to 6.457
seconds and median peak RSS from 9.46 to 5.09 GB across four runs per
schedule. The retained PoW, blowup, and
query counts do not by themselves constitute an independent FRI soundness
analysis.

`audit-state-fold-base` and `audit-state-fold-next` test the base selector,
zero-test inverse, predecessor counter, current state, selected root,
child output, transition input, and ten captured child-proof fields directly
in the circuit, including the interaction and FRI proof-of-work nonces.
`--low-memory`
on either wrap command trades some proving time for memory: one local step-3
sample took 3.62 s and 9.31 GB peak RSS normally, versus 3.82 s and
7.00 GB in low-memory mode. Both paths produced the same 550,173-byte
proof. The native top verifier took 0.07 s wall and 205 MB in that local
sample. These are single-machine observations, not speed guarantees.
That sample used the original v1 square/add key; v2 bound the ordered body,
and v3 widened the counter. Each version has different key and proof bytes.
`inspect-state-fold PACKAGE` rebuilds the AIR and reports raw rows and
padding headroom. It also reports cumulative gate counts at 24 points from
proof-witness creation through Merkle and FRI checks to finalization. In the
affine-square fixture, Merkle and FRI decommitments account for 91.97% of
the fold's raw variables; the state digest itself adds 664. These are circuit
counts, not direct time or memory measurements. The
[cost map](../../../../design/s31/RECURSION_PERFORMANCE.md) records the
next efficiency targets and their soundness conditions. Compared with
`inspect-fold` on the same square/add source, this
state transition adds only 48 raw variables, 4 equality rows, 32 QM31
operation rows, and 16 M31-to-u32 rows; its triple-XOR and Blake-G raw row
counts do not change. Both AIRs occupy the same padded component sizes.
The [v1 historical measurement](../../../../design/s31/measurements/state-fold-v1-2026-10-07.json)
contains the original square/add geometry and sampled timings. The
[v2 performance record](../../../../design/s31/measurements/state-fold-general-v2-2026-10-07.json)
and [v3 counter record](../../../../design/s31/measurements/state-fold-u32-v3-2026-10-07.json)
separate earlier local timing samples from the current counter geometry.

The current step extractor covers a four-lane M31 recurrence composed from
square, add-constant, and multiply-constant operations. It does not yet
compile an arbitrary S31 function into
the fold or handle Bitcoin's 80-byte header state, SHA256d, target rule and
sparse-wide proof profile. The state-fold AIR shows the interface those
larger transitions need: a typed state, a constrained transition, and a
public digest binding the initial and current states under one key.
