# One key for repeated sparse-wide proof verification

The [sparse-wide chain](recursion-sparse-wide.md) verifies a wide-integer or
Bitcoin-header proof twice, but those two wrappers have different AIR keys.
This chapter adds a third verifier AIR whose **same sealed key** can prove
step 0, step 1, step 2, and later steps. It folds a fixed claim about one
leaf execution. It does not add another Bitcoin header at each step.

## Follow one concrete execution

[`wide_order.s31`](../examples/wide_order.s31) checks a private 256-bit sum,
comparison, and Poseidon2 commitment. Its eight public ABI words in the
checked fixture are

```text
W0 = [1516562408, 720678098, 331586352, 1266462312,
       857462184, 360942592, 889867968, 271788129]
```

The leaf `P0` has key `K0`. `P1` verifies `P0` in a circuit under `K1`, and
`P2` verifies `P1` in another circuit under `K2`. Each verifier hashes its
verified public claim with the **exact bytes** of the child key:

```text
H(K,W) = BLAKE2s-256(person="S31RCV2!", SHA256(K) || LE32(W[0..8]))
D1 = H(K0,W0)
D2 = H(K1,D1)
```

`LE32(W[0..8])` means eight unsigned 32-bit integers, each in little-endian
byte order. The preimage to each `H` is 64 bytes. The checked `D2` is

```text
[688750252, 4201526075, 1455165893, 523156567,
 1197271172, 173808460, 1837880353, 1126895954]
```

Its second word exceeds \(p=2^{31}-1\). These are **raw 32-bit hash words**,
not M31 public inputs. Truncating them to field elements would change the
verified statement.

The new fold key `KF` binds `SHA256(K2)`, the fourfold FRI schedule, the
preprocessed AIR root `RF`, its circuit hash, padded component sizes, and the
pinned AIR/projection assets. Its base proof is `P2`, under `K2`; subsequent
children are proofs under `KF` itself. The fold's public digest is

```text
F(RF,n,D2) = BLAKE2s-256(person="S31FOL2!",
    RF[32 bytes] || LE32(n) || LE32(D2[0..8]))
```

The 68-byte preimage gives the root, step, and eight base words separate
fixed-width slots. For this fixture `RF` is
`c262acf359f951f417267296f61dc6ce3bafbc411e4c807d05c0d13f801b619b`.
Here are the actual first words of the three consecutive public outputs:

| Proof | Counter | Child checked by its AIR | First word of public `F` |
| --- | ---: | --- | ---: |
| `F0` | 0 | `P2`, with `K2` root and `D2` | 1591833951 |
| `F1` | 1 | `F0`, with `KF` root and `F(RF,0,D2)` | 1732274959 |
| `F2` | 2 | `F1`, with `KF` root and `F(RF,1,D2)` | 3966118775 |

All three are proved against `KF`. The top verifier checks `F2` and a
statement containing `W0`, `D2`, the counter, and `F(RF,2,D2)`; it
recomputes `D1` and `D2` from `K0`, `K1`, and `W0`. It needs no lower proof
files. The eight-word digest is a binding of this statement under the hash
assumption; it is not a Bitcoin block hash.

## The circuit and AIR by hand

The fold circuit has a private Boolean `base`. For step `n`, it enforces

```text
base · (base - 1) = 0
n · base = 0
(n + base) · inverse = 1
recurse = 1 - base
previous = n - recurse, with n and previous range-checked as u16
```

When `n=0`, `base=0` makes the inverse equation impossible, so the circuit
must choose `base=1` and `previous=0`. When `n>0`, `n·base=0` forces
`base=0`, and `previous=n-1`. For example, at `n=2`, the M31 inverse of 2
is `1073741824`, so `(2+0)·1073741824 = 1 mod p`. At `n=1`, the selected
previous counter is 0; at `n=0`, the base branch terminates. The `u16`
range prevents underflow and bounds this implementation to steps
0 through 65,535.

The circuit selects the child verifier's root and output word by word:

```text
selected = left + recurse · (right - left)
child_root   = base ? root(K2) : RF
child_output = base ? D2 : F(RF,previous,D2)
verify_STARK(child_proof, child_root, child_output)
public_output = F(RF,n,D2)
```

`verify_STARK` here is an actual circuit gadget. It checks the child's
commitments, Fiat–Shamir transcript, LogUp claims, AIR composition,
Merkle openings, FRI folds, and proof of work. The verifier's many wire
values form trace columns; gate equations such as `c-a·b=0`, the selector
equation, range checks, and lookup closure become AIR constraints. Stwo
interpolates each trace column over the trace domain into a polynomial and
proves those polynomials satisfy the AIR. See [AIR and polynomials](air.md)
for a small filled trace and the composition/FRI calculation.

At step 0, the AIR can only use `root(K2)` and `D2` as the child verifier
boundary. At step 1, it can only use its own root and `F(RF,0,D2)`. These
are circuit constraints, not host checks added after proving. The prover
does natively authenticate the child proof first to construct its witness,
but an adversarial prover may choose arbitrary witness values. Acceptance
depends on the constrained verifier gadget and the outer STARK.

## Why a self-verifying AIR has a finite key

Writing its own root as a literal constant in the fold AIR would require
finding a hash fixed point: the root depends on the AIR, and the AIR would
depend on the root. Instead, the circuit guesses a 32-byte root `R` and
outputs `F(R,n,D2)`. The **native top verifier** recomputes the public
output using the sealed actual `RF`. Collision resistance binds the guessed
`R` to `RF`. On a recursive branch, the same guessed root is used to verify
the child proof. The decreasing counter eventually reaches `P2`, which is
verified against the fixed `K2` root. This is a computational argument under
the hash, STARK, and in-circuit-verifier assumptions, not a formal proof.

The first sparse-wide wrapper's padded layout is too small for this fold
verifier. The second wrapper's fourfold layout fits the fold's witness-free
topology **without increasing any padded component**. Key generation rebuilds
the `K1` and `K2` topologies, derives the fold topology, and rejects a
mismatch. `inspect-fold` reports the actual raw and padded rows; for
`wide_order` with fourfold leaf FRI, it reports 5,589,558 raw variables,
with 18,488 spare `triple_xor` rows before that component's next padding
boundary. Each proof checks value-bearing versus witness-free gate lists
before proving and checks its output proof natively before writing it.

The [source-key replay fixture](../acceptance_sparse_wide_fold_key_binding.py)
builds a second valid package with the same leaf AIR rows but a different
source identity. It repairs every public hash and fold-key field in the old
top statement under the second package's exact bytes. The second native
verifier rejects the old top proof **after** accepting that repaired
statement. Its [record](../../../../design/s31/measurements/sparse-wide-fold-key-binding-source-v1-2026-10-07.json)
shows distinct fold roots. The
[FRI-only record](../../../../design/s31/measurements/sparse-wide-fold-key-binding-fri-v1-2026-10-07.json)
repeats this test with identical source and leaf AIR identity but a
different child FRI schedule; top proof replay still fails.

## Reproduce and challenge it

From the repository root:

```sh
python3 src/frontends/s31/s31.py build \
  src/frontends/s31/examples/wide_order.s31 \
  --lowering sparse-wide-gate --fri-fold-step 4 --out zig-out/s31/wide-fold
python3 src/frontends/s31/s31.py prove zig-out/s31/wide-fold \
  src/frontends/s31/examples/wide_order.valid.json zig-out/s31/wide-fold/leaf.proof
python3 src/frontends/s31/s31.py wrap zig-out/s31/wide-fold \
  zig-out/s31/wide-fold/leaf.proof zig-out/s31/wide-fold/first.proof --low-memory
python3 src/frontends/s31/s31.py wrap-next zig-out/s31/wide-fold \
  zig-out/s31/wide-fold/first.proof zig-out/s31/wide-fold/second.proof --low-memory
python3 src/frontends/s31/s31.py fold-base zig-out/s31/wide-fold \
  zig-out/s31/wide-fold/second.proof zig-out/s31/wide-fold/fold0.proof --low-memory
python3 src/frontends/s31/s31.py fold-next zig-out/s31/wide-fold \
  zig-out/s31/wide-fold/fold0.proof zig-out/s31/wide-fold/fold1.proof --low-memory
python3 src/frontends/s31/s31.py verify-fold zig-out/s31/wide-fold \
  zig-out/s31/wide-fold/fold1.proof
python3 src/frontends/s31/s31.py inspect-fold zig-out/s31/wide-fold
python3 src/frontends/s31/s31.py fold-advance zig-out/s31/wide-fold \
  zig-out/s31/wide-fold/second.proof zig-out/s31/wide-fold/batch-top.proof \
  --steps 3 --checkpoint-dir zig-out/s31/wide-fold/checkpoints --low-memory
python3 src/frontends/s31/inspect_recursive_claim.py \
  zig-out/s31/wide-fold zig-out/s31/wide-fold/batch-top.proof
python3 src/frontends/s31/acceptance_sparse_wide_fold.py
python3 src/frontends/s31/acceptance_sparse_wide_fold.py --bitcoin
```

The acceptance fixture proves steps 0, 1, and 2, reproduces `KF` byte for
byte, audits fourteen altered circuit values at both the base and recursive
branches, challenges repaired false public claims and a damaged top proof,
then deletes lower proof files and verifies the top proof alone. The Bitcoin
run uses [`bitcoin_header_pair.s31`](../examples/bitcoin_header_pair.s31),
which checks two linked historical headers *within one leaf proof*.

`fold-advance` accepts a base or existing fold proof, checks all output
paths and the `u16` counter before starting, then retains the sealed
preprocessed AIR, commitment, and padded witness-free topology across steps.
It still natively verifies each child proof and compares every new
value-bearing gate list to that topology before proving. Checkpoints permit
resuming. The acceptance fixture requires byte-identical proofs and
statements versus separate commands, including a resumed run.

`inspect_recursive_claim.py` first runs the package's native top verifier,
then independently recomputes `D1`, `D2`, and the fold digest from the exact
sealed key bytes. Its JSON report names `W0`, the two wrapper digests, the
previous and current fold outputs, the leaf's typed public ABI, the FRI
schedules, key hashes, and proof size. It works after the lower proof files
are removed, making the verified public claim inspectable without
pretending to recover the private leaf witness.

The [wide-order measurement](../../../../design/s31/measurements/sparse-wide-fold-v1-2026-10-07.json)
records leaf/first/second/fold0/fold1/fold2 proof sizes of
182,891/345,589/373,568/374,579/372,837/373,231 bytes. Each fold proof
therefore stays close to the second wrapper's size. Measurements are local
samples, not guaranteed latency or a concrete-security estimate.
The [cached batch run](../../../../design/s31/measurements/sparse-wide-fold-batch-v1-2026-10-07.json)
took 5.786 seconds for three steps versus 6.578 seconds summed across
separate commands in one local sample. Its output bytes match exactly;
the timing includes command and package setup as well as proving.
The [three-trial memory record](../../../../design/s31/measurements/sparse-wide-fold-batch-memory-v1-2026-10-07.json)
measured 5.573 seconds median for the batch versus 6.420 seconds for
separate commands. Peak resident size rose from 3.736 to 3.814 GB because
the batch keeps its topology in memory. These are local macOS process
measurements, not a universal speed or memory estimate.
Reproduce that comparison with
[`benchmark_fixed_fold_batch.py`](../benchmark_fixed_fold_batch.py), passing
the built package and its valid assignment; it alternates execution order,
checks proof and statement byte equality, and records per-process peak RSS.
The [two-header Bitcoin batch](../../../../design/s31/measurements/bitcoin-sparse-wide-fold-batch-v1-2026-10-07.json)
also matches all separate proof bytes; it took 6.650 seconds versus
7.352 seconds summed across its three commands in one local run.
The [onefold child schedule](../../../../design/s31/measurements/sparse-wide-fold-fri1-batch-v1-2026-10-07.json)
also passes the same-key fold and batch checks. Its wrapper and fold
verifiers still use the sealed fourfold schedule; the leaf and first
wrapper proofs are larger than with a fourfold leaf.

## Exact claim and next boundary

For trusted `K0`, `K1`, `K2`, and `KF`, acceptance of `Fn` says a valid
`P2` exists for `D2`, then `n` prior fold proofs exist with decreasing
counters, ending at step 0. Under the assumptions above, a valid `P0`
exists for `W0`, so the compiled S31 leaf relation has a satisfying
witness. The same `W0` and `D2` are carried through every fold step.

This is **claim recursion**, not a growing Bitcoin header chain. A real
light-client fold must add a constrained state transition that consumes a
new header, checks its previous hash, target, timestamps, and accumulated
work, and publishes the updated state. Bitcoin's complete consensus rules
and a concrete recursive security analysis remain outside this prototype.
