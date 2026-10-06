# Fixed-key S31 fold: design and soundness obligations

Status: design draft, 2026-10-07. The shipped [two-level chain](../../src/frontends/s31/docs/recursion-chain.md) uses distinct sealed keys `K1` and `K2`. This document specifies the next experiment: one wrapper key that can verify a base wrapper proof or an earlier proof made under **itself**. No command in the current package claims this behavior yet.

## Target relation

Let `P1` be a first-level S31 wrapper proof with public digest `D1` and sealed key `K1`. Let `R1` be `K1`'s preprocessed root. Let `KF` be the proposed fixed-fold key and `RF` its root. `L1` and `LF` must have exactly the same child-proof layout and PCS parameters, so one in-circuit STARK verifier can check either proof type. Key generation rejects a program when this geometry equality does not hold.

The fold statement exposes a step count `n` in `[0, 65535]`, the original eight public leaf words `W0`, and `D1`. The native verifier checks `D1 = Blake2s(person="S31RCV2!", SHA256(K0) || LE32(W0))` and verifies the final fold proof against `KF`. The fold proof's eight public words are:

```text
F(R, n, D1) = Blake2s-256(person="S31FOLD1",
    LE32(R.word[0] XOR n) || LE32(R.word[1..8]) || LE32(D1[0..8]))
```

`F` uses one 64-byte Blake2s block. For a fixed `R`, the XOR encoding of the 16-bit `n` in the first root word is injective. `D1` remains eight raw `u32` words, including values above the M31 modulus. The native verifier computes `F(RF,n,D1)` with the **sealed actual** `RF`, never a root chosen by the proof statement.

The fold circuit guesses `R`, `n`, `D1`, a child proof and one branch bit `base`. Its constraints enforce:

```text
base ∈ {0,1}
n · base = 0
(n + base) · inv = 1
recurse = 1 - base
prev = n - recurse, with prev ∈ u16

child_root   = base ? R1 : R
child_output = base ? D1 : F(R, prev, D1)
verify_stark(child_proof, layout=L1, child_root, child_output)
output = F(R, n, D1)
```

The inverse equation makes `n+base` nonzero. With `base` Boolean and `n` range constrained, `base=1` exactly when `n=0`; no witness can choose the base branch at a positive step or the recursive branch at zero. `prev` decreases by one on every recursive branch. The child proof layout and verifier circuit are identical in both branches; only root and output wires are selected.

## How the apparent key cycle is avoided

`RF` cannot be compiled as a constant inside its own AIR and then hashed into `KF`: that would ask for a cryptographic fixed point. The fold circuit therefore treats `R` as a guessed value. Its output hash binds `R`, `n` and `D1`. At the outermost boundary, the generated native verifier recomputes the expected output using `KF`'s actual `RF`. Under BLAKE2s collision resistance, an accepted top proof cannot use a different `R` or change `n` or `D1` without changing that public output. In a recursive step, the circuit checks a child proof under this same `R` and expects `F(R,n-1,D1)`.

This mechanism requires more than a root value in a JSON file. The native verifier embeds `KF`, checks its profile, component layout, PCS configuration, root and circuit hash, and rejects an unsealed key. `K1` and `KF` must be produced by a trusted build from pinned AIR assets. The prover rebuilds the fold topology without witness values and compares the full gate lists before proving.

## Soundness argument to audit

For `n=0`, the fold AIR verifies a `P1` proof under the fixed `R1` and public `D1`; the existing first-level wrapper then verifies the S31 leaf. For `n>0`, it verifies a `KF` proof whose public output is `F(RF,n-1,D1)`. The range-constrained counter decreases, so induction reaches the base case. This argument depends on the soundness of the outer and child STARKs, correct in-circuit verifier and proof conversion, binding of the actual `RF` by the top native verifier, collision resistance of the public hash, and the integrity of the sealed build artifacts. It is an engineering argument, not a formal proof or independent audit. The base/inductive shape follows the classic [incrementally verifiable computation construction](https://iacr.org/archive/tcc2008/49480001/49480001.pdf), while the concrete hash/root relation here is S31-specific.

The test gate must include: base step accepted; at least three repeated steps under exactly one `KF`; a `D1` containing `u32` words above the M31 modulus; wrong step and wrong leaf claim with all host digests recomputed rejected; wrong child root, child output, FRI opening, channel salt and proof bytes rejected; a forged branch bit or zero-test inverse rejected inside the circuit; key and projection substitutions rejected; identical NoValue/value topology; and a top proof that verifies after all lower proof files are removed. Measure key generation, per-step proving, top verification, proof bytes and peak RAM separately.

## Product boundary

This fold only repeats proof verification of the same leaf claim. A Bitcoin light client needs an additional constrained state transition: verify the next header's SHA256d and target rule, link its previous-hash field to the carried tip, update work/height/state, and bind those values in `F`. The sparse-wide Bitcoin proof profile also needs an exact in-circuit verifier or a sound circuit-to-chip boundary before it can be the base child. The fixed-fold experiment must not be described as a Bitcoin light client until those relations and their adversarial tests exist.
