# S31 normalized semantics and local constraint proofs

This package gives executable Lean semantics for **all 43 operations in S31
relation IR v1** and proves the local constraint models sound and complete.
It reuses `RiscvRefinement.Field.M31` and the existing
`RiscvRefinement.Recursion.CompactPoseidon` S-box proofs through a local Lake
dependency. The [contract](../../design/s31/language/FORMAL_SEMANTICS.md) fixes
the boundary and evidence requirements.

The normalized typed relation is the language boundary. The model covers
metadata validation, shapes, canonical input values, public/private
assignments, arithmetic failures, assertions and claimed public outputs.
Public input words precede output words and the statement is zero-padded to
eight words. Fixed widths and order are part of the source-bound statement;
padding alone cannot distinguish a trailing zero from a changed width.
Transparent and blinded proof modes have identical value semantics. That
theorem does not establish zero knowledge.

## Organization and reuse

| Location | Responsibility |
| --- | --- |
| `S31/Semantics/Types`, `Validation`, `Node`, `Program`, `Json` | Typed IR, complete operation dispatch, validation, assignment and public ABI. `Json` is an executable adapter, not a parser-correctness proof. |
| `S31/Semantics/Words`, `Integers`, `Bitcoin` | Little-endian limbs, five signed/unsigned widths, checked/wrapping operations, compact target and block work. |
| `S31/Semantics/Graph`, `Poseidon2`, `Blake2s`, `Sha256` | Explicit straight-line gate schedules and exact hash encodings. No uninterpreted hash callback is used. |
| `S31/Gadgets/` | Primitive residual proofs, arbitrary auxiliary witnesses, constructive completeness and composition. |
| `S31/Evidence/` | Checked operation coverage, non-vacuity/invalid-boundary theorems and live axiom enumeration. |
| `coverage.json` | Reviewed mapping of every operation to semantics, local gadget theorems and production source functions. |
| `source-bindings.json`, `proof-inventory.json` | Generated exact source identities and the complete theorem inventory, including the reused modules and three source-derived proof declarations. |
| `scripts/s31_formal.py`, `scripts/s31_formal_lib/` | Regeneration, escape/inventory checks, independent parity and adversarial proof controls. |

The package pins Lean **4.29.0** and Mathlib revision
`8a178386ffc0f5fef0b77738bb5449d50efeea95`. The committed Lake manifest pins
transitive dependencies. Generated hash constants come directly from the
repository's Poseidon2, SHA-256, BLAKE2s and genesis assets. S31 uses the
existing canonical M31 implementation rather than copying field arithmetic;
`Gadgets/Field` proves its bridge to `ZMod 2147483647` and kernel-checks
primality.

## Proven local obligations

Soundness quantifies over every satisfying auxiliary witness. Completeness
constructs witnesses for every input within the stated range and shape
premises. Honest-witness evaluation alone is insufficient for soundness.

| Gadget family | Main results |
| --- | --- |
| Field arithmetic and zero anchors | Residual equations iff addition, multiplication, equality or zero; canonical M31/ZMod bridge and inversion iff nonzero. |
| Boolean operations and selection | Bit equation iff 0 or 1; NOT, AND, OR, XOR, scalar/Boolean selection; zero indicator sound for every inverse witness, including the unconstrained inverse at zero. |
| Range and packing | Byte range via scaled u16; 16 Boolean bits iff u16; byte-pair packing, endian round trips and canonical digest reduction, including quotient 2. |
| Carry/borrow arithmetic | Local field equations imply integer equations; whole chains iff checked or wrapping arithmetic; reversed subtraction iff ≤ or <. |
| Signed arithmetic | Sign extraction, most-significant-limb sign, two's-complement interpretation, signed comparison, overflow predicates, composed signed checked addition/subtraction iff mathematical results. |
| Packed M31 lanes | QM31 basis multiplication, coordinate extraction, active masks, scalar multiplication, production sum projection/dual literals, `mix4`, active-lane inversion. |
| Static repeats | Pointwise primitive constraints, sum witnesses, bodies and arbitrary finite repeat counts iff the executable recurrence. |
| Hashes | Arbitrary intermediate gate witnesses iff the full Poseidon2 leaf/pair, personalized terminal BLAKE2s and header double SHA-256 results, including packing and digest reduction. |
| Bitcoin target | One-hot exponent range, byte placement, nonzero byte-sum inverse and high-zero bytes iff a positive target within mainnet's `2^224-1` limit. |
| Bitcoin division/work | Nontruncated schoolbook product, terminal carry, strict remainder, unique quotient/remainder and the exact block-work formula. |
| Wires and public bindings | Constant/alias/get/concat/slice identities, assertion residuals, fixed-width segment/padding binding, proof-mode independence. |

Range premises are explicit. A modular equation alone cannot imply an integer
equation: the bridge needs both sides below M31. For the Bitcoin multiplication
columns, the maximum is `32*255² + 255 + 65535 = 2,146,590 < 2³¹-1`.
High product digits and the terminal carry are retained, so the multiplication
proof cannot accept truncation of a 512-bit product.

The hash relation checks each primitive gate and existential intermediate
wire; its definition does not call the hash interpreter. `Graph.Accepts`
proves generic straight-line composition. Word gadgets use canonical
`BitVec 32` values, per-bit polynomial equations and an integer word-add carry
equation; the range/limb lemmas separately justify those encodings. Fixed
hash schedules are marked `irreducible` to keep elaboration from repeatedly
expanding thousands of gates; they remain explicit, executable definitions
and introduce no axiom.

## Scope of the claim

**The local mathematical constraint models are proved. Production compiler
correctness is not proved.** Source hashes and the operation map make a
manual correspondence review inspectable; they cannot establish that every
Zig lowering emits exactly those constraints. In particular, raw text/JSON
parsing and specialization, general compiler lowering, chip/direct/sparse
AIR correspondence, lookup/LogUp composition over arbitrary traces, Zig
machine code, STARK soundness and zero knowledge remain separate obligations.
The typed model constrains private values mathematically; visibility affects
the public ABI and does not itself imply witness privacy.

The Python parity corpus is regression evidence for the executable semantics,
not a proof of compiler or cryptographic correctness. Hash parity includes
Python `hashlib` and the existing independent Poseidon2 implementation.
The source inventory includes both reused Lean modules, whose theorems are
also included in the live axiom audit. Only Lean's standard `propext`,
`Classical.choice` and `Quot.sound` axioms are approved. Proof sources reject
`sorry`, `admit`, custom `axiom`, `unsafe` and `native_decide`.

## Reproduce the gate

Run from the repository root with the pinned Lean toolchain available:

```sh
python3 scripts/s31_formal.py
python3 -m unittest scripts.tests.test_s31_formal
mkdir -p zig-out/s31/formal
cd formal/s31
lake exe cache get Mathlib.Data.ZMod.Basic Mathlib.Tactic
lake build S31 s31-check
lake env lean S31/Evidence/AxiomAudit.lean > ../../zig-out/s31/formal/axioms.log
LEAN_NUM_THREADS=1 lake env leanchecker -v S31 RiscvRefinement.Field.M31 RiscvRefinement.Recursion.CompactPoseidon > ../../zig-out/s31/formal/kernel.log
cd ../..
python3 scripts/s31_formal.py \
  --audit zig-out/s31/formal/axioms.log \
  --kernel-log zig-out/s31/formal/kernel.log \
  --parity formal/s31/.lake/build/bin/s31-check \
  --controls --report zig-out/s31/formal/evidence.json
```

`leanchecker` replays declarations with Lean's kernel; it is not a separate
proof assistant. One worker bounds memory without reducing its checks. The
gate requires exact replay and theorem inventories, builds every `S31.*`
source, rejects missing evidence, and compiles valid controls before requiring
invalid controls to fail. It also alters actual byte-range, carry-base and
signed-overflow definitions and requires their original proofs to fail.
Temporary mutations never alter repository sources.

The dedicated [CI workflow](../../.github/workflows/s31-formal.yml) runs these
steps without a skip path and preserves live evidence. Caches, binaries and
raw logs are ignored build artifacts. After a reviewed semantics/source
change, regenerate with `python3 scripts/s31_formal.py --write`, inspect the
diff and rerun the full gate. Regeneration updates identities; it does not
prove a new correspondence obligation. Formal checking adds no constraints
or work to the production prover.
