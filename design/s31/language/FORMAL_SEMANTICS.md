# S31 normalized semantics and constraint proofs

## Contract

Formalize every operation currently admitted by S31 relation IR v1, including
failure cases, fixed-width signed and unsigned arithmetic, array shapes,
hash encodings, static repeats, assertions and the eight-word public ABI.
The normalized relation is the semantic boundary; text specialization and
canonicalization must agree with it but are not assumed formally verified.

Reuse the existing Lean M31 model and local proof infrastructure through a
local Lake dependency. Keep S31 specifications and proofs in a separate
`formal/s31/` package, grouped by semantics, gadgets and evidence. Do not copy
field implementations or import the whole RISC-V frontend theorem surface.
The toolchain stays pinned to the existing Lean 4.29.0.

Every admitted operation must have an executable semantics and an explicit
coverage entry. New operations, changed source identities or missing proofs
must fail the gate. Hash constants are generated from pinned repository assets
and checked byte-for-byte. No uninterpreted hash callback may be presented as
complete executable semantics.

## Proof obligations

For individual arithmetic constraint gadgets, prove both soundness for
arbitrary satisfying auxiliary witnesses and completeness by constructing
honest witnesses. Keep integer range premises explicit and prove the bridge
from bounded M31 equations to integer equations. Prove Boolean selection,
zero testing, inversion, carry/borrow chains, checked/wrapping arithmetic,
signed interpretation, comparison, array operations and public bindings.
Reuse the existing Poseidon S-box residual proof where applicable and compose
round/encoding semantics through the same local arithmetic primitives.

The equations in a formal gadget must be inspectably matched to production
gadget equations. A value interpreter or equality-by-definition theorem alone
cannot certify production compilation. Coverage distinguishes executable
operation semantics, proved local constraint relations, and production
compiler/AIR correspondence. Claims remain bounded to actually checked
theorems; arbitrary-trace LogUp composition, alternative AIR lowerings,
Zig machine-code correctness, STARK soundness and zero knowledge remain
separate obligations.

## Evidence and hygiene

Build every S31 Lean source, audit theorem axioms, reject proof escapes and
check exact operation inventory and source bindings. Include constructive
non-vacuity witnesses, invalid-boundary cases and mutation controls.
Use semantic parity cases against the existing independent Python oracle,
covering all operations and each checked arithmetic failure. Parity tests
are regression evidence, not a compiler-correctness theorem.

Keep generated constants/fixtures identifiable with a deterministic generator;
keep caches, Lean binaries and raw build logs outside tracked sources.
Use focused scripts and a dedicated CI lane. Proof checking runs at build/CI
time and does not add proving-time constraints or change source/key identity.
Document all assumptions and uncovered correspondence boundaries in the
package README and PR. Keep the existing research draft status.
