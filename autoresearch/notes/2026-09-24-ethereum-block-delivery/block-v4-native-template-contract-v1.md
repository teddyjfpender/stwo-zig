# Native template authority contract (proposal, v1)

`block_v4_native_template_contract_v1.zig` separates a proposed invariant
template identity from one segment's exact claims. It is a pure hashing and
equality layer. No producer, verifier, manifest, or proof route consumes it yet;
it does not qualify a reusable verification key or establish proof authority.

The template hashes AIR semantics, PCS security configuration, exact component
geometry, and a proposed fixed-column root. The instance hashes the template
ID together with the independently admitted job, SourceSeal, segment ordinal
and statement, native public data, exact commitment plan, sealed first-round
roster, and verified global closure. `validateBound` compares these identities
to separately supplied policy pins and fresh verifier bindings. A production
caller would have to derive the pins independently of the proof bundle, fresh
verify every proof, and establish global memory/program closure before calling
it. The module deliberately returns no `CompleteBlock` or proof receipt.

The current native Tree0 is **not** invariant across blocks or segments:

- `blake3_commitment_shared_emit.zig` publishes plan-specific program
  address/multiplicity/value rows, memory boundary address/clock/namespace
  rows, and paired Merkle path topology. Its fixed root changes with the plan.
- `blake3_execution_protocol.zig` publishes `is_active` selectors from each
  opcode/clock component's exact `n_rows`; `is_first` depends on its log size.
- `guest_precompile/ethereum_preprocessed.zig` uses exact Keccak and signer
  call counts, and `air/guest_precompile/sha256_preprocessed.zig` zeros padded
  rows according to the exact SHA call count. Thus even without custody,
  existing fixed columns support reuse only for matching geometry/counts.
- `blake3_extension_prepared.zig` combines those columns into one PCS root,
  then binds it with the full public statement and plan in the current
  B3SK/B3CK key ID. Neither that root nor ID is a template identifier.

A later versioned AIR could move per-leaf RW/program custody to the globally
verified block relations and use setup columns independent of the instance.
Exact row/count selectors would still require a template per geometry unless
activity is moved into constrained dynamic columns. Its proof transcript must
bind the complete instance ID before relation challenges. Until that proof
route and its fresh receiver exist, this contract is diagnostic foundation only.

`blake3_native_prepared_template_v1.zig` is a narrower preparation experiment
for the existing AIR. It retains actual native opcode/table and Ethereum/SHA
fixed-column buffers for one exact geometry, plus their **partial** PCS root.
For every admitted plan it regenerates the BLAKE3 custody columns, commits the
complete current Tree0 in canonical column order, and derives the existing
B3CK key ID and a separate versioned instance ID binding plan, public data,
compact range geometry, and complete fixed root. The partial root is never
substituted for Tree0. The API returns preparation data only and is not used by
the producer or verifier. Two-plan parity against fresh `PreparedVerifier`
preparation is its qualification gate; the second plan is structurally
admitted with a changed public program multiplicity, not asserted to have a
valid execution proof. No proof-key reuse is claimed.

The focused q8 two-plan preparation test passed 8/8. Its cached complete
Tree0 roots and current B3CK IDs exactly matched separate fresh canonical
preparations for both plans; changing only public register state kept the
complete root and changed the key ID. On that tiny SHA fixture, template setup
took 43.46 ms and retained 12,980,622 bytes; three instance preparations took
69.59, 69.09, and 68.17 ms. The setup-plus-instance tracked peak was
129,641,328 bytes versus 129,646,376 bytes for one fresh canonical preparation.
This is a scoped diagnostic, not a throughput or proof-time benchmark: the
plan-dependent BLAKE3 custody work still dominates each preparation.

## First proof-producing redesign slice

The existing `blake3_extension_proof.zig` already has a joint-manifest
challenge path, but block-v4 currently calls its local `proveReplaying` path.
`blake3_execution_components.zig` binds the whole BLAKE3 commitment family,
and `requireClosedWithExternal` checks all relation sums inside each leaf. A
versioned block-native route must change those points together: omit the
plan-dependent program and RW custody columns/components from each leaf,
derive shared relation challenges only after all first roots are sealed, and
defer their program/memory residuals to fresh block-wide providers. Merely
deleting fixed columns or skipping the local closure check is unsound.

The smallest staged implementation is: (1) a versioned native statement/key
and proof assembly that excludes the per-leaf `blake3_public_program` fixed
rows and interactions while retaining RW custody; (2) one block-wide
program provider with multiplicities committed before the shared challenge,
authenticated against the complete decoded ROM root, and exact program-claim
closure; (3) removal of RW custody only after the native memory relation is
matched to the existing PCS-bound opcode/extension sidecars and sorted-memory
closure under the same sealed challenge. Stage (1) reduces repeated program
work but does **not** create a reusable whole key because RW fixed rows remain
dynamic. Stage (3) enables a template keyed by exact opcode/extension geometry.

An initial real fixture can run the same small `LUI; LW; ADDI; self-loop` ELF
twice with different initialized data words. Both executions have identical
opcode/profile geometry but different public RW roots and register outcomes.
Fresh native v5 proofs and block-wide program/memory providers must verify
under one template ID; swapping either public statement, omitting a fetch, or
omitting an access must fail. This is a design target, not a qualified proof.
