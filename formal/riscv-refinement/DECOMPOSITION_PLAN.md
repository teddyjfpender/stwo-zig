# RISC-V refinement source decomposition plan

The FV-1/FV-2 promotion expands several manually maintained Lean files beyond
the repository's 850-line soft ceiling. They remain cohesive during the
promotion because module boundaries and source digests are receipt inputs: a
large move mixed into the semantic change would obscure which proof obligation
changed and would invalidate every downstream bridge artifact at once.

This is a temporary review exception, not a permanent file-size waiver. After
the first exact publication receipt is reproducible, perform the following
behavior-preserving split as a dedicated follow-up. Each step must preserve
public theorem names and compare the full axiom inventory before and after.

One performance-driven split has already been completed during promotion:
the shared shift-I encoding reduction remains in `DecodeAluShift.lean`, while
SLLI, SRLI, and SRAI have independent certificate modules and an import-only
`DecodeAluShiftCertificates.lean` umbrella. This replaced one declaration
that exceeded the ten-minute kernel-build guard with three bounded artifacts;
all four paths are explicit receipt inputs.

The promotion also keeps new proof growth out of the decoder leaves:
`DecodeControlState.lean` and `DecodeMemoryState.lean` contain the concrete
state-indexed success certificates, while their existing encoding-reduction
modules remain below the ceiling. `MulDivArithmetic.lean` isolates the eight
generated-to-reviewed arithmetic value bridges from the M-extension decoder
and publication surface. All three boundaries occur explicitly in the
ordered receipt source closure.

1. Split `generated-sail-bridge/Pilot.lean` into a small observation core and
   opcode-family normalizer modules for register ALU, control flow, memory, and
   M-extension operations. Keep `Pilot.lean` as an import-only compatibility
   root.
2. Split `generated-sail-bridge/Composition.lean` into generated decode/state
   contracts, row-local execution closure, full-step trace erasure, and the
   neutral publication result type. Keep the full-step proof isolated from
   opcode-family declarations.
3. Split the large load/store production proof at its existing semantic
   boundaries: direct constraints and selector recovery; field-to-integer
   consequences; fixed-table projection; relation projection; and the public
   family theorem.
4. Split multiplication into production evaluation/node projection,
   bounded-node lifting, arithmetic semantics, and publication. Continue the
   same split for the remaining large high-multiply and division AIR/semantic
   modules.
5. Replace legacy contributor-named import paths with neutral family paths in
   one mechanical migration. Leave forwarding imports only for a documented
   compatibility window, then remove them after downstream users migrate.

The decomposition gate is:

- no theorem statement or namespace identity changes in a move-only commit;
- byte-identical production AIR and selector-source inventories;
- identical per-theorem `#print axioms` output;
- the exact 94-record generated-Sail bridge receipt still validates; and
- no manually maintained leaf created by the split exceeds 850 lines without
  a new, narrower written exception.
