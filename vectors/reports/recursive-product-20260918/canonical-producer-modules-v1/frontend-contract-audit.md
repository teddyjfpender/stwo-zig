# Frontend contract audit

This audit distinguishes typed equation authority from statement wire versions.
It does not certify all infrastructure providers as typed.

- `src/frontends/riscv/runner/mod.zig:runConfigured` already delegates terminal
  execution to `ExecutionSession(profile).initLegacy(...).runLegacy(...)`.
  Removing its V1-facing name would not remove a separate interpreter.
- `src/frontends/riscv/prover/statement_geometry.zig:buildV2` uses the same
  `populate` geometry constructor under an authenticated V2 envelope. Its
  explicit comment states that the typed component geometry is unchanged.
- `src/frontends/riscv/air/statement_v2_public_projection.zig` projects empty
  public-I/O entries; `src/frontends/riscv/prover/elf.zig` and the proof adapter
  construct actual V1 input/output entries. Redirecting those functions to V2
  without a deliberate public-I/O and statement compatibility design would
  remove a contract, not establish semantic equivalence.
- `src/frontends/riscv/prover/base_component_assembly.zig` is already the shared
  prover/verifier assembly owner. Its native infrastructure order contains
  program, memory, Merkle, Poseidon2, clock update, bitwise and five range kinds.
- Program/memory infrastructure uses `air/component.zig` and its interaction
  owners; Merkle uses `air/memory_commitment/merkle_node.zig:evaluateGeneric`;
  clock uses `air/clock_update_component.zig:evaluateGeneric`; lookup tables use
  `air/lookups/tables/component.zig` and their interaction owner. These direct
  generic evaluators need a component-by-component authority audit. The existing
  opcode and compact recursive Poseidon checks do not alone prove they derive
  from typed definitions or checked typed specializations.

Next engineering should establish the infrastructure authority inventory and
close any actual typed-definition gaps. A V1 public-envelope migration remains
separate unfinished compatibility work if one public statement format is required;
V1 naming by itself is not evidence of an untyped constraint implementation.
The final useful continuation ladder must qualify the finished canonical path.
