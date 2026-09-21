# Canonical native RISC-V and detached recursion authority boundary

This audit covers terminal RV32IM execution with public I/O, resumable native
segments, and the canonical detached recursive tree. Ethereum circuit variants,
experimental provider layouts, and production-security parameters are separate
contracts and are not admitted by this report.

## Shared execution and public statements

`runner/mod.zig:runConfigured` uses `ExecutionSession`; terminal execution is
not a second interpreter. `prover/statement_geometry.zig:buildV2` shares
`populate` with terminal statement construction. Terminal V1 statements bind
actual public input/output entries; the current resumed V2 projection has a
different public-data envelope. Those APIs preserve explicit contracts while
sharing execution, typed opcode geometry and component assembly. Removing the
V1 name without migrating its I/O contract would remove functionality.

## Typed equation ownership

The production opcode path excludes retired equation oracles under the source
closure guard. Native infrastructure now has one exhaustive admission owner,
`air/native_infrastructure_typed_admission.zig`, covering all eleven registry
kinds. Program, memory and clock use independent typed definitions; program and
memory also check the fixed/full-state policies. Six table kinds bind the typed
lookup tuple, multiplicity, schema geometry and interaction recurrence. Merkle
has independent typed direct equations and ordered provider effects.

Wide Poseidon uses the existing typed permutation and degree-three plan. The
shared bound program supplies the exact physical slot map to witness authority
and independent physical equation lowering. A pure relation contract supplies
ordered events to production relation generation and cold equation admission.
The lowered definition imports neither the native equation kernel nor witness
machinery. Admission compares every direct root, event field and LogUp recurrence
symbolically, including arbitrary invalid/inactive rows. Compact recursive
Poseidon retains its separately qualified typed layout.

Both ordinary native proof finalization and verification invoke the same
infrastructure admission owner. Recursive VM profiles invoke that owner during
native-capture and cold-source reconstruction. The registry switch is exhaustive;
a newly added kind requires an explicit authority decision. Allocation failure
cannot create a partial admitted specialization.

## Canonical recursion path

CPU/Metal leaf commands share detached leaf production; parent commands share
a dedicated parent-producer module. Native ingress, workloads, shared preparation,
publication and verifier transaction owners are separated from historical test
harnesses. Retired alternate component admission, executable wrappers and public
exports are guarded by source tests. Retained test-only oracles do not constitute
additional production authority.

## Qualification status

The prior boundary batch is fully qualified in `../typed-boundary-authority-v1`.
The wide-Poseidon batch passed focused equation/mutation/allocation tests, relation
parity, witness parity and cold profile tests. Final complete-proof qualification
passed 384 checks; the useful 1/2/4/8 continuation ladder passed 1,110 checks on
the same source and binaries. See summary.json and ladder-summary.json. Protocol identity remains separate from source/build provenance;
no key or golden proof is regenerated merely to accept these implementation edits.
