# Shared polynomial compiler and focused build ownership

Four generic compiler modules moved out of experimental materialization-cost
ownership: `direct_polynomial_graph.zig`, `direct_polynomial_program.zig`,
`fixed_polynomial_program.zig`, and `typed_poseidon2_fixed_polynomials.zig`.
Production degree-bounded components and experimental cost/search tools now
consume these same pure owners. All 27 import consumers migrated; no compatibility
facades or duplicated implementation remain. Scope/domain/digest constants and
executable bodies are unchanged after import rebinding, checked against retained
original source.

The production proposal guard remains strict. Generic compiler owners have no
proposal-authoring exemption and their transitive closure excludes experimental
cost/search modules and witness generation. The adversarial fixture rejects a
proposal import from the new compiler owner. One explicitly named test root may
collect the existing compiler/cost-parity tests; no production consumer received
proposal authorization.

Focused build registration now uses an ordered catalog of 111 specifications,
preserving every root, filter, import capability, count floor and order exactly.
The build constructor stays in build.zig, whose size falls from 1,263 to 460 lines.
All 111 steps appear in standalone build help and the focused compiler target
executes through the catalog. The test inventory keeps every import and replaces
its redundant historical introduction with the current discovery contract.

Validation: 143 compiler/candidate tests, 43 proposal/product ownership tests,
and both inventory tests pass. Final compiler validation reused its binary and
ran in 189 ms; no full suite or complete proof was repeated for unchanged bodies.
The prior complete-proof/continuation checkpoint remains in
`../typed-final-authority-v1`; this report does not assign a new proof run to the
post-checkpoint owner move.

Repository source-conformance findings fell from 120 to 112. All six proposal
ownership findings are closed; the frontend build and test-inventory ceiling
findings are closed. The remaining findings are 105 manual-source ceilings, two
build-support ceilings and five command-owner ceilings. No baseline was updated
to suppress them. Broader baseline cleanup and Linux artifact-store qualification
remain open; speed research is still deferred.
