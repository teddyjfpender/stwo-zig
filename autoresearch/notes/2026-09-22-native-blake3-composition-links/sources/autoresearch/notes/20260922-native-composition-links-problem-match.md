# Native BLAKE3 composition challenge join

Task and required semantics: connect canonical BLAKE3 transcript challenge exports
to existing native V2 composition scalar inputs without fixture relation aliases.
Inputs/model: authenticated VM composition graph bindings and evaluations; semantic
transcript exports. Fixed scale: 12 relation pairs times 8 coordinates, plus four
composition-randomness and four OODS coordinates = 104 scalar links.
Constraints: every coordinate exactly once; all destinations are canonical graph
inputs; source endpoint coordinates canonical and disjoint; no witness-derived
fixed schedule. Missing, duplicate or wrong-family roles fail closed.
Canonical problem: exact finite keyed join, using direct-address arrays. Linear
scan of exports and bindings, O(graph size) use-count scratch and O(104) links.
Prior implementation: blake3_challenge_links (fixture-only secure inputs), native
vm_air_composition_prepared_v2, scalar_wire_source.routedRow, shared arithmetic
lowering use counts. These local canonical implementations define the mandated
transfer; no new cryptography or algorithm is introduced.
Selected transfer: reuse native composition recorder and scalar routing AIR;
consume each transcript scalar once and emit with graph-derived multiplicity.
Rejected: reinterpret native pairs as universal relations or pin challenge values
in preprocessing. End-to-end prediction: integration only, no speedup claim.
Falsifier/validation: real verified BLAKE3 segment capture must satisfy native
composition graph; all 104 routes admitted, missing/duplicate exports rejected.
Open uncertainty: native public-boundary and remaining claim/sample joins still
needed before this becomes a complete recursive parent proof.
