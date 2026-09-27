# BLAKE3 captures into the existing canonical FRI arithmetic graph

Task: admit BLAKE3 verifier-owned capture values into the existing production FRI
arithmetic circuit without coupling field arithmetic to Poseidon digest storage.
Inputs: independently chosen FRI profile and successful verifier capture. Check
raw query order, each layer's folding schedule/positions/shape and canonical
field values; own all arithmetic data so later capture mutation cannot alter it.
Canonical match: exact validated representation conversion, then reuse the
existing canonical FRI arithmetic DAG (circle-to-line, line folds, last layer).
Existing captured_fri_owned.zig mixes this arithmetic with Poseidon-specific
Merkle storage; use a hash-independent arithmetic adapter rather than reinterpret
32-byte BLAKE3 digests as field digests. No new folding algorithm is introduced.
Complexity: linear in capture arithmetic data, plus existing DAG evaluation.
Evidence: core/fri.zig captures and recursion/air/fri_verifier_circuit*.zig.
Prediction: native BLAKE3 captures for fold1/2/4 satisfy the exact existing graph;
mutated DEEP answers fail; inconsistent routing is rejected before evaluation.
Validation: extend the focused complete-group gate, preserve the complete typed
hash proof, inspect arithmetic bindings against every captured group coordinate.
Limits: host graph evaluation is not an outer proof of all FRI arithmetic. The
production relation producer and full combined roster remain to be integrated.
