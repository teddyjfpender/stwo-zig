# Canonical FRI hash wire schedules and arithmetic exports

Task: turn admitted FRI graph bindings into reusable typed repacking schedules
and sorted arithmetic exports; remove test-only hand-built node mappings.
Canonical match: exact graph boundary scheduling. Each authenticated coordinate
has one canonical input node and one hash consumer. Build schedules in layer,
raw-query, offset order; append one export per coordinate in graph-node order.
Reuse verifier_arithmetic_lowering's export-aware use-count authority instead
of manually adjusting producer multiplicities. O(bindings + values) construction.
Inputs: validated canonical FRI circuit, disjoint scalar/packed circuit IDs.
Prediction: full arithmetic lowering accepts the sealed lane, every exported
input gains exactly one read, and actual evaluation materializes all operation
invocations while existing complete hash-group proofs preserve closure.
Tests: fold1/2/4 native captures, exact coordinate coverage, operation generation,
invalid group indices and namespace collision. The outer proof still needs the
materialized arithmetic rows; do not describe materialization as a combined proof.
