//! Explicit native CPU measurements with the same authorities as the deep tests.
const quotient = @import("prover/om31_quotient_batch_test.zig");
const poseidon = @import("prover/pcs/poseidon_bounded_prefix_test.zig");

test "optional native timing: wide quotient inverse batching" {
    try quotient.compare(true);
}

test "optional native timing: bounded Poseidon prefix" {
    try poseidon.measurePrefix();
}

test "optional native timing: bounded Poseidon tail reuse" {
    try poseidon.measureTailReuse();
}
