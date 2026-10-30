test {
    _ = @import("air/guest_precompile/tests/keccakf_component_test.zig");
    _ = @import("prover/tests/block_v8_endpoint_mixed_proof_test.zig");
    _ = @import("prover/tests/block_v8_endpoint_mixed_halt_negative_test.zig");
}
