//! One CPU-only provider qualification batch. Tests use scalar equations,
//! metadata, ownership, literal rejection and actual-body retention only.
//! No guest execution, STARK construction, forest or device dispatch.
comptime {
    _ = @import("prover/block_v5_ram_lanes_recursive_test_v1.zig");
    _ = @import("prover/block_v5_program_table_recursive_test_v1.zig");
    _ = @import("prover/block_v5_native_lookup_recursive_test_v1.zig");
    _ = @import("prover/block_v5_range16_recursive_cache_test_v1.zig");
    _ = @import("prover/block_v5_recursive_provider_transport_test_v1.zig");
}
test "provider bodies: actual four-family capture full verifier cache publication and strict fresh file receiver retained only" {
    @import("block_v5_recursive_provider_transport_codegen.zig").stwo_recursive_provider_transport_body_gate();
}
