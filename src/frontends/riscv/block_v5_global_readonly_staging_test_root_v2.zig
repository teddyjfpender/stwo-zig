//! Bounded host metadata/transport/witness checks; no proving calls.
test {
    _ = @import("prover/block_v5_readonly_input_global_staging_test_v2.zig");
    _ = @import("prover/block_v5_readonly_input_global_staging_bodies_v2.zig");
    _ = @import("prover/block_v5_readonly_input_global_collection_test_v2.zig");
    _ = @import("prover/block_v5_readonly_input_provider_test_v2.zig");
    _ = @import("prover/block_v5_native_capacity_readonly_collection_test_v2.zig");
    _ = @import("prover/block_v5_caller_readonly_collection_test_v2.zig");
    _ = @import("block_v5_native_readonly_stream_collection_body_v2.zig");
}
