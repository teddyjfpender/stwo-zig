//! No PCS, STARK, guest, device or segment invocation. Genuine bodies retained.
test {
    _ = @import("prover/block_v5_readonly_input_collection_test_v1.zig");
    _ = @import("prover/block_v5_readonly_input_collection_bodies_test_v1.zig");
    _ = @import("prover/block_v5_readonly_input_unit_test.zig");
    _ = @import("prover/block_v5_caller_readonly_unit_test.zig");
}
