comptime {
    _ = @import("prover/block_v5_memory_source_packed_page_test_v1.zig");
    _ = @import("block_v5_memory_source_packed_page_codegen.zig");
    // Existing canonical legacy semantic/ownership fixtures accompany the
    // factory migration; filters remain separate and no PCS is invoked.
    _ = @import("prover/block_v5_memory_source_first_test_v1.zig");
    _ = @import("prover/block_v5_memory_source_binding_test_v1.zig");
    _ = @import("block_v5_memory_source_first_codegen.zig");
    _ = @import("block_v5_memory_source_binding_codegen.zig");
}
test "source packed page root imports" {}
