//! Source-only candidate, not qualified and not a full source proof root.
test "source unified PAGE root" {
    _ = @import("prover/block_v5_memory_source_unified_page_test_v1.zig");
    _ = @import("prover/block_v5_memory_source_page_composition_test_v1.zig");
    _ = @import("prover/block_v5_memory_source_unified_page_codec_test_v1.zig");
    _ = @import("prover/block_v5_memory_source_fold_fixed_test_v1.zig");
    _ = @import("block_v5_memory_source_unified_page_codegen.zig");
}
