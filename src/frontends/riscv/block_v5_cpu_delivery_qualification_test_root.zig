//! Focused assembled delivery and large-domain caller qualification.
test {
    _ = @import("prover/block_v5_cpu_driver_test.zig");
    _ = @import("prover/block_v5_precompile_large_profile_test.zig");
    _ = @import("prover/block_v5_program_finish_collected_test.zig");
    _ = @import("prover/block_v5_memory_source_writer_test.zig");
    _ = @import("prover/block_v5_committed_trace_column_test.zig");
    _ = @import("prover/block_v5_native_recursive_stage_cache_test.zig");
    _ = @import("prover/block_v5_mainnet_initial_source_test.zig");
}
