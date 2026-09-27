test "CPU source PAGE path root" {
    _ = @import("prover/block_v5_cpu_source_pages_test_v1.zig");
    _ = @import("block_v5_cpu_source_pages_codegen.zig");
}
