//! Nonproving source-equation qualification root; no proof jobs.
comptime {
    _ = @import("prover/block_v5_memory_source_auth_test_v1.zig");
    _ = @import("block_v5_memory_source_auth_codegen.zig");
}
test "source auth root" {}
