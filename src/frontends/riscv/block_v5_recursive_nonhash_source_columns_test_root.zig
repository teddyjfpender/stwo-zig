//! Source construction and parent body generation only. No proving/device jobs.
test {
    _ = @import("recursion/air/tests/blake3_nonhash_source_columns_test.zig");
    _ = @import("block_v5_recursive_path_source_columns_test_root.zig");
}
