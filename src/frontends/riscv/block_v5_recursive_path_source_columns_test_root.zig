//! Direct path/public/root source parity plus actual assembled parent body
//! generation. This root never dispatches execution proofs or segment runs.
test {
    _ = @import("recursion/air/blake3_path_source_columns_test.zig");
    _ = @import("block_v5_recursive_pcs_source_columns_test_root.zig");
}
