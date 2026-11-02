test {
    _ = @import("rv64_large_block_recycler.zig");
    _ = @import("tests/rv64_batch_memory_test.zig");
    _ = @import("tests/rv64_ethereum_chain_test.zig");
    _ = @import("tests/rv64_ethereum_prepared_test.zig");
}
