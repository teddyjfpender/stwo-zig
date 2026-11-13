test {
    _ = @import("stwo_riscv_cpu_integration").rv64_large_block_recycler;
    _ = @import("tests/rv64_ethereum_chain_test.zig");
    _ = @import("tests/rv64_ethereum_prepared_test.zig");
}
