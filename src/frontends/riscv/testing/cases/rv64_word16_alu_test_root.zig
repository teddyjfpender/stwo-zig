test {
    _ = @import("stwo_riscv_rv64").modules.air_providers_parallel_rows_test;
    _ = @import("stwo_riscv_rv64").modules.air_word16_alu_test;
    _ = @import("stwo_riscv_rv64").modules.air_word16_u16_source_test;
    _ = @import("stwo_riscv_rv64").modules.air_word16_alu_packed_rows_test;
    _ = @import("stwo_riscv_rv64").modules.air_word16_alu_source_test;
}
test {
    _ = @import("stwo_riscv_rv64").modules.air_word16_alu_merged_prefix_test;
}
