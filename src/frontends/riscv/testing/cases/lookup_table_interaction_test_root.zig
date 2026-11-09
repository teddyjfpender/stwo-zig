const std = @import("std");

test {
    _ = @import("stwo_riscv_rv32").modules.air_lookups_tables_interaction;
    _ = @import("stwo_riscv_rv32").modules.air_lookups_tables_framework_export;
    _ = @import("stwo_riscv_rv32").modules.air_lookups_tables_component_prepared_test;
    std.testing.refAllDecls(@This());
}
