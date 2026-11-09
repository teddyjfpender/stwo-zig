const std = @import("std");

test {
    _ = @import("stwo_riscv_rv32").modules.air_lookups_tables_source_ingest_test;
    std.testing.refAllDecls(@This());
}
