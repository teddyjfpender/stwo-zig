//! Focused authenticated backend-export loop, independent of proof producers.
test {
    _ = @import("stwo_riscv_air_lang").modules.shared_air_lookups_tables_schema;
    _ = @import("recursion/air/tests/framework_polynomial_export_test.zig");
    _ = @import("recursion/air/tests/range_check_8_8_bridge_test.zig");
}
