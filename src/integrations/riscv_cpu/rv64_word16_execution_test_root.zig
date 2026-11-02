test {
    _ = @import("tests/rv64_word16_execution_jalr_test.zig");
    _ = @import("tests/rv64_word16_execution_rom_test.zig");
    _ = @import("tests/rv64_word16_execution_component_test.zig");
    _ = @import("tests/rv64_word16_execution_features_test.zig");
    _ = @import("tests/rv64_word16_execution_equations_test.zig");
    _ = @import("tests/rv64_word16_execution_fused_tail_test.zig");
    _ = @import("tests/rv64_word16_execution_u8_pairs_test.zig");
    _ = @import("tests/rv64_word16_execution_compact_decode_test.zig");
    _ = @import("tests/rv64_word16_execution_wide_clock_test.zig");
}
