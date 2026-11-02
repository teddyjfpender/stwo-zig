test {
    _ = @import("word16_execution/division_product_integration_test.zig");
    _ = @import("word16_execution/pcs_suite_test.zig");
    _ = @import("word16_execution/cpu_clock_induction_proof_test.zig");
    _ = @import("word16_execution/cpu_zero_induction_proof_test.zig");
    _ = @import("word16_execution/cpu_fused_tail_proof_test.zig");
    _ = @import("word16_execution/cpu_u8_pairs_proof_test.zig");
    _ = @import("word16_execution/shift_read_induction_proof_test.zig");
    _ = @import("word16_execution/alu_read_induction_proof_test.zig");
    _ = @import("word16_execution/cells_wire.zig");
    _ = @import("tests/rv64_word16_execution_program_test.zig");
    _ = @import("tests/rv64_word16_execution_image_test.zig");
}
