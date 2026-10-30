test "resident parent modules" {
    _ = @import("integrations/riscv_cuda/resident_parent_program_v1.zig");
    _ = @import("integrations/riscv_cuda/resident_parent_pcs_v1.zig");
    _ = @import("integrations/riscv_cuda/resident_parent_transcript_v1.zig");
}
