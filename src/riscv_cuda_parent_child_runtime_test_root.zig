test "resident child runtime modules" {
    _ = @import("integrations/riscv_cuda/resident_parent_child_paths_runtime_v1.zig");
    _ = @import("integrations/riscv_cuda/resident_parent_child_runtime_v1.zig");
}
