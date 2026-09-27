//! Independently chosen product policy; compile actual same adapter bodies.
pub const BLOCK_V5_EXECUTION_RECIPE: u32 = 1;
export fn stwo_caller_arithmetic_recursive_selected_body_gate() void {
    @import("block_v5_caller_arithmetic_recursive_codegen.zig").stwo_caller_arithmetic_recursive_body_gate();
}
