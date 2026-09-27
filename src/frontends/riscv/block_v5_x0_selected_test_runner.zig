//! Independently chosen executable recipe; discovery belongs to THIS root.
pub const BLOCK_V5_EXECUTION_RECIPE: u32 = 1;
const runner = @import("block_v5_policy_test_runner_v1.zig");
pub const std_options = runner.std_options;
pub fn main() void {
    runner.main(@import("builtin").test_functions);
}
