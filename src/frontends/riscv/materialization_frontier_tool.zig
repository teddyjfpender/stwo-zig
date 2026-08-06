//! Package-root executable boundary for the H-009 frontier command.

pub fn main() void {
    @import("air/lang/materialization_frontier_command.zig").main();
}
