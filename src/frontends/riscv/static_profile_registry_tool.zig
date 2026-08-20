//! Package-root executable boundary for the reviewed P-002 profile command.

pub fn main() void {
    @import("air/lang/static_profile_registry_command.zig").main();
}
