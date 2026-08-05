//! Package-root executable boundary for the typed-AIR manifest command.

pub fn main() void {
    @import("air/lang/compat_manifest_command.zig").main();
}
