//! Installed entry point of the circuit recursion CPU product
//! (`stwo-circuit-recursion-cpu`): the recursive tree and registry
//! generation of the circuit recursion stage (design §7.4).

pub fn main() !void {
    return @import("app.zig").main();
}

test {
    _ = @import("app.zig");
}
