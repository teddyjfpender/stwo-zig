//! `stwo-opstack-native`: native CPU production and fresh reception of one OP
//! Stack guest execution, without recursion dependencies. `cli.zig` maps the
//! product subcommands (`prove`, `verify`, `plan-candidate`, …) onto the
//! pipeline command line; `--security-profile` selects the native PCS profile.
const std = @import("std");
const cli = @import("cli.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const argv = try std.process.argsAlloc(a);
    try @import("opstack_cpu_component").Pipeline.runArgv(try cli.translate(a, argv));
}
