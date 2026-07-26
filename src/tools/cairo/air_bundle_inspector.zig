const std = @import("std");
const composition = @import("cairo_composition_bundle");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const args = try std.process.argsAlloc(allocator);
    if (args.len != 2) {
        std.debug.print("usage: cairo-air-bundle-inspector <bundle>\n", .{});
        return error.InvalidArguments;
    }
    var bundle = try composition.Bundle.readFile(allocator, args[1]);
    defer bundle.deinit();
    std.debug.print(
        "components={} constraints={} max_evaluation_log={} plan_hash={x:0>16}\n",
        .{
            bundle.components.len,
            bundle.total_constraints,
            bundle.max_evaluation_log_size,
            bundle.plan_hash,
        },
    );
}
