const std = @import("std");
const composition = @import("cairo_composition_bundle");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const args = try std.process.argsAlloc(allocator);
    if (args.len < 2 or args.len > 3 or
        (args.len == 3 and !std.mem.eql(u8, args[2], "--components")))
    {
        std.debug.print(
            "usage: cairo-air-bundle-inspector <bundle> [--components]\n",
            .{},
        );
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
    if (args.len == 3) {
        for (bundle.components) |component| {
            std.debug.print(
                "{s}[{}] trace_log={} evaluation_log={} constraints={} random_offset={} spans={} preprocessed={} denominators={} extension_parameters={} parts={}\n",
                .{
                    component.label,
                    component.instance,
                    component.trace_log_size,
                    component.evaluation_log_size,
                    component.n_constraints,
                    component.random_coefficient_offset,
                    component.trace_spans.len,
                    component.preprocessed_indices.len,
                    component.denominator_inverses.len,
                    component.ext_sources.len,
                    component.parts.len,
                },
            );
        }
    }
}
