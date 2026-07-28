const std = @import("std");
const proof_plan = @import("stwo_cairo_frontend").proof_plan;

test "Cairo CUDA proof plans preserve distinct memory instances" {
    const rows = [_]proof_plan.TracePart{.{ .id = .main, .rows = .{
        .real_rows = 16,
        .padded_rows = 16,
    } }};
    var components = [_]proof_plan.Component{
        .{
            .name = "memory_id_to_big",
            .instance = 0,
            .canonical_ordinal = 0,
            .writer = .memory_trace,
            .trace_parts = &rows,
            .producer_edges = &.{},
            .capacity_feeds = &.{},
        },
        .{
            .name = "memory_id_to_big",
            .instance = 1,
            .canonical_ordinal = 1,
            .writer = .memory_trace,
            .trace_parts = &rows,
            .producer_edges = &.{},
            .capacity_feeds = &.{},
        },
    };
    var plan = try proof_plan.CairoProofPlan.init(
        std.testing.allocator,
        &components,
    );
    defer plan.deinit();
    try std.testing.expect(
        plan.findInstance("memory_id_to_big", 0) != null,
    );
    try std.testing.expect(
        plan.findInstance("memory_id_to_big", 1) != null,
    );

    components[1].instance = 0;
    try std.testing.expectError(
        proof_plan.Error.DuplicateComponent,
        proof_plan.CairoProofPlan.init(
            std.testing.allocator,
            &components,
        ),
    );
}
