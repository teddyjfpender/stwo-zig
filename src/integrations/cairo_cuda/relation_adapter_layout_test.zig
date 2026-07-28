const std = @import("std");
const proof_plan = @import("stwo_cairo_frontend").proof_plan;
const relation_bundle = @import("stwo_cairo_frontend").witness.relation_bundle;
const adapter = @import("relation_adapter.zig");

test "relation adapter rejects cumulative memory-big ID overflow" {
    var relations = try relation_bundle.Bundle.readFile(
        std.testing.allocator,
        "vectors/cairo/cairo_relation_templates.bin",
    );
    defer relations.deinit();

    var trace_parts: [10]proof_plan.TracePart = undefined;
    var components: [10]proof_plan.Component = undefined;
    for (0..9) |index| {
        const rows: u32 = if (index == 8) 16 else 1 << 27;
        trace_parts[index] = .{
            .id = .{ .memory_big = @intCast(index) },
            .rows = .{
                .real_rows = rows,
                .padded_rows = rows,
            },
        };
        components[index] = memoryComponent(
            "memory_id_to_big",
            @intCast(index),
            @intCast(index),
            trace_parts[index .. index + 1],
        );
    }
    trace_parts[9] = .{
        .id = .memory_small,
        .rows = .{
            .real_rows = 16,
            .padded_rows = 16,
        },
    };
    components[9] = memoryComponent(
        "memory_id_to_small",
        0,
        9,
        trace_parts[9..10],
    );
    var proof = try proof_plan.CairoProofPlan.init(
        std.testing.allocator,
        &components,
    );
    defer proof.deinit();

    try std.testing.expectError(
        adapter.Error.InvalidProofGeometry,
        adapter.Plan.compile(
            std.testing.allocator,
            &proof,
            relations,
        ),
    );
}

fn memoryComponent(
    name: []const u8,
    instance: u32,
    ordinal: u32,
    trace_parts: []const proof_plan.TracePart,
) proof_plan.Component {
    return .{
        .name = name,
        .instance = instance,
        .canonical_ordinal = ordinal,
        .writer = .memory_trace,
        .trace_parts = trace_parts,
        .producer_edges = &.{},
        .capacity_feeds = &.{},
    };
}
