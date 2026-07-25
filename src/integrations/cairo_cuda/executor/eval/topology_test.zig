const std = @import("std");
const semantic_authority = @import(
    "../../../../frontends/cairo/proof_plan/semantic_authority.zig",
);
const composition = @import(
    "../../../../frontends/cairo/witness/composition_bundle.zig",
);
const fixed_tables = @import(
    "../../../../frontends/cairo/witness/fixed_table_bundle.zig",
);
const topology = @import("topology.zig");

test "SN2 eval topology preserves every heterogeneous component domain" {
    const allocator = std.testing.allocator;
    var bundle = try composition.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    defer bundle.deinit();
    var fixed = try fixed_tables.Bundle.readFile(
        allocator,
        "vectors/cairo/cairo_fixed_tables.bin",
    );
    defer fixed.deinit();
    const preprocessed_logs = try semantic_authority.preprocessedLogs(
        allocator,
        fixed,
    );
    defer allocator.free(preprocessed_logs);

    var first = try topology.Topology.derive(
        allocator,
        bundle,
        preprocessed_logs,
    );
    defer first.deinit();
    var second = try topology.Topology.derive(
        allocator,
        bundle,
        preprocessed_logs,
    );
    defer second.deinit();

    try std.testing.expectEqual(
        @as(u32, topology.expected_component_count),
        first.summary.component_count,
    );
    try std.testing.expectEqual(
        @as(u32, topology.expected_placement_count),
        first.summary.placement_count,
    );
    try std.testing.expectEqual(
        @as(u64, topology.expected_constraint_count),
        first.summary.constraint_count,
    );
    try std.testing.expect(first.accumulators.len > 1);
    try std.testing.expect(
        first.summary.accumulator_words >
            (@as(u64, 4) << @intCast(bundle.max_evaluation_log_size)),
    );
    try std.testing.expect(first.summary.lde_tile_words > 0);
    try std.testing.expectEqual(
        @as(u64, 37_356),
        first.summary.extended_parameter_words,
    );
    try std.testing.expectEqual(
        @as(u64, 74_712),
        first.summary.extended_parameter_descriptor_words,
    );
    try std.testing.expectEqual(
        @as(usize, 9_339),
        first.extended_parameter_descriptors.len,
    );
    try std.testing.expectEqualSlices(
        u8,
        &first.identity,
        &second.identity,
    );

    var accounted_sources: u64 = 0;
    var accounted_placements: u64 = 0;
    for (first.components) |component| {
        accounted_sources += component.source_count;
        accounted_placements += component.placement_count;
        const rows = @as(u64, 1) <<
            @intCast(component.evaluation_log_size);
        try std.testing.expect(
            @as(u64, component.source_count) * rows <=
                first.summary.lde_tile_words,
        );
    }
    try std.testing.expectEqual(
        @as(u64, first.sources.len),
        accounted_sources,
    );
    try std.testing.expectEqual(
        @as(u64, first.placements.len),
        accounted_placements,
    );

    preprocessed_logs[0] += 1;
    var mutated = try topology.Topology.derive(
        allocator,
        bundle,
        preprocessed_logs,
    );
    defer mutated.deinit();
    try std.testing.expect(!std.mem.eql(
        u8,
        &first.identity,
        &mutated.identity,
    ));
}
