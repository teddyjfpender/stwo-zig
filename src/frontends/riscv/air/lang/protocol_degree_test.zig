const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const OpcodeLookupComponent = @import("../lookups/opcode_component.zig").OpcodeLookupComponent;
const opcode_entries = @import("../lookups/opcode_entries.zig");
const relations_mod = @import("../relation_challenges.zig");
const semantic_eval = @import("../semantic_eval.zig");
const trace = @import("../../runner/trace.zig");
const protocol_degree = @import("protocol_degree.zig");
const shadow_program = @import("shadow_program.zig");
const source = @import("source.zig");

test "protocol degree analyzes every complete production family" {
    const expected_direct = [_]protocol_degree.Degree{
        3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 3, 2, 2, 3, 2,
    };
    const expected_numerator = [_]protocol_degree.Degree{
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1,
    };
    const expected_denominator = [_]protocol_degree.Degree{
        1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 2, 2, 2, 1,
    };
    const relations = relations_mod.Relations.dummy();
    const claims = [_]QM31{QM31.zero()} ** 25;
    for (0..trace.N_FAMILIES) |family_index| {
        const family: trace.OpcodeFamily = @enumFromInt(family_index);
        var imported = try shadow_program.buildProduction(
            std.testing.allocator,
            family,
            source.SourceSpan.generated(),
        );
        defer imported.deinit();
        var analysis = try protocol_degree.analyze(
            std.testing.allocator,
            &imported,
            10,
        );
        defer analysis.deinit();
        try std.testing.expectEqual(
            expected_direct[family_index],
            analysis.maximum_direct_degree,
        );
        try std.testing.expectEqual(
            expected_numerator[family_index],
            analysis.maximum_lookup_numerator_degree,
        );
        try std.testing.expectEqual(
            expected_denominator[family_index],
            analysis.maximum_lookup_denominator_degree,
        );
        try std.testing.expectEqual(
            @as(protocol_degree.Degree, 3),
            analysis.maximum_interaction_degree,
        );
        try std.testing.expectEqual(imported.direct_constraints.len, analysis.direct.len);
        try std.testing.expectEqual(imported.lookups.len, analysis.lookups.len);
        try std.testing.expectEqual(imported.batchCount(), analysis.interactions.len);
        const declared_direct = semantic_eval.constraintLogDegreeBound(family, 10);
        try std.testing.expect(analysis.required_direct_log_degree_bound <= declared_direct);
        const lookup_component = try OpcodeLookupComponent.initVerifier(
            family,
            10,
            0,
            0,
            0,
            &relations,
            claims[0..opcode_entries.batchCount(family)],
        );
        const declared_interaction = lookup_component.maxConstraintLogDegreeBound();
        try std.testing.expectEqual(
            declared_interaction,
            analysis.required_interaction_log_degree_bound,
        );
        try std.testing.expectEqual(
            @max(declared_direct, declared_interaction),
            analysis.requiredCompositionLogDegreeBound(),
        );
        for (analysis.direct) |item| {
            try std.testing.expectEqual(@as(protocol_degree.Degree, 0), item.external_row_mask);
            try std.testing.expectEqual(
                protocol_degree.quotientExpansionBits(item.final),
                item.quotient_expansion_bits,
            );
        }
        for (analysis.interactions) |item| {
            try std.testing.expectEqual(@as(protocol_degree.Degree, 1), item.row_window);
            try std.testing.expectEqual(@as(protocol_degree.Degree, 1), item.boundary_selector);
            try std.testing.expectEqual(@as(protocol_degree.Degree, 0), item.boundary_claim);
            try std.testing.expectEqual(@as(protocol_degree.Degree, 1), item.delta);
        }
    }
}

test "interaction recurrence accounts for batching and nonlinear entries" {
    const pair = try protocol_degree.interactionTerms(
        .{ .numerator = 0, .denominator = 1 },
        .{ .numerator = 0, .denominator = 2 },
    );
    try std.testing.expectEqual(@as(protocol_degree.Degree, 3), pair.denominator_product);
    try std.testing.expectEqual(@as(protocol_degree.Degree, 4), pair.final);

    const single = try protocol_degree.interactionTerms(
        .{ .numerator = 2, .denominator = 2 },
        null,
    );
    try std.testing.expectEqual(@as(protocol_degree.Degree, 2), single.denominator_product);
    try std.testing.expectEqual(@as(protocol_degree.Degree, 3), single.final);

    const numerator_dominates = try protocol_degree.interactionTerms(
        .{ .numerator = 3, .denominator = 1 },
        .{ .numerator = 0, .denominator = 1 },
    );
    try std.testing.expectEqual(
        @as(protocol_degree.Degree, 4),
        numerator_dominates.combined_numerator,
    );
    try std.testing.expectEqual(@as(protocol_degree.Degree, 4), numerator_dominates.final);
}

test "quotient expansion follows post-vanishing degree units" {
    try std.testing.expectEqual(@as(u8, 0), protocol_degree.quotientExpansionBits(0));
    try std.testing.expectEqual(@as(u8, 0), protocol_degree.quotientExpansionBits(1));
    try std.testing.expectEqual(@as(u8, 0), protocol_degree.quotientExpansionBits(2));
    try std.testing.expectEqual(@as(u8, 1), protocol_degree.quotientExpansionBits(3));
    try std.testing.expectEqual(@as(u8, 2), protocol_degree.quotientExpansionBits(4));
    try std.testing.expectEqual(@as(u8, 2), protocol_degree.quotientExpansionBits(5));
    try std.testing.expectEqual(@as(u8, 3), protocol_degree.quotientExpansionBits(9));
}

fn allocationFailureCase(
    allocator: std.mem.Allocator,
    imported: *const shadow_program.ImportedProgram,
) !void {
    var analysis = try protocol_degree.analyze(allocator, imported, 10);
    defer analysis.deinit();
}

test "protocol degree releases every partial allocation" {
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .div,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{&imported},
    );
}

test "protocol degree rejects log-bound overflow" {
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .div,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    try std.testing.expectError(
        error.LogDegreeOverflow,
        protocol_degree.analyze(
            std.testing.allocator,
            &imported,
            std.math.maxInt(u32),
        ),
    );
}
