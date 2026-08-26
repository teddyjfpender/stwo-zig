const std = @import("std");
const circle = @import("stwo_core").circle;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const trace = @import("../../runner/trace.zig");
const compat_layout = @import("compat_layout.zig");
const protocol_degree = @import("protocol_degree.zig");
const row_window = @import("row_window.zig");
const shadow_program = @import("shadow_program.zig");
const source = @import("source.zig");

test "row-window v1: compiles canonical typed ownership for every family" {
    try std.testing.expectEqualStrings(
        "stwo.typed-air.row-window-v1",
        row_window.format_id,
    );
    try std.testing.expectEqual(@as(u16, 1), row_window.format_version);

    for (0..trace.N_FAMILIES) |family_index| {
        const family: trace.OpcodeFamily = @enumFromInt(family_index);
        var imported = try shadow_program.buildProduction(
            std.testing.allocator,
            family,
            source.SourceSpan.generated(),
        );
        defer imported.deinit();
        const layout = try compat_layout.build(&imported);
        var plan = try row_window.build(
            std.testing.allocator,
            &imported,
            &layout,
        );
        defer plan.deinit();
        try plan.validate(&imported, &layout);
        const digest_hex = std.fmt.bytesToHex(plan.plan_digest, .lower);
        try std.testing.expectEqualStrings(
            row_window.EXPECTED_NATIVE_PLAN_DIGEST_HEX[family_index],
            &digest_hex,
        );

        try std.testing.expectEqual(@as(usize, 4), plan.windows.len);
        try std.testing.expectEqual(
            2 + layout.main().len + layout.interactions().len,
            plan.columns.len,
        );
        try std.testing.expectEqual(
            plan.columns.len + layout.interactions().len,
            plan.shifted_columns.len,
        );
        try std.testing.expectEqual(
            row_window.ComponentKind.interaction,
            plan.columns[0].owner.component,
        );
        try std.testing.expectEqual(
            row_window.ComponentKind.semantic,
            plan.columns[1].owner.component,
        );

        const interaction_start = 2 + layout.main().len;
        for (plan.columns[interaction_start..]) |column| {
            try std.testing.expectEqual(
                row_window.ComponentKind.interaction,
                column.owner.component,
            );
            const end = try column.shifted.end();
            const shifted = plan.shifted_columns[column.shifted.start..end];
            try std.testing.expectEqual(@as(usize, 2), shifted.len);
            try std.testing.expectEqual(row_window.RowOffset.current, shifted[0].offset);
            try std.testing.expectEqual(row_window.RowOffset.previous, shifted[1].offset);
            try std.testing.expectEqual(
                @as(protocol_degree.Degree, 1),
                try plan.shiftedDegree(shifted[0].id),
            );
            try std.testing.expectEqual(
                @as(protocol_degree.Degree, 1),
                try plan.shiftedDegree(shifted[1].id),
            );
        }
    }
}

test "row-window v1: semantic component binding derives all 17 mask geometries" {
    for (0..trace.N_FAMILIES) |family_index| {
        const family: trace.OpcodeFamily = @enumFromInt(family_index);
        const binding = try row_window.SemanticMaskBinding.init(family);
        try binding.validate();
        try std.testing.expectEqual(family, binding.family);
        try std.testing.expectEqual(@as(u8, 1), binding.preprocessed_current_columns);
        try std.testing.expectEqual(
            @as(u32, @intCast(trace.nColumnsForFamily(family))),
            binding.owned_main_current_columns,
        );
        try std.testing.expectEqual(@as(u8, 0), binding.owned_interaction_columns);
        var expected: row_window.Digest = undefined;
        _ = try std.fmt.hexToBytes(
            &expected,
            row_window.EXPECTED_NATIVE_PLAN_DIGEST_HEX[family_index],
        );
        try std.testing.expectEqualSlices(
            u8,
            &expected,
            &binding.geometry_source_digest,
        );
    }
}

test "row-window v1: semantic component binding rejects every authority mutation" {
    var binding = try row_window.SemanticMaskBinding.init(.lui);
    const original = binding;

    binding.schema_version += 1;
    try std.testing.expectError(error.InvalidWindowDigest, binding.validate());
    binding = original;
    binding.semantic_program_digest[0] ^= 1;
    try std.testing.expectError(error.InvalidWindowDigest, binding.validate());
    binding = original;
    binding.witness_layout_digest[0] ^= 1;
    try std.testing.expectError(error.InvalidWindowDigest, binding.validate());
    binding = original;
    binding.geometry_source_digest[0] ^= 1;
    try std.testing.expectError(error.InvalidWindowDigest, binding.validate());
    binding = original;
    binding.preprocessed_current_columns = 2;
    try std.testing.expectError(error.InvalidWindowDigest, binding.validate());
    binding = original;
    binding.owned_main_current_columns += 1;
    try std.testing.expectError(error.InvalidWindowDigest, binding.validate());
    binding = original;
    binding.owned_interaction_columns = 1;
    try std.testing.expectError(error.InvalidWindowDigest, binding.validate());
    binding = original;
    binding.binding_digest[0] ^= 1;
    try std.testing.expectError(error.InvalidWindowDigest, binding.validate());
    try original.validate();
}

test "row-window v1: validator rejects owner boundary and shift corruption" {
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .lui,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);
    var plan = try row_window.build(std.testing.allocator, &imported, &layout);
    defer plan.deinit();

    plan.schema_version += 1;
    try std.testing.expectError(
        error.InvalidFormat,
        plan.validate(&imported, &layout),
    );
    plan.schema_version = row_window.format_version;

    const first_owner = plan.columns[0].owner;
    plan.columns[0].owner = row_window.ownerFor(.lui, .semantic);
    try std.testing.expectError(
        error.InvalidOwner,
        plan.validate(&imported, &layout),
    );
    plan.columns[0].owner = first_owner;

    const previous_index: usize = plan.columns[2 + layout.main().len].shifted.start + 1;
    const previous_owner = plan.shifted_columns[previous_index].owner;
    plan.shifted_columns[previous_index].owner =
        row_window.ownerFor(.lui, .semantic);
    try std.testing.expectError(
        error.InvalidOwner,
        plan.validate(&imported, &layout),
    );
    plan.shifted_columns[previous_index].owner = previous_owner;

    const first_interaction_column = 2 + layout.main().len;
    const interaction_type = plan.columns[first_interaction_column].value_type;
    plan.columns[first_interaction_column].value_type = .base_field;
    try std.testing.expectError(
        error.InvalidColumn,
        plan.validate(&imported, &layout),
    );
    plan.columns[first_interaction_column].value_type = interaction_type;

    const boundary = plan.windows[@intFromEnum(row_window.interaction_window)].boundary;
    var corrupted_claim = boundary.cyclic_first_row_claim;
    corrupted_claim.selector = @enumFromInt(1);
    plan.windows[@intFromEnum(row_window.interaction_window)].boundary =
        .{ .cyclic_first_row_claim = corrupted_claim };
    try std.testing.expectError(
        error.InvalidBoundary,
        plan.validate(&imported, &layout),
    );
    plan.windows[@intFromEnum(row_window.interaction_window)].boundary = boundary;

    plan.windows[@intFromEnum(row_window.interaction_window)].boundary = .none;
    try std.testing.expectError(
        error.InvalidBoundary,
        plan.validate(&imported, &layout),
    );
    plan.windows[@intFromEnum(row_window.interaction_window)].boundary = boundary;

    const original_offset = plan.shifted_columns[previous_index].offset;
    plan.shifted_columns[previous_index].offset = .current;
    try std.testing.expectError(
        error.InvalidShiftedColumn,
        plan.validate(&imported, &layout),
    );
    plan.shifted_columns[previous_index].offset = original_offset;
    try plan.validate(&imported, &layout);
}

test "row-window v1: semantic layout and plan identities fail closed" {
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .lui,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);
    var plan = try row_window.build(std.testing.allocator, &imported, &layout);
    defer plan.deinit();

    plan.semantic_program_digest[0] ^= 1;
    try std.testing.expectError(
        error.InvalidWindowDigest,
        plan.validate(&imported, &layout),
    );
    plan.semantic_program_digest[0] ^= 1;

    plan.witness_layout_digest[0] ^= 1;
    try std.testing.expectError(
        error.InvalidWindowDigest,
        plan.validate(&imported, &layout),
    );
    plan.witness_layout_digest[0] ^= 1;

    plan.plan_digest[0] ^= 1;
    try std.testing.expectError(
        error.InvalidWindowDigest,
        plan.validate(&imported, &layout),
    );
    plan.plan_digest[0] ^= 1;
    try plan.validate(&imported, &layout);

    var second = try row_window.build(std.testing.allocator, &imported, &layout);
    defer second.deinit();
    try std.testing.expectEqual(plan.plan_digest, second.plan_digest);
}

test "row-window v1: lowering supplies the exact interaction degree context" {
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .div,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);
    var plan = try row_window.build(std.testing.allocator, &imported, &layout);
    defer plan.deinit();

    const first = protocol_degree.FractionDegree{
        .numerator = 1,
        .denominator = 1,
    };
    const second = protocol_degree.FractionDegree{
        .numerator = 1,
        .denominator = 1,
    };
    const typed = try row_window.lowerInteractionDegree(
        &plan,
        &imported,
        &layout,
        first,
        second,
    );
    const compat = try protocol_degree.interactionTerms(first, second);
    try std.testing.expectEqualDeep(compat, typed);
    try std.testing.expectEqual(@as(protocol_degree.Degree, 1), typed.row_window);
    try std.testing.expectEqual(@as(protocol_degree.Degree, 1), typed.boundary_selector);
    try std.testing.expectEqual(@as(protocol_degree.Degree, 0), typed.boundary_claim);
    try std.testing.expectEqual(@as(protocol_degree.Degree, 3), typed.final);
}

test "row-window v1: degree lowering matches every compat interaction" {
    for (0..trace.N_FAMILIES) |family_index| {
        const family: trace.OpcodeFamily = @enumFromInt(family_index);
        var imported = try shadow_program.buildProduction(
            std.testing.allocator,
            family,
            source.SourceSpan.generated(),
        );
        defer imported.deinit();
        const layout = try compat_layout.build(&imported);
        var plan = try row_window.build(std.testing.allocator, &imported, &layout);
        defer plan.deinit();
        var analysis = try protocol_degree.analyze(
            std.testing.allocator,
            &imported,
            10,
        );
        defer analysis.deinit();

        for (analysis.interactions) |expected| {
            const first_index: usize = expected.first_lookup;
            const first_lookup = analysis.lookups[first_index];
            const first = protocol_degree.FractionDegree{
                .numerator = first_lookup.numerator,
                .denominator = first_lookup.denominator,
            };
            const second = if (expected.entry_count == 2) blk: {
                const second_lookup = analysis.lookups[first_index + 1];
                break :blk protocol_degree.FractionDegree{
                    .numerator = second_lookup.numerator,
                    .denominator = second_lookup.denominator,
                };
            } else null;
            const actual = try row_window.lowerInteractionDegree(
                &plan,
                &imported,
                &layout,
                first,
                second,
            );
            try std.testing.expectEqual(expected.row_window, actual.row_window);
            try std.testing.expectEqual(
                expected.boundary_selector,
                actual.boundary_selector,
            );
            try std.testing.expectEqual(expected.boundary_claim, actual.boundary_claim);
            try std.testing.expectEqual(expected.delta, actual.delta);
            try std.testing.expectEqual(
                expected.denominator_product,
                actual.denominator_product,
            );
            try std.testing.expectEqual(
                expected.combined_numerator,
                actual.combined_numerator,
            );
            try std.testing.expectEqual(expected.final, actual.final);
        }
    }
}

test "row-window v1: PCS mask emission is point-exact with the compat contract" {
    const family: trace.OpcodeFamily = .lui;
    const trace_log_size: u32 = 10;
    const max_log_degree_bound: u32 = 13;
    const point = circle.SECURE_FIELD_CIRCLE_GEN.mul(29);
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        family,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);
    var plan = try row_window.build(std.testing.allocator, &imported, &layout);
    defer plan.deinit();

    var generated = try row_window.emitMaskPoints(
        std.testing.allocator,
        &plan,
        &imported,
        &layout,
        point,
        trace_log_size,
        max_log_degree_bound,
    );
    defer generated.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), generated.items.len);
    try std.testing.expectEqual(@as(usize, 2), generated.items[0].len);
    try std.testing.expectEqual(layout.main().len, generated.items[1].len);
    try std.testing.expectEqual(layout.interactions().len, generated.items[2].len);

    // This is the exact split implemented by the live components: interaction
    // owns is_first and current/previous secure coordinates; semantic owns
    // is_active and current main columns. Existing component tests pin the same
    // point contract, while this focused root stays independent of the prover.
    const previous = row_window.previousRowPoint(max_log_degree_bound, point);
    for (generated.items[0], 0..) |column, index| {
        try std.testing.expectEqual(@as(usize, 1), column.len);
        try std.testing.expect(std.meta.eql(point, column[0]));
        try std.testing.expectEqual(
            if (index == 0)
                row_window.ComponentKind.interaction
            else
                row_window.ComponentKind.semantic,
            plan.columns[index].owner.component,
        );
    }
    for (generated.items[1], 0..) |column, index| {
        try std.testing.expectEqual(@as(usize, 1), column.len);
        try std.testing.expect(std.meta.eql(point, column[0]));
        try std.testing.expectEqual(
            row_window.ComponentKind.semantic,
            plan.columns[2 + index].owner.component,
        );
    }
    for (generated.items[2], 0..) |column, index| {
        try std.testing.expectEqual(@as(usize, 2), column.len);
        try std.testing.expect(std.meta.eql(point, column[0]));
        try std.testing.expect(std.meta.eql(previous, column[1]));
        try std.testing.expectEqual(
            row_window.ComponentKind.interaction,
            plan.columns[2 + layout.main().len + index].owner.component,
        );
    }

    try std.testing.expectError(
        error.LogDegreeUnderflow,
        row_window.emitMaskPoints(
            std.testing.allocator,
            &plan,
            &imported,
            &layout,
            point,
            trace_log_size,
            trace_log_size - 1,
        ),
    );
}

test "row-window v1: shifted rows reject boundary and cross-row forgeries" {
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .lui,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);
    var plan = try row_window.build(std.testing.allocator, &imported, &layout);
    defer plan.deinit();

    var pairs: [4]ReferencePair = undefined;
    for (&pairs, 0..) |*pair, index| {
        pair.* = .{
            .numerator = QM31.fromU32Unchecked(@intCast(index + 2), 1, 0, 0),
            .denominator = QM31.fromU32Unchecked(@intCast(index + 11), 0, 1, 0),
        };
    }
    const cumulative = try referenceCumulative(&pairs);

    const interaction_column = plan.columns[2 + layout.main().len];
    const current_id = plan.shifted_columns[interaction_column.shifted.start].id;
    const previous_id = plan.shifted_columns[interaction_column.shifted.start + 1].id;
    for (pairs, 0..) |pair, row| {
        const current_row = try plan.sampleRowIndex(current_id, pairs.len, row);
        const previous_row = try plan.sampleRowIndex(previous_id, pairs.len, row);
        try std.testing.expectEqual(row, current_row);
        try std.testing.expectEqual(
            if (row == 0) pairs.len - 1 else row - 1,
            previous_row,
        );
        const is_first = if (row == 0) QM31.one() else QM31.zero();
        const constraint = referenceConstraint(
            cumulative.sums[current_row],
            cumulative.sums[previous_row],
            is_first,
            cumulative.claimed,
            pair,
        );
        try std.testing.expect(constraint.isZero());
    }

    const forged_previous = cumulative.sums[0].add(QM31.one());
    const cross_row_forgery = referenceConstraint(
        cumulative.sums[1],
        forged_previous,
        QM31.zero(),
        cumulative.claimed,
        pairs[1],
    );
    try std.testing.expect(!cross_row_forgery.isZero());

    const missing_boundary_claim = referenceConstraint(
        cumulative.sums[0],
        cumulative.sums[pairs.len - 1],
        QM31.zero(),
        cumulative.claimed,
        pairs[0],
    );
    try std.testing.expect(!missing_boundary_claim.isZero());
    try std.testing.expectError(
        error.InvalidRow,
        plan.sampleRowIndex(previous_id, pairs.len, pairs.len),
    );
}

test "row-window v1: compilation and PCS emission are failure-atomic" {
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .lui,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocatePlanAndMasks,
        .{ &imported, &layout },
    );
}

const ReferencePair = struct {
    numerator: QM31,
    denominator: QM31,
};

const ReferenceCumulative = struct {
    sums: [4]QM31,
    claimed: QM31,
};

fn referenceCumulative(pairs: *const [4]ReferencePair) !ReferenceCumulative {
    var result = ReferenceCumulative{
        .sums = .{QM31.zero()} ** 4,
        .claimed = QM31.zero(),
    };
    for (pairs, 0..) |pair, index| {
        const inverse = try pair.denominator.inv();
        result.claimed = result.claimed.add(pair.numerator.mul(inverse));
        result.sums[index] = result.claimed;
    }
    return result;
}

fn referenceConstraint(
    current: QM31,
    previous: QM31,
    is_first: QM31,
    claimed: QM31,
    pair: ReferencePair,
) QM31 {
    return current.sub(previous).add(is_first.mul(claimed))
        .mul(pair.denominator).sub(pair.numerator);
}

fn allocatePlanAndMasks(
    allocator: std.mem.Allocator,
    imported: *const shadow_program.ImportedProgram,
    layout: *const compat_layout.Layout,
) !void {
    var plan = try row_window.build(allocator, imported, layout);
    defer plan.deinit();
    var masks = try row_window.emitMaskPoints(
        allocator,
        &plan,
        imported,
        layout,
        circle.SECURE_FIELD_CIRCLE_GEN.mul(17),
        10,
        13,
    );
    defer masks.deinitDeep(allocator);
}
