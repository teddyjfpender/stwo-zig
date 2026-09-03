const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const candidate_mod = @import("typed_poseidon2_degree_bounded_candidate.zig");
const production = @import("../memory_commitment/poseidon2_air.zig");
const residency = @import("typed_poseidon2_degree_bounded_residency.zig");

test "degree-bounded Poseidon candidates pin disjoint exact geometry" {
    var degree_five = try candidate_mod.Candidate.init(
        std.testing.allocator,
        .degree5,
    );
    defer degree_five.deinit();
    var degree_six = try candidate_mod.Candidate.init(
        std.testing.allocator,
        .degree6,
    );
    defer degree_six.deinit();

    try degree_five.validate();
    try degree_six.validate();
    try std.testing.expectEqual(@as(u16, 220), degree_five.geometry.materialization_columns);
    try std.testing.expectEqual(@as(u16, 239), degree_five.geometry.main_columns);
    try std.testing.expectEqual(@as(u16, 224), degree_five.geometry.permutation_direct_constraints);
    try std.testing.expectEqual(@as(u16, 227), degree_five.geometry.component_direct_constraints);
    try std.testing.expectEqual(@as(u16, 2_842), degree_five.geometry.direct_nodes);
    try std.testing.expectEqual(@as(u16, 874), degree_five.geometry.direct_multiplications);
    try std.testing.expectEqual(@as(u8, 2), degree_five.geometry.quotient_expansion_bits);

    try std.testing.expectEqual(@as(u16, 142), degree_six.geometry.materialization_columns);
    try std.testing.expectEqual(@as(u16, 161), degree_six.geometry.main_columns);
    try std.testing.expectEqual(@as(u16, 146), degree_six.geometry.permutation_direct_constraints);
    try std.testing.expectEqual(@as(u16, 149), degree_six.geometry.component_direct_constraints);
    try std.testing.expectEqual(@as(u16, 2_608), degree_six.geometry.direct_nodes);
    try std.testing.expectEqual(@as(u16, 796), degree_six.geometry.direct_multiplications);
    try std.testing.expectEqual(@as(u8, 3), degree_six.geometry.quotient_expansion_bits);
    try std.testing.expect(!std.mem.eql(u8, &degree_five.identity, &degree_six.identity));

    const saved = degree_five.identity;
    degree_five.identity[0] ^= 1;
    try std.testing.expectError(
        error.CandidateIdentityMismatch,
        degree_five.validate(),
    );
    degree_five.identity = saved;
    try degree_five.validate();
}

test "degree-bounded rows are semantically identical and narrow-shell complete" {
    inline for (.{
        candidate_mod.Profile.degree5,
        candidate_mod.Profile.degree6,
    }) |profile| {
        var candidate = try candidate_mod.Candidate.init(
            std.testing.allocator,
            profile,
        );
        defer candidate.deinit();
        const row = try std.testing.allocator.alloc(
            M31,
            candidate.mainColumnCount(),
        );
        defer std.testing.allocator.free(row);

        var input: [candidate_mod.WIDTH]u32 = undefined;
        for (&input, 0..) |*value, lane| {
            value.* = @intCast(0x1020_304 + lane * 0x10_203);
        }
        const call = production.Call{ .input = input };
        try candidate.fillRow(row, call);
        try candidate.validateNarrowRow(row, M31.one());

        const expected = production.output(production.fill(call));
        const actual = try candidate.outputs(row);
        try std.testing.expectEqualDeep(expected, actual);

        row[0] = M31.zero();
        try std.testing.expectError(
            error.DirectProgramMismatch,
            candidate.validateNarrowRow(row, M31.one()),
        );
        try candidate.fillRow(row, call);

        row[3] = row[3].add(M31.one());
        try std.testing.expect((try candidate.diagnoseRow(row)) != null);
        try candidate.fillRow(row, call);

        const mutation_columns = [3]usize{
            candidate_mod.MATERIALIZATION_COLUMN_START,
            candidate_mod.MATERIALIZATION_COLUMN_START +
                candidate.selected_values.len / 2,
            candidate.mainColumnCount() - 3,
        };
        for (mutation_columns) |column| {
            row[column] = row[column].add(M31.one());
            try std.testing.expect((try candidate.diagnoseRow(row)) != null);
            try candidate.fillRow(row, call);
        }

        row[row.len - 2] = M31.one();
        try std.testing.expectError(
            error.DirectProgramMismatch,
            candidate.validateNarrowRow(row, M31.one()),
        );
        try candidate.fillRow(row, call);
        row[row.len - 1] = M31.one();
        try std.testing.expectError(
            error.DirectProgramMismatch,
            candidate.validateNarrowRow(row, M31.one()),
        );
    }
}

test "degree-bounded quotient and composition domains are exact" {
    try std.testing.expectEqual(
        @as(u32, 26),
        try candidate_mod.Profile.degree5.maxConstraintLogDegreeBound(24),
    );
    try std.testing.expectEqual(
        @as(u32, 24),
        try candidate_mod.Profile.degree5.compositionColumnLogSize(24),
    );
    try std.testing.expectEqual(
        @as(u32, 27),
        try candidate_mod.Profile.degree6.maxConstraintLogDegreeBound(24),
    );
    try std.testing.expectEqual(
        @as(u32, 24),
        try candidate_mod.Profile.degree6.compositionColumnLogSize(24),
    );
    try std.testing.expectEqual(
        @as(u8, 2),
        candidate_mod.Profile.degree5.compositionLogSplit(),
    );
    try std.testing.expectEqual(
        @as(u8, 16),
        candidate_mod.Profile.degree5.compositionColumns(),
    );
    try std.testing.expectEqual(
        @as(u8, 3),
        candidate_mod.Profile.degree6.compositionLogSplit(),
    );
    try std.testing.expectEqual(
        @as(u8, 32),
        candidate_mod.Profile.degree6.compositionColumns(),
    );
}

test "real segment0 Tree1 plus composition floor distinguishes d5 and d6" {
    const cap: u64 = 48 * 1024 * 1024 * 1024;
    const d5_always = try residency.RealSegment0Tree1.tree1PlusCompositionFloor(
        .degree5,
        .always,
    );
    const d5_never = try residency.RealSegment0Tree1.tree1PlusCompositionFloor(
        .degree5,
        .never,
    );
    const d6_always = try residency.RealSegment0Tree1.tree1PlusCompositionFloor(
        .degree6,
        .always,
    );
    const d6_never = try residency.RealSegment0Tree1.tree1PlusCompositionFloor(
        .degree6,
        .never,
    );
    try std.testing.expectEqual(@as(u64, 56_676_327_576), d5_always);
    try std.testing.expectEqual(@as(u64, 37_784_218_384), d5_never);
    try std.testing.expectEqual(@as(u64, 44_194_078_872), d6_always);
    try std.testing.expectEqual(@as(u64, 29_462_719_248), d6_never);
    try std.testing.expect(d5_always > cap);
    try std.testing.expect(d5_never < cap);
    try std.testing.expect(d6_always < cap);
    try std.testing.expect(d6_never < cap);
}

test "full staged residency requires and accounts every tree" {
    const tree0 = [_]u32{ 11, 12, 12 };
    const tree1_other = [_]u32{ 10, 13, 14, 14 };
    const tree2 = [_]u32{ 11, 11, 12, 13 };
    const result = try residency.estimate(.{
        .profile = .degree5,
        .trace_log_size = 14,
        .log_blowup_factor = 1,
        .retention_policy = .never,
        .tree0_log_sizes = &tree0,
        .tree1_non_candidate_log_sizes = &tree1_other,
        .tree2_log_sizes = &tree2,
    });
    try std.testing.expectEqual(@as(u32, 14), result.composition_column_log_size);
    try std.testing.expectEqual(@as(u64, 16), result.composition.column_count);
    try std.testing.expectEqual(
        result.tree1_candidate.minimum_resident_bytes +
            result.tree1_non_candidate.minimum_resident_bytes,
        result.tree1.minimum_resident_bytes,
    );
    try std.testing.expectEqual(
        result.tree0.minimum_resident_bytes +
            result.tree1.minimum_resident_bytes +
            result.tree2.minimum_resident_bytes +
            result.composition.minimum_resident_bytes,
        result.retained_opening_lower_bound_bytes,
    );
    try std.testing.expect(
        result.staged_peak_lower_bound_bytes >=
            result.retained_opening_lower_bound_bytes,
    );

    try std.testing.expectError(
        error.IncompleteStageAuthority,
        residency.estimate(.{
            .profile = .degree5,
            .trace_log_size = 14,
            .log_blowup_factor = 1,
            .retention_policy = .never,
            .tree0_log_sizes = &.{},
            .tree1_non_candidate_log_sizes = &tree1_other,
            .tree2_log_sizes = &tree2,
        }),
    );
}
