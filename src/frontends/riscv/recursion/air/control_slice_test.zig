//! Adversarial and performance coverage for authority-spine rows 17 and 19.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const relation = @import("../../air/lang/relation.zig");
const public_air = @import("vm_public_logup_control.zig").Air;
const public_relation = @import("vm_public_logup_control_relation.zig").Relation;
const composition_air = @import("vm_air_composition_control.zig").Air;
const composition_relation = @import("vm_air_composition_control_relation.zig").Relation;
const witness = @import("control_slice_witness.zig");
const schedule = @import("verifier_schedule.zig");
const universal = @import("universal_challenges.zig");

test "R-012 control slices preserve exact source geometry and distinct seals" {
    var public_definition = try public_air.build(std.testing.allocator);
    defer public_definition.deinit();
    var composition_definition = try composition_air.build(std.testing.allocator);
    defer composition_definition.deinit();
    const public_plan = try public_relation.authenticate(&public_definition);
    const composition_plan = try composition_relation.authenticate(
        &composition_definition,
    );

    inline for (.{ public_air, composition_air }) |Air| {
        try std.testing.expectEqual(@as(usize, 0), Air.PHYSICAL_MAIN_COLUMN_COUNT);
        try std.testing.expectEqual(@as(usize, 9), Air.PREPROCESSED_COLUMN_COUNT);
        try std.testing.expectEqual(@as(usize, 2), Air.PROOF_KIND_PARAMETER_COUNT);
        try std.testing.expectEqual(@as(usize, 11), Air.LOGICAL_INPUT_COUNT);
        try std.testing.expectEqual(@as(usize, 1), Air.DIRECT_CONSTRAINT_COUNT);
        try std.testing.expectEqual(@as(usize, 1), Air.RELATION_EVENT_COUNT);
        try std.testing.expectEqual(@as(usize, 1), Air.INTERACTION_BATCH_COUNT);
        try std.testing.expectEqual(@as(usize, 4), Air.INTERACTION_COLUMN_COUNT);
    }
    try std.testing.expect(!std.mem.eql(
        u8,
        &public_air.SEMANTIC_DIGEST,
        &composition_air.SEMANTIC_DIGEST,
    ));
    try std.testing.expectEqual(@as(u16, 6), public_plan.compiled_node_count);
    try std.testing.expectEqual(@as(u16, 6), composition_plan.compiled_node_count);
    try std.testing.expectEqual(relation.Domain.recursion_step, public_plan.events[0].domain);
    try std.testing.expectEqual(relation.Role.consume, public_plan.events[0].role);
    try std.testing.expectEqual(relation.Domain.recursion_step, composition_plan.events[0].domain);
    try std.testing.expectEqual(relation.Role.consume, composition_plan.events[0].role);
}

test "R-012 schedule validators reject every public-LogUp slice deformation" {
    const valid = [_]schedule.VerifierStep{
        .{ .accumulate_public_logup_term = .{ .term = 0 } },
        .{ .accumulate_public_logup_term = .{ .term = 1 } },
        .assert_global_logup_zero,
    };
    try std.testing.expectEqual(
        @as(usize, 3),
        try witness.validatePublicLogupSteps(&valid, 2),
    );
    try std.testing.expectError(
        error.NonCanonicalTermIndex,
        witness.validatePublicLogupSteps(&.{
            .{ .accumulate_public_logup_term = .{ .term = 1 } },
            .assert_global_logup_zero,
        }, 1),
    );
    try std.testing.expectError(
        error.TermAfterGlobalAssertion,
        witness.validatePublicLogupSteps(&.{
            .{ .accumulate_public_logup_term = .{ .term = 0 } },
            .assert_global_logup_zero,
            .{ .accumulate_public_logup_term = .{ .term = 1 } },
        }, 1),
    );
    try std.testing.expectError(
        error.DuplicateGlobalAssertion,
        witness.validatePublicLogupSteps(&.{
            .assert_global_logup_zero,
            .assert_global_logup_zero,
        }, 0),
    );
    try std.testing.expectError(
        error.GlobalAssertionMissing,
        witness.validatePublicLogupSteps(&.{
            .{ .accumulate_public_logup_term = .{ .term = 0 } },
        }, 1),
    );
    try std.testing.expectError(
        error.TermCountMismatch,
        witness.validatePublicLogupSteps(&.{
            .{ .accumulate_public_logup_term = .{ .term = 0 } },
            .assert_global_logup_zero,
        }, 2),
    );
}

test "R-012 schedule validators reject every AIR-composition slice deformation" {
    const valid = [_]schedule.VerifierStep{
        .{ .evaluate_air_instruction = .{ .instruction = 0 } },
        .{ .evaluate_air_instruction = .{ .instruction = 1 } },
        .{ .assert_composition = .{ .sampled_value_count = 8 } },
    };
    try std.testing.expectEqual(
        @as(usize, 3),
        try witness.validateCompositionSteps(&valid, 2, 8),
    );
    try std.testing.expectError(
        error.NonCanonicalInstructionIndex,
        witness.validateCompositionSteps(&.{
            .{ .evaluate_air_instruction = .{ .instruction = 1 } },
            .{ .assert_composition = .{ .sampled_value_count = 8 } },
        }, 1, 8),
    );
    try std.testing.expectError(
        error.NonContiguousInstruction,
        witness.validateCompositionSteps(&.{
            .{ .evaluate_air_instruction = .{ .instruction = 0 } },
            .bind_protocol,
            .{ .evaluate_air_instruction = .{ .instruction = 1 } },
            .{ .assert_composition = .{ .sampled_value_count = 8 } },
        }, 2, 8),
    );
    try std.testing.expectError(
        error.InstructionAfterCompositionAssertion,
        witness.validateCompositionSteps(&.{
            .{ .evaluate_air_instruction = .{ .instruction = 0 } },
            .{ .assert_composition = .{ .sampled_value_count = 8 } },
            .{ .evaluate_air_instruction = .{ .instruction = 1 } },
        }, 1, 8),
    );
    try std.testing.expectError(
        error.DuplicateCompositionAssertion,
        witness.validateCompositionSteps(&.{
            .{ .evaluate_air_instruction = .{ .instruction = 0 } },
            .{ .assert_composition = .{ .sampled_value_count = 8 } },
            .{ .assert_composition = .{ .sampled_value_count = 8 } },
        }, 1, 8),
    );
    try std.testing.expectError(
        error.CompositionAssertionNotAdjacent,
        witness.validateCompositionSteps(&.{
            .{ .evaluate_air_instruction = .{ .instruction = 0 } },
            .bind_protocol,
            .{ .assert_composition = .{ .sampled_value_count = 8 } },
        }, 1, 8),
    );
    try std.testing.expectError(
        error.CompositionAssertionMissing,
        witness.validateCompositionSteps(&.{
            .{ .evaluate_air_instruction = .{ .instruction = 0 } },
        }, 1, 8),
    );
    try std.testing.expectError(
        error.SampledValueCountMismatch,
        witness.validateCompositionSteps(&.{
            .{ .evaluate_air_instruction = .{ .instruction = 0 } },
            .{ .assert_composition = .{ .sampled_value_count = 7 } },
        }, 1, 8),
    );
}

test "R-012 verifier-owned control slices are exact across all three lanes" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try fixture.public.validateAgainst(&fixture.vm, &fixture.recursion);
    try fixture.composition.validateAgainst(&fixture.vm, &fixture.recursion);

    try std.testing.expectEqual(@as(usize, 5), fixture.public.rows.len);
    try std.testing.expectEqual(@as(usize, 14), fixture.composition.rows.len);
    try std.testing.expectEqual(@as(u32, 11), fixture.public.rows[0].tag);
    try std.testing.expectEqual(@as(u32, 12), fixture.public.rows[2].tag);
    try std.testing.expectEqual(@as(u32, 13), fixture.composition.rows[0].tag);
    try std.testing.expectEqual(@as(u32, 14), fixture.composition.rows[3].tag);
    try std.testing.expectEqual(
        witness.LEFT_RECURSION_VERIFIER_ID,
        fixture.public.rows[3].verifier_id,
    );
    try std.testing.expectEqual(
        witness.RIGHT_RECURSION_VERIFIER_ID,
        fixture.composition.rows[9].verifier_id,
    );

    for ([_]witness.ProofKind{ .segment_leaf, .binary_node, .empty_leaf }) |kind| {
        try std.testing.expectEqual(
            switch (kind) {
                .segment_leaf => @as(usize, 3),
                .binary_node => @as(usize, 2),
                .empty_leaf => @as(usize, 0),
            },
            fixture.public.activeStepCount(kind),
        );
        try std.testing.expectEqual(
            switch (kind) {
                .segment_leaf => @as(usize, 4),
                .binary_node => @as(usize, 10),
                .empty_leaf => @as(usize, 0),
            },
            fixture.composition.activeStepCount(kind),
        );
    }

    fixture.public.rows[0].tag += 1;
    try std.testing.expectError(
        error.ScheduleAuthorityMismatch,
        fixture.public.validateAgainst(&fixture.vm, &fixture.recursion),
    );
    fixture.public.rows[0].tag -= 1;
    fixture.composition.rows[0].args[0] += 1;
    try std.testing.expectError(
        error.ScheduleAuthorityMismatch,
        fixture.composition.validateAgainst(&fixture.vm, &fixture.recursion),
    );
}

test "R-012 both control slices consume the exact row-zero producer subset" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var public_definition = try public_air.build(std.testing.allocator);
    defer public_definition.deinit();
    var composition_definition = try composition_air.build(std.testing.allocator);
    defer composition_definition.deinit();
    const public_plan = try public_relation.authenticate(&public_definition);
    const composition_plan = try composition_relation.authenticate(
        &composition_definition,
    );
    const relations = universal.UniversalRelations.dummy();

    for ([_]witness.ProofKind{ .segment_leaf, .binary_node, .empty_leaf }) |kind| {
        try assertClosedSlice(
            public_air,
            public_relation,
            &public_definition,
            &public_plan,
            fixture.public.rows,
            kind,
            &relations,
        );
        try assertClosedSlice(
            composition_air,
            composition_relation,
            &composition_definition,
            &composition_plan,
            fixture.composition.rows,
            kind,
            &relations,
        );
    }
}

test "R-012 control-slice direct writer is atomic allocation-free and zero pads" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const size = @as(usize, 1) << @intCast(fixture.composition.log_size);
    const storage = try std.testing.allocator.alloc(
        M31,
        witness.COLUMN_COUNT * size,
    );
    defer std.testing.allocator.free(storage);
    @memset(storage, M31.fromU64(99));
    var columns: [witness.COLUMN_COUNT][]M31 = undefined;
    for (&columns, 0..) |*column, index|
        column.* = storage[index * size ..][0..size];
    try fixture.composition.generateInto(
        &columns,
        &fixture.vm,
        &fixture.recursion,
    );
    for (fixture.composition.rows, 0..) |row, index| {
        for (columns, row.values()) |column, expected|
            try std.testing.expect(column[index].eql(expected));
    }
    for (columns) |column| for (column[fixture.composition.rows.len..]) |padding|
        try std.testing.expect(padding.isZero());

    const snapshot = try std.testing.allocator.dupe(M31, storage);
    defer std.testing.allocator.free(snapshot);
    columns[1] = columns[0];
    try std.testing.expectError(
        error.AliasedDestination,
        fixture.composition.generateInto(
            &columns,
            &fixture.vm,
            &fixture.recursion,
        ),
    );
    try std.testing.expectEqualSlices(M31, snapshot, storage);
}

test "R-012 control-slice interaction remains cache bounded and detects mutation" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var definition = try composition_air.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try composition_relation.authenticate(&definition);
    const events = composition_relation.events(&definition);
    const relations = universal.UniversalRelations.dummy();
    const rows = try std.testing.allocator.alloc(
        composition_relation.Row,
        fixture.composition.rows.len,
    );
    defer std.testing.allocator.free(rows);
    for (rows, fixture.composition.rows) |*target, source|
        target.* = witness.logicalRow(source, .binary_node);

    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    {
        var interaction = try plan.generateInteraction(
            measured.allocator(),
            &definition.arena,
            composition_air.SEMANTIC_DIGEST,
            events,
            rows,
            fixture.composition.log_size,
            &relations,
        );
        defer interaction.deinit(measured.allocator());
        try std.testing.expect(measured.alloc_index <= 5);
        try plan.validateInteraction(
            std.testing.allocator,
            &definition.arena,
            composition_air.SEMANTIC_DIGEST,
            events,
            rows,
            fixture.composition.log_size,
            &relations,
            &interaction,
        );
        interaction.storage[0] = interaction.storage[0].add(M31.one());
        try std.testing.expectError(
            error.InteractionColumnMismatch,
            plan.validateInteraction(
                std.testing.allocator,
                &definition.arena,
                composition_air.SEMANTIC_DIGEST,
                events,
                rows,
                fixture.composition.log_size,
                &relations,
                &interaction,
            ),
        );
    }
    try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);
}

test "R-012 control-slice construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        publicBuildFailureCase,
        .{},
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        compositionBuildFailureCase,
        .{},
    );
    var fixture = try FixturePlans.init(std.testing.allocator);
    defer fixture.deinit();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        publicPreprocessingFailureCase,
        .{ &fixture.vm, &fixture.recursion },
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        compositionPreprocessingFailureCase,
        .{ &fixture.vm, &fixture.recursion },
    );
}

fn assertClosedSlice(
    comptime Air: type,
    comptime Relation: type,
    definition: *const Air.Definition,
    plan: *const Relation.Plan,
    rows: []const witness.Row,
    kind: witness.ProofKind,
    relations: *const universal.UniversalRelations,
) !void {
    const events = Relation.events(definition);
    var total = QM31.zero();
    for (rows) |row| {
        const logical = witness.logicalRow(row, kind);
        const entries = try plan.entries(
            &definition.arena,
            Air.SEMANTIC_DIGEST,
            events,
            logical,
        );
        const active = switch (kind) {
            .segment_leaf => row.segment_mask == 1,
            .binary_node => row.segment_mask == 0,
            .empty_leaf => false,
        };
        try std.testing.expect(entries[0].numerator.eql(
            if (active) QM31.one().neg() else QM31.zero(),
        ));
        const claims = try plan.rowClaims(
            &definition.arena,
            Air.SEMANTIC_DIGEST,
            events,
            logical,
            relations,
        );
        total = total.add(claims.total());
        if (active) {
            const tuple = [_]M31{
                M31.fromU64(row.verifier_id),
                M31.fromU64(row.sequence),
                M31.fromU64(row.tag),
                M31.fromU64(row.args[0]),
                M31.fromU64(row.args[1]),
                M31.fromU64(row.args[2]),
                M31.fromU64(row.args[3]),
            };
            const denominator = try relations.get(.recursion_step).combineBase(&tuple);
            total = total.add(try denominator.inv());
        }
    }
    try std.testing.expect(total.isZero());
}

const FixturePlans = struct {
    vm: schedule.Plan,
    recursion: schedule.Plan,

    fn init(allocator: std.mem.Allocator) !FixturePlans {
        const shape = try testShape();
        var vm = try schedule.Plan.init(
            allocator,
            try schedule.ProgramSpec.init(.vm, 3, 2, 3, 2),
            shape,
        );
        errdefer vm.deinit();
        return .{
            .vm = vm,
            .recursion = try schedule.Plan.init(
                allocator,
                try schedule.ProgramSpec.init(.recursion, 3, 0, 4, 2),
                shape,
            ),
        };
    }

    fn deinit(self: *FixturePlans) void {
        self.recursion.deinit();
        self.vm.deinit();
        self.* = undefined;
    }
};

const Fixture = struct {
    vm: schedule.Plan,
    recursion: schedule.Plan,
    public: witness.PublicLogupPreprocessed,
    composition: witness.CompositionPreprocessed,

    fn init(allocator: std.mem.Allocator) !Fixture {
        var plans = try FixturePlans.init(allocator);
        errdefer plans.deinit();
        var public = try witness.PublicLogupPreprocessed.init(
            allocator,
            &plans.vm,
            2,
            &plans.recursion,
            0,
        );
        errdefer public.deinit();
        return .{
            .vm = plans.vm,
            .recursion = plans.recursion,
            .public = public,
            .composition = try witness.CompositionPreprocessed.init(
                allocator,
                &plans.vm,
                3,
                8,
                &plans.recursion,
                4,
                8,
            ),
        };
    }

    fn deinit(self: *Fixture) void {
        self.composition.deinit();
        self.public.deinit();
        self.recursion.deinit();
        self.vm.deinit();
        self.* = undefined;
    }
};

fn publicBuildFailureCase(allocator: std.mem.Allocator) !void {
    var definition = try public_air.build(allocator);
    defer definition.deinit();
}

fn compositionBuildFailureCase(allocator: std.mem.Allocator) !void {
    var definition = try composition_air.build(allocator);
    defer definition.deinit();
}

fn publicPreprocessingFailureCase(
    allocator: std.mem.Allocator,
    vm: *const schedule.Plan,
    recursion: *const schedule.Plan,
) !void {
    var preprocessing = try witness.PublicLogupPreprocessed.init(
        allocator,
        vm,
        2,
        recursion,
        0,
    );
    defer preprocessing.deinit();
}

fn compositionPreprocessingFailureCase(
    allocator: std.mem.Allocator,
    vm: *const schedule.Plan,
    recursion: *const schedule.Plan,
) !void {
    var preprocessing = try witness.CompositionPreprocessed.init(
        allocator,
        vm,
        3,
        8,
        recursion,
        4,
        8,
    );
    defer preprocessing.deinit();
}

fn testShape() !@import("../fixed_profile.zig").ProofShapeV1 {
    const fixed_profile = @import("../fixed_profile.zig");
    const protocol = @import("../protocol.zig");
    const channel = @import("../poseidon2_channel.zig");
    const fri = try fixed_profile.FriSchedule.init(8, protocol.PCS_CONFIG.fri_config);
    return .{
        .air_program_id = channel.hashBytes("control-slice-air", 0x5450),
        .preprocessing_id = channel.hashBytes("control-slice-preprocessing", 0x5450),
        .table_layout_id = channel.hashBytes("control-slice-layout", 0x5450),
        .table_count = 16,
        .claimed_sum_count = 4,
        .sampled_value_count = 8,
        .preprocessed_column_count = 4,
        .tree_column_counts = .{ 4, 4, 4, 4 },
        .tree_heights = .{ 9, 9, 9, 9 },
        .column_log_degree = 8,
        .proof_wire_bytes = 1024,
        .fri = fri,
    };
}
