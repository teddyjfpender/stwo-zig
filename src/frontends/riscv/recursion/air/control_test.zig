const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const control = @import("control.zig");
const relation = @import("../../air/lang/relation.zig");
const relation_plan = @import("control_relation.zig");
const witness = @import("control_witness.zig");
const schedule = @import("verifier_schedule.zig");
const universal = @import("universal_challenges.zig");

test "R-012 exact control component compiles its source geometry and seal" {
    var definition = try control.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try relation_plan.authenticate(&definition);
    try std.testing.expectEqual(@as(usize, 0), control.PHYSICAL_MAIN_COLUMN_COUNT);
    try std.testing.expectEqual(@as(usize, 10), control.PREPROCESSED_COLUMN_COUNT);
    try std.testing.expectEqual(@as(usize, 2), control.PROOF_KIND_PARAMETER_COUNT);
    try std.testing.expectEqual(@as(usize, 1), definition.arena.constraintsView().len);
    try std.testing.expectEqual(@as(usize, 2), definition.arena.effectsView().len);
    try std.testing.expectEqual(@as(u16, 4), plan.compiled_node_count);
    try std.testing.expectEqual(@as(usize, 2), relation_plan.Runtime.BATCH_COUNT);
    try std.testing.expectEqual(@as(usize, 8), relation_plan.Runtime.INTERACTION_COLUMN_COUNT);
    try std.testing.expectEqual(relation.Domain.recursion_step, plan.events[0].domain);
    try std.testing.expectEqual(relation.Role.emit, plan.events[0].role);
    try std.testing.expectEqual(relation.Role.consume, plan.events[1].role);
}

test "R-012 exact control rows honor segment binary and empty public selectors" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var definition = try control.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try relation_plan.authenticate(&definition);
    const relations = universal.UniversalRelations.dummy();

    const segment = witness.logicalRow(fixture.preprocessing.rows[0], .segment_leaf);
    const segment_entries = try plan.entries(
        &definition.arena,
        control.SEMANTIC_DIGEST,
        definition.events,
        segment,
    );
    try std.testing.expect(segment_entries[0].numerator.eql(QM31.one()));

    const segment_row_in_binary = witness.logicalRow(
        fixture.preprocessing.rows[0],
        .binary_node,
    );
    const inactive = try plan.entries(
        &definition.arena,
        control.SEMANTIC_DIGEST,
        definition.events,
        segment_row_in_binary,
    );
    try std.testing.expect(inactive[0].numerator.isZero());
    try std.testing.expect(inactive[1].numerator.isZero());

    const binary_offset = fixture.vm.steps.len;
    const binary = witness.logicalRow(
        fixture.preprocessing.rows[binary_offset],
        .binary_node,
    );
    const binary_entries = try plan.entries(
        &definition.arena,
        control.SEMANTIC_DIGEST,
        definition.events,
        binary,
    );
    try std.testing.expect(binary_entries[0].numerator.eql(QM31.one()));

    const empty = witness.logicalRow(fixture.preprocessing.rows[0], .empty_leaf);
    const empty_pairs = try plan.rowPairs(
        &definition.arena,
        control.SEMANTIC_DIGEST,
        definition.events,
        empty,
        &relations,
    );
    for (empty_pairs) |pair| {
        try std.testing.expect(pair.n1.isZero());
        try std.testing.expect(pair.n2.isZero());
    }
}

test "R-012 exact control terminal rows close internally and nonterminals bridge" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var definition = try control.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try relation_plan.authenticate(&definition);
    const relations = universal.UniversalRelations.dummy();

    for ([_]witness.ProofKind{ .segment_leaf, .binary_node, .empty_leaf }) |kind| {
        var total = QM31.zero();
        for (fixture.preprocessing.rows) |row| {
            const logical = witness.logicalRow(row, kind);
            const claims = try plan.rowClaims(
                &definition.arena,
                control.SEMANTIC_DIGEST,
                definition.events,
                logical,
                &relations,
            );
            total = total.add(claims.total());
            const active = switch (kind) {
                .segment_leaf => row.segment_mask == 1,
                .binary_node => row.binary_mask == 1,
                .empty_leaf => false,
            };
            if (active and row.terminal_mask == 0) {
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
                total = total.sub(try denominator.inv());
            }
        }
        try std.testing.expect(total.isZero());
    }
}

test "R-012 exact control interaction is allocation-bounded and validates mutations" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var definition = try control.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try relation_plan.authenticate(&definition);
    const relations = universal.UniversalRelations.dummy();
    const rows = try std.testing.allocator.alloc(
        relation_plan.Row,
        fixture.preprocessing.rows.len,
    );
    defer std.testing.allocator.free(rows);
    for (rows, fixture.preprocessing.rows) |*target, source_row|
        target.* = witness.logicalRow(source_row, .segment_leaf);

    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    {
        var interaction = try plan.generateInteraction(
            measured.allocator(),
            &definition.arena,
            control.SEMANTIC_DIGEST,
            definition.events,
            rows,
            fixture.preprocessing.log_size,
            &relations,
        );
        defer interaction.deinit(measured.allocator());
        try std.testing.expect(measured.alloc_index <= 5);
        try plan.validateInteraction(
            std.testing.allocator,
            &definition.arena,
            control.SEMANTIC_DIGEST,
            definition.events,
            rows,
            fixture.preprocessing.log_size,
            &relations,
            &interaction,
        );
        interaction.storage[0] = interaction.storage[0].add(M31.one());
        try std.testing.expectError(
            error.InteractionColumnMismatch,
            plan.validateInteraction(
                std.testing.allocator,
                &definition.arena,
                control.SEMANTIC_DIGEST,
                definition.events,
                rows,
                fixture.preprocessing.log_size,
                &relations,
                &interaction,
            ),
        );
    }
    try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);
}

test "R-012 exact control construction and interaction release allocation failures" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        controlBuildFailureCase,
        .{},
    );
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var definition = try control.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try relation_plan.authenticate(&definition);
    const relations = universal.UniversalRelations.dummy();
    const rows = try std.testing.allocator.alloc(
        relation_plan.Row,
        fixture.preprocessing.rows.len,
    );
    defer std.testing.allocator.free(rows);
    for (rows, fixture.preprocessing.rows) |*target, source_row|
        target.* = witness.logicalRow(source_row, .binary_node);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        interactionFailureCase,
        .{ &definition, &plan, rows, fixture.preprocessing.log_size, &relations },
    );
}

const Fixture = struct {
    vm: schedule.Plan,
    recursion: schedule.Plan,
    preprocessing: witness.Preprocessed,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const shape = try testShape();
        var vm = try schedule.Plan.init(
            allocator,
            try schedule.ProgramSpec.init(.vm, 3, 2, 3, 2),
            shape,
        );
        errdefer vm.deinit();
        var recursion = try schedule.Plan.init(
            allocator,
            try schedule.ProgramSpec.init(.recursion, 3, 0, 3, 2),
            shape,
        );
        errdefer recursion.deinit();
        return .{
            .vm = vm,
            .recursion = recursion,
            .preprocessing = try witness.Preprocessed.init(allocator, &vm, &recursion),
        };
    }

    fn deinit(self: *Fixture) void {
        self.preprocessing.deinit();
        self.recursion.deinit();
        self.vm.deinit();
        self.* = undefined;
    }
};

fn controlBuildFailureCase(allocator: std.mem.Allocator) !void {
    var definition = try control.build(allocator);
    defer definition.deinit();
}

fn interactionFailureCase(
    allocator: std.mem.Allocator,
    definition: *const control.Definition,
    plan: *const relation_plan.Plan,
    rows: []const relation_plan.Row,
    log_size: u32,
    relations: *const universal.UniversalRelations,
) !void {
    var interaction = try plan.generateInteraction(
        allocator,
        &definition.arena,
        control.SEMANTIC_DIGEST,
        definition.events,
        rows,
        log_size,
        relations,
    );
    defer interaction.deinit(allocator);
}

fn testShape() !@import("../fixed_profile.zig").ProofShapeV1 {
    const fixed_profile = @import("../fixed_profile.zig");
    const protocol = @import("../protocol.zig");
    const channel = @import("../poseidon2_channel.zig");
    const fri = try fixed_profile.FriSchedule.init(8, protocol.PCS_CONFIG.fri_config);
    return .{
        .air_program_id = channel.hashBytes("control-air", 0x5450),
        .preprocessing_id = channel.hashBytes("control-preprocessing", 0x5450),
        .table_layout_id = channel.hashBytes("control-layout", 0x5450),
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
