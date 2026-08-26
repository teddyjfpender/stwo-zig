const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const cost = @import("materialization_cost.zig");
const direct_program = @import("materialization_direct_program.zig");
const effects = @import("effects.zig");
const fixed = @import("materialization_fixed_direct.zig");
const ir = @import("ir.zig");
const materializer = @import("degree3_materializer.zig");
const poseidon = @import("typed_poseidon2.zig");
const poseidon_fixed = @import("typed_poseidon2_fixed_direct.zig");
const source = @import("source.zig");
const types = @import("types.zig");

test "machine-derived access clock and strict gap lower as affine direct nodes" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const instruction_clock = try arena.input("clock", .clock, generated);
    const previous_clock = try arena.input("previous_clock", .clock, generated);
    const active = try arena.input("active", .bit, generated);
    const first_register = try arena.input("first_register", .register_index, generated);
    const second_register = try arena.input("second_register", .register_index, generated);
    const zero_byte = try arena.constantUnsigned(.byte, 0, generated);
    const word = [_]types.ValueId{zero_byte} ** 4;
    var schedule = try effects.AccessSchedule.begin(
        &arena,
        instruction_clock,
        active,
        generated,
    );
    _ = try schedule.registerRead(.{
        .index = first_register,
        .previous_clock = previous_clock,
        .value = word,
    }, generated);
    const second = try schedule.registerRead(.{
        .index = second_register,
        .previous_clock = previous_clock,
        .value = word,
    }, generated);
    const gap = arena.effectValues(second.clock_gap).?[0];

    var program = try direct_program.extract(std.testing.allocator, &arena, .{
        .gate = null,
        .selected = &.{gap},
        .materialization_column_start = 0,
    });
    defer program.deinit();

    try std.testing.expectEqual(@as(u64, 12), program.counts.nodes);
    try std.testing.expectEqual(@as(u64, 1), program.counts.additions);
    try std.testing.expectEqual(@as(u64, 4), program.counts.subtractions);
    try std.testing.expectEqual(@as(u64, 1), program.counts.multiplications);
    try std.testing.expectEqual(@as(u64, 3), program.counts.unique_committed_column_reads);

    const values = try std.testing.allocator.alloc(m31.M31, program.nodes().len);
    defer std.testing.allocator.free(values);
    const materialized_namespace = @as(u64, 1) << 63;
    const clock_value: u32 = 8;
    const previous_value: u32 = 29;
    const expected_gap = m31.M31.fromCanonical(
        4 * (clock_value - 1) + @intFromEnum(types.AccessOrdinal.second) -
            previous_value - 1,
    );
    for (program.nodes(), values) |node, *value| {
        value.* = switch (node.op) {
            .constant => m31.M31.fromU64(node.value),
            .committed => blk: {
                if ((node.value & materialized_namespace) != 0)
                    break :blk expected_gap;
                const source_value: types.ValueId = @enumFromInt(@as(u32, @intCast(node.value)));
                if (source_value == instruction_clock)
                    break :blk m31.M31.fromCanonical(clock_value);
                if (source_value == previous_clock)
                    break :blk m31.M31.fromCanonical(previous_value);
                return error.UnexpectedCommittedValue;
            },
            .add => values[node.lhs].add(values[node.rhs]),
            .sub => values[node.lhs].sub(values[node.rhs]),
            .mul => values[node.lhs].mul(values[node.rhs]),
            .neg => values[node.lhs].neg(),
            .fixed_committed, .row_mask => return error.UnexpectedDirectNode,
        };
    }
    try std.testing.expect(values[program.roots()[0].node].isZero());
}

test "canonical Poseidon direct program owns the exact H-009 DAG and layout" {
    var fixture = try PoseidonFixture.init(std.testing.allocator);
    defer fixture.deinit();
    var program = try fixture.extract(std.testing.allocator);
    defer program.deinit();

    try std.testing.expectEqual(@as(usize, 3_460), program.nodes().len);
    try std.testing.expectEqual(program.nodes().len, program.creationEvents().len);
    try std.testing.expectEqual(@as(usize, 430), program.roots().len);
    try std.testing.expectEqual(@as(usize, 426), program.selectedColumns().len);
    try std.testing.expectEqualDeep(direct_program.StructuralCounts{
        .nodes = 3_460,
        .root_uses = 430,
        .additions = 1_346,
        .subtractions = 429,
        .negations = 0,
        .multiplications = 1_080,
        .unique_committed_column_reads = 445,
        .streaming_peak_live_nodes = 39,
    }, program.counts);

    var prior_creation_event: usize = 0;
    for (program.creationEvents()) |event| {
        try std.testing.expect(event > prior_creation_event);
        prior_creation_event = event;
    }
    var prior_fold_event: usize = 0;
    for (program.roots()) |root| {
        try std.testing.expect(root.node < program.nodes().len);
        try std.testing.expect(root.fold_event > prior_fold_event);
        prior_fold_event = root.fold_event;
    }
    for (program.selectedColumns(), 0..) |column, ordinal| {
        try std.testing.expectEqual(fixture.selected[ordinal], column.source_value);
        try std.testing.expectEqual(fixed.CommitmentTree.main, column.tree);
        try std.testing.expectEqual(
            @as(u64, poseidon_fixed.main_prefix_columns + ordinal),
            column.physical_column,
        );
        try std.testing.expectEqual(
            direct_program.Op.committed,
            program.nodes()[column.direct_node].op,
        );
    }
    try std.testing.expectEqual(
        @as(u64, 3_460 * @sizeOf(m31.M31)),
        try program.retainedScratchBytes(m31.M31),
    );
    try std.testing.expectEqual(
        @as(u64, 3_460 * @sizeOf(m31.PackedM31)),
        try program.retainedScratchBytes(m31.PackedM31),
    );

    const expected_hex =
        "0fce9141ff3a4411c734f3a31fef5177e38c280e38b4e66fa8d9a402b6c63249";
    const digest_hex = std.fmt.bytesToHex(program.programDigest(), .lower);
    try std.testing.expectEqualStrings(expected_hex, &digest_hex);
    var expected_digest: direct_program.Digest = undefined;
    _ = try std.fmt.hexToBytes(&expected_digest, expected_hex);
    try program.authenticate(expected_digest);
    expected_digest[0] ^= 1;
    try std.testing.expectError(
        error.ProgramDigestMismatch,
        program.authenticate(expected_digest),
    );
}

test "materialization cost consumes the canonical program with exact parity" {
    var fixture = try PoseidonFixture.init(std.testing.allocator);
    defer fixture.deinit();
    var program = try fixture.extract(std.testing.allocator);
    defer program.deinit();
    var report = try cost.analyze(std.testing.allocator, &fixture.arena, .{
        .roots = &fixture.roots,
        .gate = fixture.gate,
        .selected = fixture.selected,
        .geometry = .{ .fixed_direct_roots = poseidon_fixed.fixed_root_count },
        .fixed_direct_program = poseidon_fixed.program,
    });
    defer report.deinit();

    try std.testing.expectEqual(program.counts.nodes, report.vector.canonical_direct_nodes);
    try std.testing.expectEqual(program.counts.root_uses, report.vector.direct_roots);
    try std.testing.expectEqual(program.counts.additions, report.vector.canonical_direct_additions);
    try std.testing.expectEqual(program.counts.subtractions, report.vector.canonical_direct_subtractions);
    try std.testing.expectEqual(program.counts.negations, report.vector.canonical_direct_negations);
    try std.testing.expectEqual(program.counts.multiplications, report.vector.canonical_direct_multiplications);
    try std.testing.expectEqual(
        program.counts.unique_committed_column_reads,
        report.vector.unique_committed_column_reads,
    );
    try std.testing.expectEqual(
        program.counts.streaming_peak_live_nodes,
        report.vector.canonical_streaming_peak_live_nodes,
    );
}

test "late and duplicate roots remain ordered authenticated uses" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const value = try arena.input("value", .felt, source.SourceSpan.generated());
    const selected = [_]types.ValueId{value};
    var program = try direct_program.extract(std.testing.allocator, &arena, .{
        .gate = null,
        .selected = &selected,
        .materialization_column_start = late_program.materialization_column_start,
        .fixed_direct_program = late_program,
    });
    defer program.deinit();

    try std.testing.expectEqual(@as(usize, 4), program.nodes().len);
    try std.testing.expectEqualSlices(usize, &.{ 1, 4, 5, 6 }, program.creationEvents());
    try std.testing.expectEqualDeep(&[_]direct_program.RootUse{
        .{ .node = 0, .fold_event = 2 },
        .{ .node = 0, .fold_event = 3 },
        .{ .node = 3, .fold_event = 7 },
        .{ .node = 0, .fold_event = 8 },
    }, program.roots());
    try std.testing.expectEqual(@as(u64, 4), program.counts.streaming_peak_live_nodes);

    var rephased = try direct_program.extract(std.testing.allocator, &arena, .{
        .gate = null,
        .selected = &selected,
        .materialization_column_start = rephased_program.materialization_column_start,
        .fixed_direct_program = rephased_program,
    });
    defer rephased.deinit();
    const program_digest = program.programDigest();
    const rephased_digest = rephased.programDigest();
    try std.testing.expect(!std.mem.eql(u8, &program_digest, &rephased_digest));
}

test "direct-program identity binds physical placement independently of the DAG" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const value = try arena.input("value", .felt, source.SourceSpan.generated());
    const selected = [_]types.ValueId{value};
    var first = try direct_program.extract(std.testing.allocator, &arena, .{
        .gate = null,
        .selected = &selected,
        .materialization_column_start = 7,
    });
    defer first.deinit();
    var moved = try direct_program.extract(std.testing.allocator, &arena, .{
        .gate = null,
        .selected = &selected,
        .materialization_column_start = 8,
    });
    defer moved.deinit();
    var replay = try direct_program.extract(std.testing.allocator, &arena, .{
        .gate = null,
        .selected = &selected,
        .materialization_column_start = 7,
    });
    defer replay.deinit();

    try std.testing.expectEqualDeep(first.nodes(), moved.nodes());
    try std.testing.expectEqualDeep(first.roots(), moved.roots());
    const first_digest = first.programDigest();
    const moved_digest = moved.programDigest();
    const replay_digest = replay.programDigest();
    try std.testing.expect(!std.mem.eql(u8, &first_digest, &moved_digest));
    try std.testing.expectEqual(first_digest, replay_digest);
    try std.testing.expectError(
        error.MaterializationColumnStartMismatch,
        direct_program.extract(std.testing.allocator, &arena, .{
            .gate = null,
            .selected = &selected,
            .materialization_column_start = 8,
            .fixed_direct_program = late_program,
        }),
    );
}

test "direct-program extraction releases every partial allocation" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const value = try arena.input("value", .felt, source.SourceSpan.generated());
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{ &arena, value },
    );
}

const PoseidonFixture = struct {
    allocator: std.mem.Allocator,
    arena: ir.Arena,
    gate: types.ValueId,
    roots: [poseidon.WIDTH]types.ValueId,
    selected: []types.ValueId,

    fn init(allocator: std.mem.Allocator) !PoseidonFixture {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const generated = source.SourceSpan.generated();
        const gate = try arena.input("riscv.poseidon2_m31.enabled", .selector, generated);
        const definition = try poseidon.define(
            &arena,
            poseidon.DefinitionSpans.uniform(generated),
        );
        const roots = poseidon.values(definition.outputs);
        var plan = try materializer.plan(allocator, &arena, .{
            .roots = &roots,
            .gate = gate,
        });
        defer plan.deinit();
        const selected = try allocator.alloc(types.ValueId, plan.materializations.len);
        errdefer allocator.free(selected);
        for (plan.materializations, selected) |item, *value|
            value.* = item.source_value;
        std.mem.sort(types.ValueId, selected, {}, valueLessThan);
        return .{
            .allocator = allocator,
            .arena = arena,
            .gate = gate,
            .roots = roots,
            .selected = selected,
        };
    }

    fn extract(
        self: *const PoseidonFixture,
        allocator: std.mem.Allocator,
    ) !direct_program.Program {
        return direct_program.extract(allocator, &self.arena, .{
            .gate = self.gate,
            .selected = self.selected,
            .materialization_column_start = poseidon_fixed.main_prefix_columns,
            .fixed_direct_program = poseidon_fixed.program,
        });
    }

    fn deinit(self: *PoseidonFixture) void {
        self.allocator.free(self.selected);
        self.arena.deinit();
        self.* = undefined;
    }
};

const late_nodes = [_]fixed.Node{.{ .op = .constant, .value = 7 }};
const duplicate_prefix_roots = [_]fixed.NodeId{
    @enumFromInt(0),
    @enumFromInt(0),
};
const one_root = [_]fixed.NodeId{@enumFromInt(0)};
const duplicate_suffix_roots = [_]fixed.NodeId{
    @enumFromInt(0),
    @enumFromInt(0),
};
const late_program = fixed.Program{
    .scope_id = "test.materialization-direct.late-root",
    .scope_version = 1,
    .materialization_tree = .main,
    .materialization_column_start = 2,
    .columns = &.{},
    .nodes = &late_nodes,
    .prefix_roots = &duplicate_prefix_roots,
    .suffix_roots = &one_root,
};
const rephased_program = fixed.Program{
    .scope_id = "test.materialization-direct.rephased-root",
    .scope_version = 1,
    .materialization_tree = .main,
    .materialization_column_start = 2,
    .columns = &.{},
    .nodes = &late_nodes,
    .prefix_roots = &one_root,
    .suffix_roots = &duplicate_suffix_roots,
};

fn allocationFailureCase(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    value: types.ValueId,
) !void {
    const selected = [_]types.ValueId{value};
    var program = try direct_program.extract(allocator, arena, .{
        .gate = null,
        .selected = &selected,
        .materialization_column_start = late_program.materialization_column_start,
        .fixed_direct_program = late_program,
    });
    defer program.deinit();
}

fn valueLessThan(_: void, lhs: types.ValueId, rhs: types.ValueId) bool {
    return @intFromEnum(lhs) < @intFromEnum(rhs);
}
