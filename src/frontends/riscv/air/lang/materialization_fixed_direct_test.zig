const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const fixed = @import("materialization_fixed_direct.zig");
const poseidon = @import("typed_poseidon2_fixed_direct.zig");
const production = @import("../memory_commitment/poseidon2_air.zig");

test "fixed direct: canonical Poseidon program pins scope roots and placements" {
    try poseidon.program.validateFor(std.testing.allocator, 426);
    const identity = try poseidon.program.identity(std.testing.allocator);

    try std.testing.expectEqual(fixed.format_version, identity.format_version);
    try std.testing.expectEqualStrings(poseidon.cost_scope_id, identity.scope_id);
    try std.testing.expectEqual(poseidon.cost_scope_version, identity.scope_version);
    try std.testing.expectEqual(@as(u32, 3), identity.column_count);
    try std.testing.expectEqual(@as(u32, 11), identity.node_count);
    try std.testing.expectEqual(@as(u32, 4), identity.fixed_root_count);
    try std.testing.expectEqual(@as(u64, 430), try poseidon.program.totalRootCount(426));

    try expectColumn(0, "enabler", .gate, .main, 0);
    try expectColumn(1, "wide", .component, .main, 443);
    try expectColumn(2, "io", .component, .main, 444);
    try std.testing.expectEqual(
        @as(u64, 17),
        try poseidon.columns[1].placement.resolve(0),
    );
    try std.testing.expectEqual(
        @as(u64, 18),
        try poseidon.columns[2].placement.resolve(0),
    );

    try std.testing.expectEqualDeep([_]fixed.Node{
        .{ .op = .column, .value = 0 },
        .{ .op = .constant, .value = 1 },
        .{ .op = .sub, .lhs = 1, .rhs = 0 },
        .{ .op = .mul, .lhs = 0, .rhs = 2 },
        .{ .op = .column, .value = 1 },
        .{ .op = .sub, .lhs = 1, .rhs = 4 },
        .{ .op = .mul, .lhs = 4, .rhs = 5 },
        .{ .op = .column, .value = 2 },
        .{ .op = .sub, .lhs = 1, .rhs = 7 },
        .{ .op = .mul, .lhs = 7, .rhs = 8 },
        .{ .op = .mul, .lhs = 4, .rhs = 7 },
    }, poseidon.nodes);
    try std.testing.expectEqualSlices(
        fixed.NodeId,
        &.{@enumFromInt(3)},
        &poseidon.prefix_roots,
    );
    try std.testing.expectEqualSlices(
        fixed.NodeId,
        &.{ @enumFromInt(6), @enumFromInt(9), @enumFromInt(10) },
        &poseidon.suffix_roots,
    );

    try std.testing.expectEqualSlices(u8, &poseidon.canonical_digest, &identity.digest);
}

test "fixed direct: lowering is phase checked lazy and preserves root order" {
    var lowering = try fixed.Lowering.init(std.testing.allocator, poseidon.program, 426);
    defer lowering.deinit();
    var emitter = RecordingEmitter{};
    var prefix: [poseidon.prefix_roots.len]u32 = undefined;
    var suffix: [poseidon.suffix_roots.len]u32 = undefined;

    try std.testing.expectError(
        error.InvalidLoweringPhase,
        lowering.lowerSuffix(&emitter, &suffix),
    );
    try std.testing.expectError(
        error.InvalidDestinationLength,
        lowering.lowerPrefix(&emitter, &.{}),
    );
    try lowering.lowerPrefix(&emitter, &prefix);
    try std.testing.expectEqual(fixed.LoweringPhase.prefix_complete, lowering.phase);
    try std.testing.expectEqualSlices(u32, &.{3}, &prefix);
    try std.testing.expectEqual(@as(usize, 4), emitter.len);
    try std.testing.expectEqualDeep(Event{ .column = .{
        .role = "enabler",
        .binding = .gate,
        .tree = .main,
        .resolved = 0,
    } }, emitter.events[0]);
    try std.testing.expectEqualDeep(Event{ .constant = 1 }, emitter.events[1]);
    try std.testing.expectEqualDeep(Event{ .binary = .{
        .op = .sub,
        .lhs = 1,
        .rhs = 0,
    } }, emitter.events[2]);
    try std.testing.expectEqualDeep(Event{ .binary = .{
        .op = .mul,
        .lhs = 0,
        .rhs = 2,
    } }, emitter.events[3]);

    try std.testing.expectError(
        error.InvalidLoweringPhase,
        lowering.lowerPrefix(&emitter, &prefix),
    );
    try lowering.lowerSuffix(&emitter, &suffix);
    try std.testing.expectEqual(fixed.LoweringPhase.complete, lowering.phase);
    try std.testing.expectEqualSlices(u32, &.{ 6, 9, 10 }, &suffix);
    try std.testing.expectEqual(@as(usize, 11), emitter.len);
    try std.testing.expectEqualStrings("wide", emitter.events[4].column.role);
    try std.testing.expectEqual(@as(u64, 443), emitter.events[4].column.resolved);
    try std.testing.expectEqualStrings("io", emitter.events[7].column.role);
    try std.testing.expectEqual(@as(u64, 444), emitter.events[7].column.resolved);
    // The shared constant was emitted in the prefix and not duplicated.
    var constants: usize = 0;
    for (emitter.events[0..emitter.len]) |event| switch (event) {
        .constant => constants += 1,
        else => {},
    };
    try std.testing.expectEqual(@as(usize, 1), constants);
}

test "fixed direct: lowering binds one emitter across both phases" {
    var lowering = try fixed.Lowering.init(std.testing.allocator, poseidon.program, 426);
    defer lowering.deinit();
    var first = RecordingEmitter{};
    var second = RecordingEmitter{};
    var prefix: [poseidon.prefix_roots.len]u32 = undefined;
    var suffix: [poseidon.suffix_roots.len]u32 = undefined;

    try lowering.lowerPrefix(&first, &prefix);
    try std.testing.expectError(
        error.InvalidLoweringEmitter,
        lowering.lowerSuffix(&second, &suffix),
    );
    try lowering.lowerSuffix(&first, &suffix);
}

test "fixed direct: every Poseidon fixed root equals the production polynomial" {
    var prng = std.Random.DefaultPrng.init(0x4830_3039_2d666978);
    const random = prng.random();
    for (0..16) |_| {
        var main: [production.N_MAIN_COLUMNS]QM31 = undefined;
        for (&main) |*value| value.* = QM31.fromU32Unchecked(
            random.int(u32) % fixed.m31_modulus,
            random.int(u32) % fixed.m31_modulus,
            random.int(u32) % fixed.m31_modulus,
            random.int(u32) % fixed.m31_modulus,
        );
        const expected = production.evaluate(main);
        const actual = try evaluateFixed(main);
        inline for (.{ 0, 427, 428, 429 }, 0..) |constraint, root| {
            try std.testing.expect(actual[root].eql(expected[constraint]));
        }
    }
}

test "fixed direct: malformed canonical programs fail closed" {
    const base = poseidon.program;

    var empty_scope = base;
    empty_scope.scope_id = "";
    try expectInvalid(error.EmptyScopeId, empty_scope);

    var zero_version = base;
    zero_version.scope_version = 0;
    try expectInvalid(error.InvalidScopeVersion, zero_version);

    var columns = poseidon.columns;
    columns[1].role = columns[0].role;
    var duplicate_role = base;
    duplicate_role.columns = &columns;
    try expectInvalid(error.DuplicateColumnRole, duplicate_role);

    columns = poseidon.columns;
    columns[1].binding = .gate;
    var duplicate_gate = base;
    duplicate_gate.columns = &columns;
    try expectInvalid(error.DuplicateGateColumn, duplicate_gate);

    columns = poseidon.columns;
    columns[1].placement = .{ .absolute = 0 };
    var duplicate_place = base;
    duplicate_place.columns = &columns;
    try std.testing.expectError(
        error.DuplicateColumnPlacement,
        duplicate_place.validateFor(std.testing.allocator, 426),
    );

    var nodes = poseidon.nodes;
    nodes[1].value = fixed.m31_modulus;
    var invalid_constant = base;
    invalid_constant.nodes = &nodes;
    try expectInvalid(error.InvalidConstant, invalid_constant);

    nodes = poseidon.nodes;
    nodes[2].lhs = 2;
    var forward_operand = base;
    forward_operand.nodes = &nodes;
    try expectInvalid(error.InvalidNode, forward_operand);

    nodes = poseidon.nodes;
    nodes[3].lhs = 2;
    nodes[3].rhs = 0;
    var noncanonical_mul = base;
    noncanonical_mul.nodes = &nodes;
    try expectInvalid(error.NonCanonicalNode, noncanonical_mul);

    nodes = poseidon.nodes;
    nodes[7] = nodes[4];
    var duplicate_node = base;
    duplicate_node.nodes = &nodes;
    try expectInvalid(error.DuplicateNode, duplicate_node);

    nodes = poseidon.nodes;
    nodes[7].value = 3;
    var invalid_column = base;
    invalid_column.nodes = &nodes;
    try expectInvalid(error.InvalidColumn, invalid_column);

    var bad_prefix = poseidon.prefix_roots;
    bad_prefix[0] = @enumFromInt(poseidon.nodes.len);
    var invalid_root = base;
    invalid_root.prefix_roots = &bad_prefix;
    try expectInvalid(error.InvalidRoot, invalid_root);

    var unused_node = base;
    unused_node.suffix_roots = poseidon.suffix_roots[0..2];
    try expectInvalid(error.UnusedNode, unused_node);

    var columns_with_unused: [poseidon.columns.len + 1]fixed.Column = undefined;
    @memcpy(columns_with_unused[0..poseidon.columns.len], &poseidon.columns);
    columns_with_unused[poseidon.columns.len] = .{
        .role = "unused",
        .binding = .component,
        .tree = .main,
        .placement = .{ .absolute = 1_000 },
    };
    var unused_column = base;
    unused_column.columns = &columns_with_unused;
    try expectInvalid(error.UnusedColumn, unused_column);

    columns = poseidon.columns;
    columns[1].placement = .{ .after_materializations = .{
        .prefix_columns = std.math.maxInt(u32),
        .trailing_offset = 0,
    } };
    columns[2].placement = .{ .after_materializations = .{
        .prefix_columns = std.math.maxInt(u32),
        .trailing_offset = std.math.maxInt(u32),
    } };
    var overflow = base;
    overflow.columns = &columns;
    overflow.materialization_column_start = std.math.maxInt(u32);
    try std.testing.expectError(
        error.PlacementOverflow,
        overflow.validateFor(std.testing.allocator, std.math.maxInt(u64)),
    );
}

test "fixed direct: ordered root multiplicity is canonical and authenticated" {
    const nodes = [_]fixed.Node{.{ .op = .constant, .value = 1 }};
    const single = [_]fixed.NodeId{@enumFromInt(0)};
    const repeated = [_]fixed.NodeId{ @enumFromInt(0), @enumFromInt(0) };
    const once = fixed.Program{
        .scope_id = "test.root-multiplicity",
        .scope_version = 1,
        .materialization_tree = .main,
        .materialization_column_start = 0,
        .columns = &.{},
        .nodes = &nodes,
        .prefix_roots = &single,
        .suffix_roots = &.{},
    };
    var twice = once;
    twice.prefix_roots = &repeated;

    try once.validate(std.testing.allocator);
    try twice.validate(std.testing.allocator);
    try std.testing.expectEqual(@as(u32, 2), try twice.fixedRootCount());
    try expectDifferent(
        try once.digestValue(std.testing.allocator),
        try twice.digestValue(std.testing.allocator),
    );
}

test "fixed direct: v1 authenticates only main-tree materializations" {
    inline for (.{ fixed.CommitmentTree.preprocessed, .interaction }) |tree| {
        var program = poseidon.program;
        program.materialization_tree = tree;
        try std.testing.expectError(
            error.UnsupportedMaterializationTree,
            program.identity(std.testing.allocator),
        );
    }
}

test "fixed direct: digest binds scope columns algebra and phase order" {
    const canonical = try poseidon.program.digestValue(std.testing.allocator);

    var scope = poseidon.program;
    scope.scope_version += 1;
    try expectDifferent(canonical, try scope.digestValue(std.testing.allocator));

    var columns = poseidon.columns;
    columns[2].role = "atomic-io";
    var role = poseidon.program;
    role.columns = &columns;
    try expectDifferent(canonical, try role.digestValue(std.testing.allocator));

    var nodes = poseidon.nodes;
    nodes[10] = .{ .op = .add, .lhs = 4, .rhs = 7 };
    var algebra = poseidon.program;
    algebra.nodes = &nodes;
    try expectDifferent(canonical, try algebra.digestValue(std.testing.allocator));

    var suffix = poseidon.suffix_roots;
    std.mem.swap(fixed.NodeId, &suffix[0], &suffix[1]);
    var order = poseidon.program;
    order.suffix_roots = &suffix;
    try expectDifferent(canonical, try order.digestValue(std.testing.allocator));
}

test "fixed direct: failed emission poisons lowering transaction" {
    var lowering = try fixed.Lowering.init(std.testing.allocator, poseidon.program, 426);
    defer lowering.deinit();
    var emitter = RecordingEmitter{ .fail_after = 2 };
    var prefix: [poseidon.prefix_roots.len]u32 = undefined;
    try std.testing.expectError(error.EmissionFailed, lowering.lowerPrefix(&emitter, &prefix));
    try std.testing.expectEqual(fixed.LoweringPhase.poisoned, lowering.phase);
    try std.testing.expectError(
        error.InvalidLoweringPhase,
        lowering.lowerPrefix(&emitter, &prefix),
    );
}

test "fixed direct: every partial allocation is released" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

const ColumnEvent = struct {
    role: []const u8,
    binding: fixed.ColumnBinding,
    tree: fixed.CommitmentTree,
    resolved: u64,
};

const BinaryEvent = struct {
    op: fixed.BinaryOp,
    lhs: u32,
    rhs: u32,
};

const Event = union(enum) {
    constant: u32,
    column: ColumnEvent,
    binary: BinaryEvent,
    neg: u32,
};

const RecordingEmitter = struct {
    events: [32]Event = undefined,
    len: usize = 0,
    fail_after: ?usize = null,

    pub fn constant(self: *RecordingEmitter, value: u32) !u32 {
        return self.append(.{ .constant = value });
    }

    pub fn column(
        self: *RecordingEmitter,
        _: *const fixed.Digest,
        value: *const fixed.Column,
        resolved: u64,
    ) !u32 {
        return self.append(.{ .column = .{
            .role = value.role,
            .binding = value.binding,
            .tree = value.tree,
            .resolved = resolved,
        } });
    }

    pub fn binary(
        self: *RecordingEmitter,
        op: fixed.BinaryOp,
        lhs: u32,
        rhs: u32,
    ) !u32 {
        return self.append(.{ .binary = .{ .op = op, .lhs = lhs, .rhs = rhs } });
    }

    pub fn neg(self: *RecordingEmitter, value: u32) !u32 {
        return self.append(.{ .neg = value });
    }

    fn append(self: *RecordingEmitter, event: Event) !u32 {
        if (self.fail_after) |limit| if (self.len == limit)
            return error.EmissionFailed;
        if (self.len >= self.events.len) return error.CapacityExceeded;
        const result = std.math.cast(u32, self.len) orelse
            return error.CapacityExceeded;
        self.events[self.len] = event;
        self.len += 1;
        return result;
    }
};

fn expectColumn(
    index: usize,
    role: []const u8,
    binding: fixed.ColumnBinding,
    tree: fixed.CommitmentTree,
    resolved: u64,
) !void {
    const column = poseidon.columns[index];
    try std.testing.expectEqualStrings(role, column.role);
    try std.testing.expectEqual(binding, column.binding);
    try std.testing.expectEqual(tree, column.tree);
    try std.testing.expectEqual(resolved, try column.placement.resolve(426));
}

fn expectInvalid(expected: anyerror, program: fixed.Program) !void {
    try std.testing.expectError(expected, program.validate(std.testing.allocator));
}

fn expectDifferent(lhs: fixed.Digest, rhs: fixed.Digest) !void {
    try std.testing.expect(!std.mem.eql(u8, &lhs, &rhs));
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var lowering = try fixed.Lowering.init(allocator, poseidon.program, 426);
    defer lowering.deinit();
    var emitter = RecordingEmitter{};
    var prefix: [poseidon.prefix_roots.len]u32 = undefined;
    var suffix: [poseidon.suffix_roots.len]u32 = undefined;
    try lowering.lowerPrefix(&emitter, &prefix);
    try lowering.lowerSuffix(&emitter, &suffix);
}

fn evaluateFixed(main: [production.N_MAIN_COLUMNS]QM31) ![poseidon.fixed_root_count]QM31 {
    var values: [poseidon.nodes.len]QM31 = undefined;
    for (poseidon.nodes, &values) |node, *value| value.* = switch (node.op) {
        .constant => QM31.fromBase(M31.fromU64(node.value)),
        .column => main[try poseidon.columns[node.value].placement.resolve(426)],
        .add => values[node.lhs].add(values[node.rhs]),
        .sub => values[node.lhs].sub(values[node.rhs]),
        .neg => values[node.lhs].neg(),
        .mul => values[node.lhs].mul(values[node.rhs]),
    };
    var result: [poseidon.fixed_root_count]QM31 = undefined;
    var cursor: usize = 0;
    for (poseidon.prefix_roots) |root| {
        result[cursor] = values[@intFromEnum(root)];
        cursor += 1;
    }
    for (poseidon.suffix_roots) |root| {
        result[cursor] = values[@intFromEnum(root)];
        cursor += 1;
    }
    return result;
}
