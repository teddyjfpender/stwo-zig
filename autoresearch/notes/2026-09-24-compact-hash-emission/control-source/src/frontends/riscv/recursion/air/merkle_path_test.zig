//! Exactness, relation closure, mutation, OOM, and hot-path gates for row 33.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const degree = @import("../../air/lang/degree.zig");
const digest = @import("../../air/lang/digest.zig");
const relation = @import("../../air/lang/relation.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const types = @import("../../air/lang/types.zig");
const component = @import("merkle_path.zig");
const interaction_mod = @import("merkle_path_relation.zig");
const support = @import("test_support.zig");
const witness = @import("merkle_path_witness.zig");

test "R-012 Merkle path preserves exact Stark-V row-33 geometry and seal" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    try std.testing.expectEqual(@as(usize, 45), component.DECLARED_COMMITTED_COLUMN_COUNT);
    try std.testing.expectEqual(@as(usize, 46), definition.main.physical().len);
    try std.testing.expectEqual(@as(usize, 11), definition.constraints.len);
    try std.testing.expectEqual(@as(usize, 3), definition.events.len);
    try std.testing.expectEqual(@as(usize, 2), component.INTERACTION_BATCH_COUNT);
    try std.testing.expectEqual(@as(usize, 8), component.INTERACTION_COLUMN_COUNT);

    var degrees = try degree.analyze(std.testing.allocator, &definition.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(
        @as(degree.Degree, component.MAXIMUM_CONSTRAINT_DEGREE),
        degrees.maximumConstraintDegree(),
    );
    const identity_value = try digest.computeIdentity(&definition.arena);
    try std.testing.expectEqualStrings(
        component.SEMANTIC_DIGEST_HEX,
        &std.fmt.bytesToHex(identity_value.bytes, .lower),
    );

    const binding = try witness.Binding.canonical(&definition);
    _ = try witness.Executor.init(&definition, &binding);
    try std.testing.expectEqualStrings(
        witness.BINDING_DIGEST_HEX,
        &std.fmt.bytesToHex(binding.identityDigest(), .lower),
    );
    const plan = try interaction_mod.authenticate(&definition);
    const domains = [_]relation.Domain{
        .poseidon2_io,
        .recursion_merkle_node,
        .recursion_merkle_node,
    };
    const roles = [_]relation.Role{ .request, .consume, .emit };
    for (plan.events, domains, roles) |event, domain, role| {
        try std.testing.expectEqual(domain, event.domain);
        try std.testing.expectEqual(role, event.role);
    }
}

test "R-012 Merkle path static profile proves its direct roots are quadratic" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const profile = try static_profile.collect(std.testing.allocator, &definition.arena, .{
        .physical_main_columns = component.PHYSICAL_MAIN_COLUMN_COUNT,
        .lookup_layout = .{
            .batch_size = component.LOOKUP_BATCH_SIZE,
            .interaction_coordinates_per_batch = 4,
        },
    });
    try profile.validate();
    try std.testing.expectEqual(@as(u32, 46), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 11), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 3), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 2), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 8), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 2), profile.maximum_logical_constraint_degree);
}

test "R-012 Merkle path witness selects the exact branch and authenticates Poseidon" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);

    const left_selected = fixtureInvocation(0, false);
    const left_row = try witness.logicalRow(left_selected);
    try expectSatisfied(&definition, left_row);
    for (0..component.DIGEST_WORD_COUNT) |index| {
        try std.testing.expectEqual(left_row[6 + index], left_row[38 + index]);
        try std.testing.expectEqual(
            M31.fromCanonical(left_selected.step.sibling[index]),
            left_row[14 + index],
        );
    }
    var state: [component.STATE_WIDTH]M31 = left_row[6..22].*;
    @import("../../air/memory_commitment/poseidon2.zig").permute(&state);
    try std.testing.expectEqualSlices(M31, &state, left_row[22..38]);

    const entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        left_row,
    );
    try std.testing.expect(entries[0].numerator.eql(QM31.one().neg()));
    try std.testing.expect(entries[1].numerator.eql(QM31.one().neg()));
    try std.testing.expect(entries[2].numerator.eql(QM31.one()));
    try std.testing.expect(entries[1].values[0].eql(QM31.fromBase(left_row[1])));
    try std.testing.expect(entries[1].values[1].eql(QM31.fromBase(left_row[2])));
    try std.testing.expect(entries[1].values[2].eql(QM31.fromBase(left_row[3])));

    const right_selected = fixtureInvocation(1, true);
    const right_row = try witness.logicalRow(right_selected);
    try expectSatisfied(&definition, right_row);
    for (0..component.DIGEST_WORD_COUNT) |index| {
        try std.testing.expectEqual(right_row[14 + index], right_row[38 + index]);
        try std.testing.expectEqual(
            M31.fromCanonical(right_selected.step.sibling[index]),
            right_row[6 + index],
        );
    }
    const leaf_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        right_row,
    );
    try std.testing.expect(leaf_entries[2].numerator.eql(QM31.one()));
}

test "R-012 prepared Merkle path is a sealed top-to-bottom relation chain" {
    const steps = fixtureSteps();
    const leaf = fixtureDigest(701);
    var path = try witness.PreparedPath.init(
        std.testing.allocator,
        17,
        2,
        3,
        leaf,
        &steps,
    );
    defer path.deinit();
    try path.validateAgainstAuthority();
    try std.testing.expectEqual(@as(usize, steps.len), path.rows.len);
    try std.testing.expectEqual(@as(u32, 2), path.rows[0].depth);
    try std.testing.expectEqual(@as(u32, 3), path.rows[0].index);
    try std.testing.expectEqual(@as(u32, 3), path.rows[1].depth);
    try std.testing.expectEqual(@as(u32, 7), path.rows[1].index);
    try std.testing.expectEqual(@as(u32, 4), path.rows[2].depth);
    try std.testing.expectEqual(@as(u32, 14), path.rows[2].index);
    try std.testing.expect(!path.rows[0].is_leaf);
    try std.testing.expect(!path.rows[1].is_leaf);
    try std.testing.expect(path.rows[2].is_leaf);
    try std.testing.expectEqualSlices(u32, &leaf, &path.rows[2].child);

    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    var rows: [steps.len][component.LOGICAL_INPUT_COUNT]M31 = undefined;
    var entries: [steps.len][component.RELATION_EVENT_COUNT]interaction_mod.Entry = undefined;
    for (path.rows, 0..) |invocation, index| {
        rows[index] = try witness.logicalRow(invocation);
        entries[index] = try plan.entries(
            &definition.arena,
            component.SEMANTIC_DIGEST,
            definition.events,
            rows[index],
        );
    }
    for (0..steps.len - 1) |index| {
        try std.testing.expect(entries[index][2].numerator.eql(QM31.one()));
        try std.testing.expect(entries[index + 1][1].numerator.eql(QM31.one().neg()));
        try expectSecureEqual(
            entries[index][2].values[0..entries[index][2].arity],
            entries[index + 1][1].values[0..entries[index + 1][1].arity],
        );
    }
    try std.testing.expect(entries[steps.len - 1][2].numerator.eql(QM31.one()));
    for (path.root, 0..) |word, index| try std.testing.expect(
        entries[0][1].values[3 + index].eql(
            QM31.fromBase(M31.fromCanonical(word)),
        ),
    );
}

test "R-012 Merkle path constraints and relations reject every mutable class" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    const honest = try witness.logicalRow(fixtureInvocation(0, false));
    try expectSatisfied(&definition, honest);

    var forged_enabler = honest;
    forged_enabler[0] = M31.fromCanonical(2);
    try expectConstraintRejected(&definition, forged_enabler, 0);

    var forged_direction = honest;
    forged_direction[4] = M31.fromCanonical(2);
    try expectConstraintRejected(&definition, forged_direction, 1);

    var forged_leaf = honest;
    forged_leaf[5] = M31.fromCanonical(2);
    try expectConstraintRejected(&definition, forged_leaf, 2);

    for (0..component.DIGEST_WORD_COUNT) |word| {
        var forged_child = honest;
        forged_child[38 + word] = forged_child[38 + word].add(M31.one());
        try expectConstraintRejected(&definition, forged_child, 3 + word);
    }

    const honest_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        honest,
    );
    inline for (.{ @as(usize, 22), @as(usize, 30) }) |column| {
        var forged_output = honest;
        forged_output[column] = forged_output[column].add(M31.one());
        try expectSatisfied(&definition, forged_output);
        const forged_entries = try plan.entries(
            &definition.arena,
            component.SEMANTIC_DIGEST,
            definition.events,
            forged_output,
        );
        try std.testing.expect(!forged_entries[0].values[column - 6].eql(
            honest_entries[0].values[column - 6],
        ));
    }

    const padding = [_]M31{M31.zero()} ** component.LOGICAL_INPUT_COUNT;
    try expectSatisfied(&definition, padding);
}

test "R-012 Merkle path writer is allocation-free padded and failure atomic" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const steps = fixtureSteps();
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var path = try witness.PreparedPath.init(
        measured.allocator(),
        17,
        2,
        3,
        fixtureDigest(701),
        &steps,
    );
    defer path.deinit();
    try std.testing.expectEqual(@as(usize, 1), measured.alloc_index);

    const log_size: u32 = 2;
    const size: usize = 1 << log_size;
    const sentinel = M31.fromCanonical(0x5151);
    const storage = try std.testing.allocator.alloc(M31, component.PHYSICAL_MAIN_COLUMN_COUNT * size);
    defer std.testing.allocator.free(storage);
    @memset(storage, sentinel);
    var columns: [component.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
    splitColumns(component.PHYSICAL_MAIN_COLUMN_COUNT, size, storage, &columns);
    const before = measured.alloc_index;
    try executor.generatePreparedPathInto(&columns, &path, log_size);
    try std.testing.expectEqual(before, measured.alloc_index);
    for (0..path.rows.len) |row| try std.testing.expectEqual(@as(u32, 1), columns[0][row].toU32());
    for (path.rows.len..size) |row| for (columns) |column|
        try std.testing.expect(column[row].isZero());

    @memset(storage, sentinel);
    columns[component.PHYSICAL_MAIN_COLUMN_COUNT - 1] =
        columns[component.PHYSICAL_MAIN_COLUMN_COUNT - 1][0 .. size - 1];
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generatePreparedPathInto(&columns, &path, log_size),
    );
    for (storage) |value| try std.testing.expect(value.eql(sentinel));

    splitColumns(component.PHYSICAL_MAIN_COLUMN_COUNT, size, storage, &columns);
    @memset(storage, sentinel);
    var invalid = fixtureInvocation(2, false);
    try std.testing.expectError(
        error.InvalidTraceRow,
        executor.generateMainInto(&columns, &.{invalid}, log_size),
    );
    for (storage) |value| try std.testing.expect(value.eql(sentinel));

    invalid = fixtureInvocation(0, false);
    invalid.child[0] = @import("stwo_core").fields.m31.Modulus;
    try std.testing.expectError(
        error.InvalidTraceRow,
        executor.generateMainInto(&columns, &.{invalid}, log_size),
    );
    for (storage) |value| try std.testing.expect(value.eql(sentinel));
}

test "R-012 Merkle path writer rejects input destination and plan-header aliases" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const steps = fixtureSteps();
    var path = try witness.PreparedPath.init(
        std.testing.allocator,
        17,
        2,
        3,
        fixtureDigest(701),
        &steps,
    );
    defer path.deinit();
    const size: usize = 4;
    const storage = try std.testing.allocator.alloc(M31, component.PHYSICAL_MAIN_COLUMN_COUNT * size);
    defer std.testing.allocator.free(storage);
    var columns: [component.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
    splitColumns(component.PHYSICAL_MAIN_COLUMN_COUNT, size, storage, &columns);

    columns[0] = @as([*]M31, @ptrCast(path.rows.ptr))[0..size];
    try std.testing.expectError(
        error.AliasedInput,
        executor.generatePreparedPathInto(&columns, &path, 2),
    );

    splitColumns(component.PHYSICAL_MAIN_COLUMN_COUNT, size, storage, &columns);
    columns[0] = @as([*]M31, @ptrCast(&path))[0..size];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generatePreparedPathInto(&columns, &path, 2),
    );
}

test "R-012 prepared Merkle path detects every retained-input mutation" {
    const steps = fixtureSteps();
    var path = try witness.PreparedPath.init(
        std.testing.allocator,
        17,
        2,
        3,
        fixtureDigest(701),
        &steps,
    );
    defer path.deinit();
    path.rows[1].step.sibling[3] += 1;
    try std.testing.expectError(error.AuthorityMismatch, path.validate());
    path.rows[1].step.sibling[3] -= 1;
    try path.validateAgainstAuthority();

    path.root[0] += 1;
    try std.testing.expectError(error.AuthorityMismatch, path.validate());
}

test "R-012 prepared Merkle path releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

test "R-012 Merkle path definition rejects detached metadata" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    definition.child_index = definition.main.index;
    try std.testing.expectError(
        error.InvalidMerklePathDefinition,
        definition.validate(),
    );
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    const steps = fixtureSteps();
    var path = try witness.PreparedPath.init(
        allocator,
        17,
        2,
        3,
        fixtureDigest(701),
        &steps,
    );
    defer path.deinit();
    try path.validateAgainstAuthority();
}

fn fixtureInvocation(direction: u32, is_leaf: bool) witness.Invocation {
    return .{
        .tree_id = 17,
        .depth = 2,
        .index = 3,
        .child = fixtureDigest(11),
        .step = .{ .direction = direction, .sibling = fixtureDigest(101) },
        .is_leaf = is_leaf,
    };
}

fn fixtureSteps() [3]witness.PathStep {
    return .{
        .{ .direction = 1, .sibling = fixtureDigest(101) },
        .{ .direction = 0, .sibling = fixtureDigest(301) },
        .{ .direction = 1, .sibling = fixtureDigest(501) },
    };
}

fn fixtureDigest(start: u32) [component.DIGEST_WORD_COUNT]u32 {
    var result: [component.DIGEST_WORD_COUNT]u32 = undefined;
    for (&result, 0..) |*word, index| word.* = start + @as(u32, @intCast(index * 7));
    return result;
}

fn expectSatisfied(
    definition: *const component.Definition,
    row: [component.LOGICAL_INPUT_COUNT]M31,
) !void {
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
    defer std.testing.allocator.free(values);
    for (definition.constraints, 0..) |_, index|
        try std.testing.expect(support.constraintAt(
            &definition.arena,
            &definition.constraints,
            values,
            index,
        ).isZero());
}

fn expectConstraintRejected(
    definition: *const component.Definition,
    row: [component.LOGICAL_INPUT_COUNT]M31,
    constraint_index: usize,
) !void {
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
    defer std.testing.allocator.free(values);
    try std.testing.expect(!support.constraintAt(
        &definition.arena,
        &definition.constraints,
        values,
        constraint_index,
    ).isZero());
}

fn expectSecureEqual(lhs: []const QM31, rhs: []const QM31) !void {
    try std.testing.expectEqual(lhs.len, rhs.len);
    for (lhs, rhs) |left, right| try std.testing.expect(left.eql(right));
}

fn splitColumns(
    comptime count: usize,
    size: usize,
    storage: []M31,
    columns: *[count][]M31,
) void {
    for (columns, 0..) |*column, index|
        column.* = storage[index * size ..][0..size];
}

comptime {
    _ = types.ValueId;
}
