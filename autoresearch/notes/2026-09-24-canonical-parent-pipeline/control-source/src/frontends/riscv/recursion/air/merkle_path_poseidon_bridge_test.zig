//! Shared-provider closure and hot scheduling gates for universal rows 33/34.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const poseidon_authority = @import("../../air/lang/typed_poseidon2_proof_authority.zig");
const poseidon_production = @import("../../air/memory_commitment/poseidon2_air.zig");
const component = @import("merkle_path.zig");
const path_relation = @import("merkle_path_relation.zig");
const path = @import("merkle_path_witness.zig");
const bridge = @import("merkle_path_poseidon_bridge.zig");

test "R-012 Merkle path derives the exact shared Poseidon IO call" {
    const invocation = fixtureInvocation(1);
    const call = try bridge.call(invocation);
    try std.testing.expect(!call.wide);
    try std.testing.expect(call.io);
    try std.testing.expectEqual(@as(?u32, null), call.narrow_output);
    try std.testing.expectEqualSlices(u32, &invocation.step.sibling, call.input[0..8]);
    try std.testing.expectEqualSlices(u32, &invocation.child, call.input[8..16]);

    const left_invocation = fixtureInvocation(0);
    const left_call = try bridge.call(left_invocation);
    try std.testing.expectEqualSlices(u32, &left_invocation.child, left_call.input[0..8]);
    try std.testing.expectEqualSlices(u32, &left_invocation.step.sibling, left_call.input[8..16]);
}

test "R-012 Merkle request closes exactly against the existing typed Poseidon provider" {
    const invocation = fixtureInvocation(1);
    const path_row = try path.logicalRow(invocation);
    var path_definition = try component.build(std.testing.allocator);
    defer path_definition.deinit();
    const request_plan = try path_relation.authenticate(&path_definition);
    const request_entries = try request_plan.entries(
        &path_definition.arena,
        component.SEMANTIC_DIGEST,
        path_definition.events,
        path_row,
    );

    var authority = try poseidon_authority.Authority.init(std.testing.allocator);
    defer authority.deinit();
    const call = try bridge.call(invocation);
    const provider_main = poseidon_production.fill(call);
    const provider_row = try authority.relation_plan.rowFromMain(
        std.testing.allocator,
        authority.relationAuthority(),
        provider_main,
    );
    const provider_entries = try authority.relation_plan.entries(
        std.testing.allocator,
        authority.relationAuthority(),
        provider_row,
    );

    try std.testing.expect(request_entries[0].numerator.eql(QM31.one().neg()));
    try std.testing.expect(provider_entries[3].numerator.eql(QM31.one()));
    try std.testing.expect(
        request_entries[0].numerator.add(provider_entries[3].numerator).isZero(),
    );
    try std.testing.expectEqual(
        @as(usize, request_entries[0].arity),
        @as(usize, provider_entries[3].arity),
    );
    for (
        request_entries[0].values[0..request_entries[0].arity],
        provider_entries[3].values[0..provider_entries[3].arity],
    ) |request_value, provider_value| try std.testing.expect(
        request_value.eql(provider_value),
    );
    try std.testing.expectEqualSlices(M31, path_row[22..38], &provider_row.output);
}

test "R-012 prepared Poseidon bridge uses one cold allocation and no hot allocation" {
    const invocations = [_]path.Invocation{
        fixtureInvocation(0),
        fixtureInvocation(1),
        fixtureInvocation(0),
    };
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var batch = try bridge.PreparedBatch.init(measured.allocator(), &invocations);
    defer batch.deinit();
    try std.testing.expectEqual(@as(usize, 1), measured.alloc_index);
    try batch.validate();

    var authority = try poseidon_authority.Authority.init(std.testing.allocator);
    defer authority.deinit();
    const log_size: u32 = 2;
    const size: usize = 1 << log_size;
    const sentinel = M31.fromCanonical(0x5151);
    const storage = try std.testing.allocator.alloc(M31, bridge.MAIN_COLUMN_COUNT * size);
    defer std.testing.allocator.free(storage);
    @memset(storage, sentinel);
    var columns: [bridge.MAIN_COLUMN_COUNT][]M31 = undefined;
    splitColumns(bridge.MAIN_COLUMN_COUNT, size, storage, &columns);
    const before = measured.alloc_index;
    try batch.generateMainInto(&authority.executor, &columns, log_size);
    try std.testing.expectEqual(before, measured.alloc_index);
    var active: usize = 0;
    for (columns[0]) |value| active += @intFromBool(value.eql(M31.one()));
    try std.testing.expectEqual(invocations.len, active);

    @memset(storage, sentinel);
    batch.calls[0].wide = true;
    try std.testing.expectError(
        error.InvalidCallGeometry,
        batch.generateMainInto(&authority.executor, &columns, log_size),
    );
    for (storage) |value| try std.testing.expect(value.eql(sentinel));
}

test "R-012 Poseidon bridge conversion is alias-safe failure atomic" {
    var invocations = [_]path.Invocation{ fixtureInvocation(0), fixtureInvocation(1) };
    const sentinel = bridge.Call{
        .input = [_]u32{17} ** bridge.WIDTH,
        .wide = true,
        .io = false,
        .narrow_output = 99,
    };
    var calls = [_]bridge.Call{sentinel} ** invocations.len;
    invocations[1].step.direction = 2;
    try std.testing.expectError(
        error.InvalidWitness,
        bridge.fillCallsInto(&calls, &invocations),
    );
    for (calls) |call| try std.testing.expect(std.meta.eql(call, sentinel));

    invocations[1].step.direction = 1;
    const aliased = @as([*]bridge.Call, @ptrCast(&invocations))[0..invocations.len];
    try std.testing.expectError(
        error.AliasedInput,
        bridge.fillCallsInto(aliased, &invocations),
    );
}

test "R-012 prepared Poseidon bridge protects its header before writes" {
    const invocations = [_]path.Invocation{fixtureInvocation(0)};
    var batch = try bridge.PreparedBatch.init(std.testing.allocator, &invocations);
    defer batch.deinit();
    var authority = try poseidon_authority.Authority.init(std.testing.allocator);
    defer authority.deinit();
    const size: usize = 4;
    const storage = try std.testing.allocator.alloc(M31, bridge.MAIN_COLUMN_COUNT * size);
    defer std.testing.allocator.free(storage);
    var columns: [bridge.MAIN_COLUMN_COUNT][]M31 = undefined;
    splitColumns(bridge.MAIN_COLUMN_COUNT, size, storage, &columns);
    columns[0] = @as([*]M31, @ptrCast(&batch))[0..size];
    try std.testing.expectError(
        error.AliasedDestination,
        batch.generateMainInto(&authority.executor, &columns, 2),
    );
}

test "R-012 prepared Poseidon bridge releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    const invocations = [_]path.Invocation{ fixtureInvocation(0), fixtureInvocation(1) };
    var batch = try bridge.PreparedBatch.init(allocator, &invocations);
    defer batch.deinit();
    try batch.validate();
}

fn fixtureInvocation(direction: u32) path.Invocation {
    return .{
        .tree_id = 17,
        .depth = 2,
        .index = 3,
        .child = fixtureDigest(11),
        .step = .{ .direction = direction, .sibling = fixtureDigest(101) },
        .is_leaf = false,
    };
}

fn fixtureDigest(start: u32) [component.DIGEST_WORD_COUNT]u32 {
    var result: [component.DIGEST_WORD_COUNT]u32 = undefined;
    for (&result, 0..) |*word, index| word.* = start + @as(u32, @intCast(index * 7));
    return result;
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
