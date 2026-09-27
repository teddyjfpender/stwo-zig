//! Original algebra/IR/closure fixtures only. No fake Fresh, key or receipt.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Context = @import("../recursion/block_v5_requester_memory_fixed_context_v1.zig");
const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
const Algebra = @import("../recursion/air/block_v5_requester_memory_algebra_v1.zig");
const R = @import("../recursion/air/composition_graph_recorder.zig");
const Storage = @import("../recursion/air/blake3_parent_row_storage.zig");
const FixedGraph = @import("../recursion/air/block_v5_recursive_fixed_graph_attach_v1.zig");
const OriginalGraph = @import("../recursion/air/block_v5_heterogeneous_scoped_graph_rows_v1.zig");
const Identifiers = @import("../recursion/air/block_v5_requester_public_fixed_identifier_ports_v1.zig");
const FixedAttach = @import("../recursion/block_v5_recursive_fixed_attachments_v1.zig").Scoped;
const Scoped = @import("../recursion/block_v5_heterogeneous_scoped_public_bus_v1.zig");
const Direct = @import("../recursion/air/blake3_direct_cohort_columns_v1.zig");
const OriginalClosed = @import("../recursion/air/block_v5_closed_public_supply_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Family = @import("../recursion/block_v5_requester_memory_fixed_assembly_v1.zig");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Values = struct {
    terms: [2][4]M = .{ .{ M.fromCanonical(3), M.zero(), M.zero(), M.zero() }, .{ M.fromCanonical(5), M.zero(), M.zero(), M.zero() } },
    pub fn validate(_: @This()) !void {}
    pub fn at(self: @This(), wire: Scoped.Wire) ![4]M {
        if (wire.kind != .child_cell or wire.child >= self.terms.len or wire.coordinate != 0) return error.InvalidPureFinalCoordinate;
        return self.terms[wire.child];
    }
};
fn childContext(first: u8) Base.Context {
    return .{ .child_key_id = @splat(first), .child_config = Base.CSP_CONFIG, .graph_ids = .{ @splat(first + 1), @splat(first + 2), @splat(first + 3) }, .transcript_plan_id = @splat(first + 4) };
}
fn oracle(reversed: bool) Base.Context {
    var ids: [5]core.channel.blake3.Channel = @splat(.{});
    for (&ids, 0..) |*channel, i| {
        channel.mixU32s(&.{ 0x42354d52, 22, @intCast(i), 2 });
        inline for (.{ @as([32]u8, @splat(1)), @as([32]u8, @splat(2)), @as([32]u8, @splat(3)) }) |pin| channel.mixRoot(pin);
    }
    for (0..2) |position| {
        const index = if (reversed) 1 - position else position;
        const child = childContext(@intCast(10 + 10 * index));
        for (&ids) |*channel| {
            channel.mixRoot(@splat(@intCast(4 + index)));
            channel.mixRoot(@splat(@intCast(6 + index)));
        }
        for (ids[1..4], child.graph_ids) |*channel, graph| channel.mixRoot(graph);
        ids[4].mixRoot(child.transcript_plan_id);
    }
    for (&ids) |*channel| {
        channel.mixRoot(@splat(8));
        channel.mixRoot(@splat(9));
    }
    return .{ .child_key_id = ids[0].digestBytes(), .child_config = Base.CSP_CONFIG, .graph_ids = .{ ids[1].digestBytes(), ids[2].digestBytes(), ids[3].digestBytes() }, .transcript_plan_id = ids[4].digestBytes() };
}
fn context(first: [32]u8, memory: [32]u8, seal: [32]u8, closure: [32]u8) Base.Context {
    var ids = Context.Owned.init(first, memory, seal);
    ids.child(@splat(4), @splat(6), childContext(10));
    ids.child(@splat(5), @splat(7), childContext(20));
    ids.attachment(@splat(8));
    ids.attachment(closure);
    return ids.finish(Base.CSP_CONFIG);
}
test "FINAL22 fixed assembly: exact original context child ordering graph and closure channels" {
    const actual = context(@splat(1), @splat(2), @splat(3), @splat(9));
    try std.testing.expectEqualDeep(oracle(false), actual);
    try std.testing.expect(!std.meta.eql(actual, oracle(true)));
    var changed = @as([32]u8, @splat(1));
    changed[0] ^= 1;
    try std.testing.expect(!std.meta.eql(actual, context(changed, @splat(2), @splat(3), @splat(9))));
    changed = @splat(2);
    changed[0] ^= 1;
    try std.testing.expect(!std.meta.eql(actual, context(@splat(1), changed, @splat(3), @splat(9))));
    changed = @splat(3);
    changed[0] ^= 1;
    try std.testing.expect(!std.meta.eql(actual, context(@splat(1), @splat(2), changed, @splat(9))));
    changed = @splat(9);
    changed[0] ^= 1;
    try std.testing.expect(!std.meta.eql(actual, context(@splat(1), @splat(2), @splat(3), changed)));
}
const ScalarSink = struct {
    total: Q = .zero(),
    pub fn zero(self: *@This(), value: Q, err: anyerror) !void {
        self.total = value;
        if (!value.isZero()) return err;
    }
};
const SymbolSink = struct {
    builder: *R.Builder,
    pub fn zero(self: *@This(), value: R.Scalar, _: anyerror) !void {
        try self.builder.constrainZero(value);
    }
};
fn transitionGraph(a: std.mem.Allocator) !R.Circuit {
    var builder = R.Builder.init(a);
    defer builder.deinit();
    const left = (try builder.input()).value;
    const right = (try builder.input()).value;
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    var sink = SymbolSink{ .builder = &builder };
    try Algebra.close(R.Scalar, &sink, left, right);
    builder.deactivate();
    return builder.finish();
}
test "FINAL22 fixed assembly: original transition sign scalar symbolic parity and changed memory rejects" {
    const value = Q.fromU32Unchecked(11, 19, 23, 29);
    var scalar = ScalarSink{};
    try Algebra.close(Q, &scalar, value, value.neg());
    var circuit = try transitionGraph(std.testing.allocator);
    defer circuit.deinit();
    const values = try std.testing.allocator.alloc(Q, circuit.nodes.len);
    defer std.testing.allocator.free(values);
    try circuit.evaluateInto(&.{ value, value.neg() }, values);
    for (circuit.outputs) |output| try std.testing.expectEqualDeep(scalar.total, values[output]);
    var failed = false;
    Algebra.close(Q, &scalar, value, value.neg().add(Q.one())) catch {
        failed = true;
    };
    try std.testing.expect(failed);
    // Original evaluateInto fills the node values, then rejects a nonzero
    // constrained output. Compare that exact rejected output to scalar algebra.
    try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateInto(&.{ value, value.neg().add(Q.one()) }, values));
    for (circuit.outputs) |output| {
        try std.testing.expectEqualDeep(scalar.total, values[output]);
        try std.testing.expect(!values[output].isZero());
    }
}
fn emptyLive(a: std.mem.Allocator) !Storage.Prepared {
    var result = Storage.Prepared{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 0 };
    inline for (0..Storage.Airs.len) |i| result.fixed[i] = &.{};
    errdefer result.deinit();
    inline for (Storage.Airs, 0..) |Air, i| {
        var emitter = try Direct.ForAir(Air).init(a, 0);
        defer emitter.deinit();
        const taken = try emitter.take();
        result.main[i] = taken.main;
        result.fixed[i] = taken.fixed;
    }
    return result;
}
fn smallChild(a: std.mem.Allocator, circuit: u32) !Storage.Prepared {
    var result = try emptyLive(a);
    errdefer result.deinit();
    var emitter = try Direct.ForAir(Storage.Airs[2]).init(a, 1);
    defer emitter.deinit();
    try emitter.append(try @import("../recursion/air/blake3_boundary.zig").logicalRow(circuit, 0, M.one(), 1));
    const taken = try emitter.take();
    result.releaseCohort(2);
    result.main[2] = taken.main;
    result.fixed[2] = taken.fixed;
    return result;
}
fn closureAllocation(a: std.mem.Allocator, left: Storage.FixedTuple(false), right: Storage.FixedTuple(false)) !void {
    var fixed = try FixedAttach.init(a, .{ .max_children = 2 });
    defer fixed.deinit();
    const first = [_]Scoped.Wire{.{ .circuit = 17, .wire = 0, .uses = 1, .child = 0, .kind = .child_cell, .coordinate = 0 }};
    const second = [_]Scoped.Wire{.{ .circuit = 27, .wire = 0, .uses = 2, .negative = true, .child = 1, .kind = .child_cell, .coordinate = 0 }};
    try fixed.appendChild(left, &first);
    try fixed.appendChild(right, &second);
    _ = try fixed.closePublicSupply(Values{}, .{});
    try std.testing.expectEqual(@as(usize, 0), fixed.wires.items.len);
    try std.testing.expectEqual(@as(usize, 4), fixed.fixed[2].items.len);
}
test "FINAL22 fixed assembly: closed suppliers exact original signed Boundary tails identity and empty external schedule" {
    const a = std.testing.allocator;
    var left = try smallChild(a, 17);
    defer left.deinit();
    var right = try smallChild(a, 27);
    defer right.deinit();
    var fixed = try FixedAttach.init(a, .{ .max_children = 2 });
    defer fixed.deinit();
    const first = [_]Scoped.Wire{.{ .circuit = 17, .wire = 0, .uses = 1, .child = 0, .kind = .child_cell, .coordinate = 0 }};
    const second = [_]Scoped.Wire{.{ .circuit = 27, .wire = 0, .uses = 2, .negative = true, .child = 1, .kind = .child_cell, .coordinate = 0 }};
    try fixed.appendChild(left.fixed, &first);
    try fixed.appendChild(right.fixed, &second);
    var live = try emptyLive(a);
    defer live.deinit();
    var emitter = try Direct.ForAir(Storage.Airs[2]).init(a, fixed.fixed[2].items.len);
    defer emitter.deinit();
    for (fixed.fixed[2].items) |tail| {
        var row: Storage.Airs[2].Row = @splat(M.zero());
        row[4..].* = tail;
        row[0..4].* = tail[4..8].*;
        try emitter.append(row);
    }
    const taken = try emitter.take();
    live.releaseCohort(2);
    live.main[2] = taken.main;
    live.fixed[2] = taken.fixed;
    const wires = try a.dupe(Scoped.Wire, fixed.wires.items);
    defer a.free(wires);
    const closed = try OriginalClosed.append(a, &live, wires, Values{}, .{});
    const fixed_closed = try fixed.closePublicSupply(Values{}, .{});
    try std.testing.expectEqualDeep(closed, fixed_closed);
    for (live.fixed[2], fixed.fixed[2].items) |actual, expected| try std.testing.expectEqualDeep(actual, expected);
    try std.testing.expectEqual(@as(usize, 0), fixed.wires.items.len);
    _ = try @import("../recursion/block_v5_requester_memory_public_v1.zig").scheduleDigest(&.{});
    try std.testing.expectError(error.ClosedRequesterMemoryHasNoPublicTerms, @import("../recursion/block_v5_requester_memory_public_v1.zig").scheduleDigest(&first));
    try std.testing.expectError(error.ConsumedRecursiveFixedAttachments, fixed.closePublicSupply(Values{}, .{}));
}
test "FINAL22 fixed assembly: bounded two-child namespace and closure OOM release upstream outside injection" {
    var left = try smallChild(std.testing.allocator, 17);
    defer left.deinit();
    var right = try smallChild(std.testing.allocator, 27);
    defer right.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, closureAllocation, .{ left.fixed, right.fixed });
}
test "FINAL22 fixed assembly: genuine fixed graph tuple schedule matches original source lowering" {
    const a = std.testing.allocator;
    var circuit = try transitionGraph(a);
    defer circuit.deinit();
    const sources = [_]Scoped.Wire{
        .{ .circuit = 0, .wire = 0, .uses = 1, .child = 0, .kind = .child_cell, .coordinate = 0 },
        .{ .circuit = 0, .wire = 0, .uses = 1, .child = 1, .kind = .child_cell, .coordinate = 0 },
    };
    var fixed = try FixedGraph.Owned.derive(a, &circuit, &sources);
    defer fixed.deinit();
    var inputs = Values{};
    inputs.terms[1] = .{ M.fromCanonical(core.fields.m31.Modulus - 3), M.zero(), M.zero(), M.zero() };
    const arguments = [_]Q{ Q.fromM31Array(inputs.terms[0]), Q.fromM31Array(inputs.terms[1]) };
    const values = try a.alloc(Q, circuit.nodes.len);
    defer a.free(values);
    try circuit.evaluateInto(&arguments, values);
    var original = try OriginalGraph.materializeLocallyAdmittedFor(a, .{ .circuit = &circuit, .inputs = &arguments, .values = values, .sources = &sources }, inputs);
    defer original.deinit();
    try fixed.validateLive(&original);
    var port = try Identifiers.Owned.init(a, &.{circuit.graph()}, &.{FixedGraph.CIRCUIT});
    defer port.deinit();
    var namespace = try @import("../recursion/air/block_v5_recursive_fixed_namespace_v1.zig").prepareForArithmetic(a, fixed.fixed, 5, try port.port());
    defer namespace.deinit();
    try namespace.requireIndependentMainPort();
    try namespace.validateLive(&original.rows);
    fixed.wires[0].coordinate += 1;
    try std.testing.expectError(error.UntrustedRecursiveFixedGraph, fixed.validateLive(&original));
}
test "FINAL22 fixed assembly: lower capture-free missing port and initial guards cannot grant authority" {
    try std.testing.expectError(error.RequesterMemoryFixedResourceLimit, Family.ForBackend(Cpu).initViaOriginalMemory(std.testing.failing_allocator, undefined, 0, .csp_q70_pow26, .{}));
    try std.testing.expectError(error.RequesterMemoryFixedResourceLimit, Family.ForBackend(Cpu).initViaOriginalMemory(std.testing.failing_allocator, undefined, 1, .csp_q70_pow26, .{ .max_setup_bytes = 0 }));
    try std.testing.expectError(error.MissingIndependentMemoryRootFixedSetup, Family.Owned.requireCaptureFreeMemorySetup(undefined));
    try std.testing.expect(!@hasDecl(Family.Owned, "verify"));
    try std.testing.expect(!@hasField(Family.Owned, "capture"));
    try std.testing.expect(!Family.Owned.complete_block_authority);
}
test "FINAL22 fixed assembly: real nested backing budget stays live beyond creator release" {
    const backing = try Budget.create(std.testing.allocator, 32 << 20);
    var creator = true;
    defer if (creator) backing.destroy();
    const metadata = try Budget.createRetainingParent(backing.allocator(), 4 << 20);
    defer metadata.destroy();
    const live = try Budget.createRetainingParent(backing.allocator(), 16 << 20);
    defer live.destroy();
    const allocation = try live.allocator().alloc(u8, 6 << 20);
    defer live.allocator().free(allocation);
    backing.destroy();
    creator = false;
    @memset(allocation, 1);
    try std.testing.expectEqual(@as(u8, 1), allocation[allocation.len - 1]);
    const retained = try metadata.allocator().alloc(u8, 128);
    defer metadata.allocator().free(retained);
    @memset(retained, 2);
    try std.testing.expectEqual(@as(u8, 2), retained[0]);
}
