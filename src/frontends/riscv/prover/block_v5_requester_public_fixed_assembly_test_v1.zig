//! Genuine original compiler metadata oracles; no successful captures or keys.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Ports = @import("../recursion/block_v5_requester_public_assembly_ports_v1.zig");
const Scoped = @import("../recursion/block_v5_heterogeneous_scoped_public_bus_v1.zig");
const Bus = @import("../recursion/block_v5_requester_public_bus_v1.zig");
const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
const Public = @import("../recursion/block_v5_requester_public_compensation_v1.zig");
const Storage = @import("../recursion/air/blake3_parent_row_storage.zig");
const Join = @import("../recursion/air/block_v5_requester_public_fixed_join_v1.zig");
const Identifiers = @import("../recursion/air/block_v5_requester_public_fixed_identifier_ports_v1.zig");
const OriginalArithmetic = @import("../recursion/block_v5_recursive_parent_fixed_assembly_v1.zig").Arithmetic;
const C = @import("../recursion/air/composition_circuit.zig");
const Fusion = @import("../recursion/air/arithmetic_fusion_rows.zig");
const Lower = @import("../recursion/air/verifier_arithmetic_lowering.zig");
const Namespace = @import("../recursion/air/block_v5_recursive_fixed_namespace_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Assembly = @import("../recursion/block_v5_requester_public_fixed_assembly_v1.zig");
fn inputs() Ports.ContextInputs {
    return .{ .source_authority = @splat(1), .public_identity = @splat(2), .requester_expected = @splat(3), .tuple_identity = @splat(4), .child_namespace = @splat(5), .tuple_namespace = @splat(6), .child = .{ .child_key_id = @splat(3), .child_config = Base.CSP_CONFIG, .graph_ids = .{ @splat(7), @splat(8), @splat(9) }, .transcript_plan_id = @splat(10) } };
}
test "PUBLIC21 fixed assembly: original five context channels and each source namespace graph mutation" {
    const input = inputs();
    var channels: [5]core.channel.blake3.Channel = @splat(.{});
    for (&channels, 0..) |*channel, i| {
        channel.mixU32s(&.{ 0x52515052, Public.VERSION, @intCast(i) });
        inline for (.{ input.source_authority, input.public_identity, input.requester_expected, input.tuple_identity, input.child_namespace, input.tuple_namespace }) |pin| channel.mixRoot(pin);
    }
    for (channels[1..4], input.child.graph_ids) |*channel, pin| channel.mixRoot(pin);
    channels[4].mixRoot(input.child.transcript_plan_id);
    const actual = Ports.context(input);
    try std.testing.expectEqualDeep(Base.Context{ .child_key_id = channels[0].digestBytes(), .child_config = input.child.child_config, .graph_ids = .{ channels[1].digestBytes(), channels[2].digestBytes(), channels[3].digestBytes() }, .transcript_plan_id = channels[4].digestBytes() }, actual);
    inline for (.{ "source_authority", "public_identity", "requester_expected", "tuple_identity", "child_namespace", "tuple_namespace" }) |name| {
        var changed = input;
        @field(changed, name)[0] ^= 1;
        try std.testing.expect(!std.meta.eql(actual, Ports.context(changed)));
    }
    for (0..3) |i| {
        var changed = input;
        changed.child.graph_ids[i][0] ^= 1;
        try std.testing.expect(!std.meta.eql(actual, Ports.context(changed)));
    }
    var changed = input;
    changed.child.transcript_plan_id[0] ^= 1;
    try std.testing.expect(!std.meta.eql(actual, Ports.context(changed)));
    changed = input;
    changed.child.child_config = Base.PCS_CONFIG;
    try std.testing.expect(!std.meta.eql(actual, Ports.context(changed)));
}
test "PUBLIC21 fixed assembly: exact external wire conversion and invalid child part kinds reject" {
    var wire = Scoped.Wire{ .circuit = 17, .wire = 9, .uses = 3, .negative = true, .child = 0, .kind = .child_cell, .coordinate = 27 };
    var actual = try Ports.childWire(wire);
    try std.testing.expectEqualDeep(Bus.Wire{ .circuit = 17, .wire = 9, .uses = 3, .negative = true, .source = .{ .original = .{ .child = 0, .kind = .frame_cell, .coordinate = 27, .part = 0 } } }, actual);
    wire.part = 2;
    actual = try Ports.childWire(wire);
    try std.testing.expectEqual(@import("../recursion/block_v5_heterogeneous_public_bus_v1.zig").Kind.pairing_coordinate, actual.source.original.kind);
    try std.testing.expectEqual(@as(u32, 2), actual.source.original.part);
    wire.part = null;
    wire.kind = .child_term;
    actual = try Ports.childWire(wire);
    try std.testing.expectEqual(@import("../recursion/block_v5_heterogeneous_public_bus_v1.zig").Kind.child_supply_packed, actual.source.original.kind);
    wire.part = 0;
    try std.testing.expectError(error.InvalidRequesterPublicSchedule, Ports.childWire(wire));
    wire.part = null;
    wire.child = 1;
    try std.testing.expectError(error.InvalidRequesterPublicSchedule, Ports.childWire(wire));
}
test "PUBLIC21 fixed assembly: canonical external order and duplicate schedules fail closed" {
    var wires = [_]Bus.Wire{
        .{ .circuit = 9, .wire = 8, .uses = 1, .source = .{ .public_word = .{ .window = 0, .word = 0 } } },
        .{ .circuit = 7, .wire = 3, .uses = 1, .source = .{ .original = .{ .child = 0, .kind = .frame_cell, .coordinate = 0, .part = 0 } } },
    };
    try Ports.sortAndRequire(&wires);
    try std.testing.expectEqual(@as(u32, 7), wires[0].circuit);
    const expected = try Bus.scheduleDigest(&wires);
    std.mem.reverse(Bus.Wire, &wires);
    try Ports.sortAndRequire(&wires);
    try std.testing.expectEqualDeep(expected, try Bus.scheduleDigest(&wires));
    wires[1] = wires[0];
    try std.testing.expectError(error.InvalidGlobalPublicSchedule, Ports.sortAndRequire(&wires));
}
fn metadataFixture(a: std.mem.Allocator, first: u32) !Storage.FixedTuple(false) {
    @setEvalBranchQuota(10_000);
    var fixed = Join.empty();
    errdefer Join.deinit(a, &fixed);
    inline for (Storage.Airs, 0..) |Air, i| {
        fixed[i] = try a.alloc(Storage.FixedRow(Air), 1);
        fixed[i][0] = @splat(M.fromCanonical(first + @as(u32, @intCast(i))));
    }
    return fixed;
}
test "PUBLIC21 fixed assembly: every original cohort preserves child then tuple join order and caps" {
    const a = std.testing.allocator;
    var child = try metadataFixture(a, 1);
    defer Join.deinit(a, &child);
    var tuple = try metadataFixture(a, 101);
    defer Join.deinit(a, &tuple);
    var joined = try Join.join(a, child, tuple, 2);
    defer Join.deinit(a, &joined);
    inline for (0..Storage.Airs.len) |i| {
        try std.testing.expectEqual(@as(usize, 2), joined[i].len);
        try std.testing.expectEqualDeep(child[i][0], joined[i][0]);
        try std.testing.expectEqualDeep(tuple[i][0], joined[i][1]);
    }
    try std.testing.expectError(error.RequesterPublicFixedResourceLimit, Join.join(std.testing.failing_allocator, child, tuple, 1));
    try std.testing.expectError(error.RequesterPublicFixedResourceLimit, Join.join(std.testing.failing_allocator, child, tuple, 0));
}
fn joinAllocation(a: std.mem.Allocator, child: Storage.FixedTuple(false), tuple: Storage.FixedTuple(false)) !void {
    var joined = try Join.join(a, child, tuple, 2);
    defer Join.deinit(a, &joined);
    try std.testing.expectEqualDeep(child[0][0], joined[0][0]);
    try std.testing.expectEqualDeep(tuple[0][0], joined[0][1]);
}
test "PUBLIC21 fixed assembly: all bounded join allocations release with admitted source buffers outside injection" {
    const a = std.testing.allocator;
    var child = try metadataFixture(a, 1);
    defer Join.deinit(a, &child);
    var tuple = try metadataFixture(a, 101);
    defer Join.deinit(a, &tuple);
    try std.testing.checkAllAllocationFailures(a, joinAllocation, .{ child, tuple });
}
const graph_nodes = [_]C.Node{ .{ .op = .input }, .{ .op = .{ .inverse = 0 } }, .{ .op = .{ .neg = 1 } }, .{ .op = .{ .add = .{ .lhs = 1, .rhs = 2 } } } };
fn graph() !C.CircuitGraph {
    return C.CircuitGraph.authenticate(&graph_nodes, &.{3}, C.computeGraphDigest(&graph_nodes, &.{3}));
}
test "PUBLIC21 fixed assembly: original six lane lowering identifiers and exact namespace parity" {
    const a = std.testing.allocator;
    const g = try graph();
    const graphs = [_]C.CircuitGraph{ g, g, g };
    var original = try OriginalArithmetic.init(a, graphs);
    defer original.deinit();
    var port = try Identifiers.Owned.init(a, &graphs, &.{ 1500, 1502, 1504 });
    defer port.deinit();
    try std.testing.expectEqualDeep(original.reference.authority_digest, port.reference.authority_digest);
    var expected = try Fusion.materializeIdentifiers(a, &original.plan, original.reference, .segment_leaf);
    defer expected.deinit();
    var actual = try Fusion.materializeIdentifiers(a, &port.plan, port.reference, .segment_leaf);
    defer actual.deinit();
    try std.testing.expectEqualSlices(u32, expected.inverse, actual.inverse);
    try std.testing.expectEqualSlices(u32, expected.linear, actual.linear);
    var fixed = Join.empty();
    // These are real ORIGINAL fixed fusion schedules, not fake proof rows.
    fixed[18] = original.fused.fixed[0];
    fixed[3] = original.fused.fixed[1];
    fixed[4] = original.fused.fixed[2];
    fixed[5] = original.fused.fixed[3];
    var left = try Namespace.prepareForArithmetic(a, fixed, 1, .{ .plan = &original.plan, .reference = original.reference, .kind = .segment_leaf });
    defer left.deinit();
    var right = try Namespace.prepareForArithmetic(a, fixed, 1, try port.port());
    defer right.deinit();
    try right.requireIndependentMainPort();
    try std.testing.expectEqualDeep(try left.identity(), try right.identity());
    try std.testing.expectEqualSlices(u32, left.original.old, right.original.old);
    const evaluations = [_]Lower.Evaluation{.{ .circuit_identity = g.identity_digest, .values = &.{ Q.one(), Q.one(), Q.one().neg(), Q.zero() } }} ** 6;
    var full = try Fusion.materialize(a, &original.plan, original.reference, .{ .lanes = &evaluations }, .segment_leaf);
    defer full.deinit();
    var live = Storage.Prepared{ .allocator = a, .main = @splat(&.{}), .fixed = Join.empty(), .input_count = 0 };
    defer live.deinit();
    // Original Rebase.geometry validates every physical cohort, including
    // empty cohorts. Emit their genuine zero-row layout through the original
    // direct compiler before replacing the four selected arithmetic cohorts.
    inline for (Storage.Airs, 0..) |Air, slot| {
        var empty_emitter = try @import("../recursion/air/blake3_direct_cohort_columns_v1.zig").ForAir(Air).init(a, 0);
        defer empty_emitter.deinit();
        const taken = try empty_emitter.take();
        live.main[slot] = taken.main;
        live.fixed[slot] = taken.fixed;
    }
    inline for (.{ 18, 3, 4, 5 }, .{ full.opening, full.multiply, full.inverse, full.linear }) |slot, logical| {
        var emitter = try @import("../recursion/air/blake3_direct_cohort_columns_v1.zig").ForAir(Storage.Airs[slot]).init(a, logical.len);
        defer emitter.deinit();
        for (logical) |row| try emitter.append(row);
        const taken = try emitter.take();
        live.releaseCohort(slot);
        live.main[slot] = taken.main;
        live.fixed[slot] = taken.fixed;
    }
    try right.validateLive(&live);
    // A newly re-sealed different graph still fails the independently expected
    // original namespace comparison; no checksum grants expected authority.
    var other = try Identifiers.Owned.init(a, &graphs, &.{ 1500, 1502, 1506 });
    defer other.deinit();
    var changed = try Namespace.prepareForArithmetic(a, fixed, 1, try other.port());
    defer changed.deinit();
    try std.testing.expect(!std.meta.eql(try right.identity(), try changed.identity()));
}
fn identifierAllocation(a: std.mem.Allocator, g: C.CircuitGraph) !void {
    var port = try Identifiers.Owned.init(a, &.{g}, &.{4_300_100});
    defer port.deinit();
    _ = try port.port();
}
test "PUBLIC21 fixed assembly: identifier metadata allocation failures and invalid geometry reject" {
    const g = try graph();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, identifierAllocation, .{g});
    try std.testing.expectError(error.InvalidRequesterPublicIdentifierPorts, Identifiers.Owned.init(std.testing.failing_allocator, &.{g}, &.{}));
    try std.testing.expectError(error.InvalidRequesterPublicIdentifierPorts, Identifiers.Owned.init(std.testing.allocator, &.{g}, &.{0}));
}
test "PUBLIC21 fixed assembly: real retained identifier custody after creator budget release" {
    const budget = try Budget.create(std.testing.allocator, 8 << 20);
    var creator_live = true;
    defer if (creator_live) budget.destroy();
    const g = try graph();
    var port = try Identifiers.Owned.init(budget.allocator(), &.{g}, &.{4_300_100});
    defer port.deinit();
    budget.destroy();
    creator_live = false;
    _ = try port.port();
}
test "PUBLIC21 fixed assembly: resource guards precede undefined independent owner and expose no proof acceptance" {
    try std.testing.expectError(error.RequesterPublicFixedResourceLimit, Assembly.Owned.init(std.testing.failing_allocator, undefined, 0, .csp_q70_pow26, .{}));
    try std.testing.expectError(error.RequesterPublicFixedResourceLimit, Assembly.Owned.init(std.testing.failing_allocator, undefined, 1, .csp_q70_pow26, .{ .max_bytes = 0 }));
    try std.testing.expect(!@hasField(Assembly.Owned, "main"));
    try std.testing.expect(!@hasField(Assembly.Owned, "capture"));
    try std.testing.expect(!@hasDecl(Assembly.Owned, "verify"));
    try std.testing.expect(!Assembly.Owned.complete_block_authority);
}
test "PUBLIC21 fixed assembly: final G geometry preserves all tails and already partitioned cohorts" {
    const a = std.testing.allocator;
    const P = @import("../recursion/air/blake3_g_partition.zig");
    var fixed = Join.empty();
    defer Join.deinit(a, &fixed);
    const count = (1 << 20) + 1;
    fixed[0] = try a.alloc(Storage.FixedRow(Storage.Airs[0]), count);
    for (fixed[0], 0..) |*row, i| row.* = @splat(M.fromCanonical(@intCast(i + 1)));
    // Exercise the original remainder guard with an over-threshold leading
    // cohort; metadata is retained unchanged rather than repartitioned.
    fixed[P.REMAINDER] = try a.alloc(Storage.FixedRow(Storage.Airs[0]), 1);
    fixed[P.REMAINDER][0] = @splat(M.one());
    const before = fixed[0].ptr;
    try Join.partition(a, &fixed);
    try std.testing.expectEqual(before, fixed[0].ptr);
    try std.testing.expectEqual(@as(usize, count), fixed[0].len);
    a.free(fixed[P.REMAINDER]);
    fixed[P.REMAINDER] = &.{};
    try Join.partition(a, &fixed);
    const shape = try P.geometry(count);
    var first: usize = 0;
    inline for (P.SHARDS, 0..) |slot, shard| {
        try std.testing.expectEqual(shape.counts[shard], fixed[slot].len);
        for (fixed[slot], 0..) |row, i| try std.testing.expectEqual(@as(u32, @intCast(first + i + 1)), row[0].toU32());
        first += fixed[slot].len;
    }
    try std.testing.expectEqual(@as(usize, count), first);
    // Repeating the original partition is stable after its first application.
    const leading = fixed[0].ptr;
    const remainder = fixed[P.REMAINDER].ptr;
    try Join.partition(a, &fixed);
    try std.testing.expectEqual(leading, fixed[0].ptr);
    try std.testing.expectEqual(remainder, fixed[P.REMAINDER].ptr);
}
