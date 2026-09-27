//! Nonproving shared-kernel fixtures. Metadata models never become a Source,
//! an independently admitted policy, a verifier capture, or a proof receipt.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Scoped = @import("../recursion/block_v5_heterogeneous_scoped_plan_v1.zig");
const Cohorts = @import("../recursion/block_v5_heterogeneous_scoped_cohorts_v1.zig");
const Routes = @import("../recursion/block_v5_heterogeneous_scoped_routes_v1.zig");
const Frames = @import("../recursion/block_v5_heterogeneous_scoped_source_v1.zig");
const Original = @import("../recursion/block_v5_heterogeneous_child_frames_v1.zig");
const Coverage = @import("block_v5_recursive_coverage_plan_v1.zig");
const Full = @import("../recursion/block_v5_heterogeneous_policy_v1.zig").Policy;
const Bus = @import("../recursion/block_v5_heterogeneous_scoped_public_bus_v1.zig");
const Equations = @import("../recursion/air/block_v5_heterogeneous_scoped_equations_v1.zig");
fn physical(kind: Coverage.Kind, index: u32) Coverage.Physical {
    return .{ .kind = kind, .subtype = switch (kind) {
        .native_arithmetic => .capacity_v1,
        .native_fused => .capacity_fused_v1,
        .caller_arithmetic => .caller_family11_v1,
        .caller_fused => .caller_fused_v1,
        .ram_lanes => .ram_lanes_v1,
        .range16 => .range16_v1,
        .rom => .rom_v1,
        .native_lookup => .six_table_lookup_v1,
    }, .index = index, .logical = .{ 0, 0 }, .logical_count = 0, .instance_id = @splat(0), .roots = @splat(@splat(0)) };
}
test "requester summary: static exact family selection retains original arithmetic fused ROM six-table and excludes RAM range" {
    inline for (std.meta.tags(Coverage.Kind)) |kind| {
        try std.testing.expect(Scoped.includes(.complete, physical(kind, 0)));
        try std.testing.expectEqual(kind != .ram_lanes and kind != .range16, Scoped.includes(.requesters, physical(kind, 0)));
    }
    const Owner = @import("../recursion/block_v5_heterogeneous_scoped_owner_v1.zig");
    try std.testing.expect(!Owner.Owner.proof_authority and !Owner.Owner.complete_block_authority);
}
fn topology(a: std.mem.Allocator, count: usize) !void {
    const children = try a.alloc(Original.Child, count + 2);
    defer a.free(children);
    for (children, 0..) |*child, i| {
        child.physical = physical(if (i == 1) .ram_lanes else if (i == count + 1) .range16 else .native_arithmetic, @intCast(i));
        child.span = null;
    }
    const full = Full{ .plan = undefined, .children = children, .expected = &.{} };
    var cohorts = try Cohorts.testing.foldMetadataForRecipe(.requesters, a, full, .{});
    defer cohorts.deinit();
    try std.testing.expectEqual(Scoped.Recipe.requesters, cohorts.recipe);
    var storage: [1]u32 = undefined;
    const ids = try cohorts.descendants(cohorts.root, &storage);
    try std.testing.expectEqual(count, ids.len);
    for (ids, 0..) |id, i| {
        try std.testing.expectEqual(@as(u32, @intCast(if (i == 0) 0 else i + 1)), id);
        try std.testing.expect(Scoped.includes(.requesters, children[id].physical));
    }
    for (cohorts.nodes) |node| try std.testing.expect(node.child_count >= 2 and node.child_count <= 4);
    var requirements = [_]Scoped.Requirement{.{ .key = .{ .kind = .transition, .scope = 0, .coordinate = 0 }, .terms = &.{}, .disposition = .retain }};
    var scoped: Scoped.Plan = undefined;
    scoped.recipe = .requesters;
    scoped.full = full;
    scoped.requirements = &requirements;
    scoped.digest = @splat(1);
    var routes = try Routes.testing.routeMetadata(a, &scoped, &cohorts, .{});
    defer routes.deinit();
    try std.testing.expectEqual(@as(usize, 0), routes.leaves[1].len);
    try std.testing.expectEqual(@as(usize, 0), routes.leaves[count + 1].len);
    if (cohorts.root == .node) {
        try std.testing.expectEqualSlices(u32, &.{0}, routes.nodes[cohorts.root.node].exports);
        try std.testing.expectEqual(@as(usize, 0), routes.nodes[cohorts.root.node].closed.len);
    }
    // A correctly rehashed route with even one RAM/provider contribution
    // cannot use the real routing kernel with a requester-only cohort.
    const forbidden = [_]Scoped.Term{.{ .selection = .{ .byte = .{ .child = 1, .cell = 0, .part = 0 } } }};
    requirements[0].terms = &forbidden;
    if (Routes.testing.routeMetadata(a, &scoped, &cohorts, .{})) |value| {
        var bad = value;
        bad.deinit();
        return error.TestExpectedError;
    } else |err| if (err != error.InvalidScopedRoute) return err;
}
test "requester summary: odd and large exact rosters use bounded four-child parents without verifying excluded descendants" {
    for ([_]usize{ 1, 2, 3, 4, 5, 7, 17, 70, 257 }) |count| try topology(std.testing.allocator, count);
}
fn faultTopology(a: std.mem.Allocator) !void {
    try topology(a, 7);
}
test "requester summary: every selected-cohort and exact routing allocation failure releases both owners" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, faultTopology, .{});
}
fn limbs(value: Q) [4][4]M {
    var bytes: [4][4]M = undefined;
    for (&bytes, value.toM31Array()) |*word, m| for (word, 0..) |*b, part| {
        b.* = M.fromCanonical((m.v >> @as(u5, @intCast(8 * part))) & 255);
    };
    return bytes;
}
fn retained(a: std.mem.Allocator) !void {
    var scoped: Scoped.Plan = undefined;
    var cohorts: Cohorts.Plan = undefined;
    var routes: Routes.Plan = undefined;
    const requirement = [_]Scoped.Requirement{.{ .key = .{ .kind = .transition, .scope = 0, .coordinate = 0 }, .terms = &.{}, .disposition = .retain }};
    const ids = [_]u32{0};
    const nodes = [_]Routes.Node{
        .{ .inputs = &ids, .exports = &ids, .closed = &.{} },
        .{ .inputs = &ids, .exports = &ids, .closed = &.{} },
        .{ .inputs = &ids, .exports = &ids, .closed = &.{} },
    };
    const slots = [_]Frames.Slot{.{ .requirement = 0, .first = 0 }};
    const l = Q.fromU32Unchecked(3, 5, 7, 11);
    const r = Q.fromU32Unchecked(13, 17, 19, 23);
    const left = limbs(l);
    const right = limbs(r);
    var children: [2]Frames.Source = undefined;
    for (&children, 0..) |*child, i| {
        child.ref = .{ .node = @intCast(i) };
        child.cells = if (i == 0) &left else &right;
        child.slots = &slots;
        child.span = null;
    }
    const output = [_]Q{l.add(r)};
    scoped.requirements = &requirement;
    cohorts.root = .{ .node = 3 }; // model a non-root merge; no authority.
    routes.scoped = &scoped;
    routes.cohorts = &cohorts;
    routes.nodes = &nodes;
    var graph = try Equations.testing.record(a, .{ .routes = &routes, .index = 2, .children = &children, .pins = &.{}, .outputs = &output });
    defer graph.deinit();
    // Nonzero requester sums are preserved for the later memory-root join.
    try std.testing.expect(!output[0].isZero());
    for (0..graph.inputs.len) |i| {
        graph.inputs[i] = graph.inputs[i].add(Q.one());
        if (graph.circuit.evaluateInto(graph.inputs, graph.values)) |_| {
            return error.TestExpectedError;
        } else |err| if (err != error.UnsatisfiedCircuit) return err;
        graph.inputs[i] = graph.inputs[i].sub(Q.one());
    }
    try graph.circuit.evaluateInto(graph.inputs, graph.values);
}
test "requester summary: original four-limb equations retain packed requests and reject every source or output mutation" {
    try retained(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, retained, .{});
}
test "requester summary: static recipe changes plan and owner key context while preserving legacy identity" {
    var plan: Scoped.Plan = undefined;
    plan.recipe = .complete;
    plan.mapping = .{ .plan = @splat(1), .coverage = @splat(2), .source_seal = @splat(3) };
    plan.requirements = &.{};
    const complete = plan.identity();
    plan.recipe = .requesters;
    const requester = plan.identity();
    try std.testing.expect(!std.meta.eql(complete, requester));
    plan.recipe = .complete;
    try std.testing.expectEqual(complete, plan.identity());
    // Retain/open disposition itself is part of the independently bound plan.
    var requirement = [_]Scoped.Requirement{.{ .key = .{ .kind = .transition, .scope = 0, .coordinate = 0 }, .terms = &.{}, .disposition = .retain }};
    plan.recipe = .requesters;
    plan.requirements = &requirement;
    const pin = plan.identity();
    requirement[0].disposition = .zero_when_complete;
    try std.testing.expect(!std.meta.eql(pin, plan.identity()));
}
const MemoryPort = @import("../recursion/block_v5_source_ram_forest_join_source_v1.zig");
const MemoryFrameModel = struct {
    config: core.pcs.PcsConfig,
    transition: Q,
    pub fn mix(self: *const @This(), channel: anytype) !void {
        channel.mixU32s(&.{ 0x53524650, 20 });
        self.config.mixInto(channel);
        channel.mixRoot(@splat(7));
        channel.mixU32s(&.{ 0x5352464a, 20, 1 });
        channel.mixFelts(&.{self.transition});
    }
};
fn memoryFraming(a: std.mem.Allocator) !void {
    const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
    const model = MemoryFrameModel{ .config = Base.PCS_CONFIG, .transition = Q.fromU32Unchecked(3, 5, 7, 11) };
    var frame = try MemoryPort.testing.recordFrame(a, &model, .{});
    defer frame.deinit();
    const first = try MemoryPort.testing.transitionCoordinate(&frame);
    try std.testing.expectEqual(@as(u32, @intCast(frame.words.len + 4)), first);
    try std.testing.expectEqual(@as(usize, 2), frame.felts.len); // config AND T.
    try std.testing.expect(frame.felts[1].eql(model.transition));
    // Fork-only configuration uses TWO config fields; original ordinals must
    // still locate the final transition, never the first equal felt value.
    var fork = model;
    fork.config.lifting_log_size = 4;
    var extended = try MemoryPort.testing.recordFrame(a, &fork, .{});
    defer extended.deinit();
    try std.testing.expectEqual(@as(u32, @intCast(extended.words.len + 8)), try MemoryPort.testing.transitionCoordinate(&extended));
    try std.testing.expectEqual(@as(usize, 3), extended.felts.len);
    try std.testing.expect(extended.felts[2].eql(model.transition));
}
test "requester summary: genuine memory port framing preserves all original configuration fields and exact transition ordinal under faults" {
    try memoryFraming(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, memoryFraming, .{});
}
