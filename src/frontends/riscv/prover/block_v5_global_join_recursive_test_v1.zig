//! Equation/coordinate fixtures only. These literal statements are NOT child
//! verifier captures and never enter a positive cryptographic parent path.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const G = @import("../recursion/air/block_v5_global_join_composition_v1.zig");
const F = @import("../recursion/block_v5_heterogeneous_child_frames_v1.zig");
const J = @import("block_v5_global_join_algebra_v1.zig");
const K = @import("../air/lookups/tables/schema.zig");
const ref_count = 11;
const zero_sums: [K.KIND_COUNT]G.Sum = @splat(&.{});
const byte_kind = @intFromEnum(K.Kind.range_check_8_8);
fn supply() [K.KIND_COUNT]G.Sum {
    var out = zero_sums;
    out[0] = &.{5};
    out[byte_kind] = &.{10};
    return out;
}
fn demand() [K.KIND_COUNT]G.Sum {
    var out = zero_sums;
    out[0] = &.{4};
    return out;
}
const states = [_]G.Scope{.{ .index = 0, .terms = &.{ 0, 1 } }};
const windows = [_]G.Scope{.{ .index = 0, .terms = &.{ 2, 3 } }};
const requests = [_]G.Request{.{ .execution = 0, .claims = demand(), .byte_part = 0 }};
const groups = [_]G.Lookup{.{ .index = 0, .supply = supply(), .requests = &requests }};
const empty_accounting: J.Accounting(G.Sum) = .{
    .native_open_sum = &.{},
    .precompile_open_sum = &.{},
    .public_program_boundary_sum = &.{},
    .program_provider_sum = &.{},
    .table_provider_sum = &.{},
    .ordinary_memory_opposite = &.{},
    .external_memory_opposite = &.{},
    .auxiliary_clock_memory_sum = &.{},
    .register_compensation_sum = &.{},
};
const Fixture = struct {
    claims: [ref_count]Q,
    cells: [4 * ref_count][4]M,
    frames: [1]F.Frame,
    refs: [ref_count]G.Ref,
    views: [1]G.testing.View,
    plan: G.Plan,
    pub fn init(self: *@This()) void {
        self.claims = .{ q(3), q(3).neg(), q(5), q(5).neg(), q(17), q(17).neg(), q(7), q(7).neg(), q(11), q(11).neg(), q(3).neg() };
        self.claims[0] = Q.fromM31Array(.{ M.fromCanonical(3), M.fromCanonical(19), M.fromCanonical(23), M.fromCanonical(29) });
        self.claims[1] = self.claims[0].neg();
        self.claims[10] = self.claims[0].neg();
        for (&self.refs, 0..) |*ref, index| ref.* = .{ .child = 0, .kind = .native_fused, .index = 0, .frame = 0, .felt = @intCast(index) };
        self.plan = .{ .refs = &self.refs, .states = &states, .registers = &windows, .register_custody_mode = 1, .lookup = &groups, .byte_parts = &.{&.{0}}, .transition_requests = &.{8}, .transition_provider = &.{9}, .program_requests = &.{&.{6}}, .program_provider = &.{7}, .accounting = empty_accounting };
        self.plan.accounting.native_open_sum = &.{4};
        self.plan.accounting.public_program_boundary_sum = &.{6};
        self.plan.accounting.program_provider_sum = &.{7};
        self.plan.accounting.table_provider_sum = &.{ 5, 10 };
        self.refresh();
    }
    pub fn refresh(self: *@This()) void {
        for (self.claims, 0..) |claim, index| for (claim.toM31Array(), 0..) |word, component| {
            for (0..4) |part| self.cells[4 * index + component][part] = M.fromCanonical((word.v >> @as(u5, @intCast(8 * part))) & 255);
        };
        self.frames = .{.{ .first = 0, .operation = .{ .felts = &self.claims } }};
        self.views = .{.{ .kind = .native_fused, .index = 0, .source_seal = @splat(9), .frames = &self.frames, .cells = &self.cells }};
    }
    pub fn pin(self: *@This()) !G.MappingPin {
        return .{ .plan = try self.plan.identity(), .coverage = @splat(8), .source_seal = @splat(9) };
    }
    pub fn record(self: *@This(), a: std.mem.Allocator) !G.Prepared {
        return G.testing.recordViews(a, &self.views, self.plan, try self.pin(), .{});
    }
};
fn q(value: u32) Q {
    return Q.fromBase(M.fromCanonical(value));
}

test "global join recursion: original byte graph preserves native scoped equations and source supplies" {
    var fixture: Fixture = undefined;
    fixture.init();
    var sink = J.ScalarSink{};
    try G.equations(Q, std.testing.allocator, &sink, fixture.plan, &fixture.claims);
    var prepared = try fixture.record(std.testing.allocator);
    defer prepared.deinit();
    try std.testing.expect(G.Prepared.aggregate_coverage_pending and G.Prepared.endpoint_source_authority_pending);
    const wires = try prepared.publicWires(std.testing.allocator, G.CIRCUIT);
    defer std.testing.allocator.free(wires);
    try std.testing.expect(wires.len > 0);
    for (wires) |wire| {
        try std.testing.expect(wire.kind == .pairing_coordinate);
        const source = prepared.sources[wire.wire];
        try std.testing.expectEqual(source.child, wire.child);
        try std.testing.expectEqual(source.cell, wire.coordinate);
        try std.testing.expectEqual(source.part, wire.part);
        try std.testing.expect(prepared.inputs[wire.wire].eql(Q.fromBase(fixture.cells[source.cell][source.part])));
    }
    _ = try @import("../recursion/block_v5_heterogeneous_public_bus_v1.zig").scheduleDigest(wires);
}
test "global join recursion: executions and register windows cannot cancel across scopes" {
    var fixture: Fixture = undefined;
    fixture.init();
    fixture.plan.states = &.{ .{ .index = 0, .terms = &.{0} }, .{ .index = 1, .terms = &.{1} } };
    var sink = J.ScalarSink{};
    try std.testing.expectError(error.UnclosedV5NativePublicState, G.equations(Q, std.testing.allocator, &sink, fixture.plan, &fixture.claims));
    try std.testing.expectError(error.UnsatisfiedCircuit, fixture.record(std.testing.allocator));
    fixture.plan.states = &states;
    fixture.plan.registers = &.{ .{ .index = 0, .terms = &.{2} }, .{ .index = 1, .terms = &.{3} } };
    try std.testing.expectError(error.UnclosedV5RegisterWindow, G.equations(Q, std.testing.allocator, &sink, fixture.plan, &fixture.claims));
    try std.testing.expectError(error.UnsatisfiedCircuit, fixture.record(std.testing.allocator));
}
test "global join recursion: provider kinds and groups keep independent equalities" {
    var fixture: Fixture = undefined;
    fixture.init();
    var swapped = supply();
    swapped[0] = &.{10};
    swapped[byte_kind] = &.{5};
    const wrong = [_]G.Lookup{.{ .index = 0, .supply = swapped, .requests = &requests }};
    fixture.plan.lookup = &wrong;
    var sink = J.ScalarSink{};
    try std.testing.expectError(error.UnclosedV5NativeLookupGroup, G.equations(Q, std.testing.allocator, &sink, fixture.plan, &fixture.claims));
    try std.testing.expectError(error.UnsatisfiedCircuit, fixture.record(std.testing.allocator));
    const no_requests = [_]G.Request{};
    const split = [_]G.Lookup{ .{ .index = 0, .supply = zero_sums, .requests = &requests }, .{ .index = 1, .supply = supply(), .requests = &no_requests } };
    fixture.plan.lookup = &split;
    try std.testing.expectError(error.UnclosedV5NativeLookupGroup, G.equations(Q, std.testing.allocator, &sink, fixture.plan, &fixture.claims));
    try std.testing.expectError(error.UnsatisfiedCircuit, fixture.record(std.testing.allocator));
}
test "global join recursion: byte partition and auxiliary sign are exact" {
    var fixture: Fixture = undefined;
    fixture.init();
    fixture.plan.accounting.native_open_sum = &.{ 4, 8 };
    fixture.plan.accounting.auxiliary_clock_memory_sum = &.{8};
    var prepared = try fixture.record(std.testing.allocator);
    prepared.deinit();
    fixture.plan.accounting.auxiliary_clock_memory_sum = &.{9};
    try std.testing.expectError(error.UnsatisfiedCircuit, fixture.record(std.testing.allocator));
    fixture.init();
    fixture.plan.byte_parts = &.{ &.{0}, &.{0} };
    try std.testing.expectError(error.InvalidGlobalJoinBytePartition, fixture.record(std.testing.allocator));
}
test "global join recursion: malformed or changed original statement and mapping fail before recording" {
    var fixture: Fixture = undefined;
    fixture.init();
    var pinned = try fixture.pin();
    pinned.coverage = @splat(0);
    try std.testing.expectError(error.InvalidGlobalJoinMapping, G.testing.recordViews(std.testing.allocator, &fixture.views, fixture.plan, pinned, .{}));
    pinned = try fixture.pin();
    pinned.plan[0] ^= 1;
    try std.testing.expectError(error.InvalidGlobalJoinMapping, G.testing.recordViews(std.testing.allocator, &fixture.views, fixture.plan, pinned, .{}));
    fixture.cells[0][0] = M.fromCanonical(4);
    try std.testing.expectError(error.MutatedGlobalJoinStatement, fixture.record(std.testing.allocator));
    fixture.refresh();
    fixture.refs[0].kind = .range16;
    try std.testing.expectError(error.InvalidGlobalJoinMapping, fixture.record(std.testing.allocator));
    fixture.init();
    fixture.frames[0].operation = .{ .words = &.{1} };
    try std.testing.expectError(error.InvalidGlobalJoinClaimFrame, fixture.record(std.testing.allocator));
    fixture.init();
    try std.testing.expectError(error.GlobalJoinResourceLimit, G.testing.recordViews(std.testing.allocator, &fixture.views, fixture.plan, try fixture.pin(), .{ .max_refs = 1 }));
}
fn construction(a: std.mem.Allocator) !void {
    var fixture: Fixture = undefined;
    fixture.init();
    var prepared = try fixture.record(a);
    defer prepared.deinit();
    const wires = try prepared.publicWires(a, G.CIRCUIT);
    defer a.free(wires);
}
test "global join recursion: exhaustive graph and public schedule allocation rollback" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, construction, .{});
}

// Structurally initialized metadata for the isolated row-lowering audit only.
// Its key/seal is intentionally invalid and is never admitted or verified.
fn metadataChild(a: std.mem.Allocator, fixture: *Fixture) F.Child {
    const B = @import("../recursion/blake3_execution_parent_protocol.zig");
    return .{
        .arena = std.heap.ArenaAllocator.init(a),
        .physical = .{ .kind = .native_fused, .subtype = .capacity_fused_v1, .index = 0, .logical = .{ 0, 1 }, .logical_count = 2, .instance_id = @splat(0), .roots = @splat(@splat(0)) },
        .recipe = .custody_v2,
        .source_seal = @splat(9),
        .key = .{ .context = .{ .child_key_id = @splat(0), .child_config = B.PCS_CONFIG, .graph_ids = @splat(@splat(0)), .transcript_plan_id = @splat(0) }, .log_sizes = @splat(1), .preprocessed_root = @splat(0) },
        .expected_id = @splat(0),
        .public_input_digest = @splat(0),
        .claim_frame = @splat(0),
        .frames = &fixture.frames,
        .cells = &fixture.cells,
        .terms = &.{},
        .span = null,
        .link = null,
        .seal = @splat(0),
    };
}
test "global join recursion: real arithmetic cohorts bind each original coordinate and reject evaluation mutation" {
    var fixture: Fixture = undefined;
    fixture.init();
    var prepared = try fixture.record(std.testing.allocator);
    defer prepared.deinit();
    var child = metadataChild(std.testing.allocator, &fixture);
    defer child.deinit();
    try std.testing.expectError(error.InvalidHeterogeneousChild, child.validate());
    const Graphs = @import("../recursion/air/block_v5_heterogeneous_graph_rows_v1.zig");
    const graph = Graphs.Graph{ .circuit = &prepared.circuit, .inputs = prepared.inputs, .values = prepared.values, .sources = prepared.sources };
    var lowered = try Graphs.testing.lowerGraph(std.testing.allocator, graph, &.{child});
    defer lowered.deinit();
    try std.testing.expect(lowered.rows.fixed[5].len > 0);
    const wires = try prepared.publicWires(std.testing.allocator, Graphs.CIRCUIT);
    defer std.testing.allocator.free(wires);
    try std.testing.expectEqual(wires.len, lowered.wires.len);
    for (wires, lowered.wires) |expected, actual| try std.testing.expect(std.meta.eql(expected, actual));
    prepared.values[0] = prepared.values[0].add(Q.one());
    try std.testing.expectError(error.MutatedHeterogeneousGraphEvaluation, Graphs.testing.lowerGraph(std.testing.allocator, graph, &.{child}));
    prepared.values[0] = prepared.values[0].sub(Q.one());
    fixture.cells[0][0] = fixture.cells[0][0].add(M.one());
    try std.testing.expectError(error.UntrustedHeterogeneousGraphInput, Graphs.testing.lowerGraph(std.testing.allocator, graph, &.{child}));
}

test "global join recursion: parent admits exact execution window and provider census without a completion token" {
    var fixture: Fixture = undefined;
    fixture.init();
    const P = @import("../recursion/block_v5_global_join_parent_preparation_v1.zig");
    try P.requireScopes(fixture.plan, 1, 1, 1);
    try std.testing.expectError(error.InvalidGlobalJoinScope, P.requireScopes(fixture.plan, 2, 1, 1));
    try std.testing.expectError(error.InvalidGlobalJoinScope, P.requireScopes(fixture.plan, 1, 2, 1));
    try std.testing.expectError(error.InvalidGlobalJoinScope, P.requireScopes(fixture.plan, 1, 1, 2));
    fixture.plan.register_custody_mode = 0;
    try std.testing.expectError(error.InvalidGlobalJoinScope, P.requireScopes(fixture.plan, 1, 1, 1));
    try std.testing.expect(P.aggregate_semantic_coverage_pending and P.endpoint_source_authority_pending);
}
