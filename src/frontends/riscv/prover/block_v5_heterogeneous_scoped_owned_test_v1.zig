//! Nonproving ownership/resource/selector and full-u64 equation checks only.
//! Metadata models never mint an Owner, a capture or a verified child.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Owner = @import("../recursion/block_v5_heterogeneous_scoped_owner_v1.zig");
const P = @import("../recursion/block_v5_heterogeneous_scoped_plan_v1.zig");
const C = @import("../recursion/block_v5_heterogeneous_scoped_cohorts_v1.zig");
const Routes = @import("../recursion/block_v5_heterogeneous_scoped_routes_v1.zig");
const Bus = @import("../recursion/block_v5_heterogeneous_scoped_public_bus_v1.zig");
const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
const Files = @import("block_v5_heterogeneous_scoped_owned_files_v1.zig");
const Wide = @import("../recursion/air/block_v5_recursive_u64_span_v1.zig");
fn pins(ids: []const [32]u8) Owner.Pins {
    return .{ .job = @splat(1), .coverage = @splat(2), .source = @splat(3), .recipe = @import("block_v5_execution_recipe_v1.zig").canonical, .scoped = @splat(4), .routing = @splat(5), .node_ids = ids };
}
fn context() Owner.Context {
    return .{ .child_key_id = @splat(6), .child_config = Base.PCS_CONFIG, .graph_ids = @splat(@splat(7)), .transcript_plan_id = @splat(8) };
}
test "scoped setup owner: independent job source recipe coverage and node IDs remain separate from artifact re-seals" {
    const original = pins(&.{@splat(9)});
    var changed = original;
    inline for (.{ "job", "coverage", "source", "scoped", "routing" }) |field| {
        changed = original;
        @field(changed, field)[0] ^= 1;
        try std.testing.expect(!std.meta.eql(original.contextIdentity(), changed.contextIdentity()));
    }
    changed = original;
    changed.node_ids = &.{@splat(10)};
    try std.testing.expectEqual(original.contextIdentity(), changed.contextIdentity());
    try std.testing.expect(!std.meta.eql(original.identity(), changed.identity()));
    var left = context();
    var right = context();
    Owner.testing.bindSetupContext(&left, original.contextIdentity());
    changed.job[0] ^= 1;
    Owner.testing.bindSetupContext(&right, changed.contextIdentity());
    try std.testing.expect(!std.meta.eql(left.child_key_id, right.child_key_id));
    for (left.graph_ids, right.graph_ids) |a, b| try std.testing.expect(!std.meta.eql(a, b));
    try std.testing.expect(!std.meta.eql(left.transcript_plan_id, right.transcript_plan_id));
}
const Local = struct {
    scoped: P.Plan = undefined,
    cohorts: C.Plan = undefined,
    routes: Routes.Plan = undefined,
    requirements: [1]P.Requirement = undefined,
    terms: [2]P.Term = undefined,
    cohorts_nodes: [1]C.Node = undefined,
    route_nodes: [1]Routes.Node = undefined,
    ids: [1]u32 = .{0},
    wires: [1]Bus.Wire = .{.{ .circuit = 1, .wire = 0, .uses = 1, .kind = .output_slot, .coordinate = 0 }},
    output: [1]Q = .{Q.one()},
    spec: Owner.NodeSpec = undefined,
    fn init(self: *@This()) !void {
        self.ids = .{0};
        self.output = .{Q.one()};
        // The caller starts this metadata model as undefined. Initialize the
        // actual schedule explicitly; field defaults do not run on assignment
        // through an existing undefined object.
        self.wires = .{.{ .circuit = 1, .wire = 0, .uses = 1, .kind = .output_slot, .coordinate = 0 }};
        self.terms = .{ .{ .selection = .{ .byte = .{ .child = 0, .cell = 7, .part = 0 } } }, .{ .selection = .{ .byte = .{ .child = 1, .cell = 9, .part = 0 } }, .negative = true } };
        self.requirements = .{.{ .key = .{ .kind = .state, .scope = 3, .coordinate = 0 }, .terms = &self.terms, .disposition = .zero_when_complete }};
        self.scoped.requirements = &self.requirements;
        self.cohorts_nodes = .{.{ .children = .{ .{ .leaf = 0 }, .{ .leaf = 1 }, undefined, undefined }, .child_count = 2, .descendants = &.{ 0, 1 }, .span = null }};
        self.cohorts.nodes = &self.cohorts_nodes;
        self.route_nodes = .{.{ .inputs = &self.ids, .exports = &self.ids, .closed = &.{} }};
        self.routes = undefined;
        self.routes.scoped = &self.scoped;
        self.routes.cohorts = &self.cohorts;
        self.routes.nodes = &self.route_nodes;
        self.spec = .{ .unbound_context = context(), .key = .{ .profile = .diagnostic_q8_pow0, .config = Base.PCS_CONFIG, .context = context(), .log_sizes = @splat(1), .preprocessed_root = @splat(1), .public_schedule_digest = try Bus.scheduleDigest(&self.wires) }, .expected_id = @splat(1), .wires = &self.wires, .children = &.{}, .outputs = &self.output, .public_input = @splat(2), .source_seal = @splat(3) };
    }
    fn requirePinned(self: *const @This(), expected: [32]u8) !void {
        try Owner.testing.requireLocalFingerprint(&self.routes, 0, self.spec, @splat(4), expected);
    }
    fn identity(self: *const @This()) ![32]u8 {
        return Owner.testing.localFingerprint(&self.routes, 0, self.spec, @splat(4));
    }
};
test "scoped setup owner: local selectors signs scope roles ordering and public outputs reject against original immutable fingerprint" {
    var fixture: Local = undefined;
    try fixture.init();
    const expected = try fixture.identity();
    try fixture.requirePinned(expected);
    fixture.terms[0].selection.byte.cell += 1;
    try std.testing.expectError(error.MutatedScopedOwnedNode, fixture.requirePinned(expected));
    try fixture.init();
    fixture.terms[1].negative = false;
    try std.testing.expectError(error.MutatedScopedOwnedNode, fixture.requirePinned(expected));
    try fixture.init();
    fixture.requirements[0].key.scope += 1;
    try std.testing.expectError(error.MutatedScopedOwnedNode, fixture.requirePinned(expected));
    try fixture.init();
    fixture.requirements[0].disposition = .retain;
    try std.testing.expectError(error.MutatedScopedOwnedNode, fixture.requirePinned(expected));
    try fixture.init();
    fixture.cohorts_nodes[0].children[0] = .{ .leaf = 1 };
    fixture.cohorts_nodes[0].children[1] = .{ .leaf = 0 };
    try std.testing.expectError(error.MutatedScopedOwnedNode, fixture.requirePinned(expected));
    try fixture.init();
    fixture.output[0] = Q.zero();
    try std.testing.expectError(error.MutatedScopedOwnedNode, fixture.requirePinned(expected));
    try fixture.init();
    fixture.spec.expected_id[0] ^= 1;
    try std.testing.expectError(error.MutatedScopedOwnedNode, fixture.requirePinned(expected));
    try fixture.init();
    fixture.ids[0] = 1;
    try std.testing.expectError(error.InvalidScopedOwnedNode, fixture.identity());
}
test "scoped setup owner: bounded process-local borrows prevent premature teardown and release all leases" {
    var guard = Owner.Guard{ .limit = 2 };
    try guard.acquire();
    try guard.acquire();
    try std.testing.expectError(error.ScopedOwnerBorrowLimit, guard.acquire());
    try std.testing.expectError(error.ActiveScopedOwnerBorrow, guard.requireUnused());
    guard.release();
    try guard.acquire();
    guard.release();
    guard.release();
    try guard.requireUnused();
    try std.testing.expect(!Owner.Owner.proof_authority and !Owner.Owner.complete_block_authority);
}
const CloneModel = struct { proposal: []const u32, nested: []const []const u8, borrowed_setup: *const u32 };
fn cloneAllocation(a: std.mem.Allocator) !void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var original = [_]u32{ 7, 11 };
    var raw = [_]u8{ 3, 5 };
    const expected_setup: u32 = 13;
    const model = CloneModel{ .proposal = &original, .nested = &.{&raw}, .borrowed_setup = &expected_setup };
    const copied = try Owner.testing.cloneOwned(CloneModel, arena.allocator(), model);
    original[0] = 17;
    raw[0] = 19;
    try std.testing.expectEqual(@as(u32, 7), copied.proposal[0]);
    try std.testing.expectEqual(@as(u8, 3), copied.nested[0][0]);
    try std.testing.expect(copied.borrowed_setup == model.borrowed_setup);
}
test "scoped setup owner: proposal slices own session-independent bytes while immutable setup borrows and every allocation failure remain explicit" {
    try cloneAllocation(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, cloneAllocation, .{});
}
fn fileExpected() Files.Expected {
    return .{ .owner = @splat(1), .routing = @splat(2), .index = 7, .key = @splat(3), .public_input = @splat(4), .source = @splat(5) };
}
test "scoped setup owner: durable header rejects resealed job keys publics sources index truncation and proof resource proposals before allocation" {
    const expected = fileExpected();
    const raw = try Files.header(expected, &.{ 1, 2, 3 }, .{});
    try std.testing.expectEqual(@as(usize, 3), try Files.admitHeader(&raw, expected, Files.HEADER_BYTES + 3, .{}));
    inline for (.{ "owner", "routing", "key", "public_input", "source" }) |field| {
        var changed = expected;
        @field(changed, field)[0] ^= 1;
        const resealed = try Files.header(changed, &.{ 1, 2, 3 }, .{});
        try std.testing.expectError(error.UntrustedScopedNodeFile, Files.admitHeader(&resealed, expected, Files.HEADER_BYTES + 3, .{}));
    }
    var changed = expected;
    changed.index += 1;
    const resealed = try Files.header(changed, &.{ 1, 2, 3 }, .{});
    try std.testing.expectError(error.UntrustedScopedNodeFile, Files.admitHeader(&resealed, expected, Files.HEADER_BYTES + 3, .{}));
    try std.testing.expectError(error.ScopedNodeFileResourceLimit, Files.admitHeader(&raw, expected, Files.HEADER_BYTES + 2, .{}));
    try std.testing.expectError(error.ScopedNodeFileResourceLimit, Files.admitHeader(&raw, expected, Files.HEADER_BYTES + 3, .{ .max_proof_bytes = 2 }));
    try std.testing.expectError(error.ScopedNodeFileResourceLimit, Files.header(expected, &.{}, .{}));
    try std.testing.expectError(error.ScopedNodeFileResourceLimit, Files.header(expected, &.{ 1, 2, 3 }, .{ .max_proof_bytes = 2 }));
}
const Zero = struct {
    pub fn zero(_: *@This(), value: Q, failure: anyerror) !void {
        if (!value.isZero()) return failure;
    }
};
fn lift(bytes: Wide.Bytes) [8]Q {
    var result: [8]Q = undefined;
    for (&result, bytes) |*value, byte| value.* = Q.fromBase(core.fields.m31.M31.fromCanonical(byte));
    return result;
}
fn carryFields(bytes: [4]u8) [4]Q {
    var result: [4]Q = undefined;
    for (&result, bytes) |*value, byte| value.* = Q.fromBase(core.fields.m31.M31.fromCanonical(byte));
    return result;
}
fn wideAllocation(a: std.mem.Allocator) !void {
    const value: u64 = 0xffff_ffff_ffff;
    var graph = try Wide.record(a, Wide.encode(value), Wide.encode(value + 1), try Wide.carries(value));
    defer graph.deinit();
}
test "scoped setup owner: true full-u64 cycle adjacency matches symbolic equations across every limb carry and high clocks" {
    var sink = Zero{};
    const cases = [_]u64{ 0, 1, 65535, 0xffff_ffff, 0xffff_ffff_ffff, (@as(u64, 1) << 63) + 7, std.math.maxInt(u64) - 1 };
    for (cases) |value| {
        try Wide.increment(Q, &sink, lift(Wide.encode(value)), lift(Wide.encode(value + 1)), carryFields(try Wide.carries(value)));
        var graph = try Wide.record(std.testing.allocator, Wide.encode(value), Wide.encode(value + 1), try Wide.carries(value));
        defer graph.deinit();
        try graph.circuit.evaluateInto(&graph.inputs, graph.values);
        graph.inputs[8] = graph.inputs[8].add(Q.one());
        try std.testing.expectError(error.UnsatisfiedCircuit, graph.circuit.evaluateInto(&graph.inputs, graph.values));
    }
    try std.testing.expect(Wide.Graph.source_authority_pending);
}
test "scoped setup owner: cycle overflow malformed carry and modularly aliased clock proposals reject with complete fault cleanup" {
    var sink = Zero{};
    const left = lift(Wide.encode(65535));
    const right = lift(Wide.encode(65536));
    var bad = carryFields(try Wide.carries(65535));
    bad[0] = Q.zero();
    try std.testing.expectError(error.UnclosedRecursiveCycleAdjacency, Wide.increment(Q, &sink, left, right, bad));
    bad[0] = Q.one().add(Q.one());
    try std.testing.expectError(error.NonbooleanRecursiveCycleCarry, Wide.increment(Q, &sink, left, right, bad));
    try std.testing.expectError(error.RecursiveCycleOverflow, Wide.carries(std.math.maxInt(u64)));
    try std.testing.expectError(error.RecursiveCycleOverflow, Wide.increment(Q, &sink, lift(Wide.encode(std.math.maxInt(u64))), lift(Wide.encode(0)), carryFields(.{ 1, 1, 1, 1 })));
    try std.testing.expectError(error.UnclosedRecursiveCycleAdjacency, Wide.increment(Q, &sink, lift(Wide.encode(7)), lift(Wide.encode(@as(u64, 8) + core.fields.m31.Modulus)), carryFields(.{ 0, 0, 0, 0 })));
    try std.testing.checkAllAllocationFailures(std.testing.allocator, wideAllocation, .{});
}

const CoordinateView = struct {
    typed: Bus.Values,
    pub fn at(self: @This(), wire: Bus.Wire) ![4]core.fields.m31.M31 {
        return self.typed.at(wire);
    }
};
test "scoped setup owner: admitted typed and generic lowering preserve every row wire identity and source mutation rejection" {
    const R = @import("../recursion/air/composition_graph_recorder.zig");
    const Kernel = @import("../recursion/air/block_v5_heterogeneous_scoped_graph_rows_v1.zig");
    const Storage = @import("../recursion/air/blake3_parent_row_storage.zig");
    const Source = @import("../recursion/block_v5_heterogeneous_scoped_source_v1.zig");
    const M = core.fields.m31.M31;
    const a = std.testing.allocator;
    var builder = R.Builder.init(a);
    defer builder.deinit();
    const left = (try builder.input()).value;
    const right = (try builder.input()).value;
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    try builder.constrainZero(left.sub(right));
    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();
    const inputs = [_]Q{ Q.fromBase(M.fromCanonical(3)), Q.fromBase(M.fromCanonical(3)) };
    const evaluated = try a.alloc(Q, circuit.nodes.len);
    defer a.free(evaluated);
    try circuit.evaluateInto(&inputs, evaluated);
    var cells = [_][4]M{ .{ M.fromCanonical(3), M.zero(), M.zero(), M.zero() }, .{ M.fromCanonical(3), M.zero(), M.zero(), M.zero() } };
    // These are coordinate views only: no Source/Values.validate, Owner or
    // verified authority is constructed by this pure lowering parity fixture.
    var children: [2]Source.Source = undefined;
    children[0].cells = cells[0..1];
    children[1].cells = cells[1..2];
    const typed = Bus.Values{ .routes = undefined, .index = 0, .children = &children, .pins = &.{}, .outputs = &.{} };
    const sources = [_]Bus.Wire{
        .{ .circuit = 0, .wire = 0, .uses = 1, .kind = .child_cell, .child = 0, .coordinate = 0 },
        .{ .circuit = 0, .wire = 1, .uses = 1, .kind = .child_cell, .child = 1, .coordinate = 0 },
    };
    const graph = Kernel.Graph{ .circuit = &circuit, .inputs = &inputs, .values = evaluated, .sources = &sources };
    var original = try Kernel.materializeLocallyAdmitted(a, graph, typed);
    defer original.deinit();
    var generic = try Kernel.materializeLocallyAdmittedFor(a, graph, CoordinateView{ .typed = typed });
    defer generic.deinit();
    try std.testing.expectEqual(original.identity, generic.identity);
    try std.testing.expectEqual(original.wires.len, generic.wires.len);
    for (original.wires, generic.wires) |old, new| try std.testing.expect(std.meta.eql(old, new));
    try std.testing.expectEqual(original.rows.input_count, generic.rows.input_count);
    inline for (0..Storage.Airs.len) |i| {
        try std.testing.expectEqual(original.rows.main[i].len, generic.rows.main[i].len);
        for (original.rows.main[i], generic.rows.main[i]) |old, new| {
            try std.testing.expectEqual(old.log_size, new.log_size);
            try std.testing.expectEqualSlices(M, old.values, new.values);
            try std.testing.expect(old.coefficient_values == null and new.coefficient_values == null);
        }
        try std.testing.expectEqual(original.rows.fixed[i].len, generic.rows.fixed[i].len);
        for (original.rows.fixed[i], generic.rows.fixed[i]) |old, new| try std.testing.expect(std.meta.eql(old, new));
    }
    cells[0][0] = M.fromCanonical(4);
    try std.testing.expectError(error.UntrustedHeterogeneousGraphInput, Kernel.materializeLocallyAdmitted(a, graph, typed));
    try std.testing.expectError(error.UntrustedHeterogeneousGraphInput, Kernel.materializeLocallyAdmittedFor(a, graph, CoordinateView{ .typed = typed }));
    cells[0][0] = M.fromCanonical(3);
    evaluated[0] = evaluated[0].add(Q.one());
    try std.testing.expectError(error.MutatedHeterogeneousGraphEvaluation, Kernel.materializeLocallyAdmitted(a, graph, typed));
    try std.testing.expectError(error.MutatedHeterogeneousGraphEvaluation, Kernel.materializeLocallyAdmittedFor(a, graph, CoordinateView{ .typed = typed }));
}
