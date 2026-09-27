//! Nonproving equation/resource/transport ownership fixtures. No fake capture
//! or owner is constructed; actual source/publisher/receiver bodies are retained
//! separately by the root marker.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Kernel = @import("../recursion/air/block_v5_scoped_public_compensation_algebra_v1.zig");
const R = @import("../recursion/air/composition_graph_recorder.zig");
const Context = @import("../recursion/block_v5_heterogeneous_scoped_public_context_v1.zig");
fn q(value: u32) Q {
    return Q.fromBase(M.fromCanonical(value));
}
const Zero = struct {
    pub fn zero(_: *@This(), value: Q, failure: anyerror) !void {
        if (!value.isZero()) return failure;
    }
};
const Recorded = struct {
    builder: *R.Builder,
    pub fn zero(self: *@This(), value: R.Scalar, _: anyerror) !void {
        try self.builder.constrainZero(value);
    }
};
fn inputValues() [12]Q {
    return .{ q(7), q(7), q(11), q(11).neg(), q(13), q(17), q(17), q(19), q(19).neg(), q(23), q(36).neg(), q(6).neg() };
}
fn equations(comptime S: type, sink: anytype, inputs: [12]S) !void {
    const Algebra = Kernel.Algebra(S);
    try Algebra.window(sink, inputs[0], inputs[1], inputs[2], inputs[3]);
    try Algebra.window(sink, inputs[5], inputs[6], inputs[7], inputs[8]);
    try Algebra.terminal(sink, inputs[10], inputs[4].add(inputs[9]));
    try Algebra.accounting(sink, inputs[11], inputs[4].add(inputs[9]), inputs[3].add(inputs[8]));
}
fn symbolicAllocation(a: std.mem.Allocator) !void {
    var builder = R.Builder.init(a);
    defer builder.deinit();
    var symbols: [12]R.Scalar = undefined;
    for (&symbols) |*value| value.* = (try builder.input()).value;
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    var sink = Recorded{ .builder = &builder };
    try equations(R.Scalar, &sink, symbols);
    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();
    const output = try a.alloc(Q, circuit.nodes.len);
    defer a.free(output);
    var values = inputValues();
    try circuit.evaluateInto(&values, output);
    // Every original field is an independently routed lower-byte input.
    for (0..values.len) |index| {
        values = inputValues();
        values[index] = values[index].add(Q.one());
        try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateInto(&values, output));
    }
}
test "scoped public bridge: scalar and recorded original scoped joins match every field mutation with allocator fault cleanup" {
    var sink = Zero{};
    try equations(Q, &sink, inputValues());
    try symbolicAllocation(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, symbolicAllocation, .{});
}
test "scoped public bridge: register claims cannot cancel across windows even when total compensation closes" {
    var sink = Zero{};
    var inputs = inputValues();
    inputs[2] = inputs[2].add(Q.one());
    inputs[7] = inputs[7].sub(Q.one());
    try std.testing.expect(inputs[2].add(inputs[3]).add(inputs[7]).add(inputs[8]).isZero());
    try std.testing.expectError(error.UnclosedV5RegisterWindow, equations(Q, &sink, inputs));
}
test "scoped public bridge: native compensation is authenticated once and missing public terms have original signs" {
    var sink = Zero{};
    const Algebra = Kernel.Algebra(Q);
    try equations(Q, &sink, inputValues());
    try std.testing.expectError(error.UntrustedGlobalNativeCompensation, Algebra.window(&sink, q(7), q(8), q(11), q(11).neg()));
    // Native compensation is already counted in the lower known residual.
    try std.testing.expectError(error.UnclosedV5GlobalAccounting, Algebra.accounting(&sink, q(6).neg().add(q(7)), q(36), q(30).neg()));
    try std.testing.expectError(error.UnclosedV5GlobalAccounting, Algebra.accounting(&sink, q(6).neg(), q(36), q(30)));
    try std.testing.expectError(error.UnclosedProgramRelation, Algebra.terminal(&sink, q(36).neg(), q(36).neg()));
}
test "scoped public bridge: exact window outputs and carries reject empty excessive and overflowing geometry before allocation" {
    try std.testing.expectEqual(@as(usize, 3), try Context.outputCount(1, 4096));
    try std.testing.expectEqual(@as(usize, 465), try Context.outputCount(67, 4096));
    try std.testing.expectEqual(@as(usize, 28668), try Context.outputCount(4096, 4096));
    try std.testing.expectError(error.ScopedPublicBridgeResourceLimit, Context.outputCount(0, 4096));
    try std.testing.expectError(error.ScopedPublicBridgeResourceLimit, Context.outputCount(1, 0));
    try std.testing.expectError(error.ScopedPublicBridgeResourceLimit, Context.outputCount(4097, 4096));
    try std.testing.expectError(error.Overflow, Context.outputCount(std.math.maxInt(usize), std.math.maxInt(usize)));
}
test "scoped public bridge: new parent identity cannot relabel old compact key or trust changed public coordinate schedule" {
    const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
    const Protocol = @import("../recursion/block_v5_reusable_scoped_public_protocol_v1.zig");
    const Bus = @import("../recursion/block_v5_heterogeneous_scoped_public_bus_v1.zig");
    const base = Base.Key{ .profile = .diagnostic_q8_pow0, .config = Base.PCS_CONFIG, .context = .{ .child_key_id = @splat(1), .child_config = Base.PCS_CONFIG, .graph_ids = @splat(@splat(2)), .transcript_plan_id = @splat(3) }, .log_sizes = @splat(1), .preprocessed_root = @splat(4) };
    var wires = [_]Bus.Wire{.{ .circuit = 1, .wire = 0, .uses = 1, .kind = .child_cell, .child = 1, .coordinate = 7 }};
    const key = try Protocol.Key.fromGeometry(base, &wires);
    try std.testing.expect(!std.meta.eql(try base.identity(), try key.identity()));
    wires[0].coordinate += 1;
    const changed = try Protocol.Key.fromGeometry(base, &wires);
    try std.testing.expect(!std.meta.eql(try key.identity(), try changed.identity()));
    try std.testing.expect(!Context.Context.complete_block_authority);
    try std.testing.expect(!@import("../recursion/block_v5_heterogeneous_scoped_public_receiver_v1.zig").Fresh.complete_source_authority);
}
test "scoped public bridge: actual fresh receiver rejects zero and oversized bytes before touching source authority or allocating" {
    const Receiver = @import("../recursion/block_v5_heterogeneous_scoped_public_receiver_v1.zig");
    var policy: Receiver.Policy = undefined;
    policy.max_proof_bytes = 1;
    const no_allocation = std.testing.failing_allocator;
    try std.testing.expectError(error.ScopedPublicBridgeResourceLimit, Receiver.verify(no_allocation, policy, &.{}, &.{}, &.{}));
    try std.testing.expectError(error.ScopedPublicBridgeResourceLimit, Receiver.verify(no_allocation, policy, &.{}, &.{}, &.{ 1, 2 }));
    policy.max_proof_bytes = 0;
    try std.testing.expectError(error.ScopedPublicBridgeResourceLimit, Receiver.verify(no_allocation, policy, &.{}, &.{}, &.{1}));
}
fn artifactAllocation(backing: std.mem.Allocator) !void {
    const Stage = @import("block_v5_heterogeneous_scoped_public_stage_v1.zig");
    const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
    const owner = try Budget.create(backing, 1 << 20);
    var control_owned = true;
    defer if (control_owned) owner.destroy();
    const a = owner.allocator();
    _ = owner.retain();
    errdefer owner.destroy();
    const bytes = try a.dupe(u8, &.{ 1, 2, 3 });
    errdefer a.free(bytes);
    const wires = try a.dupe(@import("../recursion/block_v5_heterogeneous_scoped_public_bus_v1.zig").Wire, &.{});
    errdefer a.free(wires);
    // Artifact is a proposed durable byte allocation, never a Fresh receipt.
    var artifact = Stage.Artifact{ .allocator = a, .allocation_owner = owner, .bytes = bytes, .schedule = wires, .key = undefined, .expected_id = @splat(0), .plan = @splat(0), .public_input = @splat(0), .source_seal = @splat(0) };
    owner.destroy();
    control_owned = false;
    artifact.deinit();
}
test "scoped public bridge: transferred transport buffers retain allocator owner through delayed destruction and every fault path" {
    try artifactAllocation(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, artifactAllocation, .{});
}
