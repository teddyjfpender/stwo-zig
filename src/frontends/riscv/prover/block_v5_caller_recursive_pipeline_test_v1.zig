//! Transport/order and independent admission only. No fixture accepts a fake
//! proof/capture, invokes PCS/STARKs, runs a guest, or invokes recursive proving.
const std = @import("std");
const Pipeline = @import("block_v5_caller_recursive_pipeline_v1.zig");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Session = Pipeline.ForBackend(Cpu).Session;
const Fixture = @import("tests/block_v5_caller_capture_unit_test.zig").Fixture;
const Family = @import("block_v5_precompile_family_proof_v1.zig");
const Fused = @import("block_v5_caller_fused_proof_v1.zig");
const Arithmetic = @import("block_v5_caller_arithmetic_recursive_stage_v1.zig");
const Projection = @import("block_v5_caller_fused_recursive_stage_v1.zig");

// Deliberately noncryptographic owned transport exercises the same guard as
// actual B5CF custody, without inventing a verified proof or receipt.
const Payload = struct {
    a: std.mem.Allocator,
    bytes: []u8,
    pub fn init(a: std.mem.Allocator) !Payload {
        return .{ .a = a, .bytes = try a.dupe(u8, "original-owned-transport") };
    }
    pub fn deinit(self: *Payload, a: std.mem.Allocator) void {
        std.debug.assert(std.meta.eql(a, self.a));
        a.free(self.bytes);
        self.* = undefined;
    }
};
const Guard = Pipeline.Pending(Payload);
const Consumer = struct {
    guard: *Guard,
    calls: usize = 0,
    fail: bool = false,
    fn put(raw: *anyopaque, index: u32, payload: *Payload) !void {
        const self: *Consumer = @ptrCast(@alignCast(raw));
        try std.testing.expectEqual(self.guard.index, index);
        // A reentrant callback cannot publish the same owner twice or forward
        // the arithmetic base before the fused transfer actually succeeds.
        try std.testing.expectError(error.InvalidRecursiveCallerPublicationOrder, self.guard.forward(raw, put));
        try std.testing.expectError(error.InvalidRecursiveCallerPublicationOrder, self.guard.beginCaller(index));
        self.calls += 1;
        if (self.fail) return error.InjectedCallerSinkFailure;
        payload.deinit(payload.a);
    }
};
test "caller recursive pipeline: exact index bounded ownership duplicates missing and reentrant callbacks" {
    const a = std.testing.allocator;
    var pending = Guard{ .index = 7 };
    defer pending.deinit(a);
    var payload = try Payload.init(a);
    var owns = true;
    defer if (owns) payload.deinit(a);
    const original = payload.bytes.ptr;
    try std.testing.expectError(error.UnexpectedRecursiveCallerFusedProof, pending.take(6, &payload));
    try std.testing.expect(payload.bytes.ptr == original);
    try std.testing.expectError(error.IncompleteRecursiveCallerPublication, pending.requireFinished());
    try std.testing.expectError(error.MissingRecursiveCallerFusedProof, pending.begin(7));
    try pending.take(7, &payload);
    owns = false;
    var second = try Payload.init(a);
    defer second.deinit(a);
    try std.testing.expectError(error.UnexpectedRecursiveCallerFusedProof, pending.take(7, &second));
    try std.testing.expectError(error.MissingRecursiveCallerFusedProof, pending.begin(8));
    try std.testing.expect((try pending.begin(7)).bytes.ptr == original);
    try std.testing.expectError(error.MissingRecursiveCallerFusedProof, pending.begin(7));
    var consumer = Consumer{ .guard = &pending };
    try std.testing.expectError(error.InvalidRecursiveCallerPublicationOrder, pending.forward(&consumer, Consumer.put));
    try pending.childrenPublished();
    try pending.forward(&consumer, Consumer.put);
    try std.testing.expectEqual(@as(usize, 1), consumer.calls);
    try std.testing.expectError(error.InvalidRecursiveCallerPublicationOrder, pending.forward(&consumer, Consumer.put));
    try std.testing.expectError(error.IncompleteRecursiveCallerPublication, pending.requireFinished());
    try std.testing.expectError(error.InvalidRecursiveCallerPublicationOrder, pending.beginCaller(8));
    try pending.beginCaller(7);
    try std.testing.expectError(error.InvalidRecursiveCallerPublicationOrder, pending.beginCaller(7));
    try pending.callerPublished(7);
    try pending.requireFinished();
    try std.testing.expectError(error.InvalidRecursiveCallerPublicationOrder, pending.callerPublished(7));
}
test "caller recursive pipeline: sink failure retains exactly the original owner for teardown" {
    const a = std.testing.allocator;
    var pending = Guard{ .index = 2 };
    defer pending.deinit(a);
    var payload = try Payload.init(a);
    const original = payload.bytes.ptr;
    try pending.take(2, &payload);
    _ = try pending.begin(2);
    try pending.childrenPublished();
    var consumer = Consumer{ .guard = &pending, .fail = true };
    try std.testing.expectError(error.InjectedCallerSinkFailure, pending.forward(&consumer, Consumer.put));
    try std.testing.expect(pending.value.?.bytes.ptr == original);
    try std.testing.expectError(error.IncompleteRecursiveCallerPublication, pending.requireFinished());
    try std.testing.expectError(error.InvalidRecursiveCallerPublicationOrder, pending.beginCaller(2));
}
fn baseCaller(_: *anyopaque, _: u32, _: *Family.Proof) !void {
    return error.UnexpectedProofInvocation;
}
fn baseFused(_: *anyopaque, _: u32, _: *Fused.Proof) !void {
    return error.UnexpectedProofInvocation;
}
fn arithmeticSink(_: *anyopaque, _: u32, _: *Arithmetic.Artifact) !void {
    return error.UnexpectedProofInvocation;
}
fn fusedSink(_: *anyopaque, _: u32, _: *Projection.Artifact) !void {
    return error.UnexpectedProofInvocation;
}
fn sessionCase(a: std.mem.Allocator, fixture: *const Fixture) !void {
    var context: u8 = 0;
    var session = try Session.init(a, 0, fixture.pin(), fixture.sealed, fixture.pins, &fixture.entries, .{ .context = &context, .put_caller = baseCaller, .put_fused = baseFused }, .{ .arithmetic = .{ .context = &context, .put_caller_arithmetic = arithmeticSink }, .fused = .{ .context = &context, .put_caller_fused = fusedSink } }, .{ .arithmetic = .{ .profile = .diagnostic_q8_pow0 }, .fused = .{ .profile = .diagnostic_q8_pow0 } });
    defer session.deinit();
    try std.testing.expectEqualDeep(session.arithmetic.binding, session.fused.binding);
    try std.testing.expectError(error.IncompleteRecursiveCallerPublication, session.requireFinished());
    const sink = session.sink();
    // This invalid pointer is never dereferenced: exact lifetime/order must
    // reject missing companion before a base callback can see any payload.
    var unavailable: Family.Proof = undefined;
    try std.testing.expectError(error.InvalidRecursiveCallerPublicationOrder, sink.put_caller(sink.context, 0, &unavailable));
}
test "caller recursive pipeline: independent original admission and all allocation failures release both policies" {
    const a = std.testing.allocator;
    const fixture = try Fixture.initWithKeccak(a, 1);
    try sessionCase(a, &fixture);
    try std.testing.checkAllAllocationFailures(a, sessionCase, .{&fixture});
}
test "caller recursive pipeline: altered original caller root fails before either proof family runs" {
    const a = std.testing.allocator;
    const fixture = try Fixture.init(a);
    var pin = fixture.pin();
    pin.roots[1][0] ^= 1;
    var context: u8 = 0;
    try std.testing.expectError(error.UntrustedV5CallerCompositePin, Session.init(a, 0, pin, fixture.sealed, fixture.pins, &fixture.entries, .{ .context = &context, .put_caller = baseCaller, .put_fused = baseFused }, .{ .arithmetic = .{ .context = &context, .put_caller_arithmetic = arithmeticSink }, .fused = .{ .context = &context, .put_caller_fused = fusedSink } }, .{ .arithmetic = .{ .profile = .diagnostic_q8_pow0 }, .fused = .{ .profile = .diagnostic_q8_pow0 } }));
}
