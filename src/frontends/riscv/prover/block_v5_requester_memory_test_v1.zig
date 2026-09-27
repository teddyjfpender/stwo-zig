//! Nonproving original equation/protocol/security/resource fixtures. There are
//! no synthetic Fresh children and no complete-block authority assertions.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const R = @import("../recursion/air/composition_graph_recorder.zig");
const A = @import("../recursion/air/block_v5_requester_memory_algebra_v1.zig");
const Original = @import("block_v5_global_join_algebra_v1.zig");
const Public = @import("../recursion/block_v5_requester_memory_public_v1.zig");
const Protocol = @import("../recursion/block_v5_requester_memory_protocol_v1.zig");
const Sink = struct {
    builder: *R.Builder,
    pub fn zero(self: *@This(), value: R.Scalar, _: anyerror) !void {
        try self.builder.constrainZero(value);
    }
};
fn lift(bytes: [4][4]R.Scalar) R.Scalar {
    var limbs: [4]R.Scalar = undefined;
    for (&limbs, bytes) |*limb, word| {
        limb.* = R.Scalar.zero();
        for (word, 0..) |byte, part| limb.* = limb.add(byte.mul(R.Scalar.fromBase(M.fromCanonical(@as(u32, 1) << @as(u5, @intCast(8 * part))))));
    }
    return R.fromPartialEvals(limbs);
}
fn symbolic(a: std.mem.Allocator) !void {
    var builder = R.Builder.init(a);
    defer builder.deinit();
    const request = Q.fromU32Unchecked(3, 5, 7, 11);
    var inputs: [32]Q = undefined;
    var symbols: [2][4][4]R.Scalar = undefined;
    for (&symbols, [_]Q{ request, request.neg() }, 0..) |*field, value, which| {
        for (field, value.toM31Array(), 0..) |*word, limb, component| {
            for (word, 0..) |*symbol, part| {
                symbol.* = (try builder.input()).value;
                inputs[16 * which + 4 * component + part] = Q.fromBase(M.fromCanonical((limb.v >> @as(u5, @intCast(8 * part))) & 255));
            }
        }
    }
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    var sink = Sink{ .builder = &builder };
    try A.close(R.Scalar, &sink, lift(symbols[0]), lift(symbols[1]));
    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();
    const outputs = try a.alloc(Q, circuit.nodes.len);
    defer a.free(outputs);
    try circuit.evaluateInto(&inputs, outputs);
    for (0..inputs.len) |i| {
        inputs[i] = inputs[i].add(Q.one());
        if (circuit.evaluateInto(&inputs, outputs)) |_| return error.TestExpectedError else |err| if (err != error.UnsatisfiedCircuit) return err;
        inputs[i] = inputs[i].sub(Q.one());
    }
    try circuit.evaluateInto(&inputs, outputs);
}
test "requester memory join: original packed transition sign and byte-lifted symbolic equation reject every root limb mutation" {
    var sink = Original.ScalarSink{};
    const requests = Q.fromU32Unchecked(3, 5, 7, 11);
    try Original.Algebra(Q).transition(&sink, requests, requests.neg());
    try A.close(Q, &sink, requests, requests.neg());
    try std.testing.expectError(error.UnclosedV5PackedTransitionBus, A.close(Q, &sink, requests, requests));
    try std.testing.expectError(error.UnclosedV5PackedTransitionBus, A.close(Q, &sink, requests, Q.zero()));
    try A.close(Q, &sink, Q.zero(), Q.zero()); // typed absence's equation only.
    try symbolic(std.testing.allocator);
}
test "requester memory join: every genuine symbolic graph allocation failure releases all bounded owners" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, symbolic, .{});
}
test "requester memory join: actual parent receiver caps and fixed two-child policy reject before touching any child or allocating" {
    const Receiver = @import("../recursion/block_v5_requester_memory_receiver_v1.zig");
    var policy: Receiver.Policy = undefined;
    policy.max_proof_bytes = 1;
    try std.testing.expectError(error.WidePublicResourceLimit, Receiver.verify(std.testing.failing_allocator, policy, &.{}));
    try std.testing.expectError(error.WidePublicResourceLimit, Receiver.verify(std.testing.failing_allocator, policy, &.{ 1, 2 }));
    try std.testing.expectError(error.RequesterMemoryResourceLimit, Public.Owner.init(std.testing.failing_allocator, undefined, .{ .max_children = 1 }));
    try std.testing.expect(!Receiver.Fresh.complete_block_authority and !Public.Owner.complete_block_authority);
}
test "requester memory join: independent equal-security policy rejects query PoW FRI lifting and profile relabeling" {
    const Coverage = @import("block_v5_recursive_coverage_plan_v1.zig");
    const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
    const expected = Coverage.Security{ .base = Base.PCS_CONFIG, .recursive = Base.PCS_CONFIG };
    try expected.require(Base.PCS_CONFIG);
    var changed = Base.PCS_CONFIG;
    changed.pow_bits += 1;
    try std.testing.expectError(error.UntrustedV5CoverageSecurity, expected.require(changed));
    changed = Base.PCS_CONFIG;
    changed.fri_config.n_queries += 1;
    try std.testing.expectError(error.UntrustedV5CoverageSecurity, expected.require(changed));
    changed = Base.PCS_CONFIG;
    changed.fri_config.log_blowup_factor += 1;
    try std.testing.expectError(error.UntrustedV5CoverageSecurity, expected.require(changed));
    changed = Base.PCS_CONFIG;
    changed.lifting_log_size = 4;
    if (expected.require(changed)) |_| return error.TestExpectedError else |_| {}
}
test "requester memory join: final grammar rejects original VERSION20 key and every nonempty residual supplier schedule" {
    const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
    const Old = @import("../recursion/block_v5_source_ram_forest_join_protocol_v1.zig");
    const geometry = Base.Key{ .profile = .diagnostic_q8_pow0, .config = Base.PCS_CONFIG, .context = .{ .child_key_id = @splat(1), .child_config = Base.PCS_CONFIG, .graph_ids = @splat(@splat(2)), .transcript_plan_id = @splat(3) }, .log_sizes = @splat(1), .preprocessed_root = @splat(4) };
    const original = try Old.Key.fromGeometry(geometry, &.{});
    const final = try Protocol.Key.fromGeometry(geometry, &.{});
    try std.testing.expect(!std.meta.eql(try original.identity(), try final.identity()));
    const wire = [_]Public.Wire{.{ .circuit = 1, .wire = 0, .uses = 1, .kind = .child_term, .child = 0, .coordinate = 0 }};
    try std.testing.expectError(error.ClosedRequesterMemoryHasNoPublicTerms, Public.scheduleDigest(&wire));
    try std.testing.expectError(error.ClosedRequesterMemoryHasNoPublicTerms, Protocol.Key.fromGeometry(geometry, &wire));
}
