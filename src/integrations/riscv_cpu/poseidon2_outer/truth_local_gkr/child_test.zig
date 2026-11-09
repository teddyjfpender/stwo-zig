const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const N = @import("native.zig");
const Child = @import("child.zig");
const A = @import("authority.zig");
const C = @import("../../rv64_recursion/om31_poseidon/common.zig");
const G = @import("../../logup_gkr/om31_circuit_verifier.zig");
const Frame = @import("../../word16_global_execution/services/gkr_local/truth_frame.zig");
const a = std.testing.allocator;
fn root(ctx: *C.Context, bytes: [36]u8) !C.Hash {
    var out: C.Hash = undefined;
    for (&out, try core.crypto.poseidon2_m31_sponge.decode(bytes)) |*wire, v| wire.* = try ctx.guess(C.Q.fromBase(v));
    return out;
}
fn digest(ctx: *C.Context, bytes: [32]u8) !@import("../full_p2_frame.zig").Digest {
    var out: @import("../full_p2_frame.zig").Digest = undefined;
    for (&out, 0..) |*wire, i| wire.* = try circuit.builder.wrappers.guessU32(C.Q, ctx, circuit.builder.wrappers.u32Value(C.Q, std.mem.readInt(u32, bytes[i * 4 ..][0..4], .little)));
    return out;
}
test "OP truth local GKR native and constrained transcript receipt eta parity" {
    const M = core.fields.m31.M31;
    const Provider = struct {
        pub fn emitRange(_: @This(), _: Frame.Instance, row: usize, first: usize, count: usize, sink: anytype) !void {
            for (first..first + count) |query| sink.emitBase(.byte, [1]M{M.fromCanonical(@intCast(row / 2 + query))}, if (row % 2 == 0) M.one() else M.one().neg());
        }
    };
    const shapes = [_]A.Shape{ .{ .original = .{ .kind = .product, .log_size = 5 } }, .{ .original = .{ .kind = .linear, .log_size = 5 } }, .{ .original = .{ .kind = .bytes, .log_size = 8 } } };
    const Hash = @import("../pure_p2_native.zig");
    const scope = N.Scope{ .statement = [_]u8{9} ** 32, .fixed = Hash.hashWords(&.{1}), .main = Hash.hashWords(&.{2}), .manifest = Hash.hashWords(&.{3}), .ordinal = 11 };
    var produced = try N.proveUnbound(a, scope, shapes, Provider{});
    defer produced.deinit(a);
    var native = try N.verifyPending(a, scope, shapes, &produced.result.proof, produced.digest);
    defer native.deinit(a);
    var owner = try C.PoseidonContext.init(a, 9);
    defer owner.deinit();
    C.begin(&owner);
    var active = true;
    defer if (active) C.finish() catch {};
    const ctx = owner.algebra();
    const wires = Child.Scope{ .statement = try digest(ctx, scope.statement), .fixed = try root(ctx, scope.fixed), .main = try root(ctx, scope.main), .manifest = try root(ctx, scope.manifest), .ordinal = try circuit.builder.wrappers.guessU32(C.Q, ctx, circuit.builder.wrappers.u32Value(C.Q, scope.ordinal)) };
    const proof = try G.wireProof(ctx, &produced.result.proof);
    var pending = try Child.verify(ctx, wires, shapes, &proof);
    defer pending.artifact.deinit(a);
    try std.testing.expect(pending.eta.value().eql(native.eta));
    for (pending.artifact.ood_point, native.artifact.ood_point) |actual, expected| try std.testing.expect(actual.value().eql(expected));
    for (pending.artifact.claims_to_verify_by_instance, native.artifact.claims_to_verify_by_instance) |actual, expected| for (actual, expected) |x, y| try std.testing.expect(x.value().eql(y));
    for (pending.receipt, try core.crypto.poseidon2_m31_sponge.decode(produced.digest)) |actual, expected| try std.testing.expect(ctx.get(actual).eql(C.Q.fromBase(expected)));
    try C.finish();
    active = false;
    try owner.setOutputs(&pending.receipt);
    try owner.finalize();
    try std.testing.expect(try owner.isCircuitValid());
    const v = pending.receipt[8];
    ctx.value_table.items[v.idx] = ctx.get(v).add(C.Q.one());
    try std.testing.expect(!try owner.isCircuitValid());
}
