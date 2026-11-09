const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const R = @import("../../word16_global_execution/services/roster.zig");
const T = @import("worker.zig");
const Base = @import("../pure_p2_truth_worker.zig");
const Manifest = @import("../pure_p2_manifest.zig");
const a = std.testing.allocator;
const marker: u8 = 0;
fn build(_: *const anyopaque, alloc: std.mem.Allocator, truth: R.Truth) !R.TruthSource {
    return switch (truth) {
        .keccak => |t| blk: {
            var input: [2]A.crypto.keccak.trace.State = undefined;
            for (&input, 0..) |*state, i| for (state, 0..) |*lane, j| {
                lane.* = @intCast(7919 * i + 31 * j);
            };
            break :blk .{ .keccak = try @FieldType(R.TruthSource, "keccak").initSpanPolicy(alloc, &input, t.first_id, t.setup.log, t.setup.policy) };
        },
        .secp => |t| blk: {
            const S = A.crypto.secp256k1;
            const input = [_]S.trace.Input{.{ .coordinates = .{ 1, 2, 3, 4, 5, 6 } }};
            var batch = try S.batch.Batch.initWithLogsForPolicy(alloc, S.program.get(t.setup.kind), &input, t.first_id, t.setup.logs[0], t.setup.logs[1], .canonical_inputs);
            errdefer batch.deinit();
            var counts: [256]u64 = undefined;
            for (&counts, batch.product.byte_counts, batch.linear.byte_counts) |*value, x, y| value.* = x + y;
            break :blk .{ .secp = .{ .batch = batch, .bytes = try A.range.provider.Trace.init(alloc, &counts) } };
        },
        else => error.UnsupportedLocalGkrTruth,
    };
}
fn run(truth: R.Truth) !void {
    return runWithHook(truth, void);
}
pub fn runWithHook(truth: R.Truth, comptime Hook: type) !void {
    const profile = @import("../op_profile.zig").Profile.op_target_b4_q72_p0_fold4_v1;
    var key = try T.Key.init(a, truth, profile);
    defer key.deinit();
    var fresh = try T.Key.init(a, truth, profile);
    defer fresh.deinit();
    const expected = try fresh.expected(truth, 0);
    try std.testing.expectEqualDeep(expected, try key.expected(truth, 0));
    const limits = T.Limits{ .live_bytes = 2 << 30, .main_bytes = 128 << 20, .interaction_bytes = 128 << 20, .gkr_bytes = 512 << 20 };
    const builder = Base.SourceBuilder{ .context = &marker, .build = build };
    var tiny = limits;
    tiny.live_bytes = 1;
    try std.testing.expectError(error.OutOfMemory, T.Worker.init(a, &key, truth, builder, expected, tiny));
    tiny = limits;
    tiny.interaction_bytes = 1;
    try std.testing.expectError(error.OpTruthLocalBudget, T.Worker.init(a, &key, truth, builder, expected, tiny));
    var worker = try T.Worker.init(a, &key, truth, builder, expected, limits);
    defer worker.deinit();
    const stage = try worker.seal();
    var entries = [_]Manifest.Entry{.{ .authority = expected, .scope = .{ .statement = expected.statement, .fixed = expected.fixed, .main = stage.main, .ordinal = 0 }, .local = null, .global_relations = expected.global_relations }};
    const digest = try Manifest.digest(@splat(0x93), &entries);
    const pending = Manifest.Pending{ .entries = &entries, .digest = digest, .shared = try Manifest.drawShared(digest) };
    var proof = try worker.complete(&pending, 0);
    defer proof.deinit(a);
    const wire = try T.encode(a, &proof);
    defer a.free(wire);
    var decoded = try T.decode(a, wire, 1 << 28);
    defer decoded.deinit(a);
    var capture: core.pcs.ForField(core.fields.om31.OM31).verifier.VerifiedProofCapture(@import("../pure_p2_worker_protocol.zig").W.H) = undefined;
    const claim = try T.verifyWithCapture(a, &fresh, truth, expected, &pending, 0, &decoded, &capture);
    defer capture.deinit(a);
    if (Hook != void) try Hook.run(a, &fresh, truth, expected, &pending, &decoded, &capture);
    try std.testing.expect(claim.ram.isZero());
    try std.testing.expectEqual(@as(usize, 0), worker.budget_owner.snapshot().live_bytes);
    try std.testing.expectError(error.OpTruthLocalEnvelope, T.decode(a, wire, wire.len - 1));
    var wrong = expected;
    wrong.ordinal += 1;
    try std.testing.expectError(error.GlobalGkrManifestOrdinal, T.verify(a, &fresh, truth, wrong, &pending, 0, &decoded));
    decoded.receipt[32] ^= 1;
    try std.testing.expect(std.meta.isError(T.verify(a, &fresh, truth, expected, &pending, 0, &decoded)));
    decoded.receipt[32] ^= 1;
    decoded.claims[0] = decoded.claims[0].add(core.fields.om31.OM31.one());
    try std.testing.expect(std.meta.isError(T.verify(a, &fresh, truth, expected, &pending, 0, &decoded)));
    const old_expected = try key.base.expected(truth, 0);
    try std.testing.expectError(error.OpTruthLocalExpected, T.verify(a, &fresh, truth, old_expected, &pending, 0, &decoded));
    std.debug.print("OP_TRUTH_LOCAL_GKR_WORKER kind={s} pcs={d} local={d} peak={d} fresh_fixed_receiver=true native_fragment_only=true\n", .{ @tagName(truth), proof.bytes.len, proof.local.len, worker.budget_owner.snapshot().peak_live_bytes });
}
test "OP truth local GKR sealed worker durable fresh receiver and legacy isolation" {
    var keccak = try @import("../../word16_global_execution/keccak/shared/roster.zig").TruthSetup.init(a, 5);
    defer keccak.deinit();
    try run(.{ .keccak = .{ .setup = &keccak, .first_id = 3, .calls = 2 } });
    const program = A.crypto.secp256k1.program.get(.add);
    const logs = [2]u32{ try A.crypto.secp256k1.layout.logSize(.product, program, 1), try A.crypto.secp256k1.layout.logSize(.linear, program, 1) };
    var secp = try @import("../../word16_global_execution/secp/roster.zig").TruthSetup.init(a, .add, logs);
    defer secp.deinit();
    try run(.{ .secp = .{ .setup = &secp, .first_id = 5, .calls = 1 } });
}
fn codecRoundtrip(alloc: std.mem.Allocator) !void {
    const value = T.Encoded{ .bytes = @constCast("PCS"), .local = @constCast("OPTLGKR1"), .receipt = @import("../pure_p2_native.zig").hashWords(&.{17}), .claims = .{ core.fields.om31.OM31.zero(), core.fields.om31.OM31.one() } };
    const bytes = try T.encode(alloc, &value);
    defer alloc.free(bytes);
    var decoded = try T.decode(alloc, bytes, 1 << 20);
    defer decoded.deinit(alloc);
    try std.testing.expectEqualSlices(u8, value.bytes, decoded.bytes);
    try std.testing.expectEqualSlices(u8, value.local, decoded.local);
    try std.testing.expectEqualDeep(value.claims, decoded.claims);
}
test "OP truth local GKR framing allocation failures and malformed sizes fail closed" {
    try std.testing.checkAllAllocationFailures(a, codecRoundtrip, .{});
    var bytes: [124]u8 = @splat(0);
    @memcpy(bytes[0..8], "OPTLPCS1");
    std.mem.writeInt(u64, bytes[8..16], std.math.maxInt(u64), .little);
    try std.testing.expectError(error.OpTruthLocalEnvelope, T.decode(std.testing.failing_allocator, &bytes, 1 << 20));
}
