//! Standalone physical fragments, not a complete execution inventory receiver.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const R = @import("../word16_global_execution/services/roster.zig");
const T = @import("pure_p2_truth_worker.zig");
const Manifest = @import("pure_p2_manifest.zig");
const Protocol = @import("pure_p2_worker_protocol.zig");
const O = Protocol.W.O;
const a = std.testing.allocator;
const marker: u8 = 0;
fn build(_: *const anyopaque, alloc: std.mem.Allocator, truth: R.Truth) !R.TruthSource {
    return switch (truth) {
        .sha256 => |t| block: {
            var source = try A.crypto.sha256.trace.Source.init(alloc, &.{A.crypto.sha256.native.PADDING}, t.first_id, t.setup.log);
            alloc.free(source.fixed);
            source.fixed = t.setup.fixed;
            source.owns_fixed = false;
            break :block .{ .sha256 = .{ .source = source } };
        },
        .arith256_mod => |t| block: {
            var source = try A.crypto.arith256.trace.Source.init(alloc, &.{.{ .a = 2, .b = 3, .c = 1, .m = 97, .r_before = 0 }}, t.first_id, t.setup.log);
            alloc.free(source.fixed);
            source.fixed = t.setup.fixed;
            source.owns_fixed = false;
            break :block .{ .arith256_mod = .{ .source = source } };
        },
        .curve => |t| switch (t.setup.op) {
            inline else => |op| block: {
                const Native = A.crypto.curves.Native(op);
                const words = @import("../word16_global_execution/services/curves_fixture.zig").initialWords(op);
                var packet: Native.Packet = undefined;
                for (&packet, 0..) |*value, i| value.* = @truncate(words[i / 8] >> @intCast(8 * (i % 8)));
                var source = try A.crypto.curves.Trace(op).Source.init(alloc, &.{packet}, t.first_id, t.setup.log);
                alloc.free(source.fixed);
                source.fixed = t.setup.fixed;
                source.owns_fixed = false;
                break :block .{ .curve = @unionInit(@FieldType(R.TruthSource, "curve"), @tagName(op), source) };
            },
        },
        .secp_row => |t| switch (t.setup.kind) {
            inline else => |op| block: {
                const Native = A.crypto.curves.Native(op);
                const values = [_]u256{ 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8, 1, 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8, 1 };
                var packet: Native.Packet = undefined;
                for (&packet, 0..) |*value, i| value.* = @truncate(values[i / 32] >> @intCast(8 * (i % 32)));
                var source = try A.crypto.curves.Trace(op).Source.init(alloc, &.{packet}, t.first_id, t.setup.log);
                alloc.free(source.fixed);
                source.fixed = t.setup.fixed;
                source.owns_fixed = false;
                break :block .{ .secp_row = @unionInit(@FieldType(R.TruthSource, "secp_row"), @tagName(op), source) };
            },
        },
        .keccak => |t| block: {
            var input: [2]A.crypto.keccak.trace.State = undefined;
            for (&input, 0..) |*state, i| for (state, 0..) |*lane, j| {
                lane.* = @as(u64, @intCast(7919 * i + 31 * j));
            };
            break :block .{ .keccak = try @FieldType(R.TruthSource, "keccak").initSpanPolicy(alloc, &input, t.first_id, t.setup.log, t.setup.policy) };
        },
        .secp => |t| block: {
            const S = A.crypto.secp256k1;
            const input = [_]S.trace.Input{.{ .coordinates = .{ 1, 2, 3, 4, 5, 6 } }};
            const program = S.program.get(t.setup.kind);
            var batch = try S.batch.Batch.initWithLogsForPolicy(alloc, program, &input, t.first_id, t.setup.logs[0], t.setup.logs[1], .canonical_inputs);
            errdefer batch.deinit();
            var counts: [256]u64 = undefined;
            for (&counts, batch.product.byte_counts, batch.linear.byte_counts) |*value, x, y| value.* = x + y;
            break :block .{ .secp = .{ .batch = batch, .bytes = try A.range.provider.Trace.init(alloc, &counts) } };
        },
    };
}
fn run(truth: R.Truth) !void {
    return runWithHook(truth, void);
}
pub fn runWithHook(truth: R.Truth, comptime Hook: type) !void {
    const profile = Protocol.Profile.op_target_b4_q72_p0_fold4_v1;
    var key = try T.Key.init(a, truth, profile);
    defer key.deinit();
    var receiver_key = try T.Key.init(a, truth, profile);
    defer receiver_key.deinit();
    const expected = try key.expected(truth, 0);
    const fresh_expected = try receiver_key.expected(truth, 0);
    try std.testing.expectEqualDeep(expected, fresh_expected);
    const limits = T.Limits{ .live_bytes = 1 << 30, .main_bytes = 128 << 20, .interaction_bytes = 512 << 20, .advice_bytes = 128 << 20 };
    const builder = T.SourceBuilder{ .context = &marker, .build = build };
    var too_small = limits;
    too_small.live_bytes = 1;
    try std.testing.expectError(error.OutOfMemory, T.Worker.init(a, &key, truth, builder, expected, too_small));
    too_small = limits;
    too_small.main_bytes = 0;
    try std.testing.expectError(error.OpTruthBudget, T.Worker.init(a, &key, truth, builder, expected, too_small));
    var worker = try T.Worker.init(a, &key, truth, builder, expected, limits);
    defer worker.deinit();
    const stage = try worker.seal();
    // A fragment has no CPU roster. Its synthetic pending challenge is used
    // only here; complete inventory acceptance must use verifyAndSeal.
    var entries = [_]Manifest.Entry{.{ .authority = fresh_expected, .scope = .{ .statement = fresh_expected.statement, .fixed = fresh_expected.fixed, .main = stage.main, .ordinal = 0 }, .local = null, .global_relations = fresh_expected.global_relations }};
    const digest = try Manifest.digest(@splat(0x52), &entries);
    const pending = Manifest.Pending{ .entries = &entries, .digest = digest, .shared = try Manifest.drawShared(digest) };
    var proof = try worker.complete(&pending, 0);
    defer proof.deinit(a);
    // The new pending-fragment scope shares the exact old producer body.
    // Independent source construction must preserve every proof and claim byte.
    var scoped_worker = try T.Worker.init(a, &key, truth, builder, expected, limits);
    defer scoped_worker.deinit();
    const scoped_stage = try scoped_worker.seal();
    try std.testing.expectEqualSlices(u8, &stage.main, &scoped_stage.main);
    var scoped_proof = try scoped_worker.completeSealed(.{ .manifest = digest, .main = scoped_stage.main });
    defer scoped_proof.deinit(a);
    try std.testing.expectEqualSlices(u8, proof.bytes, scoped_proof.bytes);
    try std.testing.expectEqualSlices(O, proof.claims, scoped_proof.claims);
    _ = try T.verifySealed(a, &receiver_key, truth, fresh_expected, .{ .manifest = digest, .main = stage.main }, &scoped_proof);
    const bytes = try T.encode(a, &proof);
    defer a.free(bytes);
    var received = try T.decode(a, bytes, 1 << 28);
    defer received.deinit(a);
    try std.testing.expectEqual(@as(usize, 0), worker.budget_owner.snapshot().live_bytes);
    var capture: core.pcs.ForField(O).verifier.VerifiedProofCapture(Protocol.W.H) = undefined;
    const claim = try T.verifyWithCapture(a, &receiver_key, truth, fresh_expected, &pending, 0, &received, &capture);
    defer capture.deinit(a);
    if (Hook != void) try Hook.run(a, &receiver_key, truth, fresh_expected, &pending, &received, &capture);
    try std.testing.expect(claim.ram.isZero());
    if (truth == .keccak) try std.testing.expect(claim.wire.isZero()) else try std.testing.expect(claim.kio.isZero());
    try std.testing.expectError(error.OpTruthEnvelope, T.decode(a, bytes, bytes.len - 1));
    var wrong = truth;
    switch (wrong) {
        inline else => |*value| value.first_id += 1,
    }
    try std.testing.expectError(error.OpTruthExpected, T.verify(a, &receiver_key, wrong, fresh_expected, &pending, 0, &received));
    const last: usize = if (truth == .keccak or truth == .secp) 3 else 0;
    received.claims[last] = received.claims[last].add(O.one());
    try std.testing.expect(std.meta.isError(T.verify(a, &receiver_key, truth, fresh_expected, &pending, 0, &received)));
    std.debug.print("OP_P2_TRUTH_CATALOG family={s} source={s} profile={s} proof_bytes={} peak_worker_bytes={} fresh_fixed_receiver=true local_closed=true inventory_accepted=false\n", .{ @tagName(truth.family()), @tagName(truth), @tagName(profile), proof.bytes.len, worker.budget_owner.snapshot().peak_live_bytes });
}
test "OP catalog pure P2 SHA and arith256 physical fragments" {
    var sha = try @import("../word16_global_execution/sha256/roster.zig").TruthSetup.init(a, 5);
    defer sha.deinit();
    try run(.{ .sha256 = .{ .setup = &sha, .first_id = 1, .calls = 1 } });
    var arith = try @import("../word16_global_execution/arith256/roster.zig").TruthSetup.init(a, 8);
    defer arith.deinit();
    try run(.{ .arith256_mod = .{ .setup = &arith, .first_id = 1, .calls = 1 } });
}
test "OP catalog pure P2 all canonical curve physical fragments" {
    inline for (comptime std.enums.values(A.crypto.curves.Op)) |op| {
        var setup = try @import("../word16_global_execution/curves/roster.zig").TruthSetup.init(a, op, 8);
        defer setup.deinit();
        try run(.{ .curve = .{ .setup = &setup, .first_id = 1, .calls = 1 } });
    }
}
test "OP catalog pure P2 secp row ADD DOUBLE physical fragments" {
    inline for (.{ A.crypto.curves.spec.SecpKind.add, A.crypto.curves.spec.SecpKind.double }) |op| {
        var setup = try @import("../word16_global_execution/secp/row_roster.zig").TruthSetup.init(a, op, 8);
        defer setup.deinit();
        try run(.{ .secp_row = .{ .setup = &setup, .first_id = 1, .calls = 1 } });
    }
}
test "OP catalog pure P2 Keccak and classic secp physical fragments" {
    var keccak = try @import("../word16_global_execution/keccak/shared/roster.zig").TruthSetup.init(a, 5);
    defer keccak.deinit();
    try run(.{ .keccak = .{ .setup = &keccak, .first_id = 3, .calls = 2 } });
    const S = A.crypto.secp256k1;
    const logs = [2]u32{ try S.layout.logSize(.product, S.program.get(.add), 1), try S.layout.logSize(.linear, S.program.get(.add), 1) };
    var secp = try @import("../word16_global_execution/secp/roster.zig").TruthSetup.init(a, .add, logs);
    defer secp.deinit();
    try run(.{ .secp = .{ .setup = &secp, .first_id = 5, .calls = 1 } });
}
