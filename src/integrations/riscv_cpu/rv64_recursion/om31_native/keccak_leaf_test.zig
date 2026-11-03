const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const V = @import("mod.zig");
const L = @import("keccak_leaf.zig");
const R = @import("../../word16_global_execution/services/roster.zig");
const W = @import("../../word16_global_execution/services/gkr_local/worker_protocol.zig");
const Worker = @import("../../word16_global_execution/services/gkr_local/truth_worker.zig");
const M = @import("../../word16_global_execution/services/gkr_local/manifest.zig");
const Setup = @import("../../word16_global_execution/keccak/shared/roster.zig").TruthSetup;
const Key = @import("../../word16_global_execution/keccak/shared/key.zig").Key;
const C = V.common;
const a = std.testing.allocator;
fn exercise(policy: A.crypto.keccak.equations.BatchPolicy) !void {
    var setup = try Setup.initPolicy(a, 5, Key.Suite.production(), policy);
    defer setup.deinit();
    const truth = R.Truth{ .keccak = .{ .setup = &setup, .first_id = 3, .calls = 2 } };
    var input: [2]A.crypto.keccak.trace.State = undefined;
    for (&input, 0..) |*state, i| for (state, 0..) |*lane, j| {
        lane.* = @intCast(7919 * i + 31 * j);
    };
    const Source = @FieldType(R.TruthSource, "keccak");
    const source = R.TruthSource{ .keccak = try Source.initSpanPolicy(a, &input, 3, 5, policy) };
    var cfg = W.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 2) };
    cfg.fri_config.fold_step = 4;
    const expected = M.ExpectedWorker{ .kind = .keccak, .ordinal = 0, .statement = try Worker.truthStatement(truth, cfg, @splat(17)), .fixed = truth.key().root, .global_relations = .{ .ram = false, .kio = true, .wire = false }, .mass = try Worker.truthMass(truth), .local_instances = null };
    var worker = try Worker.TruthWorker.init(a, truth, source, expected, cfg, 1 << 30);
    defer worker.deinit(a);
    const stage = try worker.seal(a);
    var entries = [_]M.Entry{.{ .kind = .keccak, .global_relations = expected.global_relations, .mass = expected.mass, .scope = .{ .statement = expected.statement, .fixed = expected.fixed, .main = stage.main, .ordinal = 0 }, .local = null }};
    const digest: [32]u8 = @splat(29);
    const pending = M.PendingManifest{ .entries = &entries, .digest = digest, .shared = M.drawShared(digest) };
    var encoded = try worker.complete(a, &pending, 0, 1 << 30);
    defer encoded.deinit(a);
    var captured: V.proof.NativeCapture = undefined;
    var native = try L.capture(a, truth, expected, &pending, cfg, &encoded, null, &captured);
    defer native.deinit(a);
    defer captured.deinit(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const geometry = try L.shape(arena.allocator(), truth, cfg);
    const values = try V.proof.fromNative(arena.allocator(), &native, &captured, &geometry);
    const public = L.Public{ .ordinal = 0, .statement = expected.statement, .manifest = digest, .claims = encoded.claims[0..5].* };
    var ctx = try C.Context.init(a, 0);
    defer ctx.deinit();
    C.lane.begin(&ctx);
    var active = true;
    defer if (active) C.lane.finish() catch {};
    const leaf = try L.build(&ctx, truth, cfg, null, public, &values);
    for (leaf.verified.fri_input, captured.deep_answers) |wire, value| try std.testing.expect(wire.value().eql(value));
    const words = L.statementWords(truth, public, stage.main);
    const claims = try L.checkStatement(&words, truth, expected, digest, stage.main);
    try std.testing.expect(claims.ram.isZero() and claims.wire.isZero() and claims.kio.eql(public.claims[3]));
    var h = std.crypto.hash.blake2.Blake2s256.init(.{});
    var word: [4]u8 = undefined;
    for (words) |value| {
        std.mem.writeInt(u32, &word, value, .little);
        h.update(&word);
    }
    var output: [32]u8 = undefined;
    h.final(&output);
    try V.frame.requireDigest(&ctx, leaf.output, output);
    try C.lane.finish();
    active = false;
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}
test "OM31 V3 classic Keccak compact truth leaf covers mixed heights five masks periodic samples" {
    try exercise(.triple_v2);
}
test "OM31 V3 classic Keccak R27 throughput truth leaf accepts production policy geometry" {
    try exercise(.throughput_r27_v1);
}
