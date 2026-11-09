//! Small physical opt-in qualification. No live Session/topology uses the cache.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const core = @import("stwo_core");
const Native = @import("worker.zig");
const Local = @import("native.zig");
const Cache = @import("outer_key_cache.zig").Cache;
const Full = @import("statement.zig");
const View = @import("leaf_test.zig").View;
const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
const Protocol = @import("../pure_p2_worker_protocol.zig");
const Manifest = @import("../pure_p2_manifest.zig");
const Template = @import("../pure_p2_gkr_template.zig");
const Proof = @import("../native_omul/proof.zig");
const Scope = @import("../native_omul/scope.zig");
const Leaf = @import("../native_omul/topology.zig").SourceLeaf;
const Hook = struct {
    pub fn run(a: std.mem.Allocator, key: *const Native.Key, span: Native.Span, expected: Manifest.Expected, pending: *const Manifest.Pending, encoded: *const Native.Encoded, capture: anytype) !void {
        var native = try Protocol.W.Wire.decodeProofBytesBinary(a, encoded.bytes);
        defer native.deinit(a);
        var local = try Local.decode(a, try key.geometry(span), encoded.local);
        defer local.deinit();
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const shape = try Full.geometry(arena.allocator(), key, span);
        const values = try V.proof.fromNative(arena.allocator(), &native, capture, &shape);
        const view = View{ .key = key, .span = span, .expected = expected, .manifest = pending.digest, .main = native.commitment_scheme_proof.commitments.items[1], .receipt = encoded.receipt, .claims = encoded.claims, .local = &local.proof, .shape = &shape, .values = &values };
        const instances = try (try key.geometry(span)).instances();
        const advice = try Template.fromProofFor(a, &instances, &local.proof);
        defer a.free(advice);
        var cache = try Cache.init(a, 8 << 30, 1);
        defer cache.deinit() catch unreachable;
        var lease = try cache.acquireForProving(key, span, expected.ordinal, advice);
        errdefer if (lease.live) lease.release() catch unreachable;
        try lease.requireView(view);
        // The cache built with canonical first_id1, while this actual native
        // proof uses first_id7. Equality is of source keys, not request outputs.
        try std.testing.expectEqual(@as(u32, 7), span.first_id);
        var independent = try Leaf.initLocalMiller(a, view);
        defer independent.deinit();
        try std.testing.expectEqualSlices(u8, &(try lease.key()).base.identity, &independent.authority.base.identity);
        try std.testing.expectEqualSlices(u8, &(try lease.key()).base.fixed_root, &independent.authority.base.fixed_root);
        var scope = Scope.begin();
        defer scope.deinit();
        var actual = try view.buildForProving(a);
        defer actual.deinit();
        const output = try view.expectedOutput(a);
        const bytes = try Proof.prove(a, &actual, try lease.proverKey(), &output);
        defer a.free(bytes);
        const control = try Proof.prove(a, &actual, &independent.authority, &output);
        defer a.free(control);
        try std.testing.expectEqualSlices(u8, bytes, control);
        var wrong_view = view;
        wrong_view.span.first_id += 1;
        wrong_view.expected = try key.expected(wrong_view.span, expected.ordinal);
        try std.testing.expectError(error.MillerOuterCacheRequestMismatch, lease.requireView(wrong_view));
        try lease.release();
        try cache.finishProving();
        // Fresh native source key and cache; no producer outer key is imported.
        var fresh_native = try Native.Key.init(a, key.base.profile, key.base.frontier_log, key.base.arithmetic_log);
        defer fresh_native.deinit();
        var receiver = try Cache.initForVerification(a, 8 << 30, 1);
        defer receiver.deinit() catch unreachable;
        var fresh = try receiver.acquireForVerification(&fresh_native, span, expected.ordinal, advice);
        defer fresh.release() catch unreachable;
        try fresh.requireView(view);
        try Proof.verify(a, try fresh.key(), &output, bytes);
        var wrong_output = output;
        wrong_output[8] = wrong_output[8].add(V.common.Q.one());
        try std.testing.expect(std.meta.isError(Proof.verify(a, try fresh.key(), &wrong_output, bytes)));
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &hash, .{});
        std.debug.print("OP_MILLER_OUTER_CACHE_PHYSICAL bytes={} sha256={s} canonical_span=1 actual_first=7 exact_control_bytes=true fresh_receiver=true execution_accepted=false\n", .{ bytes.len, std.fmt.bytesToHex(hash, .lower) });
    }
};
test "Miller outer cache physical source-key reuse preserves exact proof bytes and fresh authority" {
    const budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(std.testing.allocator, 8 << 30);
    defer budget.destroy();
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    try Native.runWithHook(budget.allocator(), Hook);
}
