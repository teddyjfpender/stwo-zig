//! Complete source-derived truth catalog leaf, with original OODS authority and complete native PCS.
const std = @import("std");
const core = @import("stwo_core");
const V = @import("../rv64_recursion/om31_poseidon/mod.zig");
const C = V.common;
const Frame = @import("full_p2_frame.zig");
const Full = @import("pure_p2_truth_statement.zig");
const Native = @import("pure_p2_truth_worker.zig");
const Manifest = @import("pure_p2_manifest.zig");
const Protocol = @import("pure_p2_worker_protocol.zig");
pub const View = @import("pure_p2_truth_leaf.zig").View;
fn physicalRequested(truth: @import("../word16_global_execution/services/roster.zig").Truth) !bool {
    const value = std.posix.getenv("STWO_OP_P2_TRUTH_PHYSICAL") orelse return false;
    if (value.len == 0 or std.mem.eql(u8, value, "0")) return false;
    if (std.mem.eql(u8, value, "1")) return true;
    if (std.mem.eql(u8, value, "sha256")) return truth == .sha256;
    if (std.mem.eql(u8, value, "keccak")) return truth == .keccak;
    return error.InvalidOpTruthPhysicalGate;
}
const Hook = struct {
    pub fn run(a: std.mem.Allocator, key: *const Native.Key, truth: @import("../word16_global_execution/services/roster.zig").Truth, expected: Manifest.Expected, pending: *const Manifest.Pending, encoded: *const Native.Encoded, capture: anytype) !void {
        const Pool = @import("stwo_prover_engine").work_pool;
        var pool: Pool.WorkPool = .{};
        const needs_pool = Pool.currentScopedPool() == null;
        if (needs_pool) try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
        defer if (needs_pool) pool.deinit();
        var pool_binding: ?Pool.ScopedPoolBinding = if (needs_pool) try Pool.ScopedPoolBinding.init(&pool) else null;
        defer if (pool_binding) |*binding| binding.deinit();
        var proof = try Protocol.W.Wire.decodeProofBytesBinary(a, encoded.bytes);
        defer proof.deinit(a);
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const shape = try Full.geometry(arena.allocator(), key, truth);
        const values = try V.proof.fromNative(arena.allocator(), &proof, capture, &shape);
        const source = View{ .key = key, .truth = truth, .expected = expected, .manifest = pending.digest, .main = proof.commitment_scheme_proof.commitments.items[1], .claims = encoded.claims, .shape = &shape, .values = &values };
        var timer = try std.time.Timer.start();
        var owner = try source.build(a, false);
        var owns = true;
        defer if (owns) owner.deinit();
        const build_ns = timer.lap();
        const census = try std.json.Stringify.valueAlloc(a, .{ .scope = "actual_catalog_truth_PCS_FRI_OODS_globalIO_publicframe", .raw = try owner.rawCounts(), .cells = try owner.census(false), .permutations = owner.calls.items.len, .production_admission_open = false }, .{});
        defer a.free(census);
        std.debug.print("OP_PURE_P2_TRUTH_CIRCUIT {s}\n", .{census});
        if (!try physicalRequested(truth)) return;
        const Authority = @import("authority.zig").Authority;
        const Proof = @import("proof.zig");
        const output = try source.expectedOutput(a);
        var identity: [32]u8 = undefined;
        const bytes = blk: {
            var authority = try Authority.initForProfile(a, &owner, key.profile);
            defer authority.deinit();
            identity = authority.identity;
            break :blk try Proof.prove(a, &owner, &authority, &output);
        };
        defer a.free(bytes);
        owner.deinit();
        owns = false;
        const prove_ns = timer.lap();
        var receiver_source = try source.build(a, true);
        defer receiver_source.deinit();
        var receiver = try Authority.initForProfile(a, &receiver_source, key.profile);
        defer receiver.deinit();
        try std.testing.expectEqualSlices(u8, &identity, &receiver.identity);
        try Proof.verify(a, &receiver, &output, bytes);
        const receive_ns = timer.lap();
        var wrong = output;
        wrong[8] = wrong[8].add(C.Q.one());
        try std.testing.expect(std.meta.isError(Proof.verify(a, &receiver, &wrong, bytes)));
        const changed = try a.dupe(u8, bytes);
        defer a.free(changed);
        changed[40] ^= 1;
        try std.testing.expect(std.meta.isError(Proof.verify(a, &receiver, &output, changed)));
        std.debug.print("OP_PURE_P2_TRUTH_PHYSICAL bytes={} build_ns={} prove_ns={} fresh_receive_ns={} fragment_only=true\n", .{ bytes.len, build_ns, prove_ns, receive_ns });
    }
};

test "OP pure P2 complete catalog SHA truth circuit" {
    var sha = try @import("../word16_global_execution/sha256/roster.zig").TruthSetup.init(std.testing.allocator, 5);
    defer sha.deinit();
    try @import("pure_p2_truth_catalog_test.zig").runWithHook(.{ .sha256 = .{ .setup = &sha, .first_id = 1, .calls = 1 } }, Hook);
}
test "OP pure P2 complete catalog Keccak truth circuit" {
    var setup = try @import("../word16_global_execution/keccak/shared/roster.zig").TruthSetup.init(std.testing.allocator, 5);
    defer setup.deinit();
    try @import("pure_p2_truth_catalog_test.zig").runWithHook(.{ .keccak = .{ .setup = &setup, .first_id = 3, .calls = 2 } }, Hook);
}
test "OP pure P2 complete catalog arith256 truth circuit" {
    var setup = try @import("../word16_global_execution/arith256/roster.zig").TruthSetup.init(std.testing.allocator, 8);
    defer setup.deinit();
    try @import("pure_p2_truth_catalog_test.zig").runWithHook(.{ .arith256_mod = .{ .setup = &setup, .first_id = 1, .calls = 1 } }, Hook);
}
test "OP pure P2 complete catalog canonical curve truth circuits" {
    const A = @import("stwo_riscv_frontend").rv64_air;
    inline for (comptime std.enums.values(A.crypto.curves.Op)) |op| {
        var setup = try @import("../word16_global_execution/curves/roster.zig").TruthSetup.init(std.testing.allocator, op, 8);
        defer setup.deinit();
        try @import("pure_p2_truth_catalog_test.zig").runWithHook(.{ .curve = .{ .setup = &setup, .first_id = 1, .calls = 1 } }, Hook);
    }
}
test "OP pure P2 complete catalog secp row truth circuits" {
    const A = @import("stwo_riscv_frontend").rv64_air;
    inline for (.{ A.crypto.curves.spec.SecpKind.add, A.crypto.curves.spec.SecpKind.double }) |op| {
        var setup = try @import("../word16_global_execution/secp/row_roster.zig").TruthSetup.init(std.testing.allocator, op, 8);
        defer setup.deinit();
        try @import("pure_p2_truth_catalog_test.zig").runWithHook(.{ .secp_row = .{ .setup = &setup, .first_id = 1, .calls = 1 } }, Hook);
    }
}
test "OP pure P2 complete catalog classic secp truth circuits" {
    const A = @import("stwo_riscv_frontend").rv64_air;
    inline for (.{ A.crypto.secp256k1.program.Kind.add, A.crypto.secp256k1.program.Kind.double }) |op| {
        const S = A.crypto.secp256k1;
        const logs = [2]u32{ try S.layout.logSize(.product, S.program.get(op), 1), try S.layout.logSize(.linear, S.program.get(op), 1) };
        var setup = try @import("../word16_global_execution/secp/roster.zig").TruthSetup.init(std.testing.allocator, op, logs);
        defer setup.deinit();
        try @import("pure_p2_truth_catalog_test.zig").runWithHook(.{ .secp = .{ .setup = &setup, .first_id = 5, .calls = 1 } }, Hook);
    }
}
