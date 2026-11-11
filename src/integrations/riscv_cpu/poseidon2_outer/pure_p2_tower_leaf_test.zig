//! Real Miller truth leaf, with original OODS authority and complete native PCS.
const std = @import("std");
const core = @import("stwo_core");
const V = @import("../rv64_recursion/om31_poseidon/mod.zig");
const C = V.common;
const Frame = @import("full_p2_frame.zig");
const Full = @import("pure_p2_tower_statement.zig");
const Native = @import("pure_p2_tower_worker.zig");
const Manifest = @import("pure_p2_manifest.zig");
const Protocol = @import("pure_p2_worker_protocol.zig");
pub const View = @import("pure_p2_tower_leaf.zig").View;
fn physicalRequested() !bool {
    const value = std.posix.getenv("STWO_OP_P2_TOWER_PHYSICAL") orelse return false;
    if (value.len == 0 or std.mem.eql(u8, value, "0")) return false;
    if (std.mem.eql(u8, value, "1")) return true;
    return error.InvalidOpTowerPhysicalGate;
}
const Hook = struct {
    pub fn run(a: std.mem.Allocator, key: *const Native.Key, span: Native.Span, expected: Manifest.Expected, pending: *const Manifest.Pending, encoded: *const Native.Encoded, capture: anytype) !void {
        var proof = try Protocol.W.Wire.decodeProofBytesBinary(a, encoded.bytes);
        defer proof.deinit(a);
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const shape = try Full.geometry(arena.allocator(), key);
        const values = try V.proof.fromNative(arena.allocator(), &proof, capture, &shape);
        const source = View{ .key = key, .span = span, .expected = expected, .manifest = pending.digest, .main = proof.commitment_scheme_proof.commitments.items[1], .claims = encoded.claims, .shape = &shape, .values = &values };
        var timer = try std.time.Timer.start();
        var owner = try source.build(a, false);
        var owns = true;
        defer if (owns) owner.deinit();
        const build_ns = timer.lap();
        const census = try std.json.Stringify.valueAlloc(a, .{ .scope = "actual_Miller_truth_PCS_FRI_OODS_localSSA_globalWire_publicframe", .raw = try owner.rawCounts(), .cells = try owner.census(false), .permutations = owner.calls.items.len, .production_admission_open = false }, .{});
        defer a.free(census);
        std.debug.print("OP_PURE_P2_TOWER_CIRCUIT {s}\n", .{census});
        {
            var production = try source.buildForProving(a);
            defer production.deinit();
            try std.testing.expectEqualDeep(try owner.rawCounts(), try production.rawCounts());
            try std.testing.expectEqualDeep(try owner.census(false), try production.census(false));
            try std.testing.expect(try production.isCircuitValid());
        }
        if (!try physicalRequested()) return;
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
        std.debug.print("OP_PURE_P2_TOWER_PHYSICAL bytes={} build_ns={} prove_ns={} fresh_receive_ns={} fragment_only=true\n", .{ bytes.len, build_ns, prove_ns, receive_ns });
    }
};
test "OP pure P2 complete Miller truth circuit binds original AIR and expected public frame" {
    try @import("../delegations/op_tower/pure_p2_worker_test.zig").exercise(Hook);
}
