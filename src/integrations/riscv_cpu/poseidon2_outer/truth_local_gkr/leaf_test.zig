//! Source-derived complete recursive proof of opt-in truth-local GKR+P2.
const std = @import("std");
const core = @import("stwo_core");
const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
const C = V.common;
const Full = @import("statement.zig");
const Native = @import("worker.zig");
const Local = @import("native.zig");
const Manifest = @import("../pure_p2_manifest.zig");
const R = @import("../../word16_global_execution/services/roster.zig");
const Protocol = @import("../pure_p2_worker_protocol.zig");
pub const View = @import("leaf.zig").View;

const Hook = struct {
    pub fn run(backing: std.mem.Allocator, key: *const Native.Key, truth: R.Truth, expected: Manifest.Expected, pending: *const Manifest.Pending, encoded: *const Native.Encoded, capture: anytype) !void {
        const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.createRetainingParent(backing, if (std.posix.getenv("STWO_OP_TRUTH_LOCAL_GKR_PHYSICAL") != null) 12 << 30 else 8 << 30);
        defer budget.destroy();
        const a = budget.allocator();
        var proof = try Protocol.W.Wire.decodeProofBytesBinary(a, encoded.bytes);
        defer proof.deinit(a);
        const shapes = try @import("authority.zig").shapes(truth);
        var local = try Local.decode(a, shapes, encoded.local);
        defer local.deinit();
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const shape = try Full.geometry(arena.allocator(), key, truth);
        const values = try V.proof.fromNative(arena.allocator(), &proof, capture, &shape);
        const view = View{ .key = key, .truth = truth, .expected = expected, .manifest = pending.digest, .main = proof.commitment_scheme_proof.commitments.items[1], .receipt = encoded.receipt, .claims = encoded.claims, .local = &local.proof, .shape = &shape, .values = &values };
        var owner = try view.build(a, false);
        defer owner.deinit();
        std.debug.print("OP_TRUTH_LOCAL_GKR_RECURSION kind={s} raw={any} cells={any} p2={d} native={d} gkr={d}\n", .{ @tagName(truth), try owner.rawCounts(), try owner.census(false), owner.calls.items.len, encoded.bytes.len, encoded.local.len });
        const requested = std.posix.getenv("STWO_OP_TRUTH_LOCAL_GKR_PHYSICAL") orelse return;
        if (!std.mem.eql(u8, requested, "1") and !std.mem.eql(u8, requested, @tagName(truth))) return;
        const Authority = @import("../authority.zig").Authority;
        const Proof = @import("../proof.zig");
        const output = try view.expectedOutput(a);
        var key_source = try view.build(a, true);
        defer key_source.deinit();
        var authority = try Authority.initForProfile(a, &key_source, key.base.profile);
        defer authority.deinit();
        const bytes = try Proof.prove(a, &owner, &authority, &output);
        defer a.free(bytes);
        try Proof.verify(a, &authority, &output, bytes);
        var wrong = output;
        wrong[8] = wrong[8].add(C.Q.one());
        try std.testing.expect(std.meta.isError(Proof.verify(a, &authority, &wrong, bytes)));
        std.debug.print("OP_TRUTH_LOCAL_GKR_PHYSICAL kind={s} bytes={d} fresh_source_key=true\n", .{ @tagName(truth), bytes.len });
    }
};
test "OP truth local GKR complete recursive Keccak and secp numerical authority" {
    const a = std.testing.allocator;
    var keccak = try @import("../../word16_global_execution/keccak/shared/roster.zig").TruthSetup.init(a, 5);
    defer keccak.deinit();
    try @import("worker_test.zig").runWithHook(.{ .keccak = .{ .setup = &keccak, .first_id = 3, .calls = 2 } }, Hook);
    const S = @import("stwo_riscv_frontend").rv64_air.crypto.secp256k1;
    const logs = [2]u32{ try S.layout.logSize(.product, S.program.get(.add), 1), try S.layout.logSize(.linear, S.program.get(.add), 1) };
    var secp = try @import("../../word16_global_execution/secp/roster.zig").TruthSetup.init(a, .add, logs);
    defer secp.deinit();
    try @import("worker_test.zig").runWithHook(.{ .secp = .{ .setup = &secp, .first_id = 5, .calls = 1 } }, Hook);
}
