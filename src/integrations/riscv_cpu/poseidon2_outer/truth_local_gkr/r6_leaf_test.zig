//! Explicit composition of the two opt-in width changes. The R5 constructor,
//! authority identity and retained artifacts remain unchanged.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const C = @import("../../rv64_recursion/om31_poseidon/common.zig");
const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
const R = @import("../../word16_global_execution/services/roster.zig");
const Manifest = @import("../pure_p2_manifest.zig");
const W = @import("../pure_p2_worker_protocol.zig").W;
const N = @import("native.zig");
const Native = @import("worker.zig");
const View = @import("leaf_test.zig").View;
const Full = @import("statement.zig");
const Scope = @import("../native_omul/scope.zig");
const Key = @import("../native_omul/authority.zig").Key;
const Proof = @import("../native_omul/proof.zig");
fn build(view: View, a: std.mem.Allocator, trace_only: bool) !C.PoseidonContext {
    var scope = Scope.begin();
    defer scope.deinit();
    return view.build(a, trace_only);
}
const Hook = struct {
    pub fn run(backing: std.mem.Allocator, key: *const Native.Key, truth: R.Truth, expected: Manifest.Expected, pending: *const Manifest.Pending, encoded: *const Native.Encoded, capture: anytype) !void {
        const owner_budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(backing, 8 << 30);
        defer owner_budget.destroy();
        const a = owner_budget.allocator();
        var proof = try W.Wire.decodeProofBytesBinary(a, encoded.bytes);
        defer proof.deinit(a);
        var local = try N.decode(a, try @import("authority.zig").shapes(truth), encoded.local);
        defer local.deinit();
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const shape = try Full.geometry(arena.allocator(), key, truth);
        const values = try V.proof.fromNative(arena.allocator(), &proof, capture, &shape);
        const view = View{ .key = key, .truth = truth, .expected = expected, .manifest = pending.digest, .main = proof.commitment_scheme_proof.commitments.items[1], .receipt = encoded.receipt, .claims = encoded.claims, .local = &local.proof, .shape = &shape, .values = &values };
        var owner = try build(view, a, false);
        defer owner.deinit();
        const raw = try owner.rawCounts();
        var rows: [6]usize = undefined;
        var cells: u64 = 0;
        for (raw, @import("../layout.zig").FACTS, 0..) |count, fact, i| {
            rows[i] = try std.math.ceilPowerOfTwo(usize, @max(if (i == 4) @as(usize, 65536) else 16, @as(usize, @intCast(count))));
            cells += rows[i] * (fact.fixed + fact.main + fact.classic_interaction);
        }
        const Row = @import("../native_omul/row.zig");
        rows[5] = try std.math.ceilPowerOfTwo(usize, @max(16, owner.native_mul_calls.items.len));
        cells += rows[5] * (Row.FIXED + Row.MAIN + Row.INTER);
        std.debug.print("OP_TRUTH_LOCAL_GKR_R6 kind={s} raw={any} native_omul={d} padded={any} cells={d}\n", .{ @tagName(truth), raw, owner.native_mul_calls.items.len, rows, cells });
        const requested = std.posix.getenv("STWO_OP_TRUTH_LOCAL_GKR_R6_PHYSICAL") orelse return;
        if (!std.mem.eql(u8, requested, "1") and !std.mem.eql(u8, requested, @tagName(truth))) return;
        var source = try build(view, a, true);
        defer source.deinit();
        var authority = try Key.init(a, &source, key.base.profile);
        defer authority.deinit();
        const output = try view.expectedOutput(a);
        const bytes = try Proof.prove(a, &owner, &authority, &output);
        defer a.free(bytes);
        try Proof.verify(a, &authority, &output, bytes);
        var wrong = output;
        wrong[8] = wrong[8].add(C.Q.one());
        try std.testing.expect(std.meta.isError(Proof.verify(a, &authority, &wrong, bytes)));
        std.debug.print("OP_TRUTH_LOCAL_GKR_R6_PHYSICAL kind={s} bytes={d} peak={d} independent_source_key=true\n", .{ @tagName(truth), bytes.len, owner_budget.snapshot().peak_live_bytes });
    }
};
test "OP truth local GKR R6 complete recursive source and padding census" {
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
