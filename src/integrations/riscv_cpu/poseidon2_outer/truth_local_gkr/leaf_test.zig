//! Source-derived complete recursive proof of opt-in truth-local GKR+P2.
const std = @import("std");
const core = @import("stwo_core");
const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
const C = V.common;
const Frame = @import("../full_p2_frame.zig");
const Full = @import("statement.zig");
const Native = @import("worker.zig");
const Local = @import("native.zig");
const Manifest = @import("../pure_p2_manifest.zig");
const R = @import("../../word16_global_execution/services/roster.zig");
const Protocol = @import("../pure_p2_worker_protocol.zig");
pub const View = struct {
    key: *const Native.Key,
    truth: R.Truth,
    expected: Manifest.Expected,
    manifest: [36]u8,
    main: [36]u8,
    receipt: [36]u8,
    claims: [2]C.O,
    local: *const @import("stwo_prover_engine").lookups.gkr_verifier.ForField(C.O).GkrBatchProof,
    shape: *const V.Shape,
    values: *const V.Captured,
    pub fn expectedOutput(self: View, a: std.mem.Allocator) ![9]C.Q {
        const words = try Full.expectedWords(a, self.key, self.truth, self.expected, self.manifest, self.main, self.receipt, self.claims);
        defer a.free(words);
        const hash = @import("../pure_p2_native.zig").hashWords(words);
        var out: [9]C.Q = undefined;
        for (&out, try core.crypto.poseidon2_m31_sponge.decode(hash)) |*wire, value| wire.* = C.Q.fromBase(value);
        return out;
    }
    pub fn build(self: View, a: std.mem.Allocator, trace_only: bool) !C.PoseidonContext {
        return self.buildMode(a, trace_only, true);
    }
    pub fn buildForProving(self: View, a: std.mem.Allocator) !C.PoseidonContext {
        return self.buildMode(a, false, false);
    }
    fn buildMode(self: View, a: std.mem.Allocator, trace_only: bool, diagnostics: bool) !C.PoseidonContext {
        var structural = @import("../../rv64_recursion/circuit_lane.zig").StructuralScope.init();
        defer structural.deinit();
        var owner = if (trace_only) try C.PoseidonContext.initTraceOnly(a, 9) else try C.PoseidonContext.init(a, 9);
        errdefer owner.deinit();
        C.begin(&owner);
        var active = true;
        defer if (active) C.finish() catch {};
        const ctx = owner.algebra();
        const proof = try V.proof.guess(ctx, self.values, self.shape);
        var frame = Frame.Frame.init(ctx);
        var statement = try Full.Statement.init(&frame, self.key, self.truth, self.expected, self.manifest, self.receipt, self.claims, .{ .fixed = proof.commitments[0], .main = proof.commitments[1] }, self.local);
        defer statement.deinit(ctx);
        _ = try V.verify(ctx, self.shape, &proof, &statement);
        const output = try frame.finish();
        if (!trace_only) for (output, try self.expectedOutput(a)) |wire, want| try std.testing.expect(ctx.get(wire).eql(want));
        try C.finish();
        active = false;
        try owner.setOutputs(&output);
        try owner.finalize();
        if (!trace_only and diagnostics) {
            try std.testing.expect(try owner.isCircuitValid());
            for ([_]C.Var{ statement.pending.artifact.claims_to_verify_by_instance[0][0].c0.v, proof.sampled_values[1][0][0].c0.v, statement.claims[0].c0.v, output[8] }) |port| {
                const old = ctx.get(port);
                ctx.value_table.items[port.idx] = old.add(C.Q.one());
                const accepted = try owner.isCircuitValid();
                ctx.value_table.items[port.idx] = old;
                try std.testing.expect(!accepted);
            }
        }
        return owner;
    }
};
const Hook = struct {
    pub fn run(backing: std.mem.Allocator, key: *const Native.Key, truth: R.Truth, expected: Manifest.Expected, pending: *const Manifest.Pending, encoded: *const Native.Encoded, capture: anytype) !void {
        const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.createRetainingParent(backing, 8 << 30);
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
