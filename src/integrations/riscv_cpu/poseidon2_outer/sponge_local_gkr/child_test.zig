//! Actual qualified CPU local proofs, through the complete native join fixture.
//! Checks transcript, every marginal, eta, all nine receipt limbs and mutations.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const P = @import("../../rv64_recursion/om31_poseidon/common.zig");
const C = @import("../full_p2_common.zig");
const Public = @import("../full_p2_frame.zig");
const G = @import("../../logup_gkr/om31_circuit_verifier.zig");
const Native = @import("native.zig");
const Child = @import("child.zig");
const Detached = @import("worker.zig");
const B = circuit.builder;
fn root(ctx: *C.Context, bytes: [36]u8) !C.Hash {
    var out: C.Hash = undefined;
    for (&out, try core.crypto.poseidon2_m31_sponge.decode(bytes)) |*v, value| v.* = try ctx.guess(C.Q.fromBase(value));
    return out;
}
fn digest(ctx: *C.Context, bytes: [32]u8) !Public.Digest {
    var out: Public.Digest = undefined;
    for (&out, 0..) |*v, i| v.* = try B.wrappers.guessU32(C.Q, ctx, B.wrappers.u32Value(C.Q, std.mem.readInt(u32, bytes[4 * i ..][0..4], .little)));
    return out;
}
const Hook = struct {
    pub fn detached(a: std.mem.Allocator, worker: *const Detached.Worker, encoded: *const Detached.Encoded, manifest: [36]u8, main: [36]u8) !void {
        const scope = Native.DetachedScope{ .statement = worker.expected.statement, .fixed = worker.key.root, .main = main, .manifest = manifest, .ordinal = worker.expected.ordinal };
        var proof = try Native.decode(a, worker.geometry, encoded.local);
        defer proof.deinit();
        var native = try Native.verifyDetachedPending(a, scope, worker.geometry, &proof.proof, encoded.receipt);
        defer native.deinit(a);
        var owner = try P.PoseidonContext.init(a, 9);
        defer owner.deinit();
        P.begin(&owner);
        var active = true;
        defer if (active) P.finish() catch {};
        const ctx = owner.algebra();
        const wires = try G.wireProof(ctx, &proof.proof);
        const public = Child.Scope{ .statement = try digest(ctx, scope.statement), .fixed = try root(ctx, scope.fixed), .main = try root(ctx, scope.main), .manifest = try root(ctx, scope.manifest), .ordinal = try B.wrappers.guessU32(C.Q, ctx, B.wrappers.u32Value(C.Q, scope.ordinal)), .calls = try B.wrappers.guessU32(C.Q, ctx, B.wrappers.u32Value(C.Q, worker.geometry.calls)), .permutations = try B.wrappers.guessU32(C.Q, ctx, B.wrappers.u32Value(C.Q, worker.geometry.permutations)), .first_id = try B.wrappers.guessU32(C.Q, ctx, B.wrappers.u32Value(C.Q, worker.geometry.first_id)) };
        var pending = try Child.verify(ctx, public, worker.geometry, &wires);
        defer pending.deinit(a);
        try std.testing.expect(pending.eta.value().eql(native.eta));
        try std.testing.expectEqual(native.artifact.ood_point.len, pending.artifact.ood_point.len);
        for (pending.artifact.ood_point, native.artifact.ood_point) |actual, expected| try std.testing.expect(actual.value().eql(expected));
        for (pending.artifact.claims_to_verify_by_instance, native.artifact.claims_to_verify_by_instance) |actual, expected| for (actual, expected) |x, y| try std.testing.expect(x.value().eql(y));
        for (pending.receipt, try core.crypto.poseidon2_m31_sponge.decode(encoded.receipt)) |port, value| try std.testing.expect(ctx.get(port).eql(C.Q.fromBase(value)));
        P.finish() catch |err| return err;
        active = false;
        try owner.setOutputs(&pending.receipt);
        try owner.finalize();
        try std.testing.expect(try owner.isCircuitValid());
        const mutants = [_]C.Var{ wires.output_claims_by_instance[0][0].c0.v, pending.artifact.claims_to_verify_by_instance[pending.artifact.claims_to_verify_by_instance.len - 1][0].c0.v, pending.receipt[8] };
        for (mutants) |port| {
            const old = ctx.get(port);
            ctx.value_table.items[port.idx] = old.add(C.Q.one());
            const accepted = try owner.isCircuitValid();
            ctx.value_table.items[port.idx] = old;
            try std.testing.expect(!accepted);
        }
        try std.testing.expectEqual(@as(usize, 0), ctx.circuit.blake_g_gate.items.len);
        const data = try std.json.Stringify.valueAlloc(a, .{ .scope = "detached_child_only_pending_physical_binding", .ordinal = scope.ordinal, .instances = 8, .native_transcript_marginals_eta_receipt_exact = true, .raw = try owner.rawCounts(), .census = try owner.census(false) }, .{});
        defer a.free(data);
        std.debug.print("OP_DETACHED_SPONGE_CHILD {s}\n", .{data});
    }
};
test "detached sponge typed child matches complete joined native transcript and receipt" {
    try @import("../sponge_cpu/join_test.zig").exerciseWithHook(false, Hook);
}

test "detached sponge coherent phantom claim raw STARK passes and full receiver rejects" {
    try @import("../sponge_cpu/join_test.zig").exerciseWithHook(false, void);
}

test "detached sponge joins frontier CPUs with sealed local-GKR Keccak truth" {
    const Local = struct {
        pub const local_truth = true;
    };
    try @import("../sponge_cpu/join_test.zig").exerciseWithHook(false, Local);
}
