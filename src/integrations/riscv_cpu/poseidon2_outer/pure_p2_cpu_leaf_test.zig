//! Actual source CPU proof, checked local child and pure-P2 verifier graph.
//! Numerical circuit qualification only until the physical outer gate is added.
const std = @import("std");
const core = @import("stwo_core");
const V = @import("../rv64_recursion/om31_poseidon/mod.zig");
const C = V.common;
const Public = @import("full_p2_frame.zig");
const Full = @import("pure_p2_cpu_statement.zig");
const Protocol = @import("pure_p2_worker_protocol.zig");
const Native = @import("pure_p2_native.zig");
const Hook = struct {
    pub fn run(a: std.mem.Allocator, setups: anytype, requests: anytype, keys: anytype, inventory: anytype, pending: anytype, encoded: anytype, capture: anytype, stages: anytype) !void {
        var native = try Protocol.W.Wire.decodeProofBytesBinary(a, encoded[0].bytes);
        defer native.deinit(a);
        const config = keys[0].profile.config();
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const shape = try @import("../rv64_recursion/om31_native/cpu_capture.zig").geometry(arena.allocator(), setups[0], config);
        const values = try V.proof.fromNative(arena.allocator(), &native, capture, &shape);
        var owner = try C.PoseidonContext.init(a, 9);
        defer owner.deinit();
        C.begin(&owner);
        var active = true;
        defer if (active) C.finish() catch {};
        const ctx = owner.algebra();
        const proof = try V.proof.guess(ctx, &values, &shape);
        var frame = Public.Frame.init(ctx);
        var statement = try Full.Statement.init(&frame, setups[0], requests[0], inventory.first_ids[0], inventory.workers[0], pending.digest, encoded[0].claims, .{ .fixed = proof.commitments[0], .main = proof.commitments[1], .fixed_source = keys[0].root }, stages[0].local.?.proof, config, .{ .identity = keys[0].identity, .root = keys[0].root, .profile = keys[0].profile });
        defer statement.deinit(ctx);
        _ = try V.verify(ctx, &shape, &proof, &statement);
        const output = try frame.finish();
        const expected_words = try Full.expectedWords(a, setups[0], requests[0], inventory.first_ids[0], inventory.workers[0], pending.digest, native.commitment_scheme_proof.commitments.items[1], stages[0].local.?.receipt, encoded[0].claims);
        defer a.free(expected_words);
        const expected = try core.crypto.poseidon2_m31_sponge.decode(Native.hashWords(expected_words));
        for (output, expected) |port, value| try std.testing.expect(ctx.get(port).eql(C.Q.fromBase(value)));
        try C.finish();
        active = false;
        try owner.setOutputs(&output);
        try owner.finalize();
        try std.testing.expect(try owner.isCircuitValid());
        const mutants = [_]C.Var{ proof.sampled_values[1][0][0].c0.v, statement.pending.artifact.claims_to_verify_by_instance[0][0].c0.v, output[8] };
        for (mutants) |port| {
            const old = ctx.get(port);
            ctx.value_table.items[port.idx] = old.add(C.Q.one());
            const accepted = try owner.isCircuitValid();
            ctx.value_table.items[port.idx] = old;
            try std.testing.expect(!accepted);
        }
        try std.testing.expectEqual(@as(usize, 0), ctx.circuit.blake_g_gate.items.len);
        try std.testing.expectEqual(@as(usize, 0), ctx.circuit.triple_xor.items.len);
        const json = try std.json.Stringify.valueAlloc(a, .{ .scope = "actualCPU_source_AIR_OODS_masks_terminal_PCS_GKR_FS_publicframe", .raw = try owner.rawCounts(), .cells = try owner.census(false), .permutations = owner.calls.items.len, .variables = ctx.circuit.n_vars, .public_words = expected_words.len, .native_assignment_exact = true, .production_admission_open = false, .recursive_execution_acceptance = false }, .{});
        defer a.free(json);
        std.debug.print("OP_PURE_P2_COMPLETE_CPU_CIRCUIT {s}\n", .{json});
    }
};
test "OP pure P2 complete CPU circuit matches actual native proof and expected public frame" {
    try @import("pure_p2_cpu_fixture.zig").exercise(Hook);
}
