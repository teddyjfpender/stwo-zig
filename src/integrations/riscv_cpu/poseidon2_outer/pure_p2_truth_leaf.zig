//! Complete source-derived truth catalog leaf, with original OODS authority and complete native PCS.
const std = @import("std");
const core = @import("stwo_core");
const V = @import("../rv64_recursion/om31_poseidon/mod.zig");
const C = V.common;
const Frame = @import("full_p2_frame.zig");
const Full = @import("pure_p2_truth_statement.zig");
const Native = @import("pure_p2_truth_worker.zig");
const Manifest = @import("pure_p2_manifest.zig");
pub const View = struct {
    key: *const Native.Key,
    truth: @import("../word16_global_execution/services/roster.zig").Truth,
    expected: Manifest.Expected,
    manifest: [36]u8,
    main: [36]u8,
    claims: []const C.O,
    shape: *const V.Shape,
    values: *const V.Captured,
    pub fn expectedOutput(self: View, a: std.mem.Allocator) ![9]C.Q {
        const words = try Full.expectedWords(a, self.key, self.truth, self.expected, self.manifest, self.main, self.claims);
        defer a.free(words);
        const digest = @import("pure_p2_native.zig").hashWords(words);
        var out: [9]C.Q = undefined;
        for (&out, try core.crypto.poseidon2_m31_sponge.decode(digest)) |*wire, value| wire.* = C.Q.fromBase(value);
        return out;
    }
    /// Production construction skips only repeated diagnostic circuit scans;
    /// topology/public words are identical and fresh physical verification stays mandatory.
    pub fn buildForProving(self: View, a: std.mem.Allocator) !C.PoseidonContext {
        return self.buildMode(a, false, false);
    }
    pub fn build(self: View, a: std.mem.Allocator, trace_only: bool) !C.PoseidonContext {
        return self.buildMode(a, trace_only, true);
    }
    fn buildMode(self: View, a: std.mem.Allocator, trace_only: bool, diagnostic_checks: bool) !C.PoseidonContext {
        var structural = @import("../rv64_recursion/circuit_lane.zig").StructuralScope.init();
        defer structural.deinit();
        var owner = if (trace_only) try C.PoseidonContext.initTraceOnly(a, 9) else try C.PoseidonContext.init(a, 9);
        errdefer owner.deinit();
        C.begin(&owner);
        var active = true;
        defer if (active) C.finish() catch {};
        const ctx = owner.algebra();
        const proof = try V.proof.guess(ctx, self.values, self.shape);
        var frame = Frame.Frame.init(ctx);
        var statement = try Full.Statement.init(&frame, self.key, self.truth, self.expected, self.manifest, self.claims, .{ .fixed = proof.commitments[0], .main = proof.commitments[1] });
        _ = try V.verify(ctx, self.shape, &proof, &statement);
        const output = try frame.finish();
        if (!trace_only) for (output, try self.expectedOutput(a)) |wire, expected| try std.testing.expect(ctx.get(wire).eql(expected));
        try C.finish();
        active = false;
        try owner.setOutputs(&output);
        try owner.finalize();
        if (!trace_only and diagnostic_checks) {
            try std.testing.expect(try owner.isCircuitValid());
            for ([_]C.Var{ proof.sampled_values[1][0][0].c0.v, statement.claims[0].c0.v, frame.free_words.items[0].get(), frame.free_words.items[1].get(), frame.free_words.items[9 + 18 + 8].get(), frame.free_words.items[frame.free_words.items.len - 2].get(), frame.free_words.items[frame.free_words.items.len - 1].get(), output[8] }) |port| {
                const original = ctx.get(port);
                ctx.value_table.items[port.idx] = original.add(C.Q.one());
                const accepted = try owner.isCircuitValid();
                ctx.value_table.items[port.idx] = original;
                try std.testing.expect(!accepted);
            }
        }
        try std.testing.expectEqual(@as(usize, 0), ctx.circuit.blake_g_gate.items.len);
        try std.testing.expectEqual(@as(usize, 0), ctx.circuit.triple_xor.items.len);
        return owner;
    }
};
