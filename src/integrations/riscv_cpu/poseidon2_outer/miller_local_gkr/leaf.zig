//! Source-derived complete recursive proof of opt-in truth-local GKR+P2.
const std = @import("std");
const core = @import("stwo_core");
const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
const C = V.common;
const Frame = @import("../full_p2_frame.zig");
const Full = @import("statement.zig");
const Native = @import("worker.zig");
const Manifest = @import("../pure_p2_manifest.zig");
pub const View = struct {
    key: *const Native.Key,
    span: Native.Span,
    expected: Manifest.Expected,
    manifest: [36]u8,
    main: [36]u8,
    receipt: [36]u8,
    claims: [2]C.O,
    local: *const @import("stwo_prover_engine").lookups.gkr_verifier.ForField(C.O).GkrBatchProof,
    shape: *const V.Shape,
    values: *const V.Captured,
    pub fn expectedOutput(self: View, a: std.mem.Allocator) ![9]C.Q {
        const words = try Full.expectedWords(a, self.key, self.span, self.expected, self.manifest, self.main, self.receipt, self.claims);
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
    pub fn emitInto(self: View, a: std.mem.Allocator, ctx: *C.Context, trace_only: bool) !@import("../pure_p2_source_emission.zig").Emission {
        _ = try C.sidecar(ctx);
        const proof = try V.proof.guess(ctx, self.values, self.shape);
        var frame = Frame.Frame.init(ctx);
        var statement = try Full.Statement.init(&frame, self.key, self.span, self.expected, self.manifest, self.receipt, self.claims, .{ .fixed = proof.commitments[0], .main = proof.commitments[1] }, self.local);
        defer statement.deinit(ctx);
        _ = try V.verify(ctx, self.shape, &proof, &statement);
        const output = try frame.finish();
        if (!trace_only) for (output, try self.expectedOutput(a)) |wire, want| try std.testing.expect(ctx.get(wire).eql(want));
        return .{ .output = output, .mutation_ports = [_]C.Var{ statement.pending.artifact.claims_to_verify_by_instance[0][0].c0.v, proof.sampled_values[1][0][0].c0.v, statement.claims[0].c0.v, output[8] } };
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
        const emitted = try self.emitInto(a, ctx, trace_only);
        const output = emitted.output;
        try C.finish();
        active = false;
        try owner.setOutputs(&output);
        try owner.finalize();
        if (!trace_only and diagnostics) {
            try std.testing.expect(try owner.isCircuitValid());
            for (emitted.mutation_ports) |port| {
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
