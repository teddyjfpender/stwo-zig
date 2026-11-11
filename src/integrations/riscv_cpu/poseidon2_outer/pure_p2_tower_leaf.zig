//! Real Miller truth leaf, with original OODS authority and complete native PCS.
const std = @import("std");
const core = @import("stwo_core");
const V = @import("../rv64_recursion/om31_poseidon/mod.zig");
const C = V.common;
const Frame = @import("full_p2_frame.zig");
const Full = @import("pure_p2_tower_statement.zig");
const Native = @import("pure_p2_tower_worker.zig");
const Manifest = @import("pure_p2_manifest.zig");
pub const View = struct {
    key: *const Native.Key,
    span: Native.Span,
    expected: Manifest.Expected,
    manifest: [36]u8,
    main: [36]u8,
    claims: [4]C.O,
    shape: *const V.Shape,
    values: *const V.Captured,
    pub fn expectedOutput(self: View, a: std.mem.Allocator) ![9]C.Q {
        const words = try Full.expectedWords(a, self.key, self.span, self.expected, self.manifest, self.main, self.claims);
        defer a.free(words);
        const digest = @import("pure_p2_native.zig").hashWords(words);
        var out: [9]C.Q = undefined;
        for (&out, try core.crypto.poseidon2_m31_sponge.decode(digest)) |*wire, value| wire.* = C.Q.fromBase(value);
        return out;
    }
    pub fn build(self: View, a: std.mem.Allocator, trace_only: bool) !C.PoseidonContext {
        return self.buildMode(a, trace_only, true);
    }
    /// Same constrained graph and witness; adversarial mutation checks belong
    /// to qualification, not every leaf in a block's production loop.
    pub fn buildForProving(self: View, a: std.mem.Allocator) !C.PoseidonContext {
        return self.buildMode(a, false, false);
    }
    pub fn emitInto(self: View, a: std.mem.Allocator, ctx: *C.Context, trace_only: bool) !@import("pure_p2_source_emission.zig").Emission {
        const detail = try self.emitDetails(a, ctx, trace_only);
        return .{ .output = detail.output, .mutation_ports = .{ detail.ports[0], detail.ports[1], detail.ports[2], detail.output[8] } };
    }
    const Details = struct { output: [9]C.Var, ports: [3]C.Var };
    fn emitDetails(self: View, a: std.mem.Allocator, ctx: *C.Context, trace_only: bool) !Details {
        _ = try C.sidecar(ctx);
        const proof = try V.proof.guess(ctx, self.values, self.shape);
        var frame = Frame.Frame.init(ctx);
        var statement = try Full.Statement.init(&frame, self.key, self.span, self.expected, self.manifest, self.claims, .{ .fixed = proof.commitments[0], .main = proof.commitments[1] });
        _ = try V.verify(ctx, self.shape, &proof, &statement);
        const output = try frame.finish();
        if (!trace_only) for (output, try self.expectedOutput(a)) |wire, expected| {
            if (!ctx.get(wire).eql(expected)) return error.InvalidOpTowerLeafOutput;
        };
        return .{ .output = output, .ports = .{ proof.sampled_values[1][0][0].c0.v, statement.claims[0].c0.v, output[8] } };
    }
    fn buildMode(self: View, a: std.mem.Allocator, trace_only: bool, comptime qualify: bool) !C.PoseidonContext {
        var structural = @import("../rv64_recursion/circuit_lane.zig").StructuralScope.init();
        defer structural.deinit();
        var owner = if (trace_only) try C.PoseidonContext.initTraceOnly(a, 9) else try C.PoseidonContext.init(a, 9);
        errdefer owner.deinit();
        C.begin(&owner);
        var active = true;
        defer if (active) C.finish() catch {};
        const ctx = owner.algebra();
        const emitted = try self.emitDetails(a, ctx, trace_only);
        const output = emitted.output;
        try C.finish();
        active = false;
        try owner.setOutputs(&output);
        try owner.finalize();
        if (qualify and !trace_only) {
            try std.testing.expect(try owner.isCircuitValid());
            for (emitted.ports) |port| {
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
