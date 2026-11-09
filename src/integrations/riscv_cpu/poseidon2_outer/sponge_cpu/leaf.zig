//! Concrete source view for the new CPU flavor. No producer key or geometry
//! enters this builder; native proof values are witness assignments only.
const std = @import("std");
const core = @import("stwo_core");
const P = @import("../../rv64_recursion/om31_poseidon/common.zig");
const C = @import("../full_p2_common.zig");
const Public = @import("../full_p2_frame.zig");
const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
const R = @import("../../word16_global_execution/services/roster.zig");
const Request = @import("../../word16_global_execution/services/protocol.zig").Request;
const T = @import("../../word16_global_execution/services/types.zig");
const CPU = @import("worker.zig");
const Key = @import("key.zig").Key;
const Statement = @import("statement.zig");
pub const View = struct {
    setup: *const R.CpuSetup,
    request: Request,
    span: T.OpTowerSpan,
    first: [T.FAMILIES]u32,
    key: *const Key,
    expected: CPU.Expected,
    manifest: [36]u8,
    main: [36]u8,
    receipt: [36]u8,
    claims: []const C.O,
    child: *const @import("stwo_prover_engine").lookups.gkr_verifier.ForField(C.O).GkrBatchProof,
    shape: *const V.Shape,
    values: *const V.Captured,
    pub fn expectedOutput(self: View, a: std.mem.Allocator) ![9]C.Q {
        const words = try Statement.expectedWords(a, self.setup, self.request, self.span, self.first, self.key, self.expected, self.manifest, self.main, self.receipt, self.claims);
        defer a.free(words);
        var out: [9]C.Q = undefined;
        for (&out, try core.crypto.poseidon2_m31_sponge.decode(@import("../pure_p2_native.zig").hashWords(words))) |*v, value| v.* = C.Q.fromBase(value);
        return out;
    }
    pub fn build(self: View, a: std.mem.Allocator, trace_only: bool) !P.PoseidonContext {
        return self.buildMode(a, trace_only, true);
    }
    pub fn buildForProving(self: View, a: std.mem.Allocator) !P.PoseidonContext {
        return self.buildMode(a, false, false);
    }
    /// Append this complete native verifier to an already active context.
    /// The caller owns structural/native-multiply scopes and finalizes once.
    pub fn emitInto(self: View, a: std.mem.Allocator, ctx: *C.Context, trace_only: bool) !@import("../pure_p2_source_emission.zig").Emission {
        _ = try P.sidecar(ctx);
        const proof = try V.proof.guess(ctx, self.values, self.shape);
        var frame = Public.Frame.init(ctx);
        var statement = try Statement.Statement.init(&frame, self.setup, self.request, self.span, self.first, self.key, self.expected, self.manifest, self.claims, .{ .fixed = proof.commitments[0], .main = proof.commitments[1] }, self.child);
        defer statement.deinit(ctx);
        _ = try V.verify(ctx, self.shape, &proof, &statement);
        const output = try frame.finish();
        if (!trace_only) for (output, try self.expectedOutput(a)) |port, value| if (!ctx.get(port).eql(value)) return error.SpongeCpuPublicFrameMismatch;
        const last = statement.pending.artifact.claims_to_verify_by_instance.len - 1;
        const mutants = [_]C.Var{ proof.sampled_values[1][self.setup.columnCount(1)][0].c0.v, statement.pending.artifact.claims_to_verify_by_instance[last][0].c0.v, statement.claims[statement.claims.len - 1].c0.v, output[8] };
        return .{ .output = output, .mutation_ports = mutants };
    }
    fn buildMode(self: View, a: std.mem.Allocator, trace_only: bool, qualify: bool) !P.PoseidonContext {
        var structural = @import("../../rv64_recursion/circuit_lane.zig").StructuralScope.init();
        defer structural.deinit();
        var owner = if (trace_only) try P.PoseidonContext.initTraceOnly(a, 9) else try P.PoseidonContext.init(a, 9);
        errdefer owner.deinit();
        P.begin(&owner);
        var active = true;
        defer if (active) P.finish() catch {};
        const ctx = owner.algebra();
        const emitted = try self.emitInto(a, ctx, trace_only);
        const output = emitted.output;
        try P.finish();
        active = false;
        try owner.setOutputs(&output);
        try owner.finalize();
        if (!trace_only and qualify) {
            if (!try owner.isCircuitValid()) return error.CircuitCheckFailure;
            for (emitted.mutation_ports) |port| {
                const old = ctx.get(port);
                ctx.value_table.items[port.idx] = old.add(C.Q.one());
                const accepted = try owner.isCircuitValid();
                ctx.value_table.items[port.idx] = old;
                if (accepted) return error.AcceptedSpongeCpuLeafMutation;
            }
        }
        if (ctx.circuit.blake_g_gate.items.len != 0) return error.UnexpectedSpongeCpuBlakeGate;
        return owner;
    }
};
