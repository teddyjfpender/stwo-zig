//! Isolated lane component using the established degree4 quotient adapter.
//! All54 current cells open; only previous-row lane1 endpoint cells shift.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Q = core.fields.qm31.QM31;
const P = core.fields.packed_qm31.PackedQM31;
const Air = @import("../air/block/word_memory_lanes_v1.zig");
const Trace = @import("../air/block/word_memory_lanes_trace_v1.zig");
const Protocol = @import("block_v5_ram_lanes_protocol_v1.zig");
const Interaction = @import("block_v5_ram_lanes_interaction_v1.zig");
pub const Spec = struct {
    pub const SECURE_POLYNOMIAL_KIND: engine.air.secure_polynomial_program_v1.Kind = .ram_lanes_equations_v1;
    pub fn exportSecurePolynomial(self: Spec, a: std.mem.Allocator, size: u32) !engine.air.secure_polynomial_program_v1.Program {
        return @import("block_v5_ram_lanes_gpu_program_v1.zig").equations(a, self, size);
    }
    pub const FIXED_COUNT = Air.FIXED_COLUMNS;
    pub const MAIN_COUNT = Air.MAIN_COLUMNS;
    pub const INTERACTION_COUNT = Interaction.COLUMN_COUNT;
    pub const CONSTRAINT_COUNT = Air.DIRECT_COUNT + Interaction.CONSTRAINT_COUNT;
    pub const DEGREE = 4;
    pub const EXPANSION_BITS = 2;
    pub const PREVIOUS_MAIN_MASK: [MAIN_COUNT]bool = blk: {
        var needed: [MAIN_COUNT]bool = @splat(false);
        for (Air.shiftedColumns) |column| needed[column] = true;
        break :blk needed;
    };
    claim: Protocol.Claim,
    interaction_claim: Interaction.Claim,
    challenges: *const Protocol.Challenges,
    pub const Domain = struct {
        claim: Protocol.Claim,
        challenges: *const Protocol.Challenges,
        normalized: Interaction.Normalized,
        endpoints: Interaction.Endpoints,
        packed_normalized: [Interaction.PLANES]P,
        packed_endpoints: Interaction.EndpointConstants(P),
        packed_challenges: @import("block_v5_word_packed_challenges_v1.zig").Challenges,
        pub fn evaluate(self: Domain, fixed: [FIXED_COUNT]Q, row: [MAIN_COUNT]Q, previous: [MAIN_COUNT]Q, current: [INTERACTION_COUNT]Q, before: [INTERACTION_COUNT]Q, size: u32) ![CONSTRAINT_COUNT]Q {
            if (size != self.claim.rowCapacity()) return error.InvalidV5RamLanesGeometry;
            const public = Trace.fixedPoint(Q, fixed, self.claim);
            return Air.constraints(self.claim, public, lanes(Q, row), lanes(Q, previous)) ++
                Interaction.constraintsPrepared(self.challenges, &self.endpoints, public, lanes(Q, row), lanes(Q, previous), current, before, self.normalized);
        }
        pub fn evaluatePacked(self: *const Domain, fixed: [FIXED_COUNT]P, row: [MAIN_COUNT]P, previous: [MAIN_COUNT]P, current: [INTERACTION_COUNT]P, before: [INTERACTION_COUNT]P) [CONSTRAINT_COUNT]P {
            @setEvalBranchQuota(400000);
            const public = Trace.fixedPoint(P, fixed, self.claim);
            return Air.Algebra(P).constraints(self.claim, public, lanes(P, row), lanes(P, previous)) ++
                Interaction.Algebra(P).constraintsPrepared(&self.packed_challenges, &self.packed_endpoints, public, lanes(P, row), lanes(P, previous), current, before, self.packed_normalized);
        }
    };
    pub fn prepareDomain(self: Spec, size: u32) !Domain {
        try self.claim.validate();
        if (size != self.claim.rowCapacity()) return error.InvalidV5RamLanesGeometry;
        const normalized = try Interaction.normalize(self.interaction_claim, self.claim);
        const endpoints = try Interaction.publicEndpoints(self.claim, self.challenges);
        var packed_normalized: [Interaction.PLANES]P = undefined;
        for (&packed_normalized, normalized) |*out, value| out.* = P.splat(value);
        return .{ .claim = self.claim, .challenges = self.challenges, .normalized = normalized, .endpoints = endpoints, .packed_normalized = packed_normalized, .packed_endpoints = Interaction.liftEndpoints(P, endpoints), .packed_challenges = .init(self.challenges) };
    }
    pub fn evaluate(self: Spec, fixed: [FIXED_COUNT]Q, row: [MAIN_COUNT]Q, previous: [MAIN_COUNT]Q, current: [INTERACTION_COUNT]Q, before: [INTERACTION_COUNT]Q, size: u32) ![CONSTRAINT_COUNT]Q {
        return (try self.prepareDomain(size)).evaluate(fixed, row, previous, current, before, size);
    }
};
fn lanes(comptime S: type, flat: [Air.MAIN_COLUMNS]S) Air.Algebra(S).Row {
    return .{ flat[0..27].*, flat[27..54].* };
}

/// The delegate supplies masks/CPU domain recovery/SIMD and bounded pool
/// evaluation. This wrapper reports exact per-equation degree metadata.
pub const Component = struct {
    inner: @import("block_v5_word_quotient_adapter_v1.zig").For(Spec),
    const Self = @This();
    const Prover = engine.air.component_prover;
    const Accumulation = engine.air.accumulation;
    const Adapter = core.air.derive.ComponentAdapter(Self, Prover.ComponentProver, Prover.Trace, Accumulation.DomainEvaluationAccumulator);
    pub fn init(log_size: u32, spec: Spec) !Self {
        try spec.claim.validate();
        if (log_size != spec.claim.row_log) return error.InvalidV5RamLanesGeometry;
        _ = try Interaction.normalize(spec.interaction_claim, spec.claim);
        return .{ .inner = .{ .log_size = log_size, .spec = spec } };
    }
    pub fn asProverComponent(self: *const Self) Prover.ComponentProver {
        var result = Adapter.asProverComponent(self);
        result.secure_polynomial_capability_v1 = self.inner.asProverComponent().secure_polynomial_capability_v1;
        result.domain_parallel_evaluator = evaluateParallel;
        result.pool_exclusive_domain = true;
        return result;
    }
    fn evaluateParallel(raw: *const anyopaque, trace: *const Prover.Trace, accumulator: *Accumulation.DomainEvaluationAccumulator, pool: *engine.work_pool.WorkPool) !void {
        const self: *const Self = @ptrCast(@alignCast(raw));
        const delegate = self.inner.asProverComponent();
        try delegate.domain_parallel_evaluator.?(delegate.ctx, trace, accumulator, pool);
    }
    pub fn asVerifierComponent(self: *const Self) core.air.components.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn nConstraints(self: *const Self) usize {
        return self.inner.nConstraints();
    }
    pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
        return self.inner.maxConstraintLogDegreeBound();
    }
    pub fn compositionLogSplit(self: *const Self) u32 {
        return self.inner.compositionLogSplit();
    }
    pub fn constraintDegreeBound(_: *const Self, index: usize) !u8 {
        if (index < Air.DIRECT_COUNT) return Air.constraintDegree(index);
        return Interaction.constraintDegree(index - Air.DIRECT_COUNT);
    }
    pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !core.air.components.TraceLogDegreeBounds {
        return self.inner.traceLogDegreeBounds(a);
    }
    pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: core.circle.CirclePointQM31, max_log: u32) !core.air.components.MaskPoints {
        return self.inner.maskPoints(a, point, max_log);
    }
    pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
        return self.inner.preprocessedColumnIndices(a);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: core.circle.CirclePointQM31, mask: *const core.air.components.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
        return self.inner.evaluateConstraintQuotientsAtPoint(point, mask, accumulator, max_log);
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const Prover.Trace, accumulator: *Accumulation.DomainEvaluationAccumulator) !void {
        return self.inner.evaluateConstraintQuotientsOnDomain(trace, accumulator);
    }
};
