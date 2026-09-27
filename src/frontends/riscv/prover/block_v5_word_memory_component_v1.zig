//! Sorted word AIR and every lookup projection share the same committed cells.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Q = core.fields.qm31.QM31;
const P = core.fields.packed_qm31.PackedQM31;
const memory = @import("../air/block/memory_component.zig");
const air = @import("../air/block/word_memory_v5.zig");
const trace = @import("../air/block/word_memory_trace_v5.zig");
const interaction = @import("block_v5_word_memory_interaction_v1.zig");
const protocol = @import("block_v5_word_memory_protocol_v1.zig");
pub const Spec = struct {
    pub const SECURE_POLYNOMIAL_KIND: engine.air.secure_polynomial_program_v1.Kind = .word_equations_v4;
    pub fn exportSecurePolynomial(self: Spec, a: std.mem.Allocator, size: u32) !engine.air.secure_polynomial_program_v1.Program {
        return @import("block_v5_word_gpu_program_v1.zig").wordEquations(a, self, size);
    }
    pub const FIXED_COUNT = @import("../air/block/word_memory_fixed_v5.zig").COLUMN_COUNT;
    pub const MAIN_COUNT = air.Layout.len;
    pub const PREVIOUS_MAIN_MASK: [MAIN_COUNT]bool = blk: {
        var needed: [MAIN_COUNT]bool = @splat(false);
        @memset(needed[air.Layout.current_key..][0..3], true);
        @memset(needed[air.Layout.current_clock..][0..4], true);
        @memset(needed[air.Layout.after..][0..2], true);
        break :blk needed;
    };
    pub fn previousMainNeeded(index: usize) bool {
        return PREVIOUS_MAIN_MASK[index];
    }
    pub const INTERACTION_COUNT = interaction.COLUMN_COUNT;
    pub const CONSTRAINT_COUNT = air.DIRECT_COUNT + interaction.CONSTRAINT_COUNT;
    pub const DEGREE = 4;
    pub const EXPANSION_BITS = 2;
    claim: memory.Claim,
    interaction_claim: interaction.Claim,
    challenges: *const protocol.Challenges,
    endpoint_constants: ?interaction.Endpoints = null,
    pub const Domain = struct {
        spec: Spec,
        normalized: interaction.Normalized,
        endpoints: interaction.Endpoints,
        packed_endpoints: interaction.EndpointConstants(P),
        packed_normalized: [interaction.COLUMN_COUNT / 4]P,
        packed_challenges: @import("block_v5_word_packed_challenges_v1.zig").Challenges,
        pub fn evaluate(self: Domain, fixed: [FIXED_COUNT]Q, row: [MAIN_COUNT]Q, previous: [MAIN_COUNT]Q, current: [INTERACTION_COUNT]Q, before: [INTERACTION_COUNT]Q, _: u32) ![CONSTRAINT_COUNT]Q {
            const public = trace.fixedPoint(fixed, self.spec.claim);
            return air.constraints(self.spec.claim, public, row, previous) ++ interaction.constraintsPrepared(self.spec.challenges, &self.endpoints, public, row, previous, current, before, self.normalized);
        }
        pub fn evaluatePacked(self: *const Domain, fixed: [FIXED_COUNT]P, row: [MAIN_COUNT]P, previous: [MAIN_COUNT]P, current: [INTERACTION_COUNT]P, before: [INTERACTION_COUNT]P) [CONSTRAINT_COUNT]P {
            @setEvalBranchQuota(200000);
            const public = trace.fixedPointGeneric(P, fixed, self.spec.claim);
            return air.Algebra(P).constraints(self.spec.claim, public, row, previous) ++ interaction.Algebra(P).constraintsPrepared(&self.packed_challenges, &self.packed_endpoints, public, row, previous, current, before, self.packed_normalized);
        }
    };
    pub fn prepareDomain(self: Spec, size: u32) !Domain {
        const normalized = try interaction.normalize(self.interaction_claim, size);
        const endpoints = self.endpoint_constants orelse try interaction.publicEndpoints(self.claim, self.challenges);
        var prepared_spec = self;
        prepared_spec.endpoint_constants = endpoints;
        var packed_shifts: [interaction.COLUMN_COUNT / 4]P = undefined;
        for (&packed_shifts, normalized) |*out, value| out.* = P.splat(value);
        return .{ .spec = prepared_spec, .normalized = normalized, .endpoints = endpoints, .packed_endpoints = interaction.liftEndpoints(P, endpoints), .packed_normalized = packed_shifts, .packed_challenges = .init(self.challenges) };
    }
    pub fn evaluate(self: Spec, fixed: [FIXED_COUNT]Q, row: [MAIN_COUNT]Q, previous: [MAIN_COUNT]Q, current: [INTERACTION_COUNT]Q, before: [INTERACTION_COUNT]Q, size: u32) ![CONSTRAINT_COUNT]Q {
        const public = trace.fixedPoint(fixed, self.claim);
        const endpoints = self.endpoint_constants orelse try interaction.publicEndpoints(self.claim, self.challenges);
        return air.constraints(self.claim, public, row, previous) ++ try interaction.constraints(self.challenges, &endpoints, public, row, previous, current, before, self.interaction_claim, size);
    }
};
pub const Component = @import("block_v5_word_quotient_adapter_v1.zig").For(Spec);
