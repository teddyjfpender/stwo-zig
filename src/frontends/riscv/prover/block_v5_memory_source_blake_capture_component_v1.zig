//! Exact scalar/packed point/domain adapter for the original capture wires.
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const P = core.fields.packed_qm31.PackedQM31;
const Air = @import("block_v5_memory_source_blake_capture_air_v1.zig");
const Interaction = @import("block_v5_memory_source_blake_capture_interaction_v1.zig");
pub const Spec = struct {
    pub const FIXED_COUNT = Air.FIXED_COUNT;
    pub const MAIN_COUNT = Air.MAIN_COUNT;
    pub const INTERACTION_COUNT = Air.INTERACTION_COUNT;
    pub const CONSTRAINT_COUNT = Air.CONSTRAINT_COUNT;
    pub const PREVIOUS_MAIN_MASK: [MAIN_COUNT]bool = @splat(false);
    pub const DEGREE = Air.DEGREE;
    pub const EXPANSION_BITS = Air.EXPANSION_BITS;
    rows: u32,
    expected_requests: u64,
    claim: Interaction.Claim,
    challenge: Air.Algebra(Q).Challenge,
    pub const Domain = struct {
        size: u32,
        challenge: Air.Algebra(Q).Challenge,
        normalized: [Air.PAIRS]Q,
        packed_challenge: Air.Algebra(P).Challenge,
        packed_normalized: [Air.PAIRS]P,
        pub fn evaluate(self: Domain, fixed: [FIXED_COUNT]Q, main: [MAIN_COUNT]Q, _: [MAIN_COUNT]Q, current: [INTERACTION_COUNT]Q, previous: [INTERACTION_COUNT]Q, size: u32) ![CONSTRAINT_COUNT]Q {
            if (size != self.size) return error.InvalidSourceBlakeCaptureGeometry;
            return Air.Algebra(Q).constraints(fixed, main, current, previous, self.normalized, self.challenge);
        }
        pub fn evaluatePacked(self: *const Domain, fixed: [FIXED_COUNT]P, main: [MAIN_COUNT]P, _: [MAIN_COUNT]P, current: [INTERACTION_COUNT]P, previous: [INTERACTION_COUNT]P) [CONSTRAINT_COUNT]P {
            return Air.Algebra(P).constraints(fixed, main, current, previous, self.packed_normalized, self.packed_challenge);
        }
    };
    pub fn prepareDomain(self: Spec, size: u32) !Domain {
        if (size != self.rows) return error.InvalidSourceBlakeCaptureGeometry;
        const normalized = try Interaction.normalize(self.claim, size, self.expected_requests);
        var powers: [6]P = undefined;
        var packed_sums: [Air.PAIRS]P = undefined;
        for (&powers, self.challenge.powers) |*out, value| out.* = P.splat(value);
        for (&packed_sums, normalized) |*out, value| out.* = P.splat(value);
        return .{ .size = size, .challenge = self.challenge, .normalized = normalized, .packed_challenge = .{ .z = P.splat(self.challenge.z), .powers = powers }, .packed_normalized = packed_sums };
    }
    pub fn evaluate(self: Spec, fixed: [FIXED_COUNT]Q, main: [MAIN_COUNT]Q, previous_main: [MAIN_COUNT]Q, current: [INTERACTION_COUNT]Q, previous: [INTERACTION_COUNT]Q, size: u32) ![CONSTRAINT_COUNT]Q {
        return (try self.prepareDomain(size)).evaluate(fixed, main, previous_main, current, previous, size);
    }
};
pub const Component = @import("block_v5_word_quotient_adapter_v1.zig").For(Spec);
