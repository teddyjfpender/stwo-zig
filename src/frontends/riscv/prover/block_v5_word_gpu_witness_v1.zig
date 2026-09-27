//! Typed admission for direct fixed12/main27 device witness generation.
//! No proof/source plan is selected by the raw resident records.
const core = @import("stwo_core");
const Claim = @import("../air/block/memory_component.zig").Claim;
const Transition = @import("../air/block/memory_transition.zig").Transition;
const word = @import("../air/block/word_memory_v5.zig");
pub const PARAMETER_WORDS = 25;
pub fn claimWords(claim: Claim) ![PARAMETER_WORDS]u32 {
    try word.validatePublicClaim(claim);
    if (claim.log_size < 1 or claim.log_size > 24) return error.InvalidWordDeviceGeometry;
    var out: [PARAMETER_WORDS]u32 = @splat(0);
    out[0] = @truncate(claim.first_row);
    out[1] = @intCast(claim.first_row >> 32);
    out[2] = @truncate(claim.total_rows);
    out[3] = @intCast(claim.total_rows >> 32);
    out[4] = claim.rows;
    out[5] = claim.log_size;
    out[6] = @intFromBool(claim.preceding != null);
    if (claim.preceding) |prior| out[7..13].* = recordWords(prior);
    out[13..19].* = recordWords(claim.first);
    out[19..25].* = recordWords(claim.last);
    return out;
}
pub fn recordWords(value: Transition) [6]u32 {
    return .{ value.space, value.address, @truncate(value.clock), @intCast(value.clock >> 32), value.before, value.after };
}
pub fn ForMetal(comptime Metal: type) type {
    return struct {
        pub fn wordWitness(runtime: *Metal.Runtime, records: *const Metal.runtime.ResidentBuffer, claim: Claim, limits: Metal.secure_polynomial_v1.Limits) !Metal.secure_polynomial_v1.WitnessResult {
            const parameters = try claimWords(claim);
            return Metal.secure_polynomial_v1.generateWitness(runtime, records, &parameters, claim.log_size, limits);
        }
        /// Counter metadata is independently matched by the producer/receiver.
        /// Generated multiplicities remain provisional until their range proof.
        pub fn rangeWitness(runtime: *Metal.Runtime, multiplicities: *const Metal.runtime.ResidentBuffer, expected_requests: u64, limits: Metal.secure_polynomial_v1.Limits) !Metal.secure_polynomial_v1.WitnessResult {
            if (expected_requests >= core.fields.m31.Modulus) return error.InvalidV5Range16Counter;
            return Metal.secure_polynomial_v1.generateWitness(runtime, multiplicities, null, 16, limits);
        }
    };
}
