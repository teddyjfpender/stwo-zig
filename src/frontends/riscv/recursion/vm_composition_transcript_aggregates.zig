//! Shared base transcript arithmetic; extension and bridge routing remain above.
const std = @import("std");
const circuit = @import("vm_air_composition_circuit.zig");
const Scalar = circuit.Scalar;
const Builder = circuit.Builder;
const component_order = @import("stwo_riscv_rv32").air.component_order;
const statement_mod = @import("stwo_riscv_rv32").air.statement;
const transcript_claims = @import("stwo_riscv_rv32").air.transcript.claims;
pub const BASE_TRANSCRIPT_CLAIM_COUNT = transcript_claims.COMPONENT_COUNT;
pub fn ForProfile(comptime Profile: type, comptime RangeIndex: type) type {
    if (RangeIndex != usize and RangeIndex != u32) @compileError("unsupported claim range index");
    return struct {
        // The caller owns the already-zeroed base prefix; do not regroup Scalar operations.
        pub fn reconstructBase(profile: *const Profile, claims: []const Scalar, destination: []Scalar) !u32 {
            if (destination.len != BASE_TRANSCRIPT_CLAIM_COUNT) return error.InvalidClaimCount;
            for (profile.entries) |entry| switch (entry.registry) {
                .opcode_lookup => |key| try addClaimRange(
                    RangeIndex,
                    &destination[
                        @intFromEnum(
                            component_order.transcriptComponentForOpcodeFamily(key.family),
                        )
                    ],
                    claims,
                    entry.claimed_sum_offset,
                    entry.claimed_sum_count,
                ),
                .infrastructure => |key| try addClaimRange(
                    RangeIndex,
                    &destination[@intFromEnum(transcriptComponentForInfra(key.kind))],
                    claims,
                    entry.claimed_sum_offset,
                    entry.claimed_sum_count,
                ),
                .opcode_semantic => {},
            };
            return profile.input_profile.claimed_sum_count;
        }
        pub fn bindBase(builder: *Builder, selector: Scalar, profile: *const Profile, claims: []const Scalar, authenticated: []const Scalar) !void {
            if (authenticated.len != BASE_TRANSCRIPT_CLAIM_COUNT) return error.InvalidClaimCount;
            var reconstructed = [_]Scalar{Scalar.zero()} ** BASE_TRANSCRIPT_CLAIM_COUNT;
            const cursor = try reconstructBase(profile, claims, &reconstructed);
            if (@as(usize, cursor) != claims.len) return error.InvalidClaimCount;
            try bindAggregates(builder, selector, authenticated, &reconstructed);
        }
    };
}
pub fn addClaimRange(comptime RangeIndex: type, destination: *Scalar, claims: []const Scalar, offset: u32, count: u32) !void {
    if (RangeIndex != usize and RangeIndex != u32) @compileError("unsupported claim range index");
    const end = std.math.add(RangeIndex, @as(RangeIndex, offset), @as(RangeIndex, count)) catch return error.ArithmeticOverflow;
    if (@as(usize, end) > claims.len) return error.InvalidClaimCount;
    for (claims[@as(usize, offset)..@as(usize, end)]) |claim| destination.* = destination.add(claim);
}
pub fn bindAggregates(builder: *Builder, selector: Scalar, authenticated: []const Scalar, reconstructed: []const Scalar) !void {
    if (authenticated.len != reconstructed.len) return error.InvalidClaimCount;
    for (authenticated, reconstructed) |value, aggregate| try builder.constrainZero(selector.mul(value.sub(aggregate)));
    try builder.check();
}
fn transcriptComponentForInfra(
    kind: statement_mod.InfraKind,
) transcript_claims.Component {
    return switch (kind) {
        .program => .program,
        .memory => .memory,
        .merkle => .merkle,
        .poseidon2 => .poseidon2,
        .clock_update => .clock_update,
        .bitwise => .bitwise,
        .range_check_20 => .range_check_20,
        .range_check_8_11 => .range_check_8_11,
        .range_check_8_8_4 => .range_check_8_8_4,
        .range_check_8_8 => .range_check_8_8,
        .range_check_m31 => .range_check_m31,
    };
}
