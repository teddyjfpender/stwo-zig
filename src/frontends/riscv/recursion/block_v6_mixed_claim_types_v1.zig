//! Typed proposals only: no proof, host receipt, routing steps or offsets.
const std = @import("std");
pub const Bus = @import("block_v6_mixed_direct_public_v1.zig");
pub const Family = enum(u32) { native = 1, range16 = 2, ram_lanes = 3, program_table = 4, native_lookup = 5, caller_arithmetic = 6, caller_fused = 7, source_raw = 8, source_fold = 9 };
pub fn Payload(comptime family: Family) type {
    return switch (family) {
        .native => Bus.Native.Claims,
        .range16, .ram_lanes, .program_table, .native_lookup => Bus.Provider.Definition(@field(Bus.Provider.Family, @tagName(family))).Claim,
        .caller_arithmetic => Bus.Auxiliary.Definition(.caller_arithmetic).Admission.Profile.ExtensionClaim,
        .caller_fused => @import("../prover/block_v5_caller_fused_proof_v1.zig").ClaimFrames,
        .source_raw, .source_fold => Bus.Auxiliary.Definition(@field(Bus.Auxiliary.Family, @tagName(family))).Bus.Claims,
    };
}
pub const Claim = union(Family) {
    native: Payload(.native),
    range16: Payload(.range16),
    ram_lanes: Payload(.ram_lanes),
    program_table: Payload(.program_table),
    native_lookup: Payload(.native_lookup),
    caller_arithmetic: Payload(.caller_arithmetic),
    caller_fused: Payload(.caller_fused),
    source_raw: Payload(.source_raw),
    source_fold: Payload(.source_fold),
};
pub const Record = struct { index: u32, claim: Claim };
pub const Label = struct { family: Family, index: u32 };
pub fn label(pin: Bus.Expected) Label {
    return switch (pin) {
        .native => |v| .{ .family = .native, .index = v.index },
        .provider => |v| .{ .family = @enumFromInt(@intFromEnum(v.family) + 1), .index = v.index },
        .auxiliary => |v| .{ .family = @enumFromInt(@intFromEnum(v.family) + 5), .index = v.index },
    };
}
pub fn require(record: Record, pin: Bus.Expected) !void {
    const expected = label(pin);
    if (record.index != expected.index or std.meta.activeTag(record.claim) != expected.family) return error.UntrustedMixedClaimRoster;
}
pub const Limits = struct { max_bytes: usize = 16 << 20, max_owned_bytes: usize = 16 << 20, max_slice_elements: usize = 65536 };
