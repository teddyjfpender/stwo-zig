//! Verifier-only admission parameters and untrusted claims for all 39 leaf rows.
const std = @import("std");
const core = @import("stwo_core");
const QM31 = core.fields.qm31.QM31;
const manifest_mod = @import("air/segment_outer_manifest_contract_v2.zig");

pub const AdmissionParametersV1 = struct {
    query_reference: @import("air/query_bits_profile.zig").Reference,
    poseidon_active_rows: u32,

    pub fn validate(self: AdmissionParametersV1, manifest: *const manifest_mod.Manifest) ![manifest_mod.COMPONENT_COUNT]u32 {
        try manifest.validate();
        var logs: [manifest_mod.COMPONENT_COUNT]u32 = undefined;
        for (manifest.placements, &logs) |placement, *log|
            log.* = (placement orelse return error.InvalidSegmentVerifierAdmission).geometry.log_size;
        try self.query_reference.validate();
        const query_rows = try std.math.add(u64, self.query_reference.vm.query_count, try std.math.mul(u64, 2, self.query_reference.recursion.query_count));
        if (query_rows > (@as(u64, 1) << @intCast(logs[@intFromEnum(manifest_mod.ComponentKey.query_bits)])) or
            self.poseidon_active_rows > (@as(u64, 1) << @intCast(logs[@intFromEnum(manifest_mod.ComponentKey.poseidon2)])))
            return error.InvalidSegmentVerifierAdmission;
        return logs;
    }
};

pub const ClaimsV1 = struct {
    values: [manifest_mod.COMPONENT_COUNT]QM31,
    poseidon_partials: [2]QM31,
    /// Required by the separately admitted q193 transcript. Absence preserves
    /// the original development wire; nonce zero is still a present nonce.
    interaction_pow: ?u64 = null,

    pub const jsonStringify = @import("detached_claims_v1.zig").jsonStringify;

    pub fn vector(self: ClaimsV1, manifest: *const manifest_mod.Manifest) !manifest_mod.ClaimVector {
        var result = try manifest_mod.ClaimVector.init(manifest);
        for (self.values, 0..) |value, index| {
            try canonical(value);
            try result.bind(@enumFromInt(index), value);
        }
        for (self.poseidon_partials) |partial| try canonical(partial);
        if (!self.poseidon_partials[0].add(self.poseidon_partials[1]).eql(self.values[@intFromEnum(manifest_mod.ComponentKey.poseidon2)]))
            return error.InvalidSegmentVerifierClaims;
        try (@import("segment_statement_claims_v2.zig").ClaimsV2{ .row10_inactive = self.values[10], .row11_statement = self.values[11] }).validate();
        try result.sealClaims(manifest);
        return result;
    }
};

fn canonical(value: QM31) !void {
    for (value.toM31Array()) |limb| if (limb.toU32() >= core.fields.m31.Modulus) return error.InvalidSegmentVerifierClaims;
}
