//! Detached parent parameter and claim admission, independent of component construction.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const air = struct {
    const qm31_mul_full = @import("air/qm31_mul_full.zig");
    const universal_catalog = @import("air/universal_catalog_entry.zig");
};
pub const manifest_mod = @import("air/universal_manifest_contract.zig");
pub const Relations = @import("air/universal_challenges.zig").UniversalRelations;
pub const LOGICAL_ROWS = @import("air/detached_parent_catalog_v1.zig").LOGICAL_ROWS;
const geometry = @import("air/universal_typed_geometry.zig");
const shared = @import("air/universal_shared_geometry.zig");
const WideGeometry = shared.PoseidonForManifest(manifest_mod, false, .canonical_only);
const CompactGeometry = shared.PoseidonForManifest(manifest_mod, true, .allow_reviewed_legacy);
const RangeGeometry = shared.RangeForManifest(manifest_mod);

// Retained proofs keep their original AIR. Only the authenticated geometry
// selects this verifier adapter; new witness production uses LOGICAL_ROWS.
pub const legacy_mul_entry = air.universal_catalog.Entry{ .Air = air.qm31_mul_full, .row = .qm31_mul, .requires_location = true };
pub fn usesLegacyMul(manifest: *const manifest_mod.Manifest) bool {
    const placement = manifest.placements[30] orelse return false;
    return std.meta.eql(placement.geometry, geometry.manifestGeometryForAir(legacy_mul_entry.Air, manifest_mod, .qm31_mul, placement.geometry.log_size));
}
pub fn usesLegacyPoseidon(manifest: *const manifest_mod.Manifest) bool {
    const placement = manifest.placements[34] orelse return false;
    return std.meta.eql(placement.geometry, WideGeometry.manifestGeometry(placement.geometry.log_size));
}

pub const ParametersV1 = struct {
    words: [manifest_mod.COMPONENT_COUNT][]const M31,
    poseidon_active_rows: u32,

    pub fn validate(self: ParametersV1, manifest: *const manifest_mod.Manifest) !void {
        try manifest.validate();
        const expected_count = LOGICAL_ROWS.len + 2 - @as(usize, @intFromBool(manifest.placements[14] == null));
        if (manifest.roster_count != expected_count) return error.DetachedParentManifestMismatch;
        inline for (LOGICAL_ROWS) |entry| try self.validateRow(entry, manifest);
        for (15..20) |row| if (manifest.placements[row] != null or self.words[row].len != 0)
            return error.DetachedParentManifestMismatch;
        const poseidon = manifest.placements[34] orelse return error.DetachedParentManifestMismatch;
        const range_placement = manifest.placements[35] orelse return error.DetachedParentManifestMismatch;
        if ((!usesLegacyPoseidon(manifest) and !CompactGeometry.acceptsGeometry(poseidon.geometry)) or
            !std.meta.eql(range_placement.geometry, RangeGeometry.manifestGeometry()) or
            self.words[34].len != 0 or self.words[35].len != 0 or
            self.poseidon_active_rows > (@as(u64, 1) << @intCast(poseidon.geometry.log_size)))
            return error.DetachedParentManifestMismatch;
    }

    fn validateRow(self: ParametersV1, comptime entry: air.universal_catalog.Entry, manifest: *const manifest_mod.Manifest) !void {
        const row = @intFromEnum(entry.row);
        if (row == 14 and manifest.placements[row] == null) {
            if (self.words[row].len != 0) return error.DetachedParentManifestMismatch;
            return;
        }
        const placement = manifest.placements[row] orelse return error.DetachedParentManifestMismatch;
        const legacy = row == 30 and usesLegacyMul(manifest);
        const expected = if (legacy) geometry.manifestGeometryForAir(legacy_mul_entry.Air, manifest_mod, .qm31_mul, placement.geometry.log_size) else geometry.manifestGeometryForAir(entry.Air, manifest_mod, entry.row, placement.geometry.log_size);
        const parameter_count = if (legacy) geometry.parameterColumnCount(legacy_mul_entry.Air) else geometry.parameterColumnCount(entry.Air);
        if (!std.meta.eql(placement.geometry, expected) or self.words[row].len != parameter_count)
            return error.DetachedParentManifestMismatch;
        for (self.words[row]) |word| try canonicalBase(word);
    }

    pub fn forRow(self: ParametersV1, comptime entry: air.universal_catalog.Entry) [geometry.parameterColumnCount(entry.Air)]M31 {
        const count = comptime geometry.parameterColumnCount(entry.Air);
        return self.words[@intFromEnum(entry.row)][0..count].*;
    }
};

pub const ClaimsV1 = struct {
    values: [manifest_mod.COMPONENT_COUNT]QM31,
    poseidon_partials: [2]QM31,
    interaction_pow: ?u64 = null,
    pub const jsonStringify = @import("detached_claims_v1.zig").jsonStringify;

    pub fn vector(self: ClaimsV1, manifest: *const manifest_mod.Manifest) !manifest_mod.ClaimVector {
        var result = try manifest_mod.ClaimVector.init(manifest);
        for (self.values, 0..) |value, row| {
            for (value.toM31Array()) |word| try canonicalBase(word);
            if (manifest.placements[row] != null) try result.bind(@enumFromInt(row), value) else if (!value.isZero())
                return error.DetachedParentInactiveClaim;
        }
        for (self.poseidon_partials) |partial| for (partial.toM31Array()) |word| try canonicalBase(word);
        if (!self.poseidon_partials[0].add(self.poseidon_partials[1]).eql(self.values[34]))
            return error.DetachedParentProviderClaimMismatch;
        try result.sealClaims(manifest);
        return result;
    }
};

pub fn canonicalBase(value: M31) !void {
    if (value.toU32() >= core.fields.m31.Modulus) return error.DetachedParentNonCanonicalField;
}
