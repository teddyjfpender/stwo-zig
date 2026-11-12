const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const base_statement = @import("../air/statement.zig");
const lookup_physical_v2 = @import("../air/lang/lookup_physical_manifest.zig");
pub fn count(core: *const base_statement.RiscVStatement, manifest: *const lookup_physical_v2.Manifest, authenticated: *const lookup_physical_v2.AuthenticatedStatement, claim: *const base_statement.RiscVInteractionClaim) !usize {
    _ = try authenticated.canonicalInteractionClaim(core, manifest, claim);
    var total_count: usize = authenticated.detailed_claim_count;
    for (core.infra_descs[0..core.n_infra]) |descriptor| {
        total_count = try std.math.add(usize, total_count, base_statement.nClaimedSumsForInfra(descriptor.kind));
    }
    return total_count;
}
pub fn write(core: *const base_statement.RiscVStatement, manifest: *const lookup_physical_v2.Manifest, claim: *const base_statement.RiscVInteractionClaim, selected_count: usize, destination: []QM31) !void {
    if (destination.len != selected_count) return error.InvalidContextCounts;
    var cursor: usize = 0;
    for (core.component_descs[0..core.n_components], 0..) |descriptor, index| {
        const row_count = manifest.entryForFamily(descriptor.family).detailed_claim_count;
        const values = try claim.opcodeClaims(descriptor.family, index);
        @memcpy(destination[cursor..][0..row_count], values[0..row_count]);
        cursor += row_count;
    }
    for (core.infra_descs[0..core.n_infra], 0..) |descriptor, index| {
        const values = try claim.infraClaims(descriptor.kind, index);
        @memcpy(destination[cursor..][0..values.len], values);
        cursor += values.len;
    }
    if (cursor != destination.len) return error.InvalidContextCounts;
}
