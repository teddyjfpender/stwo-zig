const std = @import("std");
const core = @import("stwo_core");
const subject = @import("ethereum_initial_input_manifest_v1.zig");
const base = @import("universal_adapter_manifest.zig");
const universal = @import("universal_manifest.zig");
const profile = @import("../incremental_ethereum_composition_profile_v4.zig");

fn ordinaryManifest() !base.Manifest {
    var logs = [_]u32{4} ** base.COMPONENT_COUNT;
    logs[@intFromEnum(base.ComponentKey.range_check_8_8)] = @import("range_check_8_8_bridge.zig").LOG_SIZE;
    return universal.buildForCatalog(profile.StatementRoutingOuterCatalog, logs);
}

test "Ethereum initial manifest appends exact typed lanes and rejects drift" {
    const ordinary = try ordinaryManifest();
    const value = try subject.build(&ordinary, 675173);
    try value.validate();
    try std.testing.expectEqual(@as(u8, 38), value.roster_count);
    try std.testing.expectEqualDeep(ordinary.placements, value.placements[0..36].*);
    try std.testing.expectEqual(@as(u32, 20), value.placements[36].?.geometry.log_size);
    try std.testing.expectEqual(@as(u32, 4), value.placements[37].?.geometry.log_size);
    try std.testing.expectEqualDeep(subject.LaneAir.SEMANTIC_DIGEST, value.placements[36].?.geometry.semantic_digest);
    try std.testing.expectEqualDeep(subject.PacketAir.SEMANTIC_DIGEST, value.placements[37].?.geometry.semantic_digest);
    inline for (.{ "roster_row", "log_size", "main_columns", "preprocessed_columns", "interaction_columns", "protocol_constraint_degree" }) |field| {
        var changed = value;
        @field(changed.placements[36].?.geometry, field) +%= 1;
        try std.testing.expectError(error.ManifestSealMismatch, changed.validate());
    }
    var missing = value;
    missing.placements[37] = null;
    try std.testing.expectError(error.ManifestSealMismatch, missing.validate());
    var changed_shape = value;
    changed_shape.input_capacity += 1;
    try std.testing.expectError(error.ManifestSealMismatch, changed_shape.validate());
    const other_shape = try subject.build(&ordinary, 675174);
    // Equal padded logs cannot conceal a different admitted input shape.
    try std.testing.expectEqual(value.placements[36].?.geometry.log_size, other_shape.placements[36].?.geometry.log_size);
    try std.testing.expect(!std.meta.eql(value.seal, other_shape.seal));
}

test "Ethereum initial manifest requires both new component claims" {
    const ordinary = try ordinaryManifest();
    const value = try subject.build(&ordinary, 675173);
    var claims = try subject.ClaimVector.init(&value);
    for (0..36) |index| try claims.bind(@enumFromInt(index), core.fields.qm31.QM31.zero());
    try std.testing.expectError(error.ClaimMissing, claims.sealClaims(&value));
    try claims.bind(.ethereum_initial_input_lane, core.fields.qm31.QM31.zero());
    try std.testing.expectError(error.ClaimMissing, claims.sealClaims(&value));
    try claims.bind(.ethereum_initial_input_packet, core.fields.qm31.QM31.zero());
    try claims.sealClaims(&value);
    try claims.validate(&value);
    try std.testing.expectError(error.ClaimAlreadyBound, claims.bind(.ethereum_initial_input_lane, core.fields.qm31.QM31.zero()));
    claims.values[37] = core.fields.qm31.QM31.one();
    try std.testing.expectError(error.ClaimSealMismatch, claims.validate(&value));
    var gate = try subject.ProofGate.init(&value);
    try std.testing.expectError(error.AdapterCountMismatch, gate.sealGate(&value));
}
