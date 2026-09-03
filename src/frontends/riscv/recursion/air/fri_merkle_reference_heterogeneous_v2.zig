//! Typed three-lane FRI-Merkle profile authority.
//!
//! FRI leaf, node, and anchor rows share one verifier-owned layer schedule.
//! V2 authenticates independent left and right schedules while preserving the
//! existing row encodings and semantic AIRs.

const std = @import("std");
const base = @import("fri_merkle_leaf_witness.zig");
const contract = @import("fri_merkle_leaf_witness_contract.zig");
const mapping_v2 = @import("query_mapping_witness_heterogeneous_v2.zig");
const roots_v2 = @import("merkle_root_witness_heterogeneous_v2.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const LANE_COUNT: usize = 3;
const REFERENCE_DOMAIN =
    "stwo-zig/typed-air/recursion-fri-merkle-reference/v2\x00";

pub const Error = base.Error || mapping_v2.Error || roots_v2.Error || error{
    InvalidHeterogeneousFriReference,
};

pub const Lane = struct {
    verifier_id: u32,
    profile: base.LaneProfile,
};

pub const Reference = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    lanes: [LANE_COUNT]Lane,
    authority_sha256: [32]u8,

    pub fn seal(
        vm: base.LaneProfile,
        left: base.LaneProfile,
        right: base.LaneProfile,
    ) Error!Reference {
        _ = try base.Reference.seal(vm, left);
        _ = try base.Reference.seal(vm, right);
        var result = Reference{
            .lanes = .{
                .{ .verifier_id = base.SEGMENT_VERIFIER_ID, .profile = vm },
                .{ .verifier_id = base.LEFT_RECURSION_VERIFIER_ID, .profile = left },
                .{ .verifier_id = base.RIGHT_RECURSION_VERIFIER_ID, .profile = right },
            },
            .authority_sha256 = undefined,
        };
        result.authority_sha256 = identity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const Reference) Error!void {
        if (self.format_version != FORMAT_VERSION or self.schema_version != SCHEMA_VERSION or
            self.lanes[0].verifier_id != base.SEGMENT_VERIFIER_ID or
            self.lanes[1].verifier_id != base.LEFT_RECURSION_VERIFIER_ID or
            self.lanes[2].verifier_id != base.RIGHT_RECURSION_VERIFIER_ID)
        {
            return error.InvalidHeterogeneousFriReference;
        }
        _ = try base.Reference.seal(self.lanes[0].profile, self.lanes[1].profile);
        _ = try base.Reference.seal(self.lanes[0].profile, self.lanes[2].profile);
        if (!std.mem.eql(u8, &self.authority_sha256, &identity(self)))
            return error.InvalidHeterogeneousFriReference;
    }

    pub fn validateQueryMapping(
        self: *const Reference,
        mapping: *const mapping_v2.Reference,
    ) Error!void {
        try self.validate();
        try mapping.validate();
        for (self.lanes, mapping.lanes) |fri_lane, mapping_lane| {
            if (fri_lane.verifier_id != mapping_lane.verifier_id)
                return error.InvalidHeterogeneousFriReference;
            try contract.laneMatchesMapping(fri_lane.profile, mapping_lane.profile);
        }
    }

    pub fn validateMerkleRoots(
        self: *const Reference,
        roots: *const roots_v2.Reference,
    ) Error!void {
        try self.validate();
        try roots.validate();
        for (self.lanes, roots.lanes) |fri_lane, root_lane| {
            if (fri_lane.verifier_id != root_lane.verifier_id or
                fri_lane.profile.query_count != root_lane.profile.query_count or
                fri_lane.profile.layers.len != root_lane.profile.fri_layer_count)
            {
                return error.InvalidHeterogeneousFriReference;
            }
        }
    }
};

fn identity(reference: *const Reference) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(REFERENCE_DOMAIN);
    hashInt(&hash, u16, reference.format_version);
    hashInt(&hash, u16, reference.schema_version);
    for (reference.lanes) |lane| {
        hashInt(&hash, u32, lane.verifier_id);
        contract.hashLane(&hash, lane.profile);
    }
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
