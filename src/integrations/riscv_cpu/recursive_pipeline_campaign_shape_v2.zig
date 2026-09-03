//! Process-local authenticated campaign topology for recursive worker stages.
//!
//! Cardinalities are derived from the admitted real-leaf count. Product
//! profiles may require an exact count at their outer admission boundary, but
//! recursive stages consume only this campaign-bound authority and never a
//! product literal. The value is metadata authority, not proof freshness.

const std = @import("std");

const node_artifact = @import("recursive_node_artifact_v2.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;

const identity_domain =
    "stwo-zig/recursive-pipeline-campaign-shape/v2\x00";

pub const Error = error{
    ArithmeticOverflow,
    InvalidCampaignShapeV2,
    InvalidCampaignShapeCoordinateV2,
};

pub const ParentCoordinateV2 = struct {
    height: u8,
    index: u32,
    global_ordinal: u32,
    node_kind: node_artifact.NodeKindV1,
};

/// This value must be retained by the provider which cold-admitted the
/// inventory named by `inventory_identity_sha256`. A stage revalidates the
/// seal and campaign namespace on every use; it never accepts caller options
/// as cardinality authority.
pub const CampaignShapeAuthorityV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    campaign_namespace_sha256: [32]u8,
    inventory_identity_sha256: [32]u8,
    real_leaf_count: u32,
    padded_leaf_count: u32,
    empty_leaf_count: u32,
    fold_count: u32,
    root_height: u8,
    reserved: [3]u8 = .{ 0, 0, 0 },
    identity_sha256: [32]u8,

    pub fn init(
        campaign_namespace_sha256: [32]u8,
        inventory_identity_sha256: [32]u8,
        real_leaf_count: u32,
    ) Error!CampaignShapeAuthorityV2 {
        if (allZero(campaign_namespace_sha256) or
            allZero(inventory_identity_sha256))
        {
            return error.InvalidCampaignShapeV2;
        }
        const topology = try deriveTopology(real_leaf_count);
        var result = CampaignShapeAuthorityV2{
            .campaign_namespace_sha256 = campaign_namespace_sha256,
            .inventory_identity_sha256 = inventory_identity_sha256,
            .real_leaf_count = real_leaf_count,
            .padded_leaf_count = topology.padded_leaf_count,
            .empty_leaf_count = topology.empty_leaf_count,
            .fold_count = topology.fold_count,
            .root_height = topology.root_height,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = shapeIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const CampaignShapeAuthorityV2) Error!void {
        const expected = try deriveTopology(self.real_leaf_count);
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            allZero(self.campaign_namespace_sha256) or
            allZero(self.inventory_identity_sha256) or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            self.padded_leaf_count != expected.padded_leaf_count or
            self.empty_leaf_count != expected.empty_leaf_count or
            self.fold_count != expected.fold_count or
            self.root_height != expected.root_height or
            !std.mem.eql(u8, &self.identity_sha256, &shapeIdentity(self)))
        {
            return error.InvalidCampaignShapeV2;
        }
    }

    pub fn validateAgainstCampaign(
        self: *const CampaignShapeAuthorityV2,
        campaign_namespace_sha256: [32]u8,
    ) Error!void {
        try self.validate();
        if (!std.mem.eql(
            u8,
            &self.campaign_namespace_sha256,
            &campaign_namespace_sha256,
        )) return error.InvalidCampaignShapeV2;
    }

    pub fn nodeCount(
        self: *const CampaignShapeAuthorityV2,
        height: u8,
    ) Error!u32 {
        try self.validate();
        if (height > self.root_height)
            return error.InvalidCampaignShapeCoordinateV2;
        return self.padded_leaf_count >> @intCast(height);
    }

    pub fn parentCoordinate(
        self: *const CampaignShapeAuthorityV2,
        height: u8,
        index: u32,
    ) Error!ParentCoordinateV2 {
        try self.validate();
        if (height == 0 or height > self.root_height or
            index >= self.padded_leaf_count >> @intCast(height))
        {
            return error.InvalidCampaignShapeCoordinateV2;
        }
        const width = @as(u32, 1) << @intCast(height);
        const first = std.math.mul(u32, index, width) catch
            return error.ArithmeticOverflow;
        const end = std.math.add(u32, first, width) catch
            return error.ArithmeticOverflow;
        const node_kind: node_artifact.NodeKindV1 = if (end <= self.real_leaf_count)
            .real
        else if (first >= self.real_leaf_count)
            .empty
        else
            .mixed;
        return .{
            .height = height,
            .index = index,
            .global_ordinal = try self.globalOrdinal(height, index),
            .node_kind = node_kind,
        };
    }

    fn globalOrdinal(
        self: *const CampaignShapeAuthorityV2,
        height: u8,
        index: u32,
    ) Error!u32 {
        var offset: u32 = 0;
        var cursor: u8 = 0;
        while (cursor < height) : (cursor += 1) {
            offset = std.math.add(
                u32,
                offset,
                self.padded_leaf_count >> @intCast(cursor),
            ) catch return error.ArithmeticOverflow;
        }
        return std.math.add(u32, offset, index) catch
            return error.ArithmeticOverflow;
    }
};

const DerivedTopologyV2 = struct {
    padded_leaf_count: u32,
    empty_leaf_count: u32,
    fold_count: u32,
    root_height: u8,
};

fn deriveTopology(real_leaf_count: u32) Error!DerivedTopologyV2 {
    if (real_leaf_count < 2) return error.InvalidCampaignShapeV2;
    const padded = std.math.ceilPowerOfTwo(u32, real_leaf_count) catch
        return error.ArithmeticOverflow;
    return .{
        .padded_leaf_count = padded,
        .empty_leaf_count = padded - real_leaf_count,
        .fold_count = padded - 1,
        .root_height = @intCast(std.math.log2_int(u32, padded)),
    };
}

fn shapeIdentity(value: *const CampaignShapeAuthorityV2) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(identity_domain);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.campaign_namespace_sha256);
    hash.update(&value.inventory_identity_sha256);
    hashInt(&hash, u32, value.real_leaf_count);
    hashInt(&hash, u32, value.padded_leaf_count);
    hashInt(&hash, u32, value.empty_leaf_count);
    hashInt(&hash, u32, value.fold_count);
    hashInt(&hash, u8, value.root_height);
    hash.update(&value.reserved);
    return hash.finalResult();
}

fn allZero(value: [32]u8) bool {
    return std.mem.allEqual(u8, &value, 0);
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1)
        @compileError("campaign shape authority version drifted");
}
