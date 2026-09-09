//! Process-local input boundary for the field-native common recursive fold.
//!
//! Both child leases must be live and freshly admitted. Only their durable
//! schema-2 references and field-native parent relation enter the pointer-free
//! diagnostic identity; the views themselves are never serialized.

const std = @import("std");

const artifact_mod = @import("recursive_node_artifact_v2.zig");
const artifact_v1 = @import("recursive_node_artifact_v1.zig");
const authority_mod = @import("recursive_common_wrapper_authority_v2.zig");
const manifest_mod = @import("recursive_common_wrapper_manifest_v1.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 2;
pub const CHILD_COUNT: usize = 2;
pub const PRODUCTION_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_INPUT = false;

const IDENTITY_DOMAIN = "stwo-zig/recursive-common-fold-input/v2\x00";

pub const Error = authority_mod.Error || error{
    AliasedCommonFoldChild,
    CommonFoldCampaignMismatch,
    CommonFoldInputMismatch,
    CommonFoldRegistryMismatch,
};

pub const FreshFoldInputV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    parent_coordinate: artifact_mod.TaskCoordinateV1,
    parent_node_kind: artifact_mod.NodeKindV1,
    ordered_child_circuits: [CHILD_COUNT]manifest_mod.RegisteredChildCircuitV1,
    child_views: [CHILD_COUNT]authority_mod.FreshWrapperViewV2,
    child_refs: [CHILD_COUNT]artifact_mod.ArtifactRefV1,
    campaign_namespace_sha256: [32]u8,
    registry_identity_sha256: [32]u8,
    parent: authority_mod.ParentNodePublicDerivationV2,
    identity_sha256: [32]u8,

    pub fn init(
        left: authority_mod.FreshWrapperViewV2,
        right: authority_mod.FreshWrapperViewV2,
        parent_coordinate: artifact_mod.TaskCoordinateV1,
        registry: *const registry_mod.RecursiveCircuitRegistryV1,
    ) !FreshFoldInputV2 {
        try registry.validate();
        try left.validateAgainst(registry);
        try right.validateAgainst(registry);
        try rejectAliasedChildren(left, right);
        const child_refs = [CHILD_COUNT]artifact_mod.ArtifactRefV1{
            try left.reference(),
            try right.reference(),
        };
        const campaign_namespace_sha256 =
            left.artifact.campaign_namespace_sha256;
        if (!std.mem.eql(
            u8,
            &campaign_namespace_sha256,
            &right.artifact.campaign_namespace_sha256,
        )) return error.CommonFoldCampaignMismatch;

        var result = FreshFoldInputV2{
            .parent_coordinate = parent_coordinate,
            .parent_node_kind = try artifact_v1.expectedNodeKind(
                parent_coordinate,
            ),
            .ordered_child_circuits = .{
                try childCircuit(left),
                try childCircuit(right),
            },
            .child_views = .{ left, right },
            .child_refs = child_refs,
            .campaign_namespace_sha256 = campaign_namespace_sha256,
            .registry_identity_sha256 = registry.identity_sha256,
            .parent = try authority_mod.deriveParentNodePublic(
                left,
                right,
                parent_coordinate,
                registry,
            ),
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = inputIdentity(&result);
        try result.validateAgainst(registry);
        return result;
    }

    pub fn validateAgainst(
        self: *const FreshFoldInputV2,
        registry: *const registry_mod.RecursiveCircuitRegistryV1,
    ) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION)
        {
            return error.CommonFoldInputMismatch;
        }
        try registry.validate();
        if (!std.mem.eql(
            u8,
            &self.registry_identity_sha256,
            &registry.identity_sha256,
        )) return error.CommonFoldRegistryMismatch;
        try rejectAliasedChildren(self.child_views[0], self.child_views[1]);
        for (self.child_views, self.child_refs, self.ordered_child_circuits) |
            child,
            child_ref,
            child_circuit,
        | {
            try child.validateAgainst(registry);
            if (!std.meta.eql(child_ref, try child.reference()) or
                child_circuit != try childCircuit(child))
            {
                return error.CommonFoldInputMismatch;
            }
        }
        if (!std.mem.eql(
            u8,
            &self.campaign_namespace_sha256,
            &self.child_views[0].artifact.campaign_namespace_sha256,
        ) or !std.mem.eql(
            u8,
            &self.campaign_namespace_sha256,
            &self.child_views[1].artifact.campaign_namespace_sha256,
        )) return error.CommonFoldCampaignMismatch;
        try self.parent_coordinate.validate();
        if (self.parent_node_kind != try artifact_v1.expectedNodeKind(
            self.parent_coordinate,
        )) return error.CommonFoldInputMismatch;
        try self.parent.validateAgainst(
            self.child_views[0],
            self.child_views[1],
            self.parent_coordinate,
            registry,
        );
        if (!std.mem.eql(
            u8,
            &self.identity_sha256,
            &inputIdentity(self),
        )) return error.CommonFoldInputMismatch;
    }

    pub fn orderedPair(
        self: *const FreshFoldInputV2,
    ) manifest_mod.OrderedChildCircuitPairV1 {
        return .{
            .left = self.ordered_child_circuits[0],
            .right = self.ordered_child_circuits[1],
        };
    }

    pub fn outputNodePublic(self: *const FreshFoldInputV2) *const artifact_mod.NodePublicV2 {
        return &self.parent.node_public;
    }
};

fn rejectAliasedChildren(
    left: authority_mod.FreshWrapperViewV2,
    right: authority_mod.FreshWrapperViewV2,
) !void {
    if (left.artifact == right.artifact or left.capture == right.capture or
        std.meta.eql(try left.reference(), try right.reference()))
    {
        return error.AliasedCommonFoldChild;
    }
}

fn childCircuit(
    child: authority_mod.FreshWrapperViewV2,
) !manifest_mod.RegisteredChildCircuitV1 {
    return switch (try child.role()) {
        .ethereum_incremental_leaf_wrapper_v4 => .real_leaf_wrapper,
        .canonical_empty_field_v2 => .empty_leaf_wrapper,
        manifest_mod.COMMON_FOLD_ROLE => .common_fold,
    };
}

fn inputIdentity(value: *const FreshFoldInputV2) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, value.parent_coordinate.height);
    hashInt(&hash, u32, value.parent_coordinate.index);
    hashInt(&hash, u32, value.parent_coordinate.global_ordinal);
    hashInt(&hash, u8, @intFromEnum(value.parent_node_kind));
    hash.update(&value.campaign_namespace_sha256);
    hash.update(&value.registry_identity_sha256);
    for (value.ordered_child_circuits, value.child_refs) |kind, ref| {
        hashInt(&hash, u8, @intFromEnum(kind));
        hashInt(&hash, u32, ref.kind);
        hashInt(&hash, u16, ref.format_version);
        hashInt(&hash, u16, ref.schema_version);
        hashInt(&hash, u64, ref.byte_count);
        hash.update(&ref.sha256);
    }
    for (value.parent.node_public.output_digest) |word|
        hashInt(&hash, u32, word);
    return hash.finalResult();
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (FORMAT_VERSION != 1 or SCHEMA_VERSION != 2 or CHILD_COUNT != 2 or
        PRODUCTION_ACTIVATION or SERIALIZABLE_FRESH_INPUT)
    {
        @compileError("field-native common fold input drifted");
    }
}
