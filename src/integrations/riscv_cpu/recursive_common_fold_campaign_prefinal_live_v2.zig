//! Target-bound live authority for the pre-final common-fold geometry proof.
//!
//! This source accepts only nominal role-0/role-1 cold leases admitted by the
//! same `CampaignPaddingTargetV2`.  It derives the parent NodePublic from the
//! authenticated runtime campaign shape and exposes the exact fixed-wire and
//! dynamic-manifest interfaces used by the common-fold secure engine.  It has
//! no registry, durable codec, or route; its sole purpose is to obtain role 2's
//! own cold geometry before FinalRemint can exist.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const target_mod = @import("recursive_pipeline_campaign_padding_target_v2.zig");
const prefinal =
    @import("recursive_pipeline_campaign_prefinal_fold_lease_v2.zig");
const campaign_public = @import("recursive_campaign_node_public_v2.zig");
const field_public = @import("recursive_common_fold_field_public_v2.zig");
const fixed_source = @import("recursive_common_fold_fixed_wire_v2.zig");
const manifest_mod = @import("recursive_common_fold_universal_manifest_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

const recursion = frontend.recursion;
const captured_fri = recursion.captured_fri;
const rows_source = recursion.binary_fri_outer_source;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const ROLE = registry_mod.CircuitRoleV1.common_fold_field_v2;
pub const CHILD_COUNT: usize = 2;
pub const LEFT_POSITION_CIRCUIT_ID: u32 = 761;
pub const RIGHT_POSITION_CIRCUIT_ID: u32 = 762;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;

const LIVE_DOMAIN =
    "stwo-zig/recursive-common-fold-campaign-prefinal-live/v2\x00";
const ROOT_PIN_DOMAIN =
    "stwo-zig/recursive-common-fold-campaign-prefinal-root-pin/v2\x00";
const MANIFEST_AUTHORITY_DOMAIN =
    "stwo-zig/recursive-common-fold-campaign-prefinal-manifest/v2\x00";

pub const Error = target_mod.Error || manifest_mod.Error || error{
    CampaignPreFinalChildAlias,
    CampaignPreFinalChildCustodyMismatch,
    CampaignPreFinalCommonFoldDimensionMismatch,
    CampaignPreFinalCommonFoldManifestMismatch,
    CampaignPreFinalCommonFoldTargetMismatch,
};

pub fn Types(comptime RealLease: type, comptime EmptyLease: type) type {
    assertLeafLease(RealLease, .ethereum_incremental_leaf_wrapper_v4);
    assertLeafLease(EmptyLease, .canonical_empty_field_v2);
    return TypesForFoldChild(LeafFoldChildV2(RealLease, EmptyLease));
}

fn LeafFoldChildV2(comptime RealLease: type, comptime EmptyLease: type) type {
    return union(enum(u8)) {
        ethereum_incremental_leaf_wrapper_v4: *const RealLease,
        canonical_empty_field_v2: *const EmptyLease,

        const Self = @This();

        pub fn fromReal(
            target: *const target_mod.CampaignPaddingTargetV2,
            lease: *const RealLease,
        ) !Self {
            const result = Self{
                .ethereum_incremental_leaf_wrapper_v4 = lease,
            };
            _ = try result.projection(target);
            return result;
        }

        pub fn fromEmpty(
            target: *const target_mod.CampaignPaddingTargetV2,
            lease: *const EmptyLease,
        ) !Self {
            const result = Self{
                .canonical_empty_field_v2 = lease,
            };
            _ = try result.projection(target);
            return result;
        }

        pub fn role(self: Self) registry_mod.CircuitRoleV1 {
            return switch (self) {
                .ethereum_incremental_leaf_wrapper_v4 => .ethereum_incremental_leaf_wrapper_v4,
                .canonical_empty_field_v2 => .canonical_empty_field_v2,
            };
        }

        pub fn projection(
            self: Self,
            target: *const target_mod.CampaignPaddingTargetV2,
        ) !prefinal.ProjectionV2 {
            const result = switch (self) {
                .ethereum_incremental_leaf_wrapper_v4 => |lease| blk: {
                    try lease.validateForPaddingTarget(target);
                    break :blk try lease.preFinalFoldProjection(target);
                },
                .canonical_empty_field_v2 => |lease| blk: {
                    try lease.validateForPaddingTarget(target);
                    break :blk try lease.preFinalFoldProjection(target);
                },
            };
            try result.validateAgainstPaddingTarget(target);
            if (result.role != self.role())
                return error.CampaignPreFinalChildCustodyMismatch;
            return result;
        }
    };
}

/// Shared implementation for the initial real+empty geometry transaction and
/// the post-final all-role campaign fold. `FoldChildType` must preserve its
/// nominal role and return the same target-bound neutral projection.
pub fn TypesForFoldChild(comptime FoldChildType: type) type {
    assertFoldChild(FoldChildType);

    return struct {
        const SelfTypes = @This();
        pub const FoldChild = FoldChildType;

        pub const CapturedFriPair = struct {
            children: [CHILD_COUNT]captured_fri.Owned,

            pub fn deinit(self: *CapturedFriPair) void {
                self.children[1].deinit();
                self.children[0].deinit();
                self.* = undefined;
            }
        };

        pub const FoldInputV2 = struct {
            padding_target: *const target_mod.CampaignPaddingTargetV2,
            parent_coordinate: campaign_public.TaskCoordinateV1,
            child_node_publics: [CHILD_COUNT]campaign_public.NodePublicV2,
            parent_node_public: campaign_public.NodePublicV2,

            pub fn init(
                target: *const target_mod.CampaignPaddingTargetV2,
                left: *const campaign_public.NodePublicV2,
                right: *const campaign_public.NodePublicV2,
                parent_coordinate: campaign_public.TaskCoordinateV1,
            ) !FoldInputV2 {
                const result = FoldInputV2{
                    .padding_target = target,
                    .parent_coordinate = parent_coordinate,
                    .child_node_publics = .{ left.*, right.* },
                    .parent_node_public = try campaign_public.initParent(
                        &target.shape,
                        left,
                        right,
                        parent_coordinate,
                    ),
                };
                try result.validate();
                return result;
            }

            pub fn validate(self: *const FoldInputV2) !void {
                try self.padding_target.validateSelf();
                try campaign_public.validateParentAgainst(
                    &self.padding_target.shape,
                    &self.parent_node_public,
                    &self.child_node_publics[0],
                    &self.child_node_publics[1],
                );
                if (!std.meta.eql(
                    self.parent_coordinate,
                    self.parent_node_public.coordinate,
                )) return error.CampaignPreFinalChildCustodyMismatch;
            }

            pub fn outputNodePublic(
                self: *const FoldInputV2,
            ) *const campaign_public.NodePublicV2 {
                return &self.parent_node_public;
            }
        };

        pub const LiveV2 = struct {
            pub const FoldChild = SelfTypes.FoldChild;
            pub const CapturedFriPair = SelfTypes.CapturedFriPair;

            input: *const FoldInputV2,
            children: [CHILD_COUNT]SelfTypes.FoldChild,
            padding_target: *const target_mod.CampaignPaddingTargetV2,
            public_schedule: field_public.PoseidonScheduleV2,
            identity_sha256: [32]u8,

            pub fn init(
                input: *const FoldInputV2,
                children: [CHILD_COUNT]SelfTypes.FoldChild,
            ) !LiveV2 {
                try input.validate();
                const left = try children[0].projection(input.padding_target);
                const right = try children[1].projection(input.padding_target);
                var result = LiveV2{
                    .input = input,
                    .children = children,
                    .padding_target = input.padding_target,
                    .public_schedule = try field_public.PoseidonScheduleV2.build(
                        left.node_public,
                        right.node_public,
                        input.parent_coordinate,
                    ),
                    .identity_sha256 = undefined,
                };
                result.identity_sha256 = try liveIdentity(&result);
                try result.validate();
                return result;
            }

            pub fn validate(self: *const LiveV2) !void {
                try self.input.validate();
                if (self.padding_target != self.input.padding_target)
                    return error.CampaignPreFinalCommonFoldTargetMismatch;
                const left = try self.children[0].projection(
                    self.padding_target,
                );
                const right = try self.children[1].projection(
                    self.padding_target,
                );
                if (left.node_public != &self.input.child_node_publics[0] or
                    right.node_public != &self.input.child_node_publics[1])
                {
                    // The input owns value copies, so compare values too; the
                    // pointers intentionally differ from the child owners.
                    if (!std.meta.eql(
                        left.node_public.*,
                        self.input.child_node_publics[0],
                    ) or !std.meta.eql(
                        right.node_public.*,
                        self.input.child_node_publics[1],
                    )) return error.CampaignPreFinalChildCustodyMismatch;
                }
                if (left.capture == right.capture or
                    left.graph.lane.graph.nodes.ptr ==
                        right.graph.lane.graph.nodes.ptr or
                    left.graph.evaluation.values.ptr ==
                        right.graph.evaluation.values.ptr)
                {
                    return error.CampaignPreFinalChildAlias;
                }
                const schedule = try field_public.PoseidonScheduleV2.build(
                    left.node_public,
                    right.node_public,
                    self.input.parent_coordinate,
                );
                if (!std.meta.eql(self.public_schedule, schedule) or
                    !std.meta.eql(
                        self.public_schedule.parent,
                        self.input.parent_node_public,
                    ) or !std.mem.eql(
                    u8,
                    &self.identity_sha256,
                    &try liveIdentity(self),
                )) return error.CampaignPreFinalChildCustodyMismatch;
            }

            pub fn requireFixedWireSource(self: *const LiveV2) !void {
                try self.validate();
                const left = try self.children[0].projection(
                    self.padding_target,
                );
                const right = try self.children[1].projection(
                    self.padding_target,
                );
                if (!try proofShapeDimensionsEqual(
                    &left.geometry.proof_shape,
                    &right.geometry.proof_shape,
                )) return error.CampaignPreFinalCommonFoldDimensionMismatch;
            }

            pub fn initCapturedFriPair(
                self: *const LiveV2,
                allocator: std.mem.Allocator,
            ) !SelfTypes.CapturedFriPair {
                try self.requireFixedWireSource();
                const left_projection = try self.children[0].projection(
                    self.padding_target,
                );
                const right_projection = try self.children[1].projection(
                    self.padding_target,
                );
                var left = try captured_fri.Owned.init(
                    allocator,
                    childProfile(left_projection),
                    left_projection.capture,
                );
                errdefer left.deinit();
                var right = try captured_fri.Owned.init(
                    allocator,
                    childProfile(right_projection),
                    right_projection.capture,
                );
                errdefer right.deinit();
                return .{ .children = .{ left, right } };
            }

            pub fn authenticatedCompositionLanes(
                self: *const LiveV2,
            ) ![CHILD_COUNT]rows_source.AuthenticatedCompositionLane {
                try self.validate();
                var result: [CHILD_COUNT]rows_source
                    .AuthenticatedCompositionLane = undefined;
                for (self.children, &result, 0..) |child, *destination, index| {
                    const projection = try child.projection(
                        self.padding_target,
                    );
                    destination.* = .{
                        .circuit_id = if (index == 0)
                            LEFT_POSITION_CIRCUIT_ID
                        else
                            RIGHT_POSITION_CIRCUIT_ID,
                        .circuit_identity = projection.graph.lane.graph
                            .identity_digest,
                        .graph = projection.graph.lane.graph,
                        .evaluation = projection.graph.evaluation,
                    };
                    try destination.validate();
                }
                return result;
            }
        };

        pub const RootPinV2 = struct {
            target_identity_sha256: [32]u8,
            live_identity_sha256: [32]u8,
            child_geometry_identities: [CHILD_COUNT][32]u8,
            identity_sha256: [32]u8,

            pub fn init(live: *const LiveV2) !RootPinV2 {
                try live.requireFixedWireSource();
                var result = RootPinV2{
                    .target_identity_sha256 = live.padding_target.identity_sha256,
                    .live_identity_sha256 = live.identity_sha256,
                    .child_geometry_identities = .{
                        (try live.children[0].projection(live.padding_target))
                            .geometry.authority_identity_sha256,
                        (try live.children[1].projection(live.padding_target))
                            .geometry.authority_identity_sha256,
                    },
                    .identity_sha256 = undefined,
                };
                result.identity_sha256 = rootPinIdentity(&result);
                return result;
            }

            pub fn validateAgainst(
                self: RootPinV2,
                live: *const LiveV2,
            ) !void {
                if (!std.meta.eql(self, try init(live)))
                    return error.CampaignPreFinalCommonFoldTargetMismatch;
            }
        };

        pub const FixedPolicyV2 = struct {
            pub const RootPin = RootPinV2;

            pub fn initRootPin(live: *const LiveV2) !RootPin {
                return RootPin.init(live);
            }

            pub fn validateRootPin(pin: RootPin, live: *const LiveV2) !void {
                return pin.validateAgainst(live);
            }

            pub fn validateDimensions(
                comptime dimensions: recursion.fixed_wire.Dimensions,
                live: *const LiveV2,
            ) !void {
                try live.requireFixedWireSource();
                for (live.children) |child| {
                    const projection = try child.projection(
                        live.padding_target,
                    );
                    const expected = try fixed_source.dimensionsFromShapeRuntime(
                        &projection.geometry.proof_shape,
                    );
                    if (!std.meta.eql(dimensions, expected))
                        return error.CampaignPreFinalCommonFoldDimensionMismatch;
                }
            }

            pub fn projectChild(
                child: FoldChild,
                live: *const LiveV2,
            ) !prefinal.ProjectionV2 {
                return child.projection(live.padding_target);
            }

            pub fn validateChildCustody(
                actual: prefinal.ProjectionV2,
                expected: prefinal.ProjectionV2,
                _: *const LiveV2,
            ) !void {
                if (actual.role != expected.role or
                    actual.padding_target != expected.padding_target or
                    actual.geometry != expected.geometry or
                    actual.node_public != expected.node_public or
                    actual.claimed_sums.ptr != expected.claimed_sums.ptr or
                    actual.claimed_sums.len != expected.claimed_sums.len or
                    actual.capture != expected.capture or
                    actual.query_words != expected.query_words or
                    actual.graph.lane.graph.nodes.ptr !=
                        expected.graph.lane.graph.nodes.ptr or
                    actual.graph.evaluation.values.ptr !=
                        expected.graph.evaluation.values.ptr)
                {
                    return error.CampaignPreFinalChildCustodyMismatch;
                }
            }
        };

        pub fn ManifestPolicyV2(comptime Fixed: type) type {
            return struct {
                pub fn initManifest(
                    live: *const LiveV2,
                    source_owner: *const Fixed.OwnerV2,
                ) !manifest_mod.Manifest {
                    try live.requireFixedWireSource();
                    try source_owner.validate();
                    try validateActiveLogs(live, source_owner);
                    return manifest_mod.buildForDerivedLogSizes(
                        try paddedLogs(live.padding_target),
                    );
                }

                pub fn validateManifest(
                    value: *const manifest_mod.Manifest,
                    live: *const LiveV2,
                    source_owner: *const Fixed.OwnerV2,
                ) !void {
                    const expected = try initManifest(live, source_owner);
                    if (!std.meta.eql(value.*, expected))
                        return error.CampaignPreFinalCommonFoldManifestMismatch;
                }

                pub fn contractIdentity(
                    _: *const LiveV2,
                    manifest: *const manifest_mod.Manifest,
                ) ![32]u8 {
                    return manifest_mod.contractIdentityForDerivedManifest(
                        manifest,
                        try logSizes(manifest),
                    );
                }

                pub fn profileIdentity(
                    _: *const LiveV2,
                    manifest: *const manifest_mod.Manifest,
                ) ![32]u8 {
                    return manifest_mod.profileIdentityForDerivedManifest(
                        manifest,
                        try logSizes(manifest),
                    );
                }

                pub fn programIdentity(
                    _: *const LiveV2,
                    manifest: *const manifest_mod.Manifest,
                ) ![32]u8 {
                    return manifest_mod.programIdentityForDerivedManifest(
                        manifest,
                        try logSizes(manifest),
                    );
                }

                pub fn paddingLayoutIdentity(
                    live: *const LiveV2,
                    manifest: *const manifest_mod.Manifest,
                ) ![32]u8 {
                    try validateTargetManifest(live, manifest);
                    return live.padding_target.target
                        .padding_table_layout_identity_sha256;
                }

                pub fn tableLayoutIdentity(
                    live: *const LiveV2,
                    manifest: *const manifest_mod.Manifest,
                ) ![32]u8 {
                    return paddingLayoutIdentity(live, manifest);
                }

                pub fn verificationKeyId(
                    _: *const LiveV2,
                    manifest: *const manifest_mod.Manifest,
                ) !recursion.poseidon2_channel.Digest {
                    return manifest_mod.verificationKeyIdForDerivedManifest(
                        manifest,
                        try logSizes(manifest),
                    );
                }

                pub fn nextParentVkId(
                    _: *const LiveV2,
                    manifest: *const manifest_mod.Manifest,
                ) !recursion.poseidon2_channel.Digest {
                    return manifest_mod.nextParentVkIdForDerivedManifest(
                        manifest,
                        try logSizes(manifest),
                    );
                }

                pub fn airProgramId(
                    _: *const LiveV2,
                    manifest: *const manifest_mod.Manifest,
                ) !recursion.poseidon2_channel.Digest {
                    return manifest_mod.airProgramIdForDerivedManifest(
                        manifest,
                        try logSizes(manifest),
                    );
                }

                pub fn authorityIdentity(
                    live: *const LiveV2,
                    manifest: *const manifest_mod.Manifest,
                ) [32]u8 {
                    var hash = Sha256.init(.{});
                    hash.update(MANIFEST_AUTHORITY_DOMAIN);
                    hash.update(&live.padding_target.identity_sha256);
                    hash.update(&live.identity_sha256);
                    hash.update(&manifest.seal);
                    return hash.finalResult();
                }
            };
        }
    };
}

fn validateActiveLogs(live: anytype, source_owner: anytype) !void {
    var derived = [_]u32{4} ** manifest_mod.COMPONENT_COUNT;
    try source_owner.source().installLogSizes(&derived);
    derived[manifest_mod.RANGE_ROW] = 16;
    const active = try live.padding_target.activeLogsForRole(ROLE);
    for (derived, active[0..manifest_mod.COMPONENT_COUNT]) |actual, expected|
        if (actual != expected)
            return error.CampaignPreFinalCommonFoldManifestMismatch;
}

fn paddedLogs(
    target: *const target_mod.CampaignPaddingTargetV2,
) !manifest_mod.LogSizes {
    const source = try target.paddedLogs();
    var result: manifest_mod.LogSizes = undefined;
    for (&result, source[0..manifest_mod.COMPONENT_COUNT]) |
        *destination,
        log_size,
    | destination.* = log_size;
    return result;
}

fn validateTargetManifest(live: anytype, manifest: anytype) !void {
    const expected = try manifest_mod.buildForDerivedLogSizes(
        try paddedLogs(live.padding_target),
    );
    if (!std.meta.eql(manifest.*, expected))
        return error.CampaignPreFinalCommonFoldManifestMismatch;
}

fn logSizes(
    manifest: *const manifest_mod.Manifest,
) !manifest_mod.LogSizes {
    var result: manifest_mod.LogSizes = undefined;
    inline for (manifest_mod.COMPONENT_KEYS, 0..) |key, index|
        result[index] = (try manifest.placement(key)).geometry.log_size;
    try manifest_mod.validateForDerivedLogSizes(manifest, result);
    return result;
}

fn childProfile(
    projection: prefinal.ProjectionV2,
) captured_fri.ProfileConfig {
    const pcs = projection.geometry.pcs;
    return .{
        .log_blowup_factor = pcs.fri_log_blowup_factor,
        .log_last_layer_degree_bound = pcs.fri_log_last_layer_degree_bound,
        .interaction_pow_bits = pcs.interaction_pow_bits,
        .pcs_pow_bits = pcs.pcs_pow_bits,
        .claimed_sum_count = @intCast(projection.geometry.component_count),
    };
}

fn proofShapeDimensionsEqual(
    left: *const registry_mod.FixedProofShapeV3,
    right: *const registry_mod.FixedProofShapeV3,
) !bool {
    return std.meta.eql(
        try fixed_source.dimensionsFromShapeRuntime(left),
        try fixed_source.dimensionsFromShapeRuntime(right),
    ) and left.fri_layer_count == right.fri_layer_count and
        std.mem.eql(
            u8,
            left.fri_layer_fold_widths[0..left.fri_layer_count],
            right.fri_layer_fold_widths[0..right.fri_layer_count],
        ) and std.mem.eql(
        u8,
        left.fri_layer_path_depths[0..left.fri_layer_count],
        right.fri_layer_path_depths[0..right.fri_layer_count],
    );
}

fn liveIdentity(live: anytype) ![32]u8 {
    var hash = Sha256.init(.{});
    hash.update(LIVE_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hash.update(&live.padding_target.identity_sha256);
    hash.update(&live.padding_target.shape.identity_sha256);
    hashInt(&hash, u8, live.input.parent_coordinate.height);
    hashInt(&hash, u32, live.input.parent_coordinate.index);
    hashInt(&hash, u32, live.input.parent_coordinate.global_ordinal);
    for (live.children) |child| {
        const projection = try child.projection(live.padding_target);
        hashInt(&hash, u8, @intFromEnum(projection.role));
        hash.update(&projection.geometry.authority_identity_sha256);
        hash.update(projection.graph.capture_identity_sha256);
        hash.update(projection.graph.layout_identity_sha256);
        hash.update(&projection.graph.lane.graph.identity_digest);
        hash.update(&projection.graph.evaluation.circuit_identity);
    }
    for (live.public_schedule.parent.output_digest) |word|
        hashInt(&hash, u32, word);
    return hash.finalResult();
}

fn rootPinIdentity(value: anytype) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(ROOT_PIN_DOMAIN);
    hash.update(&value.target_identity_sha256);
    hash.update(&value.live_identity_sha256);
    for (value.child_geometry_identities) |identity|
        hash.update(&identity);
    return hash.finalResult();
}

fn assertLeafLease(comptime Lease: type, comptime role: registry_mod.CircuitRoleV1) void {
    if (!@hasDecl(Lease, "ROLE") or Lease.ROLE != role)
        @compileError("campaign pre-final common fold received the wrong child role");
    inline for (.{
        "validateForPaddingTarget",
        "preFinalFoldProjection",
    }) |name| if (!@hasDecl(Lease, name))
        @compileError("campaign pre-final common fold child missing " ++ name);
}

fn assertFoldChild(comptime FoldChild: type) void {
    inline for (.{ "role", "projection" }) |name|
        if (!@hasDecl(FoldChild, name))
            @compileError("campaign common-fold child missing " ++ name);
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        @intFromEnum(ROLE) != 2 or CHILD_COUNT != 2 or
        LEFT_POSITION_CIRCUIT_ID == RIGHT_POSITION_CIRCUIT_ID or
        field_public.POSEIDON_CALL_COUNT != 116 or PRODUCTION_ACTIVATION or
        ROUTER_ACTIVATION or SERIALIZABLE_FRESH_CAPABILITY)
    {
        @compileError("campaign pre-final common-fold live contract drifted");
    }
}
