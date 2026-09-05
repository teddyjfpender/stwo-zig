//! Recursive campaign child cold-opener for final Stage104 leases.
//!
//! Each kind-10/schema-2 child ref is reopened and authenticated before its
//! nominal role selects a cold verifier. Real and empty children are heap-
//! owned role-specific leases; common children recursively invoke the same
//! final role-2 lease type. The returned pair has one exact deinitializer and
//! projects only borrowed tagged capabilities. Nothing here has a codec.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");
const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");
const campaign_store =
    @import("recursive_campaign_node_artifact_store_v2.zig");
const campaign_cas = @import("recursive_pipeline_worker_campaign_cas_v2.zig");
const empty_source =
    @import("recursive_common_canonical_empty_campaign_source_v2.zig");
const empty_proof =
    @import("recursive_common_canonical_empty_campaign_universal_proof_v2.zig");
const empty_child =
    @import("recursive_common_canonical_empty_campaign_fold_child_v2.zig");
const node_store = @import("recursive_node_artifact_store_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const CHILD_COUNT: usize = 2;
pub const TRANSITIVE_Q193_GATE_GREEN = false;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const GENUINE_GATE_ONLY = true;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const COLD_OPEN_OWNS_EVERY_CHILD = true;
pub const PARTIAL_FAILURE_DEINITS_EXACTLY_ONCE = true;

pub const Authority = final_mod.CampaignFinalRemintAuthorityV2;
pub const EmptyLease = empty_child.OwnedLeaseV2;
pub const Role = registry_mod.CircuitRoleV1;

pub const Error = error{
    CampaignChildColdOpenAlias,
    CampaignChildColdOpenMismatch,
    CampaignChildColdOpenUnavailable,
};

/// `RealColdOpener` retains the Stage101 inventory/materialization authority
/// required by role 0. It returns the frozen campaign role-0 final lease and
/// must compare that lease's node artifact with the supplied transport.
pub fn Factory(comptime RealLease: type, comptime RealColdOpener: type) type {
    assertRoleLease(RealLease, .ethereum_incremental_leaf_wrapper_v4);
    assertRealColdOpener(RealColdOpener, RealLease);

    return struct {
        pub fn ForDependencyLease(comptime Lease: type) type {
            assertDependencyLease(Lease);
            const CommonLease = commonLeaseType(Lease);
            assertRoleLease(CommonLease, .common_fold_field_v2);

            return struct {
                const Self = @This();

                pub const available = TRANSITIVE_Q193_GATE_GREEN and
                    RealColdOpener.available;
                pub const genuine_gate_only = GENUINE_GATE_ONLY;
                pub const DependencyLease = Lease;
                pub const CommonLeaseV2 = CommonLease;
                pub const RealLeaseV4 = RealLease;
                pub const RealColdOpenerV4 = RealColdOpener;

                pub const OwnedChild = union(Role) {
                    ethereum_incremental_leaf_wrapper_v4: *RealLease,
                    canonical_empty_field_v2: *EmptyLease,
                    common_fold_field_v2: *CommonLease,

                    pub fn deinit(
                        self: *OwnedChild,
                        allocator: std.mem.Allocator,
                    ) void {
                        switch (self.*) {
                            inline else => |value| {
                                value.deinit();
                                allocator.destroy(value);
                            },
                        }
                        self.* = undefined;
                    }

                    pub fn dependency(
                        self: *const OwnedChild,
                    ) Lease {
                        return switch (self.*) {
                            .ethereum_incremental_leaf_wrapper_v4 => |value| Lease.fromReal(value),
                            .canonical_empty_field_v2 => |value| Lease.fromEmpty(value),
                            .common_fold_field_v2 => |value| Lease.fromCommon(value),
                        };
                    }
                };

                pub const OwnedPair = struct {
                    children: [CHILD_COUNT]OwnedChild,

                    pub fn deinit(
                        self: *OwnedPair,
                        allocator: std.mem.Allocator,
                    ) void {
                        self.children[1].deinit(allocator);
                        self.children[0].deinit(allocator);
                        self.* = undefined;
                    }
                };

                pub fn coldOpenPairFromInputs(
                    allocator: std.mem.Allocator,
                    store: *artifact_store.Store,
                    authority: *const Authority,
                    ordered_inputs: []const artifact_store.InputRefV1,
                ) !OwnedPair {
                    if (!available)
                        return error.CampaignChildColdOpenUnavailable;
                    return coldOpenPair(
                        allocator,
                        store,
                        authority,
                        ordered_inputs,
                        false,
                    );
                }

                /// Exact transitive q193 gate over the production nominal
                /// owners. This bypasses only the still-false route-release
                /// boolean; every CAS, campaign, proof, and pointer check is
                /// identical to the eventual production cold-open body.
                pub fn coldOpenPairForGenuineGate(
                    allocator: std.mem.Allocator,
                    store: *artifact_store.Store,
                    authority: *const Authority,
                    ordered_inputs: []const artifact_store.InputRefV1,
                ) !OwnedPair {
                    return coldOpenPair(
                        allocator,
                        store,
                        authority,
                        ordered_inputs,
                        true,
                    );
                }

                fn coldOpenPair(
                    allocator: std.mem.Allocator,
                    store: *artifact_store.Store,
                    authority: *const Authority,
                    ordered_inputs: []const artifact_store.InputRefV1,
                    comptime genuine_gate: bool,
                ) !OwnedPair {
                    try authority.validateAgainstCampaign(
                        authority.shape.campaign_namespace_sha256,
                    );
                    try validateInputs(ordered_inputs);
                    var left = try coldOpenChild(
                        allocator,
                        store,
                        authority,
                        ordered_inputs[0].blob,
                        genuine_gate,
                    );
                    var left_owned = true;
                    errdefer if (left_owned) left.deinit(allocator);
                    var right = try coldOpenChild(
                        allocator,
                        store,
                        authority,
                        ordered_inputs[1].blob,
                        genuine_gate,
                    );
                    errdefer right.deinit(allocator);
                    if (std.meta.activeTag(left) ==
                        std.meta.activeTag(right) and
                        artifact_store.BlobRefV1.eql(
                            ordered_inputs[0].blob,
                            ordered_inputs[1].blob,
                        )) return error.CampaignChildColdOpenAlias;
                    left_owned = false;
                    const result = OwnedPair{ .children = .{ left, right } };
                    left = undefined;
                    right = undefined;
                    return result;
                }

                pub fn views(
                    pair: *const OwnedPair,
                    authority: *const Authority,
                ) ![CHILD_COUNT]Lease {
                    try authority.validateAgainstCampaign(
                        authority.shape.campaign_namespace_sha256,
                    );
                    const result = [CHILD_COUNT]Lease{
                        pair.children[0].dependency(),
                        pair.children[1].dependency(),
                    };
                    for (&result) |*child| try child.validateAgainst(
                        authority,
                    );
                    return result;
                }

                pub fn deinitOwnedPair(
                    pair: *OwnedPair,
                    allocator: std.mem.Allocator,
                ) void {
                    pair.deinit(allocator);
                }

                fn coldOpenChild(
                    allocator: std.mem.Allocator,
                    store: *artifact_store.Store,
                    authority: *const Authority,
                    node_ref: artifact_store.BlobRefV1,
                    comptime genuine_gate: bool,
                ) !OwnedChild {
                    try campaign_cas.validate(node_ref, .recursion_node);
                    const artifact = try campaign_store
                        .coldOpenRecursiveNodeTransport(
                        store,
                        authority.shape,
                        node_ref,
                    );
                    return switch (try roleForArtifact(&artifact)) {
                        .ethereum_incremental_leaf_wrapper_v4 => blk: {
                            const value = try allocator.create(RealLease);
                            errdefer allocator.destroy(value);
                            value.* = if (comptime genuine_gate)
                                try RealColdOpener
                                    .coldOpenNodeForGenuineGate(
                                    allocator,
                                    store,
                                    authority,
                                    node_ref,
                                    &artifact,
                                )
                            else
                                try RealColdOpener.coldOpenNode(
                                    allocator,
                                    store,
                                    authority,
                                    node_ref,
                                    &artifact,
                                );
                            errdefer value.deinit();
                            try validateRoleNode(
                                value,
                                authority,
                                node_ref,
                                &artifact,
                            );
                            break :blk .{
                                .ethereum_incremental_leaf_wrapper_v4 = value,
                            };
                        },
                        .canonical_empty_field_v2 => blk: {
                            const value = try allocator.create(EmptyLease);
                            errdefer allocator.destroy(value);
                            value.* = try coldOpenEmpty(
                                allocator,
                                store,
                                authority,
                                &artifact,
                            );
                            errdefer value.deinit();
                            try validateRoleNode(
                                value,
                                authority,
                                node_ref,
                                &artifact,
                            );
                            break :blk .{
                                .canonical_empty_field_v2 = value,
                            };
                        },
                        .common_fold_field_v2 => blk: {
                            const value = try allocator.create(CommonLease);
                            errdefer allocator.destroy(value);
                            value.* = if (comptime genuine_gate)
                                try Lease.coldOpenCommonNodeForGenuineGate(
                                    allocator,
                                    store,
                                    authority,
                                    node_ref,
                                )
                            else
                                try Lease.coldOpenCommonNode(
                                    allocator,
                                    store,
                                    authority,
                                    node_ref,
                                );
                            errdefer value.deinit();
                            try validateRoleNode(
                                value,
                                authority,
                                node_ref,
                                &artifact,
                            );
                            break :blk .{ .common_fold_field_v2 = value };
                        },
                    };
                }

                comptime {
                    if (Self.DependencyLease != Lease or
                        Self.CommonLeaseV2 != CommonLease)
                    {
                        @compileError("campaign child opener nominal type drifted");
                    }
                    rejectCodec(OwnedChild);
                    rejectCodec(OwnedPair);
                }
            };
        }
    };
}

fn coldOpenEmpty(
    allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    authority: *const Authority,
    artifact: *const campaign_artifact.Artifact,
) !EmptyLease {
    if (artifact.stage_kind != .leaf_wrapper or
        artifact.node_kind != .empty or artifact.child_count != 1)
    {
        return error.CampaignChildColdOpenMismatch;
    }
    const source_ref = try node_store.toSharedRef(
        artifact.ordered_children[0],
    );
    try campaign_cas.validate(source_ref, .stage103_source);
    var source = try store.openBlob(
        source_ref,
        .source,
        empty_source.SCHEMA_VERSION,
        empty_source.SOURCE_ENCODED_BYTE_COUNT,
    );
    defer source.deinit(store.allocator);
    const proof_ref = try node_store.toSharedRef(artifact.proof_ref);
    try campaign_cas.validate(proof_ref, .proof);
    var proof = try store.openBlob(
        proof_ref,
        .proof_artifact,
        campaign_cas.PROOF_SCHEMA_VERSION,
        campaign_cas.MAX_PROOF_BYTE_COUNT,
    );
    defer proof.deinit(store.allocator);
    var cold = try empty_proof.coldOpen(
        allocator,
        authority,
        source.bytes,
        proof.bytes,
    );
    var cold_owned = true;
    defer if (cold_owned) cold.deinit();
    const moved = cold;
    cold = undefined;
    cold_owned = false;
    var result = try EmptyLease.initOwned(authority, moved);
    errdefer result.deinit();
    if (!std.meta.eql(result.nodeArtifact().*, artifact.*))
        return error.CampaignChildColdOpenMismatch;
    return result;
}

fn validateInputs(inputs: []const artifact_store.InputRefV1) !void {
    if (inputs.len != CHILD_COUNT or inputs[0].role != .child_left or
        inputs[1].role != .child_right or inputs[0].ordinal != 0 or
        inputs[1].ordinal != 0 or artifact_store.BlobRefV1.eql(
        inputs[0].blob,
        inputs[1].blob,
    )) return error.CampaignChildColdOpenMismatch;
    for (inputs) |input| try campaign_cas.validate(
        input.blob,
        .recursion_node,
    );
}

fn roleForArtifact(
    artifact: *const campaign_artifact.Artifact,
) !Role {
    return switch (artifact.stage_kind) {
        .leaf_wrapper => switch (artifact.node_kind) {
            .real => .ethereum_incremental_leaf_wrapper_v4,
            .empty => .canonical_empty_field_v2,
            .mixed => error.CampaignChildColdOpenMismatch,
        },
        .fold, .root => .common_fold_field_v2,
    };
}

fn validateRoleNode(
    lease: anytype,
    authority: *const Authority,
    node_ref: artifact_store.BlobRefV1,
    artifact: *const campaign_artifact.Artifact,
) !void {
    try lease.validateForCampaign(authority);
    if (!std.meta.eql(lease.nodeArtifact().*, artifact.*) or
        !artifact_store.BlobRefV1.eql(
            node_ref,
            try node_store.toSharedRef(
                try campaign_artifact.artifactRef(
                    authority.shape,
                    lease.nodeArtifact(),
                ),
            ),
        )) return error.CampaignChildColdOpenMismatch;
}

fn commonLeaseType(comptime DependencyLease: type) type {
    const info = @typeInfo(DependencyLease);
    const union_info = switch (info) {
        .@"union" => |value| value,
        else => @compileError("campaign dependency lease must be a tagged union"),
    };
    inline for (union_info.fields) |field| {
        if (comptime std.mem.eql(
            u8,
            field.name,
            "common_fold_field_v2",
        )) {
            return switch (@typeInfo(field.type)) {
                .pointer => |pointer| pointer.child,
                else => @compileError("campaign common lease must be a pointer"),
            };
        }
    }
    @compileError("campaign dependency union has no common-fold arm");
}

fn assertDependencyLease(comptime Lease: type) void {
    inline for (.{
        "fromReal",
        "fromEmpty",
        "fromCommon",
        "coldOpenCommonNode",
        "coldOpenCommonNodeForGenuineGate",
        "role",
        "validateAgainst",
        "foldProjection",
    }) |name| if (!@hasDecl(Lease, name))
        @compileError("campaign dependency lease missing " ++ name);
    rejectCodec(Lease);
}

fn assertRoleLease(comptime Lease: type, comptime role: Role) void {
    if (!@hasDecl(Lease, "ROLE") or Lease.ROLE != role)
        @compileError("campaign cold-open role lease mismatch");
    inline for (.{
        "validateForCampaign",
        "campaignFoldProjection",
        "nodeArtifact",
        "deinit",
    }) |name| if (!@hasDecl(Lease, name))
        @compileError("campaign cold-open role lease missing " ++ name);
    rejectCodec(Lease);
}

fn assertRealColdOpener(comptime Opener: type, comptime Lease: type) void {
    inline for (.{
        "available",
        "LeasePayload",
        "coldOpenNode",
        "coldOpenNodeForGenuineGate",
    }) |name|
        if (!@hasDecl(Opener, name))
            @compileError("campaign real child opener missing " ++ name);
    if (Opener.LeasePayload != Lease)
        @compileError("campaign real child opener lease mismatch");
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("campaign cold-open capability gained a codec");
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or CHILD_COUNT != 2 or
        TRANSITIVE_Q193_GATE_GREEN or PRODUCTION_ACTIVATION or
        ROUTER_ACTIVATION or !GENUINE_GATE_ONLY or
        SERIALIZABLE_FRESH_CAPABILITY or
        !COLD_OPEN_OWNS_EVERY_CHILD or
        !PARTIAL_FAILURE_DEINITS_EXACTLY_ONCE)
    {
        @compileError("campaign child cold-opener contract drifted");
    }
}
