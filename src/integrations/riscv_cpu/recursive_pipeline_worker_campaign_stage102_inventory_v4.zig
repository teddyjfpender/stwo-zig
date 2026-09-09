//! Authenticated process-local Stage-102 inventory session.
//!
//! Installation cold-opens every ordered role-0 campaign node and validates
//! its Stage-102 admission, StageManifest closure, Zig keys, and Stage-101
//! proof dependency. After that one immutable pass, the persistent worker may
//! perform pointer-stable lookups for transitive cold opens. The session and
//! returned admissions are never serialized and remain valid only while the
//! provider installation token owns the worker lifetime.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const inventory_opener =
    @import("recursive_pipeline_worker_campaign_real_leaf_inventory_opener_v4.zig");
const campaign_store =
    @import("recursive_campaign_node_artifact_store_v2.zig");
const campaign_cas =
    @import("recursive_pipeline_worker_campaign_cas_v2.zig");
const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");
const policy_mod = @import("recursive_pipeline_worker_execution_policy_v2.zig");

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const ORDERED_COMPLETE_REAL_INVENTORY = true;
pub const VALIDATE_ALL_CAS_AT_INSTALL = true;
pub const ADOPTION_IS_EXACT_IDEMPOTENT_CONFIRMATION = true;
pub const REQUEST_POINTERS_RETAINED = false;

pub const Admission = inventory_opener.Stage102ColdAdmissionV4;
pub const FinalRemint = final_mod.CampaignFinalRemintAuthorityV2;
pub const Policy = policy_mod.PolicyV2;

pub const Error = error{
    CampaignStage102InventoryDuplicateV4,
    CampaignStage102InventoryIncompleteV4,
    CampaignStage102InventoryMismatchV4,
    CampaignStage102InventoryAdoptionMismatchV4,
};

pub const EntryV4 = struct {
    output_ref: artifact_store.BlobRefV1,
    admission: Admission,
};

/// `Authority` is the exact specialization returned by
/// `recursive_pipeline_worker_campaign_real_leaf_backend_v4.BackendFor`.
/// Its active-source, Stage-101 admission, and `entries` pointers are retained
/// by the caller and must outlive this session. Every pointee reachable from
/// an entry's Node and SemanticKey must already be deep-owned by that caller.
///
/// This is the immutable, seal-last replay session, not the mutable campaign
/// builder. Consequently Stage-102 publication adoption only confirms that a
/// transient worker request is canonically identical to its already-sealed
/// row. It never retains a request-arena pointer or changes the inventory.
pub fn SessionFor(comptime Authority: type) type {
    assertAuthority(Authority);

    return struct {
        pub const AuthorityV4 = Authority;

        store: *artifact_store.Store,
        authority: *const Authority,
        entries: []const EntryV4,
        policy: *const Policy,

        const Self = @This();

        /// Full install-time audit. The inventory is canonical by coordinate:
        /// entry `i` must cold-open the unique real leaf at index `i`.
        pub fn validate(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) !void {
            try self.validateIdentity();
            const final_remint = self.authority.final_remint;
            const shape = final_remint.shape;
            const expected_count = std.math.cast(
                usize,
                shape.real_leaf_count,
            ) orelse return error.CampaignStage102InventoryIncompleteV4;
            if (self.entries.len != expected_count or
                self.entries.len != self.authority.stage101_admissions.len)
            {
                return error.CampaignStage102InventoryIncompleteV4;
            }

            for (self.entries, 0..) |*entry, index| {
                try self.validateEntry(allocator, entry, index);
                for (self.entries[0..index]) |earlier| {
                    if (artifact_store.BlobRefV1.eql(
                        earlier.output_ref,
                        entry.output_ref,
                    ) or artifact_store.BlobRefV1.eql(
                        earlier.admission.stage_manifest_ref,
                        entry.admission.stage_manifest_ref,
                    ) or artifact_store.BlobRefV1.eql(
                        earlier.admission.dependency_stage_manifest_ref,
                        entry.admission.dependency_stage_manifest_ref,
                    ) or std.mem.eql(
                        u8,
                        &earlier.admission.semantic.identity,
                        &entry.admission.semantic.identity,
                    )) return error.CampaignStage102InventoryDuplicateV4;
                }
            }
        }

        pub fn authorityForCampaign(
            self: *const Self,
            namespace: artifact_store.Digest,
        ) !*const Authority {
            try self.validateNamespace(namespace);
            return self.authority;
        }

        pub fn stage102AdmissionForOutput(
            self: *const Self,
            namespace: artifact_store.Digest,
            output_ref: artifact_store.BlobRefV1,
        ) !*const Admission {
            try self.validateNamespace(namespace);
            try campaign_cas.validate(output_ref, .recursion_node);
            for (self.entries) |*entry| {
                if (artifact_store.BlobRefV1.eql(
                    entry.output_ref,
                    output_ref,
                )) return &entry.admission;
            }
            return error.CampaignStage102InventoryMismatchV4;
        }

        pub fn finalRemintForCampaign(
            self: *const Self,
            namespace: artifact_store.Digest,
        ) !*const FinalRemint {
            try self.validateNamespace(namespace);
            return self.authority.final_remint;
        }

        pub fn policyForExecution(
            self: *const Self,
            execution: artifact_store.ExecutionKeyV1,
        ) !Policy {
            try self.policy.validateAgainstExecution(execution);
            return self.policy.*;
        }

        /// Idempotently confirms a Stage-102 publication against the sealed
        /// inventory. The generic worker invokes this only after a genuine
        /// cold open and seal-last StageManifest publication. The supplied
        /// allocator is request scratch: every temporary allocation is freed
        /// before return and no supplied pointer is retained.
        pub fn adoptStage102ColdPublication(
            self: *const Self,
            allocator: std.mem.Allocator,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            output_ref: artifact_store.BlobRefV1,
            stage_manifest_ref: artifact_store.BlobRefV1,
            dependency_stage_manifest_refs: []const artifact_store.BlobRefV1,
        ) !void {
            try self.validateIdentity();
            const expected_count = try self.expectedCount();
            if (self.entries.len != expected_count or
                self.entries.len != self.authority.stage101_admissions.len or
                ordered_inputs.len != inventory_opener.STAGE102_DEPENDENCY_COUNT or
                dependency_stage_manifest_refs.len !=
                    inventory_opener.STAGE102_DEPENDENCY_COUNT)
            {
                return error.CampaignStage102InventoryAdoptionMismatchV4;
            }
            try self.policy.validateAgainstExecution(execution);
            if (node.cpu_tokens != @as(u64, self.policy.cpu_tokens_per_node) or
                node.rss_tokens != self.policy.rss_bytes_per_node)
            {
                return error.CampaignStage102InventoryAdoptionMismatchV4;
            }

            try campaign_cas.validate(output_ref, .recursion_node);
            try campaign_cas.validate(stage_manifest_ref, .stage_manifest);
            try campaign_cas.validate(
                dependency_stage_manifest_refs[0],
                .stage_manifest,
            );
            const shape = self.authority.final_remint.shape;
            const artifact = try campaign_store.coldOpenRecursiveNodeTransport(
                self.store,
                shape,
                output_ref,
            );
            if (artifact.stage_kind != .leaf_wrapper or
                artifact.node_kind != .real or artifact.child_count != 1 or
                artifact.coordinate.height != 0)
            {
                return error.CampaignStage102InventoryAdoptionMismatchV4;
            }
            const index = std.math.cast(
                usize,
                artifact.coordinate.index,
            ) orelse return error.CampaignStage102InventoryAdoptionMismatchV4;
            if (index >= self.entries.len)
                return error.CampaignStage102InventoryAdoptionMismatchV4;

            var ordered_copy = [_]artifact_store.InputRefV1{
                ordered_inputs[0],
            };
            const observed = Admission{
                .node = &node,
                .semantic = &semantic,
                .execution = &execution,
                .ordered_inputs = &ordered_copy,
                .stage_manifest_ref = stage_manifest_ref,
                .dependency_stage_manifest_ref = dependency_stage_manifest_refs[0],
            };
            try observed.validate(
                allocator,
                self.store,
                self.authority,
                self.authority.final_remint,
                output_ref,
                &artifact,
            );

            const retained = &self.entries[index];
            try self.validateEntry(allocator, retained, index);
            if (!try exactEntryMatchV4(
                allocator,
                retained,
                output_ref,
                observed,
            )) return error.CampaignStage102InventoryAdoptionMismatchV4;
        }

        fn validateIdentity(self: *const Self) !void {
            try self.policy.validate();
            const final_remint = self.authority.final_remint;
            const namespace = final_remint.shape.campaign_namespace_sha256;
            try self.authority.validate(self.store.allocator, namespace);
            try final_remint.validateAgainstCampaign(namespace);
            if (!std.mem.eql(
                u8,
                &self.authority.padding_target.shape.identity_sha256,
                &final_remint.shape.identity_sha256,
            )) {
                return error.CampaignStage102InventoryMismatchV4;
            }
        }

        fn expectedCount(self: *const Self) !usize {
            return std.math.cast(
                usize,
                self.authority.final_remint.shape.real_leaf_count,
            ) orelse return error.CampaignStage102InventoryIncompleteV4;
        }

        fn validateEntry(
            self: *const Self,
            allocator: std.mem.Allocator,
            entry: *const EntryV4,
            index: usize,
        ) !void {
            const shape = self.authority.final_remint.shape;
            try campaign_cas.validate(entry.output_ref, .recursion_node);
            const artifact = try campaign_store.coldOpenRecursiveNodeTransport(
                self.store,
                shape,
                entry.output_ref,
            );
            if (artifact.stage_kind != .leaf_wrapper or
                artifact.node_kind != .real or artifact.child_count != 1 or
                artifact.coordinate.height != 0 or
                artifact.coordinate.index != @as(u32, @intCast(index)))
            {
                return error.CampaignStage102InventoryMismatchV4;
            }
            try entry.admission.validate(
                allocator,
                self.store,
                self.authority,
                self.authority.final_remint,
                entry.output_ref,
                &artifact,
            );
            try self.policy.validateAgainstExecution(
                entry.admission.execution.*,
            );
            if (entry.admission.node.cpu_tokens !=
                @as(u64, self.policy.cpu_tokens_per_node) or
                entry.admission.node.rss_tokens !=
                    self.policy.rss_bytes_per_node)
            {
                return error.CampaignStage102InventoryMismatchV4;
            }
        }

        fn validateNamespace(
            self: *const Self,
            namespace: artifact_store.Digest,
        ) !void {
            try self.authority.final_remint.validateAgainstCampaign(
                namespace,
            );
            if (!std.mem.eql(
                u8,
                &namespace,
                &self.authority.final_remint.shape
                    .campaign_namespace_sha256,
            )) return error.CampaignStage102InventoryMismatchV4;
        }

        comptime {
            rejectCodec(Self);
        }
    };
}

fn assertAuthority(comptime Authority: type) void {
    inline for (.{
        "validate",
        "admissionForWrapperTask",
    }) |name| if (!@hasDecl(Authority, name))
        @compileError("campaign Stage102 inventory authority missing " ++ name);
    inline for (.{
        "final_remint",
        "padding_target",
        "stage101_admissions",
    }) |name| if (!@hasField(Authority, name))
        @compileError("campaign Stage102 inventory authority field missing " ++ name);
    rejectCodec(Authority);
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("campaign Stage102 inventory session gained a codec");
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or
        !ORDERED_COMPLETE_REAL_INVENTORY or !VALIDATE_ALL_CAS_AT_INSTALL or
        !ADOPTION_IS_EXACT_IDEMPOTENT_CONFIRMATION or
        REQUEST_POINTERS_RETAINED)
    {
        @compileError("campaign Stage102 inventory session contract drifted");
    }
}

/// Exact process-local admission comparison shared by the immutable session
/// and its separate seal-last builder. It allocates only request scratch and
/// never retains either operand.
pub fn exactEntryMatchV4(
    allocator: std.mem.Allocator,
    expected: *const EntryV4,
    output_ref: artifact_store.BlobRefV1,
    observed: Admission,
) !bool {
    if (!artifact_store.BlobRefV1.eql(expected.output_ref, output_ref) or
        !artifact_store.BlobRefV1.eql(
            expected.admission.stage_manifest_ref,
            observed.stage_manifest_ref,
        ) or !artifact_store.BlobRefV1.eql(
        expected.admission.dependency_stage_manifest_ref,
        observed.dependency_stage_manifest_ref,
    ) or !std.meta.eql(
        expected.admission.execution.*,
        observed.execution.*,
    ) or !orderedInputsEqual(
        expected.admission.ordered_inputs[0..],
        observed.ordered_inputs[0..],
    ) or !try semanticKeysEqual(
        allocator,
        expected.admission.semantic.*,
        observed.semantic.*,
    ) or !try nodesEqual(
        allocator,
        expected.admission.node.*,
        observed.node.*,
    )) return false;
    return true;
}

fn semanticKeysEqual(
    allocator: std.mem.Allocator,
    left: artifact_store.SemanticKeyV1,
    right: artifact_store.SemanticKeyV1,
) !bool {
    const left_bytes = try left.canonicalBytesAlloc(allocator);
    defer allocator.free(left_bytes);
    const right_bytes = try right.canonicalBytesAlloc(allocator);
    defer allocator.free(right_bytes);
    return std.mem.eql(u8, left_bytes, right_bytes);
}

fn nodesEqual(
    allocator: std.mem.Allocator,
    left: protocol.Node,
    right: protocol.Node,
) !bool {
    if (!std.mem.eql(u8, left.node_id, right.node_id) or
        left.stage_kind != right.stage_kind or
        left.stage_schema_version != right.stage_schema_version or
        !std.mem.eql(u8, left.adapter, right.adapter) or
        !dependenciesEqual(left.dependencies, right.dependencies) or
        !orderedInputsEqual(left.external_inputs, right.external_inputs) or
        !std.meta.eql(
            left.local_task_identity_sha256,
            right.local_task_identity_sha256,
        ) or !std.meta.eql(
        left.semantic_authorities,
        right.semantic_authorities,
    ) or left.cpu_tokens != right.cpu_tokens or
        left.rss_tokens != right.rss_tokens or
        left.output_kind != right.output_kind or
        left.output_schema_version != right.output_schema_version)
    {
        return false;
    }
    const left_options = try protocol.canonicalAlloc(
        allocator,
        left.semantic_options,
        false,
    );
    defer allocator.free(left_options);
    const right_options = try protocol.canonicalAlloc(
        allocator,
        right.semantic_options,
        false,
    );
    defer allocator.free(right_options);
    return std.mem.eql(u8, left_options, right_options);
}

fn dependenciesEqual(
    left: []const protocol.Dependency,
    right: []const protocol.Dependency,
) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| {
        if (!std.mem.eql(u8, a.node_id, b.node_id) or
            a.role != b.role or a.ordinal != b.ordinal)
        {
            return false;
        }
    }
    return true;
}

fn orderedInputsEqual(
    left: []const artifact_store.InputRefV1,
    right: []const artifact_store.InputRefV1,
) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!std.meta.eql(a, b)) return false;
    return true;
}
