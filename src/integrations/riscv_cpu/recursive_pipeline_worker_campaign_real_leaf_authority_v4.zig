//! Process-local authority bundle for the campaign Stage-102 worker.
//!
//! A Stage-102 request names only its Stage-101 proof dependency.  That ref is
//! insufficient to recover the seven typed inputs needed for an independent
//! cold verify, so this authority retains the validated STWCIT04 table and an
//! exact Stage-101 node/key admission for every runtime row.  It also pins the
//! same padding target and FinalRemint transaction.  No field is serializable
//! freshness authority.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const native_worker = @import("recursive_pipeline_worker_native_leaf_v4.zig");
const namespace_mod =
    @import("recursive_pipeline_campaign_namespace_v1.zig");
const table_mod =
    @import("recursive_pipeline_incremental_campaign_table_v4.zig");
const geometry_mod =
    @import("recursive_common_ethereum_incremental_leaf_campaign_provider_geometry_v4.zig");
const target_mod = @import("recursive_pipeline_campaign_padding_target_v2.zig");
const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 1;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const RUNTIME_CAMPAIGN_COUNT = true;
pub const STAGE101_INPUT_COUNT = table_mod.STAGE_INPUT_COUNT;

pub const Table = table_mod.CampaignTableV4;
pub const CampaignGeometry = geometry_mod.OwnedCampaignProviderGeometryV4;
pub const PaddingTarget = target_mod.CampaignPaddingTargetV2;
pub const FinalRemint = final_mod.CampaignFinalRemintAuthorityV2;

pub const Error = error{
    CampaignRealLeafAuthorityMismatchV4,
    CampaignRealLeafStage101AdmissionMismatchV4,
    CampaignRealLeafStage102CoordinateMismatchV4,
};

pub const Stage101AdmissionV4 = struct {
    /// The wrapper task identity is Zig-minted by the campaign planner. It is
    /// only an index until the produced campaign artifact rederives it.
    wrapper_local_task_identity_sha256: artifact_store.Digest,
    node: protocol.Node,
    semantic: *const artifact_store.SemanticKeyV1,

    pub fn validateAgainstRow(
        self: Stage101AdmissionV4,
        allocator: std.mem.Allocator,
        table: *const Table,
        row_index: usize,
        campaign_namespace_sha256: artifact_store.Digest,
    ) !void {
        if (row_index >= table.records.len or
            artifact_store.encoding.isZeroDigest(
                self.wrapper_local_task_identity_sha256,
            ))
        {
            return error.CampaignRealLeafStage101AdmissionMismatchV4;
        }
        const row = table.records[row_index];
        const expected = try native_worker.semanticProjection(
            row.segment_index,
            table.segment_count,
            &row.stage_inputs,
            campaign_namespace_sha256,
        );
        try self.semantic.validate(allocator);
        const fields = self.semantic.fields;
        if (self.node.stage_kind != .prove or
            self.node.stage_schema_version !=
                native_worker.STAGE_SCHEMA_VERSION or
            self.node.dependencies.len != 0 or
            self.node.external_inputs.len != STAGE101_INPUT_COUNT or
            self.node.output_kind != .proof_artifact or
            self.node.output_schema_version !=
                native_worker.OUTPUT_SCHEMA_VERSION or
            !native_worker.Adapter.acceptsNodeAdapter(self.node.adapter) or
            !std.mem.eql(
                u8,
                &self.node.local_task_identity_sha256,
                &expected.local_task_identity_sha256,
            ) or !std.meta.eql(
            self.node.semantic_authorities,
            expected.authorities,
        ) or !std.mem.eql(
            u8,
            &fields.campaign_namespace,
            &campaign_namespace_sha256,
        ) or !std.mem.eql(
            u8,
            &fields.local_task_identity,
            &expected.local_task_identity_sha256,
        ) or !semanticAuthoritiesEqual(fields, expected.authorities) or
            fields.stage_kind != .prove or
            fields.stage_schema_version != native_worker.STAGE_SCHEMA_VERSION or
            fields.ordered_inputs.len != STAGE101_INPUT_COUNT)
        {
            return error.CampaignRealLeafStage101AdmissionMismatchV4;
        }
        for (
            self.node.external_inputs,
            fields.ordered_inputs,
            row.stage_inputs,
        ) |node_input, key_input, expected_input| {
            if (!std.meta.eql(node_input, expected_input) or
                !std.meta.eql(key_input, expected_input))
            {
                return error.CampaignRealLeafStage101AdmissionMismatchV4;
            }
        }
        const options = try protocol.objectValue(self.node.semantic_options);
        protocol.exactKeys(options, &.{}) catch
            return error.CampaignRealLeafStage101AdmissionMismatchV4;
    }
};

/// `ActiveSources` is the exact `(role0, role1, role2)` cold-source tuple used
/// to derive the target. It is borrowed and revalidated on every use.
pub fn CampaignAuthorityV4(comptime ActiveSources: type) type {
    return struct {
        table: *const Table,
        campaign_geometry: *const CampaignGeometry,
        padding_target: *const PaddingTarget,
        final_remint: *const FinalRemint,
        active_sources: *const ActiveSources,
        stage101_admissions: []const Stage101AdmissionV4,

        const Self = @This();

        pub fn validate(
            self: *const Self,
            allocator: std.mem.Allocator,
            campaign_namespace_sha256: artifact_store.Digest,
        ) !void {
            try self.table.validate();
            try self.campaign_geometry.validateStructure();
            try self.padding_target.validateAgainstActive(
                self.active_sources.*,
            );
            try self.padding_target.validateAgainstFinal(self.final_remint);
            try self.final_remint.validateAgainstCampaign(
                campaign_namespace_sha256,
            );
            const expected_namespace = try namespace_mod.fromValidatedTable(
                self.table,
            );
            const shape = self.final_remint.shape;
            if (!std.mem.eql(
                u8,
                &expected_namespace,
                &campaign_namespace_sha256,
            ) or shape.real_leaf_count != self.table.segment_count or
                shape.real_leaf_count != self.campaign_geometry.leaf_count or
                self.stage101_admissions.len != self.table.records.len or
                !std.mem.eql(
                    u8,
                    &shape.inventory_identity_sha256,
                    &self.table.content_sha256,
                ) or !std.mem.eql(
                u8,
                &self.campaign_geometry.campaign_inventory
                    .table_identity_sha256,
                &self.table.content_sha256,
            )) return error.CampaignRealLeafAuthorityMismatchV4;
            for (self.stage101_admissions, 0..) |admission, index| {
                try admission.validateAgainstRow(
                    allocator,
                    self.table,
                    index,
                    campaign_namespace_sha256,
                );
                for (self.stage101_admissions[0..index]) |earlier| {
                    if (std.mem.eql(
                        u8,
                        &earlier.wrapper_local_task_identity_sha256,
                        &admission.wrapper_local_task_identity_sha256,
                    )) return error.CampaignRealLeafAuthorityMismatchV4;
                }
            }
        }

        pub fn admissionForWrapperTask(
            self: *const Self,
            allocator: std.mem.Allocator,
            campaign_namespace_sha256: artifact_store.Digest,
            wrapper_local_task_identity_sha256: artifact_store.Digest,
        ) !struct {
            index: usize,
            row: *const table_mod.LeafRecordV4,
            admission: *const Stage101AdmissionV4,
        } {
            try self.validate(allocator, campaign_namespace_sha256);
            for (self.stage101_admissions, 0..) |*admission, index| {
                if (std.mem.eql(
                    u8,
                    &admission.wrapper_local_task_identity_sha256,
                    &wrapper_local_task_identity_sha256,
                )) {
                    return .{
                        .index = index,
                        .row = &self.table.records[index],
                        .admission = admission,
                    };
                }
            }
            return error.CampaignRealLeafStage102CoordinateMismatchV4;
        }
    };
}

fn semanticAuthoritiesEqual(
    fields: artifact_store.SemanticKeyFieldsV1,
    expected: protocol.SemanticAuthorities,
) bool {
    return std.mem.eql(
        u8,
        &fields.protocol_identity,
        &expected.protocol_identity_sha256,
    ) and std.mem.eql(
        u8,
        &fields.program_identity,
        &expected.program_identity_sha256,
    ) and std.mem.eql(
        u8,
        &fields.profile_identity,
        &expected.profile_identity_sha256,
    ) and std.mem.eql(
        u8,
        &fields.pcs_identity,
        &expected.pcs_identity_sha256,
    ) and std.mem.eql(
        u8,
        &fields.security_identity,
        &expected.security_identity_sha256,
    ) and std.mem.eql(
        u8,
        &fields.statement_identity,
        &expected.statement_identity_sha256,
    ) and std.mem.eql(
        u8,
        &fields.provider_identity,
        &expected.provider_identity_sha256,
    ) and std.mem.eql(
        u8,
        &fields.layout_identity,
        &expected.layout_identity_sha256,
    ) and std.mem.eql(
        u8,
        &fields.registry_identity,
        &expected.registry_identity_sha256,
    );
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 1 or
        STAGE101_INPUT_COUNT != 7 or SERIALIZABLE_FRESH_CAPABILITY or
        !RUNTIME_CAMPAIGN_COUNT)
    {
        @compileError("campaign Stage102 authority contract drifted");
    }
}
