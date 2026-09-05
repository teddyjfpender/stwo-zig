//! Typed shared-CAS allocation for campaign-aware recursive worker stages.
//!
//! These checks admit only transport. `Store.openBlob` still rehashes bytes,
//! and a role-specific cold verifier remains the sole lease authority.

const artifact_store = @import("stwo_artifact_store");

const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");
const campaign_empty =
    @import("recursive_common_canonical_empty_campaign_source_v2.zig");
const campaign_store =
    @import("recursive_campaign_node_artifact_store_v2.zig");
const secure_artifact =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");

pub const SOURCE_SCHEMA_VERSION: u16 = campaign_empty.SCHEMA_VERSION;
pub const SOURCE_BYTE_COUNT: u64 = campaign_empty.SOURCE_ENCODED_BYTE_COUNT;
pub const PROOF_SCHEMA_VERSION: u16 = 1;
pub const NODE_SCHEMA_VERSION: u16 = campaign_artifact.SCHEMA_VERSION;
pub const NODE_BYTE_COUNT: u64 = campaign_artifact.ENCODED_BYTE_COUNT;
pub const STAGE_MANIFEST_SCHEMA_VERSION: u16 =
    campaign_store.STAGE_MANIFEST_SCHEMA_VERSION;
pub const MAX_PROOF_BYTE_COUNT: u64 =
    secure_artifact.MAX_CANONICAL_PROOF_BYTES + 4 * 1024 * 1024;

pub const RoleV2 = enum {
    stage103_source,
    proof,
    recursion_node,
    stage_manifest,
};

pub const Error = error{
    CampaignWorkerInputMismatch,
    CampaignWorkerProofReferenceMismatch,
    CampaignWorkerDependencyMismatch,
    CampaignWorkerOutputMismatch,
};

pub fn validate(ref: artifact_store.BlobRefV1, role: RoleV2) !void {
    try ref.validate();
    switch (role) {
        .stage103_source => if (ref.kind != .source or
            ref.schema_version != SOURCE_SCHEMA_VERSION or
            ref.byte_count != SOURCE_BYTE_COUNT)
        {
            return error.CampaignWorkerInputMismatch;
        },
        .proof => if (ref.kind != .proof_artifact or
            ref.schema_version != PROOF_SCHEMA_VERSION or
            ref.byte_count == 0 or ref.byte_count > MAX_PROOF_BYTE_COUNT)
        {
            return error.CampaignWorkerProofReferenceMismatch;
        },
        .recursion_node => if (ref.kind != .recursion_node or
            ref.schema_version != NODE_SCHEMA_VERSION or
            ref.byte_count != NODE_BYTE_COUNT)
        {
            return error.CampaignWorkerDependencyMismatch;
        },
        .stage_manifest => if (ref.kind != .stage_manifest or
            ref.schema_version != STAGE_MANIFEST_SCHEMA_VERSION or
            ref.byte_count == 0)
        {
            return error.CampaignWorkerOutputMismatch;
        },
    }
}

comptime {
    if (SOURCE_SCHEMA_VERSION != 2 or SOURCE_BYTE_COUNT != 1892 or
        PROOF_SCHEMA_VERSION != 1 or NODE_SCHEMA_VERSION != 2 or
        NODE_BYTE_COUNT != 2380 or STAGE_MANIFEST_SCHEMA_VERSION != 1)
    {
        @compileError("campaign worker CAS allocation drifted");
    }
}
