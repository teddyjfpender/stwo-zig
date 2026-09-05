//! FinalRemint-bound all-level live source for campaign common folds.
//!
//! Any ordered child pair may contain a genuine role-0 leaf, role-1 empty,
//! or a prior role-2 fold. The tagged dependency lease retains nominality;
//! this adapter revalidates its neutral projection against the same final
//! registry, reconstructs the exact pre-final target from that FinalRemint,
//! and then reuses the target-native common-fold source implementation.

const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");
const target_mod = @import("recursive_pipeline_campaign_padding_target_v2.zig");
const neutral = @import("recursive_pipeline_campaign_fold_projection_v2.zig");
const prefinal = @import("recursive_pipeline_campaign_prefinal_fold_lease_v2.zig");
const live_core = @import("recursive_common_fold_campaign_prefinal_live_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const ALL_NOMINAL_CHILD_ROLES = true;

pub const Error = error{
    CampaignFinalCommonFoldChildMismatch,
};

pub fn Types(comptime DependencyLease: type) type {
    assertDependencyLease(DependencyLease);
    const FoldChild = FinalFoldChildV2(DependencyLease);
    return live_core.TypesForFoldChild(FoldChild);
}

pub fn FinalFoldChildV2(comptime DependencyLease: type) type {
    assertDependencyLease(DependencyLease);
    return struct {
        final_remint: *const final_mod.CampaignFinalRemintAuthorityV2,
        lease: *const DependencyLease,

        const Self = @This();

        pub fn init(
            target: *const target_mod.CampaignPaddingTargetV2,
            final_remint: *const final_mod.CampaignFinalRemintAuthorityV2,
            lease: *const DependencyLease,
        ) !Self {
            const result = Self{
                .final_remint = final_remint,
                .lease = lease,
            };
            _ = try result.projection(target);
            return result;
        }

        pub fn role(self: Self) registry_mod.CircuitRoleV1 {
            return self.lease.role();
        }

        pub fn projection(
            self: Self,
            target: *const target_mod.CampaignPaddingTargetV2,
        ) !prefinal.ProjectionV2 {
            try target.validateAgainstFinal(self.final_remint);
            try self.lease.validateAgainst(self.final_remint);
            const source = try self.lease.foldProjection(self.final_remint);
            try source.validateAgainstFinal(self.final_remint);
            if (source.role != self.role() or
                source.authority != self.final_remint)
            {
                return error.CampaignFinalCommonFoldChildMismatch;
            }
            const result = prefinal.ProjectionV2{
                .role = source.role,
                .padding_target = target,
                .geometry = source.geometry,
                .node_public = source.node_public,
                .claimed_sums = source.claimed_sums,
                .claims_seal = source.claims_seal,
                .session = source.session,
                .statement = source.statement,
                .capture = source.capture,
                .query_words = source.query_words,
                .query_log_size = source.query_log_size,
                .final_transcript_digest = source.final_transcript_digest,
                .final_transcript_draw_count = source.final_transcript_draw_count,
                .query_words_identity_sha256 = source.query_words_identity_sha256,
                .graph = .{
                    .capture_identity_sha256 = source.graph
                        .capture_identity_sha256,
                    .layout_identity_sha256 = source.graph
                        .layout_identity_sha256,
                    .query_words = source.graph.query_words,
                    .query_log_size = source.graph.query_log_size,
                    .final_transcript_digest = source.graph
                        .final_transcript_digest,
                    .final_transcript_draw_count = source.graph
                        .final_transcript_draw_count,
                    .query_words_identity_sha256 = source.graph
                        .query_words_identity_sha256,
                    .lane = source.graph.lane,
                    .evaluation = source.graph.evaluation,
                },
            };
            try result.validateAgainstPaddingTarget(target);
            return result;
        }
    };
}

fn assertDependencyLease(comptime Lease: type) void {
    inline for (.{ "role", "validateAgainst", "foldProjection" }) |name|
        if (!@hasDecl(Lease, name))
            @compileError("campaign final fold dependency missing " ++ name);
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(Lease, name))
            @compileError("campaign final fold dependency gained a codec");
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or !ALL_NOMINAL_CHILD_ROLES or
        neutral.QUERY_WORD_COUNT != prefinal.QUERY_WORD_COUNT)
    {
        @compileError("campaign final common-fold live contract drifted");
    }
}
