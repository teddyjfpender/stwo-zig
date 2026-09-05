const std = @import("std");

const subject = @import("recursive_common_fold_child_capability_v2.zig");
const common_child = @import("recursive_common_fold_child_v2.zig");
const empty_child = @import("recursive_pipeline_worker_canonical_empty_v2.zig");
const live = @import("recursive_common_fold_universal_cohort_v2.zig");
const proof = @import("recursive_common_fold_universal_proof_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

const Tagged = subject.TaggedFoldChildV2(
    subject.UnavailableRealLeafChildV2,
    empty_child.FreshFoldChildV2,
    common_child.FreshFoldChildV2,
);

test "schema4 child capability is typed role-neutral and production closed" {
    try std.testing.expectEqual(@as(u16, 2), subject.FORMAT_VERSION);
    try std.testing.expectEqual(@as(u16, 1), subject.SCHEMA_VERSION);
    try std.testing.expectEqual(@as(usize, 193), subject.QUERY_WORD_COUNT);
    try std.testing.expect(!subject.SERIALIZABLE_FRESH_CAPABILITY);
    try std.testing.expect(!live.ALL_SCHEMA4_ROLE_BRANCHES_AVAILABLE);
    try std.testing.expect(!proof.Q193_BACKEND_AVAILABLE);
    try std.testing.expect(!proof.COLD_GRAPH_REMINT_AVAILABLE);
    try std.testing.expect(Tagged == live.FreshFoldChildV2);
    try std.testing.expect(@hasDecl(Tagged, "fromReal"));
    try std.testing.expect(@hasDecl(Tagged, "fromCanonical"));
    try std.testing.expect(@hasDecl(Tagged, "fromCommon"));
    try std.testing.expect(@hasDecl(Tagged, "projection"));
    try std.testing.expect(
        @typeInfo(Tagged.PayloadV2).@"union".tag_type.? ==
            registry_mod.CircuitRoleV1,
    );
    inline for (.{
        "ethereum_incremental_leaf_wrapper_v4",
        "canonical_empty_field_v2",
        "common_fold_field_v2",
    }) |name| try std.testing.expect(@hasField(Tagged.PayloadV2, name));
}

test "unavailable real branch cannot mint a fold child" {
    var unavailable = subject.UnavailableRealLeafChildV2{};
    var registry: registry_mod.RecursiveCircuitRegistryV1 = undefined;
    try std.testing.expectError(
        error.CommonFoldRealLeafCapabilityUnavailable,
        Tagged.fromReal(&unavailable, &registry),
    );
}

test "projection carries no serializable freshness or nominal child" {
    inline for (.{
        "role",
        "wrapper",
        "node_public",
        "claimed_sums",
        "claims_seal",
        "session",
        "statement",
        "geometry",
        "capture",
        "query_words",
        "query_log_size",
        "final_transcript_digest",
        "final_transcript_draw_count",
        "query_words_identity_sha256",
        "graph",
    }) |name| try std.testing.expect(@hasField(subject.ProjectionV2, name));
    try std.testing.expect(!@hasField(subject.ProjectionV2, "fresh"));
    try std.testing.expect(!@hasField(subject.ProjectionV2, "proof_bytes"));
    try std.testing.expect(!@hasField(subject.ProjectionV2, "artifact_bytes"));
    try std.testing.expect(!@hasField(subject.ProjectionV2, "child"));
}
