//! Internal segment leaf outer authority v2 authority shard; use segment_leaf_outer_authority_v2.zig publicly.

const dependency_0 = @import("segment_leaf_outer_authority_v2_contract.zig");
const dependency_1 = @import("segment_leaf_outer_authority_v2_workspace_v2.zig");
const dependency_2 = @import("segment_leaf_outer_authority_v2_verify_authority_into.zig");

const ALL_AUTHORITY_EVENTS_CHECKED = dependency_0.ALL_AUTHORITY_EVENTS_CHECKED;
const ALL_PUBLIC_LOGUP_WORDS_CHECKED = dependency_0.ALL_PUBLIC_LOGUP_WORDS_CHECKED;
const AuthorityV2 = dependency_0.AuthorityV2;
const AuthorityVerificationV2 = dependency_1.AuthorityVerificationV2;
const COMPLETE_TEMPORAL_PARENT = dependency_0.COMPLETE_TEMPORAL_PARENT;
const COMPONENT_COUNT = dependency_0.COMPONENT_COUNT;
const Error = dependency_0.Error;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const HOT_PREPARE_HEAP_ALLOCATIONS = dependency_0.HOT_PREPARE_HEAP_ALLOCATIONS;
const HOT_PUBLISH_HEAP_ALLOCATIONS = dependency_0.HOT_PUBLISH_HEAP_ALLOCATIONS;
const HOT_VERIFY_HEAP_ALLOCATIONS = dependency_0.HOT_VERIFY_HEAP_ALLOCATIONS;
const INTERACTION_BULK_INVERSIONS = dependency_0.INTERACTION_BULK_INVERSIONS;
const MANIFEST_VERSION = dependency_0.MANIFEST_VERSION;
const NATIVE_V2_PROOF_API_AVAILABLE = dependency_0.NATIVE_V2_PROOF_API_AVAILABLE;
const NativeDigest = dependency_0.NativeDigest;
const OUTER_STARK_VERIFICATION_AVAILABLE = dependency_0.OUTER_STARK_VERIFICATION_AVAILABLE;
const OuterManifestV2 = dependency_0.OuterManifestV2;
const PRODUCTION_ACTIVATION = dependency_0.PRODUCTION_ACTIVATION;
const PUBLIC_LOGUP_LOGICAL_ROWS = dependency_0.PUBLIC_LOGUP_LOGICAL_ROWS;
const PUBLIC_LOGUP_TRACE_ROWS = dependency_0.PUBLIC_LOGUP_TRACE_ROWS;
const PreparedNativeVerifierOuterAuthorityV2 = dependency_1.PreparedNativeVerifierOuterAuthorityV2;
const PreparedOuterAuthorityV2 = dependency_1.PreparedOuterAuthorityV2;
const QM31 = dependency_0.QM31;
const Sha256Digest = dependency_0.Sha256Digest;
const TracesV2 = dependency_0.TracesV2;
const VerifiedAuthorityPublicationV2 = dependency_2.VerifiedAuthorityPublicationV2;
const WorkspaceV2 = dependency_1.WorkspaceV2;
const copyTraces = dependency_2.copyTraces;
const native_relations = dependency_0.native_relations;
const overlap = dependency_1.overlap;
const preflight = dependency_0.preflight;
const public_data_v2 = dependency_0.public_data_v2;
const publicationIdentity = dependency_2.publicationIdentity;
const rebuildNativeVerifierStages = dependency_2.rebuildNativeVerifierStages;
const requireNativeDigest = dependency_0.requireNativeDigest;
const source_v2 = dependency_0.source_v2;
const statement_v1 = dependency_0.statement_v1;
const statement_v2 = dependency_0.statement_v2;
const std = dependency_0.std;
const tracesOverlap = dependency_2.tracesOverlap;
const universal = dependency_0.universal;
const validateMutableBoundary = dependency_2.validateMutableBoundary;
const workspaceOverlaps = dependency_2.workspaceOverlaps;

/// Capture-backed preparation.  Every mutable capture sidecar is expected to
/// have passed its capture-level verifier check at the integration boundary;
/// this authority independently revalidates the receipt, wire, compensated
/// sums and geometry-derived statement authority before committing any trace
/// cell or destination byte.
pub fn prepareNativeVerifierInto(
    destination: *PreparedNativeVerifierOuterAuthorityV2,
    workspace: *WorkspaceV2,
    authority: *const AuthorityV2,
    traces: TracesV2,
    data: *const public_data_v2.PublicDataV2,
    keys: *const source_v2.VerifierKeyAuthorityV2,
    native: *const native_relations.Relations,
    native_sums: *const statement_v2.NativePublicSums,
    receipt: *const statement_v2.VerifiedReceipt,
    component_descs: []const statement_v1.FamilyComponentDesc,
    infra_descs: []const statement_v1.InfraComponentDesc,
    outer: *const universal.UniversalRelations,
) Error!void {
    try validateMutableBoundary(
        std.mem.asBytes(destination),
        workspace,
        traces,
        authority,
        data,
        keys,
        native,
        outer,
    );
    const destination_bytes = std.mem.asBytes(destination);
    inline for (.{
        std.mem.asBytes(native_sums),
        std.mem.asBytes(receipt),
        std.mem.sliceAsBytes(component_descs),
        std.mem.sliceAsBytes(infra_descs),
    }) |input| {
        if (overlap(destination_bytes, input) or
            workspaceOverlaps(workspace, input) or tracesOverlap(input, traces))
        {
            return error.AliasedDestination;
        }
    }
    const staged = try rebuildNativeVerifierStages(
        workspace,
        authority,
        data,
        keys,
        native,
        native_sums,
        receipt,
        component_descs,
        infra_descs,
        outer,
    );
    copyTraces(workspace, traces);
    destination.* = staged;
}

/// Publishes the source cohort only after the independent authority verifier
/// receipt above succeeds. This bare/source-preflight path remains
/// non-production because it does not accept successful native-verifier
/// custody; recursive ingestion uses `PreparedNativeVerifierOuterAuthorityV2`.
pub fn publishVerifiedInto(
    destination: *VerifiedAuthorityPublicationV2,
    verification: *const AuthorityVerificationV2,
    prepared: *const PreparedOuterAuthorityV2,
    data: *const public_data_v2.PublicDataV2,
    native: *const native_relations.Relations,
) Error!void {
    const destination_bytes = std.mem.asBytes(destination);
    inline for (.{
        std.mem.asBytes(verification),
        std.mem.asBytes(prepared),
        std.mem.asBytes(data),
        std.mem.sliceAsBytes(data.words()),
        std.mem.asBytes(native),
    }) |input| if (overlap(destination_bytes, input))
        return error.AliasedDestination;
    try verification.validateAgainst(prepared);
    var cohort: source_v2.CohortHandoffV2 = undefined;
    try source_v2.publishCohortHandoffInto(
        &cohort,
        &prepared.source,
        &prepared.public_logup,
        data,
        native,
    );
    var staged = VerifiedAuthorityPublicationV2{
        .verification = verification.*,
        .cohort = cohort,
        .identity = undefined,
    };
    staged.identity = publicationIdentity(&staged);
    try staged.validateAgainst(prepared, data, native);
    destination.* = staged;
}

/// Intentionally has no current success path. Constructing valid V2 traces or
/// a development authority receipt cannot manufacture native proof custody.
pub fn publishProductionInto(
    destination: *VerifiedAuthorityPublicationV2,
    verification: *const AuthorityVerificationV2,
) Error!void {
    if (overlap(std.mem.asBytes(destination), std.mem.asBytes(verification)))
        return error.AliasedDestination;
    try requireNativeDigest(verification.identity);
    return error.NativeV2ProofApiUnavailable;
}

pub const StagedRowsV2 = struct {
    source: source_v2.PreparedV2,
    public_logup: source_v2.PublicLogUpPublicationV2,
    statement_claim: QM31,
    public_logup_claim: QM31,
};

comptime {
    if (FORMAT_VERSION == 1 or MANIFEST_VERSION == 1 or
        COMPONENT_COUNT != 2 or PUBLIC_LOGUP_LOGICAL_ROWS != 55 or
        PUBLIC_LOGUP_TRACE_ROWS != 64 or HOT_PREPARE_HEAP_ALLOCATIONS != 0 or
        HOT_VERIFY_HEAP_ALLOCATIONS != 0 or HOT_PUBLISH_HEAP_ALLOCATIONS != 0 or
        INTERACTION_BULK_INVERSIONS != 2 or !ALL_AUTHORITY_EVENTS_CHECKED or
        !ALL_PUBLIC_LOGUP_WORDS_CHECKED or !NATIVE_V2_PROOF_API_AVAILABLE or
        OUTER_STARK_VERIFICATION_AVAILABLE or PRODUCTION_ACTIVATION or
        COMPLETE_TEMPORAL_PARENT)
    {
        @compileError("segment-leaf V2 outer authority capability drifted");
    }
    if (@TypeOf(@as(OuterManifestV2, undefined).identity) != NativeDigest or
        @TypeOf(@as(OuterManifestV2, undefined).authority_sha_id) !=
            Sha256Digest or
        @TypeOf(@as(PreparedOuterAuthorityV2, undefined).committed_trace_sha_id) !=
            Sha256Digest)
    {
        @compileError("native and SHA identity representations drifted");
    }
}
