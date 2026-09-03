//! Cold-derived role-2 geometry for one campaign padding target.
//!
//! Every PCS width, query/path dimension, and preprocessed root comes from the
//! newly verified common-fold capture.  The active row vector comes from the
//! target's independently cold-derived role-2 source, while the padded vector
//! and role-independent table-layout identity come from the common target.
//! No role-1 selector or bootstrap geometry is accepted.

const std = @import("std");

const target_mod = @import("recursive_pipeline_campaign_padding_target_v2.zig");
const manifest_mod = @import("recursive_common_fold_universal_manifest_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const common_authority = @import("recursive_common_wrapper_authority_v2.zig");
const secure_engine =
    @import("recursive_temporal_secure_parent_native_engine_v1.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const ROLE = registry_mod.CircuitRoleV1.common_fold_field_v2;
pub const PRODUCTION_ACTIVATION = false;
pub const CAPTURE_DERIVED_ONLY = true;

pub const Error = target_mod.Error || manifest_mod.Error ||
    registry_mod.Error || error{
    CampaignPreFinalCommonGeometryMismatch,
};

pub fn geometryFromFresh(
    target: *const target_mod.CampaignPaddingTargetV2,
    manifest: *const manifest_mod.Manifest,
    fresh: *const secure_engine.FreshVerificationV1,
) !registry_mod.AuthenticatedGeometryV1 {
    try validateManifestAgainstTarget(target, manifest);
    const pcs = registry_mod.PcsConfigV1.secureTemporalParent();
    const capture = &fresh.capture;
    if (capture.commitments.len != common_authority.COMMITMENT_TREE_COUNT or
        capture.column_log_sizes.len != common_authority.COMMITMENT_TREE_COUNT)
    {
        return error.CampaignPreFinalCommonGeometryMismatch;
    }
    try validateTraceTree(manifest, capture.column_log_sizes[0], .preprocessed, pcs);
    try validateTraceTree(manifest, capture.column_log_sizes[1], .main, pcs);
    try validateTraceTree(manifest, capture.column_log_sizes[2], .interaction, pcs);
    const column_log_degree = try columnDegreeFromCapture(
        capture.column_log_sizes[3],
        pcs.fri_log_blowup_factor,
    );
    const proof_shape = try registry_mod.sealProofShapeFromCapture(
        capture,
        manifest_mod.COMPONENT_COUNT,
        column_log_degree,
        target.target.padding_table_layout_identity_sha256,
    );
    try proof_shape.validateAgainstPcs(
        pcs.fri_log_blowup_factor,
        pcs.fri_query_count,
        pcs.fri_fold_step,
        pcs.fri_log_last_layer_degree_bound,
    );

    const active_source = try target.activeLogsForRole(ROLE);
    const padded_source = try target.paddedLogs();
    var active = [_]u8{0} ** registry_mod.MAX_COMPONENT_COUNT;
    var padded = [_]u8{0} ** registry_mod.MAX_COMPONENT_COUNT;
    @memcpy(
        active[0..manifest_mod.COMPONENT_COUNT],
        active_source[0..manifest_mod.COMPONENT_COUNT],
    );
    @memcpy(
        padded[0..manifest_mod.COMPONENT_COUNT],
        padded_source[0..manifest_mod.COMPONENT_COUNT],
    );
    var preprocessed = [_]u8{0} **
        registry_mod.MAX_PREPROCESSED_COLUMN_COUNT;
    try fillBaseColumnLogs(manifest, &preprocessed);
    const logs = try logSizes(manifest);
    const result = try registry_mod.AuthenticatedGeometryV1.seal(.{
        .role = ROLE,
        .authenticated_padding = true,
        .component_count = manifest_mod.COMPONENT_COUNT,
        .preprocessed_column_count = @intCast(
            manifest.total_preprocessed_columns,
        ),
        .trace_log_size = target.target.target_trace_log_size,
        .active_component_log_sizes = active,
        .padded_component_log_sizes = padded,
        .preprocessed_column_log_sizes = preprocessed,
        .circuit_identity_sha256 = try manifest_mod
            .contractIdentityForDerivedManifest(manifest, logs),
        .program_identity_sha256 = try manifest_mod
            .programIdentityForDerivedManifest(manifest, logs),
        .profile_identity_sha256 = try manifest_mod
            .profileIdentityForDerivedManifest(manifest, logs),
        .padding_layout_identity_sha256 = target.target
            .padding_table_layout_identity_sha256,
        .preprocessed_root = capture.commitments[0],
        .pcs = pcs,
        .output_abi = registry_mod.OutputAbiV1.fieldNodePublicV2(),
        .proof_shape = proof_shape,
        .authority_identity_sha256 = undefined,
    });
    try target.validateRemintedGeometry(ROLE, &result);
    try validateFreshGeometry(target, manifest, fresh, &result);
    return result;
}

pub fn validateFreshGeometry(
    target: *const target_mod.CampaignPaddingTargetV2,
    manifest: *const manifest_mod.Manifest,
    fresh: *const secure_engine.FreshVerificationV1,
    geometry: *const registry_mod.AuthenticatedGeometryV1,
) !void {
    try target.validateRemintedGeometry(ROLE, geometry);
    try validateManifestAgainstTarget(target, manifest);
    if (!std.meta.eql(geometry.preprocessed_root, fresh.capture.commitments[0]))
        return error.CampaignPreFinalCommonGeometryMismatch;
    const expected = try registry_mod.sealProofShapeFromCapture(
        &fresh.capture,
        manifest_mod.COMPONENT_COUNT,
        geometry.proof_shape.column_log_degree,
        target.target.padding_table_layout_identity_sha256,
    );
    if (!std.meta.eql(geometry.proof_shape, expected))
        return error.CampaignPreFinalCommonGeometryMismatch;
}

fn validateManifestAgainstTarget(
    target: *const target_mod.CampaignPaddingTargetV2,
    manifest: *const manifest_mod.Manifest,
) !void {
    try target.validateSelf();
    const logs = try target.paddedLogs();
    var exact: manifest_mod.LogSizes = undefined;
    for (&exact, logs[0..manifest_mod.COMPONENT_COUNT]) |
        *destination,
        source,
    | destination.* = source;
    try manifest_mod.validateForDerivedLogSizes(manifest, exact);
}

fn logSizes(manifest: *const manifest_mod.Manifest) !manifest_mod.LogSizes {
    var result: manifest_mod.LogSizes = undefined;
    inline for (manifest_mod.COMPONENT_KEYS, 0..) |key, index|
        result[index] = (try manifest.placement(key)).geometry.log_size;
    try manifest_mod.validateForDerivedLogSizes(manifest, result);
    return result;
}

const TraceTreeV2 = enum { preprocessed, main, interaction };

fn validateTraceTree(
    manifest: *const manifest_mod.Manifest,
    captured_logs: anytype,
    tree: TraceTreeV2,
    pcs: registry_mod.PcsConfigV1,
) !void {
    const expected_count = switch (tree) {
        .preprocessed => manifest.total_preprocessed_columns,
        .main => manifest.total_main_columns,
        .interaction => manifest.total_interaction_columns,
    };
    if (captured_logs.len != expected_count)
        return error.CampaignPreFinalCommonGeometryMismatch;
    inline for (manifest_mod.COMPONENT_KEYS) |key| {
        const placement = try manifest.placement(key);
        const offset = switch (tree) {
            .preprocessed => placement.preprocessed_offset,
            .main => placement.main_offset,
            .interaction => placement.interaction_offset,
        };
        const count = switch (tree) {
            .preprocessed => placement.geometry.preprocessed_columns,
            .main => placement.geometry.main_columns,
            .interaction => placement.geometry.interaction_columns,
        };
        const extended = std.math.add(
            u32,
            placement.geometry.log_size,
            pcs.fri_log_blowup_factor,
        ) catch return error.CampaignPreFinalCommonGeometryMismatch;
        const start: usize = @intCast(offset);
        for (captured_logs[start..][0..count]) |actual|
            if (actual != extended)
                return error.CampaignPreFinalCommonGeometryMismatch;
    }
}

fn fillBaseColumnLogs(
    manifest: *const manifest_mod.Manifest,
    destination: *[registry_mod.MAX_PREPROCESSED_COLUMN_COUNT]u8,
) !void {
    inline for (manifest_mod.COMPONENT_KEYS) |key| {
        const placement = try manifest.placement(key);
        const start: usize = @intCast(placement.preprocessed_offset);
        const count: usize = @intCast(
            placement.geometry.preprocessed_columns,
        );
        const log_size = std.math.cast(
            u8,
            placement.geometry.log_size,
        ) orelse return error.CampaignPreFinalCommonGeometryMismatch;
        @memset(destination[start..][0..count], log_size);
    }
}

fn columnDegreeFromCapture(composition_logs: anytype, blowup: u32) !u8 {
    if (composition_logs.len == 0)
        return error.CampaignPreFinalCommonGeometryMismatch;
    const extended = composition_logs[0];
    for (composition_logs[1..]) |log_size| if (log_size != extended)
        return error.CampaignPreFinalCommonGeometryMismatch;
    const base = std.math.sub(u32, extended, blowup) catch
        return error.CampaignPreFinalCommonGeometryMismatch;
    return std.math.cast(u8, base) orelse
        error.CampaignPreFinalCommonGeometryMismatch;
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        @intFromEnum(ROLE) != 2 or PRODUCTION_ACTIVATION or
        !CAPTURE_DERIVED_ONLY)
    {
        @compileError("campaign pre-final common geometry contract drifted");
    }
}
