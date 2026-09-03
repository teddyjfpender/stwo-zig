//! Capture-derived campaign canonical-empty geometry.
//!
//! This helper is deliberately separate from proof transport.  The verifier
//! supplies the live PCS capture and the pre-final campaign target supplies
//! only the authenticated active-row vector and shared padded layout.  The
//! result is the independently cold-derived role-1 final geometry later
//! consumed by the three-role FinalRemint transaction.

const std = @import("std");
const stwo_core = @import("stwo_core");

const manifest_mod =
    @import("recursive_common_canonical_empty_campaign_universal_manifest_v2.zig");
const common_authority =
    @import("recursive_common_wrapper_authority_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const padding_target_mod =
    @import("recursive_pipeline_campaign_padding_target_v2.zig");
const secure_engine =
    @import("recursive_temporal_secure_parent_native_engine_v1.zig");

pub fn geometryFromFresh(
    padding_target: *const padding_target_mod.CampaignPaddingTargetV2,
    fresh: *const secure_engine.FreshVerificationV1,
) !registry_mod.AuthenticatedGeometryV1 {
    try padding_target.validateSelf();
    const active_logs = try padding_target.activeLogsForRole(
        .canonical_empty_field_v2,
    );
    const padded_logs = try padding_target.paddedLogs();
    var logs: manifest_mod.LogSizes = undefined;
    for (&logs, padded_logs[0..manifest_mod.COMPONENT_COUNT]) |
        *destination,
        source,
    | destination.* = source;
    const manifest = try manifest_mod.buildForLogSizes(logs);
    const pcs = registry_mod.PcsConfigV1.secureTemporalParent();
    const capture = &fresh.capture;
    if (capture.commitments.len != common_authority.COMMITMENT_TREE_COUNT or
        capture.column_log_sizes.len != common_authority.COMMITMENT_TREE_COUNT)
    {
        return error.CanonicalEmptyUniversalProofShapeMismatch;
    }
    try validateTraceTree(
        &manifest,
        capture.column_log_sizes[0],
        .preprocessed,
        pcs.fri_log_blowup_factor,
    );
    try validateTraceTree(
        &manifest,
        capture.column_log_sizes[1],
        .main,
        pcs.fri_log_blowup_factor,
    );
    try validateTraceTree(
        &manifest,
        capture.column_log_sizes[2],
        .interaction,
        pcs.fri_log_blowup_factor,
    );
    const column_log_degree = try columnDegreeFromCapture(
        capture.column_log_sizes[3],
        pcs.fri_log_blowup_factor,
    );
    const composition_columns = stwo_core.verifier_types.compositionColumnCount(
        stwo_core.verifier_types.COMPOSITION_LOG_SPLIT,
        stwo_core.fields.qm31.SECURE_EXTENSION_DEGREE,
    ) orelse return error.CanonicalEmptyUniversalProofShapeMismatch;
    if (capture.column_log_sizes[3].len != composition_columns)
        return error.CanonicalEmptyUniversalProofShapeMismatch;

    const proof_shape = try registry_mod.sealProofShapeFromCapture(
        capture,
        manifest_mod.COMPONENT_COUNT,
        column_log_degree,
        padding_target.target.padding_table_layout_identity_sha256,
    );
    var active = [_]u8{0} ** registry_mod.MAX_COMPONENT_COUNT;
    var padded = [_]u8{0} ** registry_mod.MAX_COMPONENT_COUNT;
    const semantic_logs = manifest_mod.exactLogSizes();
    for (semantic_logs, 0..) |log_size, index| {
        const active_log = std.math.cast(u8, log_size) orelse
            return error.CanonicalEmptyUniversalProofShapeMismatch;
        if (active_logs[index] != active_log)
            return error.CanonicalEmptyUniversalProofShapeMismatch;
        active[index] = active_log;
        padded[index] = std.math.cast(u8, logs[index]) orelse
            return error.CanonicalEmptyUniversalProofShapeMismatch;
    }
    var preprocessed = [_]u8{0} **
        registry_mod.MAX_PREPROCESSED_COLUMN_COUNT;
    try fillBaseColumnLogs(&manifest, .preprocessed, &preprocessed);
    const result = try registry_mod.AuthenticatedGeometryV1.seal(.{
        .role = .canonical_empty_field_v2,
        .authenticated_padding = true,
        .component_count = manifest_mod.COMPONENT_COUNT,
        .preprocessed_column_count = @intCast(
            manifest.total_preprocessed_columns,
        ),
        .trace_log_size = padding_target.target.target_trace_log_size,
        .active_component_log_sizes = active,
        .padded_component_log_sizes = padded,
        .preprocessed_column_log_sizes = preprocessed,
        .circuit_identity_sha256 = try manifest_mod.contractIdentityForManifest(
            &manifest,
            logs,
        ),
        .program_identity_sha256 = try manifest_mod.programIdentityForManifest(
            &manifest,
            logs,
        ),
        .profile_identity_sha256 = try manifest_mod.profileIdentityForManifest(
            &manifest,
            logs,
        ),
        .padding_layout_identity_sha256 = padding_target.target.padding_table_layout_identity_sha256,
        .preprocessed_root = capture.commitments[0],
        .pcs = pcs,
        .output_abi = registry_mod.OutputAbiV1.fieldNodePublicV2(),
        .proof_shape = proof_shape,
        .authority_identity_sha256 = undefined,
    });
    try padding_target.validateRemintedGeometry(
        .canonical_empty_field_v2,
        &result,
    );
    return result;
}

const TraceTreeV2 = enum { preprocessed, main, interaction };

fn validateTraceTree(
    manifest: *const manifest_mod.Manifest,
    captured_logs: anytype,
    tree: TraceTreeV2,
    blowup: u32,
) !void {
    const expected_count = switch (tree) {
        .preprocessed => manifest.total_preprocessed_columns,
        .main => manifest.total_main_columns,
        .interaction => manifest.total_interaction_columns,
    };
    if (captured_logs.len != @as(usize, expected_count))
        return error.CanonicalEmptyUniversalProofShapeMismatch;
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
        const expected = std.math.add(
            u32,
            placement.geometry.log_size,
            blowup,
        ) catch return error.CanonicalEmptyUniversalProofShapeMismatch;
        const start: usize = @intCast(offset);
        const column_count: usize = @intCast(count);
        for (captured_logs[start..][0..column_count]) |actual|
            if (actual != expected)
                return error.CanonicalEmptyUniversalProofShapeMismatch;
    }
}

fn fillBaseColumnLogs(
    manifest: *const manifest_mod.Manifest,
    tree: TraceTreeV2,
    destination: *[registry_mod.MAX_PREPROCESSED_COLUMN_COUNT]u8,
) !void {
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
        const log_size = std.math.cast(
            u8,
            placement.geometry.log_size,
        ) orelse return error.CanonicalEmptyUniversalProofShapeMismatch;
        const start: usize = @intCast(offset);
        const column_count: usize = @intCast(count);
        @memset(destination[start..][0..column_count], log_size);
    }
}

fn columnDegreeFromCapture(
    composition_logs: anytype,
    blowup: u32,
) !u8 {
    if (composition_logs.len == 0)
        return error.CanonicalEmptyUniversalProofShapeMismatch;
    const extended = composition_logs[0];
    for (composition_logs[1..]) |log_size|
        if (log_size != extended)
            return error.CanonicalEmptyUniversalProofShapeMismatch;
    const base = std.math.sub(u32, extended, blowup) catch
        return error.CanonicalEmptyUniversalProofShapeMismatch;
    return std.math.cast(u8, base) orelse
        error.CanonicalEmptyUniversalProofShapeMismatch;
}
