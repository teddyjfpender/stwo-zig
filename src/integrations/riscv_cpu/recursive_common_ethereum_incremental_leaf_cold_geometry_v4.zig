//! Capture-derived schema-4 registry geometry for the role-0 wrapper.
//!
//! The geometry is minted only from a genuine q193 cold verifier capture and
//! the same live campaign-bound cohort that reconstructed all 36 rows.  The
//! producer manifest, a digest, or a caller supplied maximum cannot create
//! this authority.

const std = @import("std");
const stwo_core = @import("stwo_core");

const common_authority = @import("recursive_common_wrapper_authority_v2.zig");
const manifest_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const secure_artifact =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 4;
pub const ROLE = registry_mod.CircuitRoleV4
    .ethereum_incremental_leaf_wrapper_v4;
pub const PRODUCTION_ACTIVATION = false;
pub const CAPTURE_DERIVED_ONLY = true;

pub const Error = registry_mod.Error || error{
    InvalidEthereumIncrementalColdGeometryV4,
};

pub fn geometryFromCold(
    cohort: anytype,
    session: *const secure_artifact.SessionV1,
    cold: anytype,
) !registry_mod.AuthenticatedGeometryV1 {
    try cold.validateBorrowed(cohort, session);
    const manifest = cohort.manifest();
    try manifest.validate();
    const capture = &cold.fresh.capture;
    const pcs = registry_mod.PcsConfigV1.secureTemporalParent();
    if (capture.commitments.len != common_authority.COMMITMENT_TREE_COUNT or
        capture.column_log_sizes.len != common_authority.COMMITMENT_TREE_COUNT)
    {
        return error.InvalidEthereumIncrementalColdGeometryV4;
    }
    try validateTraceTree(
        manifest,
        capture.column_log_sizes[0],
        .preprocessed,
        pcs.fri_log_blowup_factor,
    );
    try validateTraceTree(
        manifest,
        capture.column_log_sizes[1],
        .main,
        pcs.fri_log_blowup_factor,
    );
    try validateTraceTree(
        manifest,
        capture.column_log_sizes[2],
        .interaction,
        pcs.fri_log_blowup_factor,
    );
    const composition_degree = try columnDegreeFromCapture(
        capture.column_log_sizes[3],
        pcs.fri_log_blowup_factor,
    );

    const table_layout = try cohort.tableLayoutIdentity();
    const proof_shape = try registry_mod.sealProofShapeFromCapture(
        capture,
        manifest_mod.COMPONENT_COUNT,
        composition_degree,
        table_layout,
    );
    var active = [_]u8{0} ** registry_mod.MAX_COMPONENT_COUNT;
    var padded = [_]u8{0} ** registry_mod.MAX_COMPONENT_COUNT;
    var maximum_log_size: u8 = 0;
    if (cohort.paddingTarget()) |target| {
        const active_logs = try target.activeLogsForRole(ROLE);
        const padded_logs = try target.paddedLogs();
        active = active_logs;
        padded = padded_logs;
        maximum_log_size = target.target.target_trace_log_size;
    } else {
        for (cohort.logSizes(), 0..) |log_size, index| {
            const compact = std.math.cast(u8, log_size) orelse
                return error.InvalidEthereumIncrementalColdGeometryV4;
            active[index] = compact;
            padded[index] = compact;
            maximum_log_size = @max(maximum_log_size, compact);
        }
    }
    var preprocessed = [_]u8{0} **
        registry_mod.MAX_PREPROCESSED_COLUMN_COUNT;
    try fillBaseColumnLogs(manifest, &preprocessed);

    const result = try registry_mod.AuthenticatedGeometryV1.seal(.{
        .role = ROLE,
        .authenticated_padding = true,
        .component_count = manifest_mod.COMPONENT_COUNT,
        .preprocessed_column_count = @intCast(
            manifest.total_preprocessed_columns,
        ),
        .trace_log_size = maximum_log_size,
        .active_component_log_sizes = active,
        .padded_component_log_sizes = padded,
        .preprocessed_column_log_sizes = preprocessed,
        .circuit_identity_sha256 = try cohort.parentManifestIdentity(),
        .program_identity_sha256 = try cohort.programIdentity(),
        .profile_identity_sha256 = try cohort.profileIdentity(),
        .padding_layout_identity_sha256 = try cohort.paddingLayoutIdentity(),
        .preprocessed_root = capture.commitments[0],
        .pcs = pcs,
        .output_abi = registry_mod.OutputAbiV1.fieldNodePublicV2(),
        .proof_shape = proof_shape,
        .authority_identity_sha256 = undefined,
    });
    if (cohort.paddingTarget()) |target|
        try target.validateRemintedGeometry(ROLE, &result);
    return result;
}

const TraceTreeV4 = enum { preprocessed, main, interaction };

fn validateTraceTree(
    manifest: *const manifest_mod.Manifest,
    captured_logs: anytype,
    tree: TraceTreeV4,
    blowup: u32,
) !void {
    const expected_count = switch (tree) {
        .preprocessed => manifest.total_preprocessed_columns,
        .main => manifest.total_main_columns,
        .interaction => manifest.total_interaction_columns,
    };
    if (captured_logs.len != @as(usize, expected_count))
        return error.InvalidEthereumIncrementalColdGeometryV4;
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
        ) catch return error.InvalidEthereumIncrementalColdGeometryV4;
        const start: usize = @intCast(offset);
        const column_count: usize = @intCast(count);
        for (captured_logs[start..][0..column_count]) |actual|
            if (actual != expected)
                return error.InvalidEthereumIncrementalColdGeometryV4;
    }
}

fn fillBaseColumnLogs(
    manifest: *const manifest_mod.Manifest,
    destination: *[registry_mod.MAX_PREPROCESSED_COLUMN_COUNT]u8,
) !void {
    inline for (manifest_mod.COMPONENT_KEYS) |key| {
        const placement = try manifest.placement(key);
        const log_size = std.math.cast(
            u8,
            placement.geometry.log_size,
        ) orelse return error.InvalidEthereumIncrementalColdGeometryV4;
        const start: usize = @intCast(placement.preprocessed_offset);
        const count: usize = @intCast(
            placement.geometry.preprocessed_columns,
        );
        @memset(destination[start..][0..count], log_size);
    }
}

fn columnDegreeFromCapture(
    composition_logs: anytype,
    blowup: u32,
) !u8 {
    const expected_columns = stwo_core.verifier_types.compositionColumnCount(
        @import("ethereum_wrapper_composition_v1.zig").LOG_SPLIT,
        stwo_core.fields.qm31.SECURE_EXTENSION_DEGREE,
    ) orelse return error.InvalidEthereumIncrementalColdGeometryV4;
    if (composition_logs.len != expected_columns)
        return error.InvalidEthereumIncrementalColdGeometryV4;
    const extended = composition_logs[0];
    for (composition_logs[1..]) |log_size|
        if (log_size != extended)
            return error.InvalidEthereumIncrementalColdGeometryV4;
    const base = std.math.sub(u32, extended, blowup) catch
        return error.InvalidEthereumIncrementalColdGeometryV4;
    return std.math.cast(u8, base) orelse
        error.InvalidEthereumIncrementalColdGeometryV4;
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 4 or
        @intFromEnum(ROLE) != 0 or PRODUCTION_ACTIVATION or
        !CAPTURE_DERIVED_ONLY)
    {
        @compileError("role-0 cold geometry V4 drifted");
    }
}

test "Ethereum cold geometry requires admitted split two composition columns" {
    var logs = [_]u32{5} ** 16;
    try std.testing.expectEqual(@as(u8, 4), try columnDegreeFromCapture(&logs, 1));
    try std.testing.expectError(error.InvalidEthereumIncrementalColdGeometryV4, columnDegreeFromCapture(logs[0..8], 1));
    logs[15] = 6;
    try std.testing.expectError(error.InvalidEthereumIncrementalColdGeometryV4, columnDegreeFromCapture(&logs, 1));
    @memset(&logs, 0);
    try std.testing.expectError(error.InvalidEthereumIncrementalColdGeometryV4, columnDegreeFromCapture(&logs, 1));
}
