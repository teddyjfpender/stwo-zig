//! Cold-derived geometry helpers for the isolated common-fold q193 bootstrap.
//!
//! No function in this module mints production parity. The common geometry is
//! returned only after a genuine verifier capture supplies all roots and wire
//! dimensions. The temporary three-entry registry admits role 1 only; its
//! other entries are private structural sentinels.

const std = @import("std");
const stwo_core = @import("stwo_core");

const canonical_proof =
    @import("recursive_common_canonical_empty_universal_proof_v2.zig");
const common_authority = @import("recursive_common_wrapper_authority_v2.zig");
const manifest_mod =
    @import("recursive_common_fold_universal_manifest_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const secure_engine =
    @import("recursive_temporal_secure_parent_native_engine_v1.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const DIMENSIONS =
    canonical_proof.CAPTURE_DERIVED_FIXED_WIRE_DIMENSIONS_V2;
pub const FRI_FOLD_WIDTHS =
    canonical_proof.CAPTURE_DERIVED_FRI_FOLD_WIDTHS_V2;
pub const FRI_PATH_DEPTHS =
    canonical_proof.CAPTURE_DERIVED_FRI_PATH_DEPTHS_V2;

const BOOTSTRAP_REGISTRY_DOMAIN =
    "stwo-zig/recursive-common-fold-q193-bootstrap-registry/v2\x00";

pub fn bootstrapRegistry(
    left: *const canonical_proof.OwnedColdProofV2,
    right: *const canonical_proof.OwnedColdProofV2,
) !registry_mod.RecursiveCircuitRegistryV1 {
    try left.validate();
    try right.validate();
    if (!std.meta.eql(left.geometry_value, right.geometry_value))
        return error.BootstrapCanonicalChildMismatch;
    const canonical = left.geometry_value;
    const real_sentinel = try sentinelGeometry(
        canonical,
        .ethereum_incremental_leaf_wrapper_v4,
    );
    const common_sentinel = try sentinelGeometry(
        canonical,
        .common_fold_field_v2,
    );
    const entries = [registry_mod.ROLE_COUNT]registry_mod.RegistryEntryV1{
        try registry_mod.RegistryEntryV1.fromGeometry(&real_sentinel),
        try registry_mod.RegistryEntryV1.fromGeometry(&canonical),
        try registry_mod.RegistryEntryV1.fromGeometry(&common_sentinel),
    };
    const result = try registry_mod.RecursiveCircuitRegistryV1.seal(entries);
    try result.validate();
    return result;
}

pub fn geometryFromFresh(
    manifest: *const manifest_mod.Manifest,
    fresh: *const secure_engine.FreshVerificationV1,
) !registry_mod.AuthenticatedGeometryV1 {
    const logs = try logSizes(manifest);
    try manifest_mod.validateForDerivedLogSizes(manifest, logs);
    const pcs = registry_mod.PcsConfigV1.secureTemporalParent();
    const capture = &fresh.capture;
    if (capture.commitments.len != common_authority.COMMITMENT_TREE_COUNT or
        capture.column_log_sizes.len != common_authority.COMMITMENT_TREE_COUNT)
    {
        return error.BootstrapCommonGeometryMismatch;
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
        try manifest_mod.tableLayoutIdentityForDerivedManifest(manifest, logs),
    );
    try validateCaptureDerivedCommonShape(manifest, fresh, &proof_shape);

    var active = [_]u8{0} ** registry_mod.MAX_COMPONENT_COUNT;
    var padded = [_]u8{0} ** registry_mod.MAX_COMPONENT_COUNT;
    for (logs, 0..) |log_size, index| {
        active[index] = std.math.cast(u8, log_size) orelse
            return error.BootstrapCommonGeometryMismatch;
        padded[index] = active[index];
    }
    var preprocessed = [_]u8{0} **
        registry_mod.MAX_PREPROCESSED_COLUMN_COUNT;
    try fillBaseColumnLogs(manifest, .preprocessed, &preprocessed);
    return registry_mod.AuthenticatedGeometryV1.seal(.{
        .role = .common_fold_field_v2,
        .authenticated_padding = true,
        .component_count = manifest_mod.COMPONENT_COUNT,
        .preprocessed_column_count = @intCast(
            manifest.total_preprocessed_columns,
        ),
        .trace_log_size = try maximumLogSize(logs),
        .active_component_log_sizes = active,
        .padded_component_log_sizes = padded,
        .preprocessed_column_log_sizes = preprocessed,
        .circuit_identity_sha256 = try manifest_mod.contractIdentityForDerivedManifest(manifest, logs),
        .program_identity_sha256 = try manifest_mod.programIdentityForDerivedManifest(manifest, logs),
        .profile_identity_sha256 = try manifest_mod.profileIdentityForDerivedManifest(manifest, logs),
        .padding_layout_identity_sha256 = try manifest_mod.paddingIdentityForDerivedManifest(manifest, logs),
        .preprocessed_root = capture.commitments[0],
        .pcs = pcs,
        .output_abi = registry_mod.OutputAbiV1.fieldNodePublicV2(),
        .proof_shape = proof_shape,
        .authority_identity_sha256 = undefined,
    });
}

fn maximumLogSize(logs: manifest_mod.LogSizes) !u8 {
    var result: u32 = 0;
    for (logs) |log_size| result = @max(result, log_size);
    return std.math.cast(u8, result) orelse
        error.BootstrapCommonGeometryMismatch;
}

/// Recomputes the bootstrap-only common-output shape from the successful
/// verifier capture.  The canonical-empty fixed selector is an input-wire
/// authority and must not be reused as the role-2 output geometry.
pub fn validateCaptureDerivedCommonShape(
    manifest: *const manifest_mod.Manifest,
    fresh: *const secure_engine.FreshVerificationV1,
    shape: *const registry_mod.FixedProofShapeV3,
) !void {
    const logs = try logSizes(manifest);
    try manifest_mod.validateForDerivedLogSizes(manifest, logs);
    const pcs = registry_mod.PcsConfigV1.secureTemporalParent();
    const capture = &fresh.capture;
    if (capture.commitments.len != common_authority.COMMITMENT_TREE_COUNT or
        capture.column_log_sizes.len != common_authority.COMMITMENT_TREE_COUNT)
    {
        return error.BootstrapCommonGeometryMismatch;
    }
    try validateTraceTree(manifest, capture.column_log_sizes[0], .preprocessed, pcs);
    try validateTraceTree(manifest, capture.column_log_sizes[1], .main, pcs);
    try validateTraceTree(manifest, capture.column_log_sizes[2], .interaction, pcs);
    const column_log_degree = try columnDegreeFromCapture(
        capture.column_log_sizes[3],
        pcs.fri_log_blowup_factor,
    );
    const expected = try registry_mod.sealProofShapeFromCapture(
        capture,
        manifest_mod.COMPONENT_COUNT,
        column_log_degree,
        try manifest_mod.tableLayoutIdentityForDerivedManifest(manifest, logs),
    );
    try expected.validateAgainstPcs(
        pcs.fri_log_blowup_factor,
        pcs.fri_query_count,
        pcs.fri_fold_step,
        pcs.fri_log_last_layer_degree_bound,
    );
    if (!std.meta.eql(shape.*, expected))
        return error.BootstrapCommonGeometryMismatch;
}

/// Exact canonical-empty child-wire selector.  This is deliberately not a
/// validator for the independently cold-derived common-fold output shape.
pub fn requireExactFixedShape(
    shape: *const registry_mod.FixedProofShapeV3,
) !void {
    const actual = try canonical_proof.fixedWireDimensionsFromColdShape(shape);
    if (!std.meta.eql(actual, DIMENSIONS) or
        shape.fri_layer_count != FRI_FOLD_WIDTHS.len or
        !std.mem.eql(
            u8,
            shape.fri_layer_fold_widths[0..shape.fri_layer_count],
            &FRI_FOLD_WIDTHS,
        ) or !std.mem.eql(
        u8,
        shape.fri_layer_path_depths[0..shape.fri_layer_count],
        &FRI_PATH_DEPTHS,
    )) return error.BootstrapDimensionMismatch;
}

pub fn validateChildShape(
    geometry: *const registry_mod.AuthenticatedGeometryV1,
) !void {
    try geometry.validate();
    if (geometry.role != .canonical_empty_field_v2)
        return error.BootstrapCanonicalChildMismatch;
    try requireExactFixedShape(&geometry.proof_shape);
}

pub fn logSizes(
    manifest: *const manifest_mod.Manifest,
) !manifest_mod.LogSizes {
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
    if (captured_logs.len != @as(usize, expected_count))
        return error.BootstrapCommonGeometryMismatch;
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
            pcs.fri_log_blowup_factor,
        ) catch return error.BootstrapCommonGeometryMismatch;
        const start: usize = @intCast(offset);
        const column_count: usize = @intCast(count);
        for (captured_logs[start..][0..column_count]) |actual|
            if (actual != expected)
                return error.BootstrapCommonGeometryMismatch;
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
        ) orelse return error.BootstrapCommonGeometryMismatch;
        const start: usize = @intCast(offset);
        const column_count: usize = @intCast(count);
        @memset(destination[start..][0..column_count], log_size);
    }
}

fn columnDegreeFromCapture(composition_logs: anytype, blowup: u32) !u8 {
    if (composition_logs.len == 0)
        return error.BootstrapCommonGeometryMismatch;
    const extended = composition_logs[0];
    for (composition_logs[1..]) |log_size|
        if (log_size != extended)
            return error.BootstrapCommonGeometryMismatch;
    const base = std.math.sub(u32, extended, blowup) catch
        return error.BootstrapCommonGeometryMismatch;
    return std.math.cast(u8, base) orelse
        error.BootstrapCommonGeometryMismatch;
}

fn sentinelGeometry(
    canonical: registry_mod.AuthenticatedGeometryV1,
    role: registry_mod.CircuitRoleV1,
) !registry_mod.AuthenticatedGeometryV1 {
    var result = canonical;
    result.role = role;
    result.circuit_identity_sha256 = sentinelIdentity(
        "circuit",
        role,
        &canonical.authority_identity_sha256,
    );
    result.program_identity_sha256 = sentinelIdentity(
        "program",
        role,
        &canonical.authority_identity_sha256,
    );
    result.profile_identity_sha256 = sentinelIdentity(
        "profile",
        role,
        &canonical.authority_identity_sha256,
    );
    result.authority_identity_sha256 = undefined;
    return registry_mod.AuthenticatedGeometryV1.seal(result);
}

fn sentinelIdentity(
    label: []const u8,
    role: registry_mod.CircuitRoleV1,
    canonical_identity: *const [32]u8,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(BOOTSTRAP_REGISTRY_DOMAIN);
    hash.update(label);
    hashInt(&hash, u8, @intFromEnum(role));
    hash.update(canonical_identity);
    return hash.finalResult();
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    DIMENSIONS.validate();
    if (DIMENSIONS.query_count != 193 or FRI_FOLD_WIDTHS.len != 4 or
        FRI_PATH_DEPTHS.len != 4)
    {
        @compileError("common-fold bootstrap geometry selector drifted");
    }
}
