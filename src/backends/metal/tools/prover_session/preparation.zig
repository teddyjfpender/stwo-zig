//! Artifact preparation, immutable geometry keys, environment, and report framing.

const std = @import("std");
const stwo = @import("stwo");
const artifact_manifest = stwo.metal_session.artifact_manifest;
const artifact_store = stwo.metal_session.artifact_store;
const artifact_views = stwo.metal_session.artifact_views;
const metal_runtime = stwo.backends.metal.runtime;
const cairo_adapted_input = stwo.frontends.cairo.adapter.adapted_input;
const cairo_opcodes = stwo.frontends.cairo.adapter.opcodes;
const one_shot = @import("one_shot");
const protocol = stwo.metal_session.protocol;
const state = @import("state.zig");
const io = @import("io.zig");
const writeFrame = io.writeFrame;
const setenv = state.setenv;
const unsetenv = state.unsetenv;

const persistent_report_schema_version = state.persistent_report_schema_version;
const in_process_runner_linkage = state.in_process_runner_linkage;
const rust_verifier_adapter_version = state.rust_verifier_adapter_version;
const rust_verifier_envelope_abi = state.rust_verifier_envelope_abi;
const rust_verifier_mode = state.rust_verifier_mode;
const rust_verifier_cargo_lock_sha256 = state.rust_verifier_cargo_lock_sha256;
const rust_verifier_stwo_cairo_revision = state.rust_verifier_stwo_cairo_revision;
const rust_verifier_stwo_revision = state.rust_verifier_stwo_revision;
const RustVerifierConfig = state.RustVerifierConfig;
const RustVerifierEvidence = state.RustVerifierEvidence;
const PreparedGeometryKey = state.PreparedGeometryKey;
const CompositionAotAdmissionKey = state.CompositionAotAdmissionKey;
const PreparedGeometryPolicy = state.PreparedGeometryPolicy;
const PreparedHostGeometryCache = state.PreparedHostGeometryCache;
const ProofResult = state.ProofResult;
const ArtifactObjectEvidence = state.ArtifactObjectEvidence;
const ArtifactObjectsEvidence = state.ArtifactObjectsEvidence;
const ExecutableIdentity = state.ExecutableIdentity;
const ProvenanceEvidence = state.ProvenanceEvidence;
const EnvironmentValue = state.EnvironmentValue;
const VerifierScratch = state.VerifierScratch;
const ArtifactSlot = state.ArtifactSlot;
const artifact_slot_count = state.artifact_slot_count;
const PreparedArtifacts = state.PreparedArtifacts;
const RunnerArtifacts = state.RunnerArtifacts;
const RunnerRequest = state.RunnerRequest;
const ViewCache = state.ViewCache;

pub const CompositionProgramPolicy = union(enum) {
    diagnostic,
    approved_metallib: [32]u8,
};

pub fn compositionProgramPolicy(encoded_digest: ?[]const u8) !CompositionProgramPolicy {
    const encoded = encoded_digest orelse return .diagnostic;
    if (encoded.len != 64) return error.InvalidCompositionMetallibDigest;
    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, encoded) catch
        return error.InvalidCompositionMetallibDigest;
    const canonical = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, encoded, &canonical))
        return error.InvalidCompositionMetallibDigest;
    return .{ .approved_metallib = digest };
}

pub fn authorizeCompositionProgram(
    policy: CompositionProgramPolicy,
    kind: std.meta.Tag(artifact_views.CompositionProgram),
    object_id: [32]u8,
) !void {
    switch (policy) {
        .diagnostic => {},
        .approved_metallib => |approved| {
            if (kind != .metallib) return error.CompositionSourceForbidden;
            if (!std.mem.eql(u8, &approved, &object_id))
                return error.UnapprovedCompositionMetallib;
        },
    }
}

pub fn prepareArtifacts(
    allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    views: *ViewCache,
    request: protocol.Request,
    executable_measurement: artifact_manifest.Measurement,
    composition_policy: CompositionProgramPolicy,
) !PreparedArtifacts {
    var prepared = PreparedArtifacts{};
    errdefer prepared.deinit(allocator);
    prepared.entries[0] = .{
        .role = .backend_executable,
        .format_version = 1,
        .provenance = .unattested,
        .measurement = executable_measurement,
        .source_chain_complete = false,
    };
    prepared.entry_count = 1;

    try prepared.addSnapshot(store, .adapted_input, .adapted_input, request.artifacts.adapted_input, .proof_derived, .prefer_apfs_clone);
    try prepared.addSnapshot(store, .schedule, .schedule, request.artifacts.schedule, .proof_derived, .byte_copy);
    try prepared.addSnapshot(store, .witness_programs, .witness_programs, request.artifacts.witness_programs, .proof_derived, .byte_copy);
    try prepared.addSnapshot(store, .multiplicity_feeds, .multiplicity_feeds, request.artifacts.multiplicity_feeds, .proof_derived, .byte_copy);
    try prepared.addSnapshot(store, .relation_templates, .relation_templates, request.artifacts.relation_templates, .proof_derived, .byte_copy);
    try prepared.addSnapshot(store, .fixed_tables, .fixed_tables, request.artifacts.fixed_tables, .proof_derived, .byte_copy);
    try prepared.addSnapshot(store, .composition, .composition, request.artifacts.composition, .proof_derived, .byte_copy);
    try prepared.addSnapshot(store, .composition_program, .composition_program, request.artifacts.composition_program, .proof_derived, .byte_copy);
    try prepared.addSnapshot(store, .preprocessed_evaluations, .preprocessed_evaluations, request.artifacts.preprocessed_evaluations, .proof_derived, .prefer_apfs_clone);
    try prepared.addSnapshot(store, .preprocessed_tree0_merkle, .preprocessed_tree0_merkle, request.artifacts.preprocessed_tree0_merkle, .proof_derived, .prefer_apfs_clone);
    try prepared.addSnapshot(store, .preprocessed_coefficients, .preprocessed_coefficients, request.artifacts.preprocessed_coefficients, .proof_derived, .prefer_apfs_clone);
    if (request.artifacts.transcript_reference) |reference|
        try prepared.addSnapshot(store, .transcript_reference, .transcript_reference, reference, .diagnostic_fixture, .byte_copy);
    if (request.artifacts.quotient_reference) |reference|
        try prepared.addSnapshot(store, .quotient_reference, .quotient_reference, reference, .diagnostic_fixture, .byte_copy);

    var expected_tree0_root: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&expected_tree0_root, request.expected_tree0_root_hex) catch
        return error.InvalidTreeRoot;
    const composition_program_kind = try compositionProgramKind(
        request.artifacts.composition_program.diagnosticPath(),
    );
    try authorizeCompositionProgram(
        composition_policy,
        composition_program_kind,
        prepared.snapshot(.composition_program).object_id,
    );
    const composition_program: artifact_views.CompositionProgram = switch (composition_program_kind) {
        .metal => .{ .metal = immutableObject(prepared.snapshot(.composition_program)) },
        .metallib => .{ .metallib = immutableObject(prepared.snapshot(.composition_program)) },
    };
    const view_name = try std.fmt.allocPrint(
        allocator,
        "{}-{s}",
        .{ request.sequence, request.request_id },
    );
    defer allocator.free(view_name);
    prepared.view = try views.getOrCreate(store.root_path, view_name, .{
        .preprocessed_evaluations = immutableObject(prepared.snapshot(.preprocessed_evaluations)),
        .preprocessed_tree0_merkle = immutableObject(prepared.snapshot(.preprocessed_tree0_merkle)),
        .composition = immutableObject(prepared.snapshot(.composition)),
        .composition_program = composition_program,
        .expected_tree0_root = expected_tree0_root,
    });
    prepared.tree0_root_hex = std.fmt.bytesToHex(prepared.view.?.tree0_root, .lower);
    return prepared;
}

pub fn immutableObject(snapshot: *const artifact_store.Snapshot) artifact_views.ImmutableObject {
    return .{
        .path = snapshot.path,
        .object_id = snapshot.object_id,
        .bytes = snapshot.measurement.bytes,
    };
}

pub fn compositionProgramKind(path: []const u8) !std.meta.Tag(artifact_views.CompositionProgram) {
    if (std.mem.endsWith(u8, path, ".metal")) return .metal;
    if (std.mem.endsWith(u8, path, ".metallib")) return .metallib;
    return error.InvalidCompositionProgram;
}

pub fn canonicalProofProtocolDigest() ![32]u8 {
    return artifact_manifest.protocolDigest(.{
        .channel = one_shot.canonical_protocol.channel,
        .channel_salt = one_shot.canonical_protocol.channel_salt,
        .log_blowup_factor = one_shot.canonical_protocol.log_blowup_factor,
        .n_queries = one_shot.canonical_protocol.n_queries,
        .interaction_pow_bits = one_shot.canonical_protocol.interaction_pow_bits,
        .query_pow_bits = one_shot.canonical_protocol.query_pow_bits,
        .fri_fold_step = one_shot.canonical_protocol.fri_fold_step,
        .fri_lifting = one_shot.canonical_protocol.fri_lifting,
        .fri_log_last_layer_degree_bound = one_shot.canonical_protocol.fri_log_last_layer_degree_bound,
    });
}

pub fn preparedStateKey(
    objects: ArtifactObjectsEvidence,
    tree0_root_hex: [64]u8,
    budget_gib: []const u8,
    program_kind: std.meta.Tag(artifact_views.CompositionProgram),
    executable_digest: [32]u8,
    protocol_digest: [32]u8,
) !one_shot.PreparedStateKey {
    const budget_value = try std.fmt.parseFloat(f64, budget_gib);
    if (!std.math.isFinite(budget_value) or budget_value <= 0) return error.InvalidBudget;
    const budget_bytes_float = budget_value * 1024.0 * 1024.0 * 1024.0;
    if (budget_value >= 17_179_869_184.0) return error.InvalidBudget;
    const budget_bytes: u64 = @intFromFloat(budget_bytes_float);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig-metal-prepared-state-v1\x00");
    inline for (.{
        objects.schedule,
        objects.witness_programs,
        objects.multiplicity_feeds,
        objects.relation_templates,
        objects.fixed_tables,
        objects.composition,
        objects.composition_program,
        objects.preprocessed_evaluations,
        objects.preprocessed_tree0_merkle,
        objects.preprocessed_coefficients,
    }) |object| {
        hash.update(&object.object_id);
        var encoded_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &encoded_bytes, object.bytes, .little);
        hash.update(&encoded_bytes);
    }
    hash.update(&tree0_root_hex);
    var encoded_budget: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded_budget, budget_bytes, .little);
    hash.update(&encoded_budget);
    const encoded_program_kind: [1]u8 = .{@intFromEnum(program_kind)};
    hash.update(&encoded_program_kind);
    hash.update(&executable_digest);
    hash.update(&protocol_digest);
    return hash.finalResult();
}

pub fn preparedGeometryKey(
    resident_key: one_shot.PreparedStateKey,
    adapted_geometry_fingerprint: [32]u8,
    policy: PreparedGeometryPolicy,
) PreparedGeometryKey {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig-metal-prepared-geometry-v2\x00");
    hash.update(&resident_key);
    hash.update(&adapted_geometry_fingerprint);
    const encoded_policy: [1]u8 = .{@intFromBool(policy.replay_retained_lookups)};
    hash.update(&encoded_policy);
    return hash.finalResult();
}

pub fn compositionAotAdmissionKey(objects: ArtifactObjectsEvidence) CompositionAotAdmissionKey {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig-composition-aot-admission-v1\x00");
    inline for (.{ objects.composition, objects.composition_program }) |object| {
        hash.update(&object.object_id);
        var encoded_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &encoded_bytes, object.bytes, .little);
        hash.update(&encoded_bytes);
    }
    hash.update("unfused-evaluation-program-v1\x00");
    return hash.finalResult();
}

pub fn writeVerifiedResultFrame(
    writer: *std.Io.Writer,
    request: protocol.Request,
    result: ProofResult,
) !void {
    const artifact_manifest_digest: ?[]const u8 = if (result.provenance.artifact_manifest_digest) |*digest|
        digest
    else
        null;
    try writeFrame(writer, .{
        .protocol = protocol.protocol_name,
        .version = protocol.protocol_version,
        .type = "result",
        .status = "verified",
        .sequence = request.sequence,
        .request_id = request.request_id,
        .proof_verified = true,
        .outputs_committed = true,
        .self_contained = result.provenance.self_contained,
        .parity_fixture_used = result.provenance.parity_fixture_used,
        .proof_derived_artifact_used = result.provenance.proof_derived_artifact_used,
        .statement_self_derived = result.provenance.statement_self_derived,
        .artifact_manifest_digest = artifact_manifest_digest,
        .artifact_objects = result.artifact_objects,
        .provenance_complete = result.provenance.provenance_complete,
        .proof_protocol = one_shot.canonical_protocol,
        .protocol_complete = true,
        .daemon_executable_sha256 = &result.executable_identity.daemon_executable_sha256,
        .runner_executable_sha256 = &result.executable_identity.runner_executable_sha256,
        .runner_linkage = in_process_runner_linkage,
        .adapted_cycles = result.adapted_cycles,
        .adapted_input_sha256 = &result.adapted_input_sha256,
        .prove_wall_s = result.prove_wall_s,
        .prove_timing_scope = protocol.prove_timing_scope,
        .prove_mhz = result.prove_mhz,
        .session_block_wall_s = result.session_block_wall_s,
        .proof_bytes = result.proof_bytes,
        .proof_sha256 = &result.proof_sha256,
        .rust_verifier = result.rust_verifier,
        .pipeline_cache_delta = result.pipeline_cache_delta,
        .reuse = .{
            .runtime = true,
            .resident_arena = result.prepared_state_cache_hit,
            .preprocessed_state = result.prepared_state_cache_hit,
        },
    });
}

pub fn cacheDelta(
    after: metal_runtime.PipelineCacheStats,
    before: metal_runtime.PipelineCacheStats,
) metal_runtime.PipelineCacheStats {
    var delta = metal_runtime.PipelineCacheStats.zero();
    delta.library_cache_hits = after.library_cache_hits - before.library_cache_hits;
    delta.library_cache_misses = after.library_cache_misses - before.library_cache_misses;
    delta.pipeline_cache_hits = after.pipeline_cache_hits - before.pipeline_cache_hits;
    delta.binary_archive_hits = after.binary_archive_hits - before.binary_archive_hits;
    delta.binary_archive_misses = after.binary_archive_misses - before.binary_archive_misses;
    delta.direct_compiles = after.direct_compiles - before.direct_compiles;
    delta.archive_populations = after.archive_populations - before.archive_populations;
    delta.archive_serializations = after.archive_serializations - before.archive_serializations;
    delta.pipeline_preparation_seconds = after.pipeline_preparation_seconds - before.pipeline_preparation_seconds;
    delta.library_preparation_seconds = after.library_preparation_seconds - before.library_preparation_seconds;
    delta.library_cache_entries = after.library_cache_entries;
    delta.library_cache_bytes = after.library_cache_bytes;
    delta.library_cache_peak_entries = after.library_cache_peak_entries;
    delta.library_cache_peak_bytes = after.library_cache_peak_bytes;
    delta.library_cache_evictions = after.library_cache_evictions - before.library_cache_evictions;
    delta.library_cache_rejections = after.library_cache_rejections - before.library_cache_rejections;
    delta.pipeline_cache_entries = after.pipeline_cache_entries;
    delta.pipeline_cache_bytes = after.pipeline_cache_bytes;
    delta.pipeline_cache_peak_entries = after.pipeline_cache_peak_entries;
    delta.pipeline_cache_peak_bytes = after.pipeline_cache_peak_bytes;
    delta.pipeline_cache_evictions = after.pipeline_cache_evictions - before.pipeline_cache_evictions;
    delta.pipeline_cache_invalidations = after.pipeline_cache_invalidations - before.pipeline_cache_invalidations;
    delta.pipeline_cache_rejections = after.pipeline_cache_rejections - before.pipeline_cache_rejections;
    delta.library_cache_entry_limit = after.library_cache_entry_limit;
    delta.library_cache_byte_limit = after.library_cache_byte_limit;
    delta.pipeline_cache_entry_limit = after.pipeline_cache_entry_limit;
    delta.pipeline_cache_byte_limit = after.pipeline_cache_byte_limit;
    return delta;
}

pub fn requireWarmPipelineCache(delta: metal_runtime.PipelineCacheStats) !void {
    if (delta.library_cache_misses != 0) return error.UnexpectedLibraryCacheMiss;
    if (delta.binary_archive_hits != 0) return error.UnexpectedBinaryArchiveHit;
    if (delta.binary_archive_misses != 0) return error.UnexpectedBinaryArchiveMiss;
    if (delta.direct_compiles != 0) return error.UnexpectedDirectCompile;
    if (delta.archive_populations != 0) return error.UnexpectedArchivePopulation;
    if (delta.archive_serializations != 0) return error.UnexpectedArchiveSerialization;
    if (delta.library_cache_evictions != 0) return error.UnexpectedLibraryCacheEviction;
    if (delta.library_cache_rejections != 0) return error.UnexpectedLibraryCacheRejection;
    if (delta.pipeline_cache_evictions != 0) return error.UnexpectedPipelineCacheEviction;
    if (delta.pipeline_cache_invalidations != 0) return error.UnexpectedPipelineCacheInvalidation;
    if (delta.pipeline_cache_rejections != 0) return error.UnexpectedPipelineCacheRejection;
}

pub fn nanosecondsToSeconds(nanoseconds: u64) f64 {
    return @as(f64, @floatFromInt(nanoseconds)) /
        @as(f64, @floatFromInt(std.time.ns_per_s));
}

pub fn isSessionScrubbedRunnerEnvironment(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "STWO_ZIG_SN2_");
}

pub fn configureEnvironment(
    allocator: std.mem.Allocator,
    request: RunnerRequest,
    canonical_adapted_input: []const u8,
    proof_temporary: []const u8,
    statement_temporary: []const u8,
) !void {
    var environment = try std.process.getEnvMap(allocator);
    defer environment.deinit();
    const log_stage_timings = environment.get("STWO_ZIG_SN2_LOG_STAGE_TIMINGS") != null;
    const log_composition_digests = environment.get("STWO_ZIG_SN2_LOG_COMPOSITION_DIGESTS") != null;
    const log_composition_part_component = environment.get("STWO_ZIG_SN2_LOG_COMPOSITION_PART_COMPONENT");
    const composition_fusion_cap = environment.get("STWO_ZIG_SN2_COMPOSITION_FUSION_CAP");
    const composition_fusion_mode = environment.get("STWO_ZIG_SN2_COMPOSITION_FUSION_MODE");
    var iterator = environment.iterator();
    while (iterator.next()) |entry| {
        if (!isSessionScrubbedRunnerEnvironment(entry.key_ptr.*)) continue;
        const name = try allocator.dupeZ(u8, entry.key_ptr.*);
        defer allocator.free(name);
        if (unsetenv(name.ptr) != 0) return error.EnvironmentMutationFailed;
    }
    if (!std.mem.endsWith(u8, request.artifacts.composition, ".bin"))
        return error.InvalidCompositionArtifact;
    const program_kind = try compositionProgramKind(request.artifacts.composition_program);
    if (composition_fusion_mode != null and program_kind != .metal)
        return error.CompositionFusionModeRequiresSourceArtifact;

    const values = [_]struct { []const u8, []const u8 }{
        .{ "STWO_ZIG_SN2_POPULATE_INPUT", canonical_adapted_input },
        .{ "STWO_ZIG_SN2_PREPARE_METAL", "1" },
        .{ "STWO_ZIG_SN2_RESTORE_PREPROCESSED_EVALUATIONS", request.artifacts.preprocessed_evaluations },
        .{ "STWO_ZIG_SN2_TREE0_ROOT_HEX", request.tree0_root_hex },
        .{ "STWO_ZIG_SN2_EXECUTE_PREPROCESSED", "1" },
        .{ "STWO_ZIG_SN2_EXECUTE_WITNESS", "1" },
        .{ "STWO_ZIG_SN2_EXECUTE_BASE_INTERPOLATION", "1" },
        .{ "STWO_ZIG_SN2_EXECUTE_COMMITMENTS", "1" },
        .{ "STWO_ZIG_SN2_COMMIT_TREE_COUNT", "4" },
        .{ "STWO_ZIG_SN2_EXECUTE_RELATIONS", "1" },
        .{ "STWO_ZIG_SN2_PREPROCESSED_COEFFS", request.artifacts.preprocessed_coefficients },
        .{ "STWO_ZIG_SN2_EXECUTE_COMPOSITION", "1" },
        .{ "STWO_ZIG_SN2_PROOF_OUTPUT", proof_temporary },
        .{ "STWO_ZIG_SN2_COMPACT_STATEMENT_OUTPUT", statement_temporary },
        .{ "STWO_ZIG_SN2_EXECUTE_OODS", "1" },
        .{ "STWO_ZIG_SN2_EXECUTE_PROOF", "1" },
        .{ "STWO_ZIG_SN2_VERIFY_PROOF", "1" },
        .{ "STWO_ZIG_METAL_REPLAY_RETAINED_LOOKUPS", "1" },
    };
    for (values) |entry| {
        try setEnvironmentValue(allocator, .{ .name = entry[0], .value = entry[1] });
    }
    if (log_stage_timings) {
        try setEnvironmentValue(allocator, .{
            .name = "STWO_ZIG_SN2_LOG_STAGE_TIMINGS",
            .value = "1",
        });
    }
    if (log_composition_digests) {
        try setEnvironmentValue(allocator, .{
            .name = "STWO_ZIG_SN2_LOG_COMPOSITION_DIGESTS",
            .value = "1",
        });
    }
    if (log_composition_part_component) |component| {
        try setEnvironmentValue(allocator, .{
            .name = "STWO_ZIG_SN2_LOG_COMPOSITION_PART_COMPONENT",
            .value = component,
        });
    }
    if (program_kind == .metal) {
        try setEnvironmentValue(allocator, .{
            .name = "STWO_ZIG_SN2_COMPOSITION_SOURCE",
            .value = request.artifacts.composition_program,
        });
        try setEnvironmentValue(allocator, .{
            .name = "STWO_ZIG_SN2_ENABLE_COMPOSITION_PART_FUSION",
            .value = "1",
        });
        if (composition_fusion_cap) |cap| {
            try setEnvironmentValue(allocator, .{
                .name = "STWO_ZIG_SN2_COMPOSITION_FUSION_CAP",
                .value = cap,
            });
        }
        if (composition_fusion_mode) |mode| {
            try setEnvironmentValue(allocator, .{
                .name = "STWO_ZIG_SN2_COMPOSITION_FUSION_MODE",
                .value = mode,
            });
        }
    }
    for (referenceEnvironment(request.artifacts)) |optional_entry|
        if (optional_entry) |entry| try setEnvironmentValue(allocator, entry);
}

pub fn referenceEnvironment(artifacts: RunnerArtifacts) [3]?EnvironmentValue {
    return .{
        if (artifacts.transcript_reference) |value| .{
            .name = "STWO_ZIG_SN2_TRANSCRIPT_REFERENCE",
            .value = value,
        } else null,
        if (artifacts.quotient_reference) |value| .{
            .name = "STWO_ZIG_SN2_QUOTIENT_REFERENCE",
            .value = value,
        } else null,
        if (artifacts.transcript_reference != null) .{
            .name = "STWO_ZIG_SN2_REPLAY_TRANSCRIPT_AFTER_TREE2",
            .value = "1",
        } else null,
    };
}

pub fn setEnvironmentValue(allocator: std.mem.Allocator, entry: EnvironmentValue) !void {
    const name = try allocator.dupeZ(u8, entry.name);
    defer allocator.free(name);
    const value = try allocator.dupeZ(u8, entry.value);
    defer allocator.free(value);
    if (setenv(name.ptr, value.ptr, 1) != 0) return error.EnvironmentMutationFailed;
}

pub const AdaptedCounts = struct { cycles: u64, pc_count: u64 };

pub const AdaptedGeometry = struct {
    fingerprint: [32]u8,
    counts: AdaptedCounts,
};

pub fn checkedSectionEnd(offset: u64, count: u64, stride: u64, file_size: u64) !u64 {
    const bytes = std.math.mul(u64, count, stride) catch return error.InvalidAdaptedInput;
    const end = std.math.add(u64, offset, bytes) catch return error.InvalidAdaptedInput;
    if (end > file_size) return error.InvalidAdaptedInput;
    return end;
}

pub fn readU64At(file: std.fs.File, offset: u64) !u64 {
    var encoded: [8]u8 = undefined;
    if (try file.preadAll(&encoded, offset) != encoded.len) return error.InvalidAdaptedInput;
    return std.mem.readInt(u64, &encoded, .little);
}

pub fn hashU64(hash: *std.crypto.hash.sha2.Sha256, value: u64) void {
    var encoded: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded, value, .little);
    hash.update(&encoded);
}

/// Validate the canonical adapted-input layout while reading only section
/// headers. The digest includes exactly the adapted values consumed by
/// CairoProofPlan.fromWitnessSchedule's direct row-extent derivation.
///
/// Compatibility invariant: this fingerprint may key only immutable host
/// geometry, CairoProofPlan, and StagedArenaPlanner outputs when the schedule
/// and bundles are independently identity-bound. It must not key ProverInput,
/// statement bootstrap data, public-memory seeds, or native witness recipes;
/// those consume the per-proof memory payload and the other builtin segments.
pub fn adaptedGeometry(path: []const u8, expected_bytes: u64) !AdaptedGeometry {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const stat = try file.stat();
    if (stat.kind != .file or stat.size != expected_bytes) return error.InvalidAdaptedInput;
    var header: [64]u8 = undefined;
    if (try file.preadAll(&header, 0) != header.len or !std.mem.eql(u8, header[0..8], "STWZCPI\x00"))
        return error.InvalidAdaptedInput;
    if (std.mem.readInt(u32, header[8..12], .little) != cairo_adapted_input.VERSION)
        return error.InvalidAdaptedInput;
    const pc_count = std.mem.readInt(u64, header[40..48], .little);
    const opcode_count = std.mem.readInt(u32, header[56..60], .little);
    if (opcode_count != cairo_opcodes.N_OPCODES) return error.InvalidAdaptedInput;
    var geometry_hash = std.crypto.hash.sha2.Sha256.init(.{});
    geometry_hash.update("stwo-zig-cairo-adapted-row-geometry-v1\x00");
    var offset: u64 = 64;
    var cycles: u64 = 0;
    for (0..opcode_count) |_| {
        const count = try readU64At(file, offset);
        if (count > cairo_adapted_input.MAX_ITEMS) return error.InvalidAdaptedInput;
        cycles = std.math.add(u64, cycles, count) catch return error.InvalidAdaptedInput;
        hashU64(&geometry_hash, count);
        offset = try checkedSectionEnd(offset, 1, 8, stat.size);
        offset = try checkedSectionEnd(offset, count, 12, stat.size);
    }

    var memory_header: [48]u8 = undefined;
    if (try file.preadAll(&memory_header, offset) != memory_header.len)
        return error.InvalidAdaptedInput;
    const address_count = std.mem.readInt(u64, memory_header[24..32], .little);
    const f252_count = std.mem.readInt(u64, memory_header[32..40], .little);
    const small_count = std.mem.readInt(u64, memory_header[40..48], .little);
    inline for (.{ address_count, f252_count, small_count }) |count| {
        if (count > cairo_adapted_input.MAX_ITEMS) return error.InvalidAdaptedInput;
    }
    offset = try checkedSectionEnd(offset, 1, memory_header.len, stat.size);
    offset = try checkedSectionEnd(offset, address_count, 4, stat.size);
    offset = try checkedSectionEnd(offset, f252_count, 8 * @sizeOf(u32), stat.size);
    offset = try checkedSectionEnd(offset, small_count, @sizeOf(u128), stat.size);

    const public_count = try readU64At(file, offset);
    if (public_count > cairo_adapted_input.MAX_ITEMS) return error.InvalidAdaptedInput;
    offset = try checkedSectionEnd(offset, 1, 8, stat.size);
    offset = try checkedSectionEnd(offset, public_count, @sizeOf(u32), stat.size);

    const GeometryBuiltin = struct { segment_index: usize, cells: u64 };
    const geometry_builtins = [_]GeometryBuiltin{
        .{ .segment_index = 1, .cells = 5 },
        .{ .segment_index = 4, .cells = 3 },
        .{ .segment_index = 5, .cells = 6 },
        .{ .segment_index = 7, .cells = 1 },
    };
    var geometry_builtin_index: usize = 0;
    for (0..9) |segment_index| {
        var segment: [24]u8 = undefined;
        if (try file.preadAll(&segment, offset) != segment.len) return error.InvalidAdaptedInput;
        const present = segment[0];
        if (present > 1) return error.InvalidAdaptedInput;
        if (geometry_builtin_index < geometry_builtins.len and
            geometry_builtins[geometry_builtin_index].segment_index == segment_index)
        {
            geometry_hash.update(segment[0..1]);
            var instances: u64 = 0;
            if (present == 1) {
                const begin = std.mem.readInt(u64, segment[8..16], .little);
                const stop = std.mem.readInt(u64, segment[16..24], .little);
                if (begin > std.math.maxInt(usize) or stop > std.math.maxInt(usize) or stop < begin)
                    return error.InvalidAdaptedInput;
                instances = (stop - begin) / geometry_builtins[geometry_builtin_index].cells;
            }
            hashU64(&geometry_hash, instances);
            geometry_builtin_index += 1;
        }
        offset = try checkedSectionEnd(offset, 1, segment.len, stat.size);
    }
    if (geometry_builtin_index != geometry_builtins.len or offset != stat.size)
        return error.InvalidAdaptedInput;
    return .{
        .fingerprint = geometry_hash.finalResult(),
        .counts = .{ .cycles = cycles, .pc_count = pc_count },
    };
}

pub const hashFile = io.hashFile;
