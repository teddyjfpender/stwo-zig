//! JSONL session lifecycle and proof-request orchestration.

const std = @import("std");
const stwo = @import("stwo");
const artifact_manifest = stwo.metal_session.artifact_manifest;
const artifact_store = stwo.metal_session.artifact_store;
const metal_runtime = stwo.backends.metal.runtime;
const compact_interchange = stwo.frontends.cairo.compact_verifier_interchange;
const composition_bundle = stwo.frontends.cairo.witness.composition_bundle;
const composition_prewarm = stwo.integrations.cairo_metal.composition_prewarm;
const one_shot = @import("one_shot");
const protocol = stwo.metal_session.protocol;
const state = @import("state.zig");
const startup = @import("startup.zig");
const preparation = @import("preparation.zig");
const verification = @import("verification.zig");

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
const CompositionAotAdmissionCache = state.CompositionAotAdmissionCache;
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

const prepareArtifacts = preparation.prepareArtifacts;
const compositionProgramPolicy = preparation.compositionProgramPolicy;
const compositionProgramKind = preparation.compositionProgramKind;
const canonicalProofProtocolDigest = preparation.canonicalProofProtocolDigest;
const preparedStateKey = preparation.preparedStateKey;
const preparedGeometryKey = preparation.preparedGeometryKey;
const compositionAotAdmissionKey = preparation.compositionAotAdmissionKey;
const writeVerifiedResultFrame = preparation.writeVerifiedResultFrame;
const cacheDelta = preparation.cacheDelta;
const nanosecondsToSeconds = preparation.nanosecondsToSeconds;
const configureEnvironment = preparation.configureEnvironment;
const adaptedGeometry = preparation.adaptedGeometry;
const hashFile = preparation.hashFile;
const copyFileExclusive = verification.copyFileExclusive;
const cliProofLayout = verification.cliProofLayout;
const compactRuntimeProtocolFromArtifacts = verification.compactRuntimeProtocolFromArtifacts;
const runRustVerifier = verification.runRustVerifier;
const measureExecutableIdentity = verification.measureExecutableIdentity;
const temporaryPath = verification.temporaryPath;
const requireAbsent = verification.requireAbsent;
const publishOutputsExclusive = verification.publishOutputsExclusive;
const boolField = verification.boolField;
const requireCanonicalCliProtocol = verification.requireCanonicalCliProtocol;
const cliProvenance = verification.cliProvenance;
const stringField = verification.stringField;
const positiveNumberField = verification.positiveNumberField;
const positiveIntegerField = verification.positiveIntegerField;
const writeFrame = verification.writeFrame;

pub fn main() !void {
    var debug_allocator = std.heap.DebugAllocator(.{}).init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const options = try startup.parseArgs(args);
    const composition_policy = try compositionProgramPolicy(options.composition_metallib_sha256);
    const executable_identity = try measureExecutableIdentity(allocator);

    const artifact_root = try std.fmt.allocPrint(
        allocator,
        "/private/tmp/stwo-zig-metal-artifacts-{}-{}",
        .{ std.c.getpid(), std.time.nanoTimestamp() },
    );
    defer allocator.free(artifact_root);
    var store = try artifact_store.Store.initNew(allocator, artifact_root, true);
    defer store.deinit();
    var core_metallib_snapshot: ?artifact_store.Snapshot = null;
    defer if (core_metallib_snapshot) |*snapshot| snapshot.deinit(allocator);
    var runtime = switch (options.runtime_mode) {
        .diagnostic_source => try metal_runtime.Runtime.init(),
        .production_core_aot => |core_aot| runtime: {
            var snapshot = try startup.snapshotCoreMetallib(&store, core_aot);
            errdefer snapshot.deinit(allocator);
            const runtime = try metal_runtime.diagnostics.initFromMetallibUnchecked(snapshot.path);
            core_metallib_snapshot = snapshot;
            break :runtime runtime;
        },
    };
    defer runtime.deinit();
    var rust_verifier = try RustVerifierConfig.init(
        allocator,
        options.rust_verifier_path,
        options.rust_verifier_lockfile_path,
        store.root_path,
    );
    defer rust_verifier.deinit();
    var views = ViewCache.init(allocator);
    defer views.deinit();
    var prepared_state = one_shot.PreparedStateCache.init(allocator);
    defer prepared_state.deinit();
    var prepared_host_geometry = PreparedHostGeometryCache.init(allocator);
    defer prepared_host_geometry.deinit();
    var composition_aot_admissions = CompositionAotAdmissionCache{};

    const input_buffer = try allocator.alloc(u8, protocol.max_frame_bytes);
    defer allocator.free(input_buffer);
    var input = std.fs.File.stdin().reader(input_buffer);
    var output_buffer: [16 * 1024]u8 = undefined;
    var output = std.fs.File.stdout().writer(&output_buffer);
    const writer = &output.interface;

    const session_id = try std.fmt.allocPrint(
        allocator,
        "metal-{}-{}",
        .{ std.c.getpid(), std.time.nanoTimestamp() },
    );
    defer allocator.free(session_id);
    try writeFrame(writer, .{
        .protocol = protocol.protocol_name,
        .version = protocol.protocol_version,
        .type = "ready",
        .session_id = session_id,
        .daemon_executable_sha256 = &executable_identity.daemon_executable_sha256,
        .runner_executable_sha256 = &executable_identity.runner_executable_sha256,
        .runner_linkage = in_process_runner_linkage,
        .rust_verifier = .{
            .required = true,
            .schema_version = 1,
            .envelope_abi = rust_verifier_envelope_abi,
            .adapter_version = rust_verifier_adapter_version,
            .executable_sha256 = &rust_verifier.executable_sha256,
            .cargo_lock_sha256 = rust_verifier_cargo_lock_sha256,
            .stwo_cairo_revision = rust_verifier_stwo_cairo_revision,
            .stwo_revision = rust_verifier_stwo_revision,
            .verification_mode = rust_verifier_mode,
        },
        .capabilities = .{
            .strict_order = true,
            .atomic_outputs = true,
            .verified_proofs = true,
            .runtime_reuse = true,
            .resident_arena_reuse = true,
            .preprocessed_state_reuse = true,
        },
    });

    var next_sequence: u64 = 0;
    while (try input.interface.takeDelimiter('\n')) |line| {
        if (line.len == 0) return error.EmptyFrame;
        switch (try protocol.frameKind(allocator, line)) {
            .shutdown => {
                try protocol.validateShutdown(allocator, line, next_sequence);
                try writeFrame(writer, .{
                    .protocol = protocol.protocol_name,
                    .version = protocol.protocol_version,
                    .type = "closed",
                    .completed = next_sequence,
                });
                return;
            },
            .prove => {
                var parsed = try protocol.parseRequest(allocator, line, next_sequence, true);
                defer parsed.deinit();
                const request = parsed.request;
                const result = proveRequest(
                    allocator,
                    &runtime,
                    &store,
                    &views,
                    &prepared_state,
                    &prepared_host_geometry,
                    &composition_aot_admissions,
                    request,
                    executable_identity,
                    rust_verifier,
                    composition_policy,
                ) catch |err| {
                    try writeFrame(writer, .{
                        .protocol = protocol.protocol_name,
                        .version = protocol.protocol_version,
                        .type = "error",
                        .sequence = request.sequence,
                        .request_id = request.request_id,
                        .code = @errorName(err),
                        .message = "proof request failed before verified outputs were committed",
                    });
                    return err;
                };
                try writeVerifiedResultFrame(writer, request, result);
                next_sequence += 1;
            },
        }
    }
    return error.UncleanEndOfStream;
}

fn proveRequest(
    allocator: std.mem.Allocator,
    runtime: *metal_runtime.Runtime,
    store: *artifact_store.Store,
    views: *ViewCache,
    prepared_state: *one_shot.PreparedStateCache,
    prepared_host_geometry: *PreparedHostGeometryCache,
    composition_aot_admissions: *CompositionAotAdmissionCache,
    request: protocol.Request,
    executable_identity: ExecutableIdentity,
    rust_verifier: RustVerifierConfig,
    composition_policy: preparation.CompositionProgramPolicy,
) !ProofResult {
    var block_timer = try std.time.Timer.start();
    const diagnostic_adapted_input = try allocator.dupe(
        u8,
        request.artifacts.adapted_input.diagnosticPath(),
    );
    defer allocator.free(diagnostic_adapted_input);
    var prepared = try prepareArtifacts(
        allocator,
        store,
        views,
        request,
        executable_identity.measurement,
        composition_policy,
    );
    defer prepared.deinit(allocator);
    const artifact_admission_wall_s = nanosecondsToSeconds(block_timer.read());
    const artifact_objects = prepared.artifactObjects(request.artifacts);
    const composition_aot_started_ns = block_timer.read();
    const composition_aot_before = runtime.pipelineCacheStats();
    const composition_aot_cache_hit = switch (composition_policy) {
        .diagnostic => false,
        .approved_metallib => try admitCompositionAot(
            allocator,
            runtime,
            composition_aot_admissions,
            &prepared,
            artifact_objects,
        ),
    };
    const composition_aot_pipeline_cache_delta = cacheDelta(
        runtime.pipelineCacheStats(),
        composition_aot_before,
    );
    const composition_aot_admission_wall_s = nanosecondsToSeconds(
        block_timer.read() - composition_aot_started_ns,
    );
    const pipeline_cache_before = runtime.pipelineCacheStats();
    const adapted_geometry_started_ns = block_timer.read();
    const adapted_geometry = try adaptedGeometry(
        prepared.snapshot(.adapted_input).path,
        artifact_objects.adapted_input.bytes,
    );
    const adapted_geometry_fingerprint_wall_s = nanosecondsToSeconds(
        block_timer.read() - adapted_geometry_started_ns,
    );
    const prepared_state_key = try preparedStateKey(
        artifact_objects,
        prepared.tree0_root_hex,
        request.budget_gib,
        try compositionProgramKind(prepared.runnerArtifacts().composition_program),
        executable_identity.measurement.sha256,
        try canonicalProofProtocolDigest(),
    );
    const prepared_geometry_key = preparedGeometryKey(
        prepared_state_key,
        adapted_geometry.fingerprint,
        .{ .replay_retained_lookups = true },
    );
    const adapted_geometry_fingerprint_sha256 = std.fmt.bytesToHex(
        adapted_geometry.fingerprint,
        .lower,
    );
    const prepared_geometry_key_sha256 = std.fmt.bytesToHex(prepared_geometry_key, .lower);
    const adapted_snapshot = prepared.snapshot(.adapted_input);
    const adapted_input_digest = adapted_snapshot.measurement.sha256;
    const adapted_input_sha256 = std.fmt.bytesToHex(adapted_input_digest, .lower);
    const proof_protocol_digest = try canonicalProofProtocolDigest();
    var manifest_entries: [artifact_slot_count + 3]artifact_manifest.Entry = undefined;
    @memcpy(manifest_entries[0..prepared.entry_count], prepared.entries[0..prepared.entry_count]);
    var manifest_entry_count = prepared.entry_count;
    manifest_entries[manifest_entry_count] = .{
        .role = .verifier_executable,
        .format_version = 1,
        .provenance = .unattested,
        .measurement = rust_verifier.measurement,
        .source_chain_complete = false,
    };
    manifest_entry_count += 1;
    manifest_entries[manifest_entry_count] = .{
        .role = .verifier_lockfile,
        .format_version = 1,
        .provenance = .unattested,
        .measurement = rust_verifier.lockfile_measurement,
        .source_chain_complete = false,
    };
    manifest_entry_count += 1;
    const manifest = try artifact_manifest.Manifest.build(
        allocator,
        proof_protocol_digest,
        manifest_entries[0..manifest_entry_count],
    );
    const manifest_digest_hex = std.fmt.bytesToHex(manifest.sha256, .lower);
    const runner_request = RunnerRequest{
        .sequence = request.sequence,
        .request_id = request.request_id,
        .artifacts = prepared.runnerArtifacts(),
        .proof_output = request.proof_output,
        .report_output = request.report_output,
        .budget_gib = request.budget_gib,
        .tree0_root_hex = &prepared.tree0_root_hex,
    };
    var verifier_scratch = try VerifierScratch.init(allocator, store.root_path, request.sequence);
    defer verifier_scratch.deinit();
    const proof_temporary = try temporaryPath(allocator, request.proof_output, request.sequence, "proof");
    defer allocator.free(proof_temporary);
    defer std.fs.deleteFileAbsolute(proof_temporary) catch {};
    const report_temporary = try temporaryPath(allocator, request.report_output, request.sequence, "report");
    defer allocator.free(report_temporary);
    defer std.fs.deleteFileAbsolute(report_temporary) catch {};
    try requireAbsent(proof_temporary);
    try requireAbsent(report_temporary);

    try configureEnvironment(
        allocator,
        runner_request,
        runner_request.artifacts.adapted_input,
        verifier_scratch.proof,
        verifier_scratch.statement,
    );
    const runner_args = [_][]const u8{
        "metal-arena-plan",
        runner_request.artifacts.schedule,
        runner_request.budget_gib,
        runner_request.artifacts.witness_programs,
        runner_request.artifacts.multiplicity_feeds,
        runner_request.artifacts.relation_templates,
        runner_request.artifacts.fixed_tables,
        runner_request.artifacts.composition,
    };
    const cli_report_file = try std.fs.createFileAbsolute(verifier_scratch.runner_report, .{
        .read = true,
        .exclusive = true,
    });
    defer cli_report_file.close();
    var report_buffer: [16 * 1024]u8 = undefined;
    var cli_report_writer = cli_report_file.writer(&report_buffer);
    const prepared_geometry_started_ns = block_timer.read();
    const prepared_geometry_acquire = try prepared_host_geometry.begin(
        prepared_geometry_key,
        &runner_args,
    );
    const prepared_host_geometry_acquire_wall_s = nanosecondsToSeconds(
        block_timer.read() - prepared_geometry_started_ns,
    );
    var prepared_geometry_borrowed = true;
    errdefer if (prepared_geometry_borrowed) prepared_host_geometry.poison();
    var prepared_state_borrowed = true;
    errdefer if (prepared_state_borrowed) prepared_state.poison();
    const runner_started_ns = block_timer.read();
    try one_shot.proveOnePreparedGeometry(
        allocator,
        &runner_args,
        runtime,
        prepared_state,
        prepared_state_key,
        prepared_geometry_acquire.geometry,
        &cli_report_writer.interface,
    );
    try cli_report_writer.interface.flush();
    try cli_report_file.sync();
    const runner_finished_ns = block_timer.read();

    try cli_report_file.seekTo(0);
    const encoded_cli_report = try cli_report_file.readToEndAlloc(allocator, 16 * 1024 * 1024);
    defer allocator.free(encoded_cli_report);
    const cli_report = try std.json.parseFromSlice(std.json.Value, allocator, encoded_cli_report, .{});
    defer cli_report.deinit();
    if (cli_report.value != .object) return error.InvalidCliReport;
    const cli_object = cli_report.value.object;
    if (!try boolField(cli_object, "proof_verified")) return error.UnverifiedProof;
    if (!try boolField(cli_object, "proof_bundle_valid")) return error.InvalidProofBundle;
    try requireCanonicalCliProtocol(cli_object);
    const timing_scope = try stringField(cli_object, "prove_timing_scope");
    if (!std.mem.eql(u8, timing_scope, protocol.prove_timing_scope)) return error.InvalidProveTiming;
    const prove_wall_s = try positiveNumberField(cli_object, "prove_wall_s");
    const runner_provenance = cliProvenance(cli_object);
    const prepared_state_telemetry = prepared_state.requestTelemetry();
    const pipeline_cache_delta = cacheDelta(runtime.pipelineCacheStats(), pipeline_cache_before);
    switch (composition_policy) {
        .diagnostic => {},
        .approved_metallib => if (prepared_state_telemetry.cache_hit)
            try preparation.requireWarmPipelineCache(pipeline_cache_delta),
    }
    const manifest_classification = artifact_manifest.classify(manifest.entries);
    const provenance = ProvenanceEvidence{
        .self_contained = runner_provenance.self_contained and
            manifest_classification.production_source_chain_complete,
        .parity_fixture_used = runner_provenance.parity_fixture_used or
            manifest_classification.parity_fixture_used,
        .proof_derived_artifact_used = runner_provenance.proof_derived_artifact_used or
            manifest_classification.proof_derived_artifact_used,
        .statement_self_derived = runner_provenance.statement_self_derived,
        .artifact_manifest_digest = manifest_digest_hex,
        .provenance_complete = true,
    };

    const counts = adapted_geometry.counts;
    if (counts.cycles == 0) return error.InvalidAdaptedCycles;
    var retained_adapted = try store.resolveRef(adapted_snapshot.ref());
    retained_adapted.deinit(allocator);
    const prove_mhz = @as(f64, @floatFromInt(counts.cycles)) / prove_wall_s / 1_000_000.0;
    const proof_file = try std.fs.openFileAbsolute(verifier_scratch.proof, .{ .mode = .read_write });
    const proof_stat = try proof_file.stat();
    if (proof_stat.kind != .file or proof_stat.size == 0) {
        proof_file.close();
        return error.InvalidProofOutput;
    }
    const reported_proof_bytes = try positiveIntegerField(cli_object, "proof_output_bytes");
    if (reported_proof_bytes != proof_stat.size) {
        proof_file.close();
        return error.InvalidProofOutput;
    }
    try proof_file.sync();
    proof_file.close();
    const proof_digest = try hashFile(allocator, verifier_scratch.proof);
    const proof_sha256 = std.fmt.bytesToHex(proof_digest, .lower);
    const runtime_protocol = try compactRuntimeProtocolFromArtifacts(
        allocator,
        runner_request.artifacts.composition,
        runner_request.artifacts.fixed_tables,
    );
    const compact_protocol = try (try cliProofLayout(cli_object)).protocolRuntime(
        one_shot.canonical_protocol.channel_salt,
        runtime_protocol.geometry,
        runtime_protocol.trace_columns,
    );
    var envelope_summary: compact_interchange.EnvelopeSummary = undefined;
    {
        const envelope_file = try std.fs.createFileAbsolute(verifier_scratch.envelope, .{
            .read = true,
            .exclusive = true,
            .mode = 0o600,
        });
        defer envelope_file.close();
        var envelope_buffer: [64 * 1024]u8 = undefined;
        var envelope_writer = envelope_file.writer(&envelope_buffer);
        envelope_summary = try compact_interchange.writeEnvelopeFromPathsV1(
            allocator,
            &envelope_writer.interface,
            compact_protocol,
            verifier_scratch.statement,
            verifier_scratch.proof,
            .{
                .adapted_input_sha256 = &adapted_input_sha256,
                .artifact_manifest_sha256 = &manifest_digest_hex,
                .runner_executable_sha256 = &executable_identity.runner_executable_sha256,
                .backend_executable_sha256 = &executable_identity.daemon_executable_sha256,
            },
        );
        try envelope_writer.interface.flush();
        try envelope_file.sync();
    }
    if (!std.mem.eql(u8, &envelope_summary.proof_sha256, &proof_digest))
        return error.EnvelopeProofDigestMismatch;
    const rust_verifier_evidence = try runRustVerifier(
        allocator,
        rust_verifier,
        verifier_scratch.envelope,
        verifier_scratch.result,
        envelope_summary,
    );
    const staged_proof = try copyFileExclusive(
        allocator,
        verifier_scratch.proof,
        proof_temporary,
        0o600,
    );
    if (staged_proof.bytes != proof_stat.size or
        !std.mem.eql(u8, &staged_proof.sha256, &proof_digest))
        return error.StagedProofMismatch;
    try prepared_state.commit();
    const finalization_started_ns = block_timer.read();
    const final_report_file = try std.fs.createFileAbsolute(report_temporary, .{
        .read = true,
        .exclusive = true,
        .mode = 0o600,
    });
    defer final_report_file.close();
    var final_report_buffer: [16 * 1024]u8 = undefined;
    var final_report_writer = final_report_file.writer(&final_report_buffer);
    const artifact_manifest_digest: ?[]const u8 = &provenance.artifact_manifest_digest.?;
    try std.json.Stringify.value(.{
        .schema_version = persistent_report_schema_version,
        .benchmark = "persistent_sn_pie_metal_gate",
        .mode = "full-proof",
        .status = "completed",
        .proof_verified = true,
        .proving_speed_verified = true,
        .self_contained = provenance.self_contained,
        .parity_fixture_used = provenance.parity_fixture_used,
        .proof_derived_artifact_used = provenance.proof_derived_artifact_used,
        .statement_self_derived = provenance.statement_self_derived,
        .artifact_manifest_digest = artifact_manifest_digest,
        .artifact_manifest = artifact_manifest.JsonEvidence{ .manifest = &manifest },
        .artifact_objects = artifact_objects,
        .adapted_geometry_fingerprint_sha256 = &adapted_geometry_fingerprint_sha256,
        .prepared_geometry_key_sha256 = &prepared_geometry_key_sha256,
        .prepared_host_geometry_cache_hit = prepared_geometry_acquire.cache_hit,
        .prepared_state_cache_hit = prepared_state_telemetry.cache_hit,
        .prepared_state = prepared_state_telemetry,
        .provenance_complete = provenance.provenance_complete,
        .protocol = one_shot.canonical_protocol,
        .protocol_complete = true,
        .daemon_executable_sha256 = &executable_identity.daemon_executable_sha256,
        .runner_executable_sha256 = &executable_identity.runner_executable_sha256,
        .runner_linkage = in_process_runner_linkage,
        .prove_timing_scope = protocol.prove_timing_scope,
        .prove_wall_s = prove_wall_s,
        .prove_mhz = prove_mhz,
        .input = .{
            .path = diagnostic_adapted_input,
            .sha256 = &adapted_input_sha256,
            .adapted_cycles = counts.cycles,
            .pc_count = counts.pc_count,
        },
        .proof = .{
            .bytes = proof_stat.size,
            .sha256 = &proof_sha256,
        },
        .rust_verifier = rust_verifier_evidence,
        .pipeline_cache_delta = pipeline_cache_delta,
        .composition_aot = .{
            .required = composition_policy == .approved_metallib,
            .cache_hit = composition_aot_cache_hit,
            .admission_pipeline_cache_delta = composition_aot_pipeline_cache_delta,
        },
        .service_phase_timing = .{
            .artifact_admission_wall_s = artifact_admission_wall_s,
            .composition_aot_admission_wall_s = composition_aot_admission_wall_s,
            .adapted_geometry_fingerprint_wall_s = adapted_geometry_fingerprint_wall_s,
            .prepared_host_geometry_acquire_wall_s = prepared_host_geometry_acquire_wall_s,
            .pre_runner_wall_s = nanosecondsToSeconds(runner_started_ns) - artifact_admission_wall_s,
            .runner_call_wall_s = nanosecondsToSeconds(runner_finished_ns - runner_started_ns),
            .post_runner_before_report_wall_s = nanosecondsToSeconds(finalization_started_ns - runner_finished_ns),
        },
        .reuse = .{
            .runtime = true,
            .resident_arena = prepared_state_telemetry.cache_hit,
            .preprocessed_state = prepared_state_telemetry.cache_hit,
        },
        .cli_report = cli_report.value,
    }, .{ .whitespace = .indent_2 }, &final_report_writer.interface);
    try final_report_writer.interface.writeByte('\n');
    try final_report_writer.interface.flush();
    try final_report_file.sync();

    try prepared_host_geometry.validateCommit();
    try requireAbsent(request.proof_output);
    try requireAbsent(request.report_output);
    try publishOutputsExclusive(
        proof_temporary,
        request.proof_output,
        report_temporary,
        request.report_output,
    );
    prepared_host_geometry.commitAssumeValid();
    prepared_geometry_borrowed = false;
    const session_block_wall_s = @as(f64, @floatFromInt(block_timer.read())) /
        @as(f64, @floatFromInt(std.time.ns_per_s));
    prepared_state_borrowed = false;
    return .{
        .adapted_cycles = counts.cycles,
        .adapted_input_sha256 = adapted_input_sha256,
        .prove_wall_s = prove_wall_s,
        .prove_mhz = prove_mhz,
        .session_block_wall_s = session_block_wall_s,
        .proof_bytes = proof_stat.size,
        .proof_sha256 = proof_sha256,
        .pipeline_cache_delta = pipeline_cache_delta,
        .provenance = provenance,
        .executable_identity = executable_identity,
        .artifact_objects = artifact_objects,
        .prepared_state_cache_hit = prepared_state_telemetry.cache_hit,
        .rust_verifier = rust_verifier_evidence,
    };
}

fn admitCompositionAot(
    allocator: std.mem.Allocator,
    runtime: *metal_runtime.Runtime,
    admissions: *CompositionAotAdmissionCache,
    prepared: *const PreparedArtifacts,
    objects: ArtifactObjectsEvidence,
) !bool {
    const key = compositionAotAdmissionKey(objects);
    if (admissions.contains(key)) return true;

    var bundle = try composition_bundle.Bundle.readFile(
        allocator,
        prepared.snapshot(.composition).path,
    );
    defer bundle.deinit();
    const inputs = composition_prewarm.Inputs{
        .allocator = allocator,
        .runtime = runtime,
        .bundle = &bundle,
        .metallib_path = prepared.snapshot(.composition_program).path,
        // Pipeline prewarm over a content-addressed artifact-store snapshot,
        // not a proof. The session already gates this object through
        // `preparation.authorizeCompositionProgram`, and the library that a
        // proof actually loads is gated at the runner's loader
        // (`arena_binding.prepareCompositionRecipe`). Threading the session's
        // `--composition-metallib-sha256` down to here as a `pinned_digest` so
        // both gates read the same value is the identified follow-up.
        .policy = .report_only,
    };
    const first = try composition_prewarm.prewarm(inputs);
    if (first.expected_plan_count == 0 or
        first.resolved_plan_count != first.expected_plan_count)
        return error.IncompleteCompositionAotPrewarm;
    const second = try composition_prewarm.prewarm(inputs);
    try composition_prewarm.validateSecondPass(second);
    admissions.put(key);
    return false;
}
