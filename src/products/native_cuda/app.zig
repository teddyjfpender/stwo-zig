//! Lifecycle and residency reporting for Native CUDA proofs.

const std = @import("std");
const product_identity = @import("product_identity");
const stwo = @import("stwo_native_cuda");
const cli = @import("cli.zig");

const cuda = stwo.integrations.native_cuda.wide_fibonacci;
const artifacts = stwo.interop.examples_artifact;
const atomic_file = stwo.interop.atomic_file;
const output_transaction = stwo.interop.output_transaction;
const proof_wire = stwo.interop.proof_wire;
const wide_fibonacci = stwo.examples.wide_fibonacci;

const accepted_sms = [_]u32{ 86, 89, 90 };

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const process_args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, process_args);

    const parsed = cli.parse(process_args[1..]) catch |err| {
        try cli.writeUsage(std.fs.File.stderr().deprecatedWriter());
        return err;
    };
    switch (parsed) {
        .help => try cli.writeUsage(std.fs.File.stdout().deprecatedWriter()),
        .prove => |request| try prove(allocator, request),
    }
}

fn prove(allocator: std.mem.Allocator, request: cli.Prove) !void {
    try output_transaction.prepare(request.output, request.report_out);

    const proof_temporary = try atomic_file.temporaryPathAlloc(
        allocator,
        request.output,
        "proof",
    );
    defer allocator.free(proof_temporary);
    defer std.fs.cwd().deleteFile(proof_temporary) catch {};

    var total_started = try std.time.Timer.start();
    const protocol = sealedProtocol();
    const admitted = try cuda.request.admit(.{
        .statement = .{
            .log_n_rows = request.log_n_rows,
            .sequence_len = request.sequence_len,
        },
        .protocol = protocol,
    });

    var runtime_init_timer = try std.time.Timer.start();
    var runtime = try cuda.NativeRuntime.open(&accepted_sms);
    const runtime_init_ns = runtime_init_timer.read();
    var runtime_live = true;
    defer if (runtime_live) runtime.abort() catch {};
    const driver = cuda.NativeDriver{
        .allocator = allocator,
    };
    const proof_request = cuda.request.Request{
        .statement = admitted.statement,
        .protocol = admitted.protocol,
    };
    var shape_prepare_timer = try std.time.Timer.start();
    var prepared = try driver.prepare(&runtime, proof_request);
    const shape_prepare_ns = shape_prepare_timer.read();
    defer prepared.deinit(allocator);

    var verified_request_timer = try std.time.Timer.start();
    var resident_timer = try std.time.Timer.start();
    var output = try driver.runPreparedRetained(
        &runtime,
        proof_request,
        &prepared,
    );
    const resident_prove_ns = resident_timer.read();
    defer output.deinit(allocator);
    try requireResident(output.verdict);

    var decode_timer = try std.time.Timer.start();
    var proof = try cuda.proof_decode.decodeProof(allocator, output.bundle);
    var proof_live = true;
    defer if (proof_live) proof.deinit(allocator);
    const canonical = try proof_wire.encodeProofBytes(allocator, proof);
    defer allocator.free(canonical);
    const decode_ns = decode_timer.read();

    const pcs_config = try pcsConfig();

    var verification_timer = try std.time.Timer.start();
    // The verifier owns the proof after this point, including on failure.
    proof_live = false;
    try wide_fibonacci.verify(
        allocator,
        pcs_config,
        .{
            .log_n_rows = admitted.statement.log_n_rows,
            .sequence_len = admitted.statement.sequence_len,
        },
        proof,
    );
    const verification_ns = verification_timer.read();
    const verified_request_ns = verified_request_timer.read();

    var repetition_prove_ns: [cli.max_repetitions]u64 = undefined;
    var repetition_decode_ns: [cli.max_repetitions]u64 = undefined;
    var repetition_verification_ns: [cli.max_repetitions]u64 = undefined;
    var repetition_verified_request_ns: [cli.max_repetitions]u64 = undefined;
    var repetition_device_ns: [cli.max_repetitions]u64 = undefined;
    var runtime_proof_indices: [cli.max_repetitions]u64 = undefined;
    repetition_prove_ns[0] = resident_prove_ns;
    repetition_decode_ns[0] = decode_ns;
    repetition_verification_ns[0] = verification_ns;
    repetition_verified_request_ns[0] = verified_request_ns;
    repetition_device_ns[0] = output.verdict.counters.device_elapsed_ns;
    runtime_proof_indices[0] = output.verdict.runtime_proof_index;
    var final_verdict = output.verdict;
    var repetition: u32 = 1;
    while (repetition < request.repeat) : (repetition += 1) {
        var repeated_verified_timer = try std.time.Timer.start();
        var repeated_timer = try std.time.Timer.start();
        var repeated = try driver.runPreparedRetained(
            &runtime,
            proof_request,
            &prepared,
        );
        repetition_prove_ns[repetition] = repeated_timer.read();
        repetition_device_ns[repetition] =
            repeated.verdict.counters.device_elapsed_ns;
        runtime_proof_indices[repetition] =
            repeated.verdict.runtime_proof_index;
        defer repeated.deinit(allocator);
        try requireResident(repeated.verdict);
        try requireStableRepetition(output.verdict, repeated.verdict);
        final_verdict = repeated.verdict;

        var repeated_decode_timer = try std.time.Timer.start();
        var repeated_proof = try cuda.proof_decode.decodeProof(
            allocator,
            repeated.bundle,
        );
        var repeated_proof_live = true;
        defer if (repeated_proof_live) repeated_proof.deinit(allocator);
        const repeated_canonical = try proof_wire.encodeProofBytes(
            allocator,
            repeated_proof,
        );
        defer allocator.free(repeated_canonical);
        repetition_decode_ns[repetition] = repeated_decode_timer.read();
        if (!std.mem.eql(u8, canonical, repeated_canonical))
            return error.UnstableCanonicalProof;

        var repeated_verification_timer = try std.time.Timer.start();
        repeated_proof_live = false;
        try wide_fibonacci.verify(
            allocator,
            pcs_config,
            .{
                .log_n_rows = admitted.statement.log_n_rows,
                .sequence_len = admitted.statement.sequence_len,
            },
            repeated_proof,
        );
        repetition_verification_ns[repetition] =
            repeated_verification_timer.read();
        repetition_verified_request_ns[repetition] =
            repeated_verified_timer.read();
    }

    if (runtime.completedProofs() != request.repeat)
        return error.IncompleteCudaRuntimeSequence;
    var runtime_teardown_timer = try std.time.Timer.start();
    try runtime.close();
    const runtime_teardown_ns = runtime_teardown_timer.read();
    runtime_live = false;

    try artifacts.writeNativeProofArtifact(
        allocator,
        proof_temporary,
        pcs_config,
        "prove",
        .{ .wide_fibonacci = .{
            .log_n_rows = admitted.statement.log_n_rows,
            .sequence_len = admitted.statement.sequence_len,
        } },
        canonical,
    );

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(canonical, &digest, .{});
    const proof_sha256 = std.fmt.bytesToHex(digest, .lower);
    const build_identity = std.fmt.bytesToHex(
        output.verdict.build_identity,
        .lower,
    );
    const device_uuid = std.fmt.bytesToHex(output.verdict.platform.uuid, .lower);
    const report = try renderReport(
        allocator,
        request,
        admitted,
        final_verdict,
        proof_sha256,
        build_identity,
        device_uuid,
        canonical.len,
        &prepared,
        repetition_prove_ns[0..request.repeat],
        repetition_decode_ns[0..request.repeat],
        repetition_verification_ns[0..request.repeat],
        repetition_verified_request_ns[0..request.repeat],
        repetition_device_ns[0..request.repeat],
        runtime_proof_indices[0..request.repeat],
        runtime_init_ns,
        shape_prepare_ns,
        runtime_teardown_ns,
        total_started.read(),
    );
    defer allocator.free(report);

    const stdout = std.fs.File.stdout().deprecatedWriter();
    try output_transaction.publishResult(
        atomic_file,
        allocator,
        proof_temporary,
        request.output,
        report,
        request.report_out,
        stdout,
    );
    if (request.report_out != null) try writeLine(stdout, report);
}

fn sealedProtocol() cuda.request.Protocol {
    return .{
        .pow_bits = 10,
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
        .fold_step = 1,
        .lifting_log_size = null,
    };
}

fn pcsConfig() !stwo.core.pcs.PcsConfig {
    var fri_config = try stwo.core.fri.FriConfig.init(0, 1, 3);
    fri_config.fold_step = 1;
    return .{
        .pow_bits = 10,
        .fri_config = fri_config,
        .lifting_log_size = null,
    };
}

fn requireResident(verdict: anytype) !void {
    const counters = verdict.counters;
    if (!verdict.isResident() or !verdict.aot.isStrict())
        return error.NonResidentCudaProof;
    if (!counters.deviceTimingComplete())
        return error.IncompleteCudaDeviceTiming;
    if (verdict.pool_used_bytes != 0)
        return error.CudaPoolNotReleased;
    if (!counters.stagesCompleteExactlyOnce())
        return error.IncompleteCudaProofStages;
    if (counters.cpu_fallback_attempts != 0 or
        counters.cpu_fallbacks_completed != 0)
    {
        return error.CpuFallbackObserved;
    }
    if (counters.d2h_proof_operations != 1 or
        counters.d2h_proof_bytes == 0)
    {
        return error.MissingTerminalProofRead;
    }

    for (counters.stages, 0..) |stage, index| {
        const is_terminal = index ==
            @intFromEnum(stwo.backends.cuda.runtime.telemetry.Stage.proof_assembly);
        if (is_terminal) {
            if (stage.d2h_proof_operations !=
                counters.d2h_proof_operations or
                stage.d2h_proof_bytes != counters.d2h_proof_bytes)
            {
                return error.NonTerminalDeviceRead;
            }
        } else if (stage.d2h_proof_operations != 0 or
            stage.d2h_proof_bytes != 0)
        {
            return error.NonTerminalDeviceRead;
        }
    }
}

fn requireStableRepetition(first: anytype, repeated: @TypeOf(first)) !void {
    if (!first.counters.hasSameTopology(repeated.counters) or
        first.aot_entries != repeated.aot_entries or
        first.lane_count != repeated.lane_count or
        first.pool_used_bytes != repeated.pool_used_bytes or
        first.pool_reserved_bytes != repeated.pool_reserved_bytes or
        first.device.current != repeated.device.current or
        first.device.sm_major != repeated.device.sm_major or
        first.device.sm_minor != repeated.device.sm_minor or
        !std.mem.eql(u8, &first.build_identity, &repeated.build_identity) or
        !std.mem.eql(u8, &first.platform.uuid, &repeated.platform.uuid))
    {
        return error.UnstableCudaTopology;
    }
}

fn renderReport(
    allocator: std.mem.Allocator,
    request: cli.Prove,
    geometry: cuda.request.Geometry,
    verdict: anytype,
    proof_sha256: [64]u8,
    build_identity: [64]u8,
    device_uuid: [32]u8,
    proof_bytes: usize,
    prepared: anytype,
    resident_prove_ns: []const u64,
    decode_ns: []const u64,
    verification_ns: []const u64,
    verified_request_ns: []const u64,
    device_elapsed_ns: []const u64,
    runtime_proof_indices: []const u64,
    runtime_init_ns: u64,
    shape_prepare_ns: u64,
    runtime_teardown_ns: u64,
    total_ns: u64,
) ![]u8 {
    const counters = verdict.counters;
    const structural = &prepared.structural;
    const plan = &structural.cuda_plan;
    const program_digest = std.fmt.bytesToHex(
        structural.proof_program.program_digest,
        .lower,
    );
    const plan_cache_key = std.fmt.bytesToHex(plan.cache_key, .lower);
    return std.json.Stringify.valueAlloc(allocator, .{
        .schema_version = @as(u32, 4),
        .product = "stwo-native-cuda",
        .backend = cli.backend_name,
        .application = cli.air_name,
        .protocol = cli.protocol_name,
        .product_identity = .{
            .schema_version = product_identity.schema_version,
            .name = product_identity.product,
            .frontend = product_identity.frontend,
            .backend = product_identity.backend,
            .role = product_identity.role,
            .protocol_features = product_identity.protocol_features,
            .protocol_manifest_sha256 = product_identity.protocol_manifest_sha256,
            .identity_sha256 = product_identity.identity_sha256,
            .implementation_repository = product_identity.implementation_repository,
            .implementation_commit = product_identity.implementation_commit,
            .implementation_tree = if (product_identity.implementation_tree_available)
                product_identity.implementation_tree
            else
                null,
            .implementation_dirty = product_identity.implementation_dirty,
            .dirty_content_sha256 = if (product_identity.dirty_content_sha256_available)
                product_identity.dirty_content_sha256
            else
                null,
            .zig_version = product_identity.zig_version,
            .target_arch = product_identity.target_arch,
            .target_os = product_identity.target_os,
            .target_abi = product_identity.target_abi,
            .cpu_model = product_identity.cpu_model,
            .cpu_features_sha256 = product_identity.cpu_features_sha256,
            .optimize = product_identity.optimize,
            .runtime_manifest = product_identity.runtime_manifest,
            .sdk_manifest = product_identity.sdk_manifest,
            .aot_manifest = product_identity.aot_manifest,
        },
        .statement = .{
            .log_n_rows = geometry.statement.log_n_rows,
            .sequence_len = geometry.statement.sequence_len,
            .trace_rows = geometry.trace_rows,
            .trace_cells = geometry.trace_cells,
        },
        .plan = .{
            .program_sha256 = &program_digest,
            .cache_key_sha256 = &plan_cache_key,
            .schedule_version = plan.target.version,
            .compiled_once = true,
            .reuse_count = request.repeat,
            .node_count = plan.schedule.len,
            .request_bytes = plan.prediction.request_bytes,
            .persistent_bytes = plan.prediction.persistent_bytes,
            .predicted_minimum_launches = plan.prediction.minimum_launches,
            .transcript_barriers = plan.prediction.transcript_barriers,
        },
        .proof = .{
            .path = request.output,
            .format = artifacts.EXCHANGE_MODE,
            .canonical_bytes = proof_bytes,
            .canonical_sha256 = &proof_sha256,
            .upstream_commit = artifacts.UPSTREAM_COMMIT,
            .zig_verified = true,
        },
        .timing_ns = .{
            .runtime_init = runtime_init_ns,
            .shape_prepare = shape_prepare_ns,
            .resident_prove = resident_prove_ns[0],
            .terminal_decode = decode_ns[0],
            .independent_verification = verification_ns[0],
            .verified_request = verified_request_ns[0],
            .runtime_teardown = runtime_teardown_ns,
            .total_before_publication = total_ns,
        },
        .process_repetition = .{
            .count = request.repeat,
            .persistent_session = true,
            .all_canonical_bytes_identical = true,
            .stable_launch_topology = true,
            .zero_final_pool_usage = true,
            .resident_prove_ns = resident_prove_ns,
            .terminal_decode_ns = decode_ns,
            .independent_verification_ns = verification_ns,
            .verified_request_ns = verified_request_ns,
            .device_elapsed_ns = device_elapsed_ns,
            .runtime_proof_indices = runtime_proof_indices,
        },
        .residency = .{
            .resident = true,
            .strict_aot = true,
            .all_stages_complete_once = true,
            .terminal_d2h_operations = counters.d2h_proof_operations,
            .terminal_d2h_bytes = counters.d2h_proof_bytes,
            .h2d_bytes = counters.h2d_bytes,
            .d2d_bytes = counters.d2d_bytes,
            .cpu_fallback_attempts = counters.cpu_fallback_attempts,
            .cpu_fallbacks_completed = counters.cpu_fallbacks_completed,
            .kernel_launches = counters.kernel_launches,
            .graph_launches = counters.graph_launches,
            .sync_calls = counters.sync_calls,
            .device_timing_intervals = counters.device_timing_intervals,
            .device_elapsed_ns = counters.device_elapsed_ns,
            .peak_live_bytes = counters.peak_live_bytes,
            .pool_used_bytes = verdict.pool_used_bytes,
            .pool_reserved_bytes = verdict.pool_reserved_bytes,
        },
        .device_stage_timing_ns = .{
            .ingress = counters.stages[
                @intFromEnum(stwo.backends.cuda.runtime.telemetry.Stage.ingress)
            ].device_elapsed_ns,
            .trace_generation = counters.stages[
                @intFromEnum(stwo.backends.cuda.runtime.telemetry.Stage.trace_generation)
            ].device_elapsed_ns,
            .trace_commit = counters.stages[
                @intFromEnum(stwo.backends.cuda.runtime.telemetry.Stage.trace_commit)
            ].device_elapsed_ns,
            .constraint_evaluation = counters.stages[
                @intFromEnum(stwo.backends.cuda.runtime.telemetry.Stage.constraint_evaluation)
            ].device_elapsed_ns,
            .oods = counters.stages[
                @intFromEnum(stwo.backends.cuda.runtime.telemetry.Stage.oods)
            ].device_elapsed_ns,
            .quotient = counters.stages[
                @intFromEnum(stwo.backends.cuda.runtime.telemetry.Stage.quotient)
            ].device_elapsed_ns,
            .fri_commit = counters.stages[
                @intFromEnum(stwo.backends.cuda.runtime.telemetry.Stage.fri_commit)
            ].device_elapsed_ns,
            .pow = counters.stages[
                @intFromEnum(stwo.backends.cuda.runtime.telemetry.Stage.pow)
            ].device_elapsed_ns,
            .decommit = counters.stages[
                @intFromEnum(stwo.backends.cuda.runtime.telemetry.Stage.decommit)
            ].device_elapsed_ns,
            .proof_assembly = counters.stages[
                @intFromEnum(stwo.backends.cuda.runtime.telemetry.Stage.proof_assembly)
            ].device_elapsed_ns,
            .total = counters.device_elapsed_ns,
        },
        .aot = .{
            .entries = verdict.aot_entries,
            .loads = verdict.aot.aot_loads,
            .cache_hits = verdict.aot.aot_cache_hits,
            .misses = verdict.aot.aot_misses,
            .launches = verdict.aot.launches,
            .launch_failures = verdict.aot.launch_failures,
            .build_identity_sha256 = &build_identity,
        },
        .device = .{
            .ordinal = verdict.device.current,
            .sm_major = verdict.device.sm_major,
            .sm_minor = verdict.device.sm_minor,
            .uuid = &device_uuid,
            .driver_version = verdict.platform.driver_version,
            .runtime_version = verdict.platform.runtime_version,
            .toolkit_version = verdict.platform.toolkit_version,
            .global_memory_bytes = verdict.platform.total_global_memory,
            .multiprocessors = verdict.platform.multiprocessor_count,
        },
    }, .{});
}

fn writeLine(writer: anytype, bytes: []const u8) !void {
    try writer.writeAll(bytes);
    try writer.writeByte('\n');
}

test "sealed product protocol is admitted and cannot drift" {
    const geometry = try cuda.request.admit(.{
        .statement = .{ .log_n_rows = 5, .sequence_len = 8 },
        .protocol = sealedProtocol(),
    });
    try std.testing.expectEqual(@as(u32, 10), geometry.protocol.pow_bits);
    try std.testing.expectEqual(@as(u32, 1), geometry.protocol.fold_step);
    try std.testing.expectEqual(@as(usize, 3), geometry.protocol.n_queries);
}
