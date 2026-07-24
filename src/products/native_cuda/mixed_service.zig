//! Deterministic mixed-family traffic through one process-owned CUDA runtime.

const std = @import("std");
const stwo = @import("stwo_native_cuda");
const cli = @import("cli.zig");
const report = @import("mixed_service_report.zig");
const proof_route = @import("proof_route.zig");
const poseidon_route = @import("poseidon_route.zig");
const state_machine_route = @import("state_machine_route.zig");
const wide_route = @import("wide_route.zig");

const atomic_file = stwo.interop.atomic_file;
const artifacts = stwo.interop.examples_artifact;
const proof_wire = stwo.interop.proof_wire;
const service_module = stwo.prover.execution.request_service;
const Runtime = wide_route.cuda.NativeRuntime;
const Verdict = stwo.backends.cuda.runtime.verdict.Verdict;
const accepted_sms = [_]u32{ 86, 89, 90 };

const Family = enum {
    wide_fibonacci,
    poseidon,
    state_machine,
};

const WideRequest = struct {
    geometry: wide_route.cuda.request.Geometry,
    proof_request: wide_route.cuda.request.Request,
    prepared: wide_route.cuda.NativeDriver.PreparedProof,
    mode: cli.ExecutionMode,
};

const PoseidonRequest = struct {
    geometry: poseidon_route.cuda.geometry.Geometry,
    proof_request: poseidon_route.cuda.geometry.Request,
    prepared: poseidon_route.cuda.NativeDriver.PreparedProof,
    mode: cli.ExecutionMode,
};

const StateMachineRequest = struct {
    geometry: state_machine_route.cuda.geometry.Geometry,
    proof_request: state_machine_route.cuda.geometry.Request,
    prepared: state_machine_route.cuda.NativeDriver.PreparedProof,
    mode: cli.ExecutionMode,
};

const Request = union(Family) {
    wide_fibonacci: WideRequest,
    poseidon: PoseidonRequest,
    state_machine: StateMachineRequest,
};

const Geometry = union(Family) {
    wide_fibonacci: wide_route.cuda.request.Geometry,
    poseidon: poseidon_route.cuda.geometry.Geometry,
    state_machine: state_machine_route.cuda.geometry.Geometry,
};

const Proof = struct {
    geometry: Geometry,
    canonical: []u8,
    verdict: Verdict,
    resident_ns: u64,
    decode_ns: u64,
    verification_ns: u64,
    verified_request_ns: u64,
};

const RequestType = Request;
const ProofType = Proof;

const Workload = struct {
    pub const Request = RequestType;
    pub const Proof = ProofType;

    pub fn execute(
        allocator: std.mem.Allocator,
        runtime: *Runtime,
        request: *RequestType,
    ) !ProofType {
        return switch (request.*) {
            .wide_fibonacci => |*value| result: {
                const executed = try executeRoute(
                    wide_route,
                    allocator,
                    runtime,
                    value.proof_request,
                    &value.prepared,
                    value.geometry,
                    value.mode,
                );
                break :result .{
                    .geometry = .{ .wide_fibonacci = value.geometry },
                    .canonical = executed.canonical,
                    .verdict = executed.verdict,
                    .resident_ns = executed.resident_ns,
                    .decode_ns = executed.decode_ns,
                    .verification_ns = executed.verification_ns,
                    .verified_request_ns = executed.verified_request_ns,
                };
            },
            .poseidon => |*value| result: {
                const executed = try executeRoute(
                    poseidon_route,
                    allocator,
                    runtime,
                    value.proof_request,
                    &value.prepared,
                    value.geometry,
                    value.mode,
                );
                break :result .{
                    .geometry = .{ .poseidon = value.geometry },
                    .canonical = executed.canonical,
                    .verdict = executed.verdict,
                    .resident_ns = executed.resident_ns,
                    .decode_ns = executed.decode_ns,
                    .verification_ns = executed.verification_ns,
                    .verified_request_ns = executed.verified_request_ns,
                };
            },
            .state_machine => |*value| result: {
                const executed = try executeRoute(
                    state_machine_route,
                    allocator,
                    runtime,
                    value.proof_request,
                    &value.prepared,
                    value.geometry,
                    value.mode,
                );
                break :result .{
                    .geometry = .{ .state_machine = value.geometry },
                    .canonical = executed.canonical,
                    .verdict = executed.verdict,
                    .resident_ns = executed.resident_ns,
                    .decode_ns = executed.decode_ns,
                    .verification_ns = executed.verification_ns,
                    .verified_request_ns = executed.verified_request_ns,
                };
            },
        };
    }

    pub fn deinitRequest(
        allocator: std.mem.Allocator,
        request: *RequestType,
    ) void {
        switch (request.*) {
            inline else => |*value| value.prepared.deinit(allocator),
        }
    }

    pub fn deinitProof(
        allocator: std.mem.Allocator,
        proof: *ProofType,
    ) void {
        allocator.free(proof.canonical);
        proof.* = undefined;
    }

    pub fn shapeCached(runtime: *Runtime, key: [32]u8) bool {
        return runtime.hasPreparedExecution(key);
    }

    pub fn runtimeReady(runtime: *Runtime) bool {
        return runtime.isReady();
    }

    pub fn executionLaneCount(runtime: *Runtime) u32 {
        return runtime.executionLaneCount();
    }

    pub fn failureDisposition(
        _: *Runtime,
        _: anyerror,
    ) service_module.FailureDisposition {
        return .poison_runtime;
    }
};

const Service = service_module.ServiceFor(
    Runtime,
    Workload,
    service_module.SystemClock,
);

const Execution = struct {
    canonical: []u8,
    verdict: Verdict,
    resident_ns: u64,
    decode_ns: u64,
    verification_ns: u64,
    verified_request_ns: u64,
};

fn executeRoute(
    comptime Route: type,
    allocator: std.mem.Allocator,
    runtime: *Runtime,
    proof_request: anytype,
    prepared: anytype,
    geometry: anytype,
    mode: cli.ExecutionMode,
) !Execution {
    const driver = Route.cuda.NativeDriver{ .allocator = allocator };
    var request_timer = try std.time.Timer.start();
    var resident_timer = try std.time.Timer.start();
    var output = switch (mode) {
        .graphs => try driver.runPreparedRetained(
            runtime,
            proof_request,
            prepared,
        ),
        .direct => try driver.runPreparedRetainedDirect(
            runtime,
            proof_request,
            prepared,
        ),
    };
    const resident_ns = resident_timer.read();
    defer output.deinit(allocator);
    try proof_route.requireResident(output.verdict, mode);

    var decode_timer = try std.time.Timer.start();
    var proof = try Route.cuda.proof_decode.decodeProof(
        allocator,
        output.bundle,
    );
    var proof_live = true;
    defer if (proof_live) proof.deinit(allocator);
    const canonical = try proof_wire.encodeProofBytes(allocator, proof);
    errdefer allocator.free(canonical);
    const decode_ns = decode_timer.read();

    var verification_timer = try std.time.Timer.start();
    proof_live = false;
    try Route.verify(
        allocator,
        try proof_route.pcsConfig(),
        geometry,
        proof,
    );
    return .{
        .canonical = canonical,
        .verdict = output.verdict,
        .resident_ns = resident_ns,
        .decode_ns = decode_ns,
        .verification_ns = verification_timer.read(),
        .verified_request_ns = request_timer.read(),
    };
}

pub fn run(
    allocator: std.mem.Allocator,
    request: cli.Sustain,
) !void {
    try std.fs.cwd().makeDir(request.output_dir);
    var output_dir_owned = true;
    errdefer if (output_dir_owned)
        std.fs.cwd().deleteTree(request.output_dir) catch {};

    var total_timer = try std.time.Timer.start();
    var runtime_init_timer = try std.time.Timer.start();
    var runtime = try Runtime.open(&accepted_sms);
    const runtime_init_ns = runtime_init_timer.read();
    var runtime_live = true;
    defer if (runtime_live) runtime.abort() catch {};

    const request_count = std.math.mul(
        usize,
        @as(usize, request.cycles),
        @typeInfo(Family).@"enum".fields.len,
    ) catch return error.SizeOverflow;
    var shape_prepare_timer = try std.time.Timer.start();
    var prepared_requests: std.ArrayList(Request) = .empty;
    var submitted: usize = 0;
    defer {
        for (prepared_requests.items[submitted..]) |*queued|
            Workload.deinitRequest(allocator, queued);
        prepared_requests.deinit(allocator);
    }
    for (0..request_count) |ordinal| {
        try prepared_requests.append(allocator, try prepareRequest(
            allocator,
            &runtime,
            familyAt(ordinal),
            request.execution_mode,
        ));
    }
    const shape_prepare_ns = shape_prepare_timer.read();

    const clock = try service_module.SystemClock.start();
    runtime_live = false;
    var service = try Service.init(
        allocator,
        runtime,
        clock,
        .{
            .max_pending = request_count,
            .max_request_device_bytes = 16 * 1024 * 1024 * 1024,
            .max_queued_input_bytes = 64 * 1024 * 1024 * 1024,
        },
        runtime_init_ns,
    );
    defer service.deinit();

    for (prepared_requests.items) |*queued| {
        const metadata = metadataFor(queued);
        const admission = try service.submit(queued.*, metadata);
        switch (admission) {
            .accepted => submitted += 1,
            else => return error.MixedServiceAdmissionRejected,
        }
    }

    var rows: std.ArrayList(report.Row) = .empty;
    defer {
        for (rows.items) |row| allocator.free(row.proof.artifact_path);
        rows.deinit(allocator);
    }
    var family_digests = [_]?[32]u8{null} ** 3;
    var total_trace_rows: u64 = 0;
    var total_trace_cells: u64 = 0;
    var total_device_ns: u64 = 0;
    var service_timer = try std.time.Timer.start();
    for (0..request_count) |ordinal| {
        switch (try service.pumpOne()) {
            .completed => {},
            else => return error.MixedServiceExecutionFailed,
        }
        switch (try service.publishNext()) {
            .proof => |published| {
                var proof = published.proof;
                defer Workload.deinitProof(allocator, &proof);
                const expected_ticket: u64 = @intCast(ordinal + 1);
                if (published.receipt.ticket != expected_ticket or
                    proof.verdict.runtime_proof_index != expected_ticket)
                {
                    return error.NonSequentialMixedServiceProof;
                }
                const row = try publishProof(
                    allocator,
                    request.output_dir,
                    ordinal,
                    published.receipt,
                    &proof,
                    &family_digests,
                );
                errdefer allocator.free(row.proof.artifact_path);
                try rows.append(allocator, row);
                total_trace_rows = try add(
                    total_trace_rows,
                    row.statement.trace_rows,
                );
                total_trace_cells = try add(
                    total_trace_cells,
                    row.statement.trace_cells,
                );
                total_device_ns = try add(
                    total_device_ns,
                    row.timing_ns.device_critical_path,
                );
            },
            else => return error.MixedServicePublicationFailed,
        }
    }
    const service_wall_ns = service_timer.read();
    const telemetry = service.snapshot();
    if (telemetry.requests_completed != request_count or
        telemetry.publications != request_count or
        telemetry.shape_misses != 0 or
        service.runtime.completedProofs() != request_count)
    {
        return error.IncompleteMixedServiceSequence;
    }

    var teardown_timer = try std.time.Timer.start();
    try service.close();
    const runtime_teardown_ns = teardown_timer.read();
    const rendered = try report.render(
        allocator,
        request,
        rows.items,
        telemetry,
        queueDigest(request.cycles),
        .{
            .trace_rows = total_trace_rows,
            .trace_cells = total_trace_cells,
            .device_ns = total_device_ns,
        },
        .{
            .runtime_init_ns = runtime_init_ns,
            .shape_prepare_ns = shape_prepare_ns,
            .service_wall_ns = service_wall_ns,
            .runtime_teardown_ns = runtime_teardown_ns,
            .total_ns = total_timer.read(),
        },
    );
    defer allocator.free(rendered);
    const with_newline = try std.mem.concat(
        allocator,
        u8,
        &.{ rendered, "\n" },
    );
    defer allocator.free(with_newline);
    try atomic_file.writeExclusive(
        allocator,
        request.report_out,
        with_newline,
    );
    output_dir_owned = false;
    try std.fs.File.stdout().writeAll(with_newline);
}

fn prepareRequest(
    allocator: std.mem.Allocator,
    runtime: *Runtime,
    family: Family,
    mode: cli.ExecutionMode,
) !Request {
    return switch (family) {
        .wide_fibonacci => result: {
            const geometry = try wide_route.admit(
                proveShape(family),
                wide_route.protocol(),
            );
            const proof_request = wide_route.proofRequest(geometry);
            const driver = wide_route.cuda.NativeDriver{
                .allocator = allocator,
            };
            break :result .{ .wide_fibonacci = .{
                .geometry = geometry,
                .proof_request = proof_request,
                .prepared = try driver.prepare(runtime, proof_request),
                .mode = mode,
            } };
        },
        .poseidon => result: {
            const geometry = try poseidon_route.admit(
                proveShape(family),
                poseidon_route.protocol(),
            );
            const proof_request = poseidon_route.proofRequest(geometry);
            const driver = poseidon_route.cuda.NativeDriver{
                .allocator = allocator,
            };
            break :result .{ .poseidon = .{
                .geometry = geometry,
                .proof_request = proof_request,
                .prepared = try driver.prepare(runtime, proof_request),
                .mode = mode,
            } };
        },
        .state_machine => result: {
            const geometry = try state_machine_route.admit(
                proveShape(family),
                state_machine_route.protocol(),
            );
            const proof_request = state_machine_route.proofRequest(geometry);
            const driver = state_machine_route.cuda.NativeDriver{
                .allocator = allocator,
            };
            break :result .{ .state_machine = .{
                .geometry = geometry,
                .proof_request = proof_request,
                .prepared = try driver.prepare(runtime, proof_request),
                .mode = mode,
            } };
        },
    };
}

fn metadataFor(request: *const Request) service_module.RequestMetadata {
    return switch (request.*) {
        inline else => |*value| metadata: {
            const bytes =
                value.prepared.structural.cuda_plan.prediction.request_bytes;
            break :metadata .{
                .shape_key = value.prepared.cacheKey(),
                .predicted_device_bytes = bytes,
                // This conservative upper bound prevents the queue admission
                // policy from understating retained host-side plan ownership.
                .retained_input_bytes = bytes,
            };
        },
    };
}

fn publishProof(
    allocator: std.mem.Allocator,
    output_dir: []const u8,
    ordinal: usize,
    receipt: service_module.Receipt,
    proof: *const Proof,
    family_digests: *[3]?[32]u8,
) !report.Row {
    const family = std.meta.activeTag(proof.geometry);
    const path = try std.fmt.allocPrint(
        allocator,
        "{s}/{d:0>3}-{s}.proof.json",
        .{ output_dir, ordinal, @tagName(family) },
    );
    errdefer allocator.free(path);
    const pcs = try proof_route.pcsConfig();
    switch (proof.geometry) {
        .wide_fibonacci => |geometry| try wide_route.writeArtifact(
            allocator,
            path,
            pcs,
            geometry,
            proof.canonical,
        ),
        .poseidon => |geometry| try poseidon_route.writeArtifact(
            allocator,
            path,
            pcs,
            geometry,
            proof.canonical,
        ),
        .state_machine => |geometry| try state_machine_route.writeArtifact(
            allocator,
            path,
            pcs,
            geometry,
            proof.canonical,
        ),
    }
    var canonical_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(
        proof.canonical,
        &canonical_digest,
        .{},
    );
    const family_index = @intFromEnum(family);
    const exact = if (family_digests[family_index]) |expected|
        std.mem.eql(u8, &expected, &canonical_digest)
    else
        true;
    if (!exact) return error.UnstableCanonicalProof;
    family_digests[family_index] = canonical_digest;

    const artifact_bytes = try std.fs.cwd().readFileAlloc(
        allocator,
        path,
        artifacts.MAX_ARTIFACT_BYTES,
    );
    defer allocator.free(artifact_bytes);
    var artifact_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(
        artifact_bytes,
        &artifact_digest,
        .{},
    );
    const counters = proof.verdict.counters;
    return .{
        .ordinal = ordinal,
        .family = @tagName(family),
        .statement = statementReport(proof.geometry),
        .receipt = .{
            .ticket = receipt.ticket,
            .runtime_generation = receipt.runtime_generation,
            .queue_depth_at_admission = receipt.queue_depth_at_admission,
            .queue_wait_ns = receipt.queue_wait_ns,
            .service_ns = receipt.service_ns,
            .service_cold = receipt.service_cold,
            .shape_cache_hit = receipt.shape_cache_hit,
            .shape_retained_after = receipt.shape_retained_after,
            .shape_key_sha256 = std.fmt.bytesToHex(
                receipt.shape_key,
                .lower,
            ),
            .predicted_device_bytes = receipt.predicted_device_bytes,
            .retained_input_bytes_upper_bound = receipt.retained_input_bytes,
        },
        .proof = .{
            .artifact_path = path,
            .format = artifacts.EXCHANGE_MODE,
            .canonical_bytes = proof.canonical.len,
            .canonical_sha256 = std.fmt.bytesToHex(
                canonical_digest,
                .lower,
            ),
            .artifact_sha256 = std.fmt.bytesToHex(
                artifact_digest,
                .lower,
            ),
            .zig_verified = true,
            .exact_for_repeated_family_input = exact,
        },
        .oracle_hook = .{
            .required = true,
            .authority = "pinned-rust-stwo",
            .upstream_commit = artifacts.UPSTREAM_COMMIT,
            .artifact_path = path,
            .artifact_sha256 = std.fmt.bytesToHex(
                artifact_digest,
                .lower,
            ),
            .receipt = null,
        },
        .timing_ns = .{
            .resident_prove = proof.resident_ns,
            .terminal_decode = proof.decode_ns,
            .independent_verification = proof.verification_ns,
            .verified_request = proof.verified_request_ns,
            .device_critical_path = counters.device_elapsed_ns,
        },
        .residency = .{
            .resident = proof.verdict.isResident(),
            .strict_aot = proof.verdict.aot.isStrict(),
            .runtime_proof_index = proof.verdict.runtime_proof_index,
            .cpu_fallback_attempts = counters.cpu_fallback_attempts,
            .cpu_fallbacks_completed = counters.cpu_fallbacks_completed,
            .terminal_d2h_operations = counters.d2h_proof_operations,
            .terminal_d2h_bytes = counters.d2h_proof_bytes,
            .kernel_launches = counters.kernel_launches,
            .graph_launches = counters.graph_launches,
            .sync_calls = counters.sync_calls,
            .peak_live_bytes = counters.peak_live_bytes,
        },
        .device = .{
            .uuid = std.fmt.bytesToHex(
                proof.verdict.platform.uuid,
                .lower,
            ),
            .sm = try proof.verdict.device.sm(),
            .ordinal = proof.verdict.platform.device_ordinal,
            .total_global_memory = proof.verdict.platform.total_global_memory,
            .multiprocessors = proof.verdict.platform.multiprocessor_count,
            .driver_version = proof.verdict.platform.driver_version,
            .runtime_version = proof.verdict.platform.runtime_version,
            .toolkit_version = proof.verdict.platform.toolkit_version,
        },
    };
}

fn familyAt(ordinal: usize) Family {
    return @enumFromInt(ordinal % 3);
}

fn queueDigest(cycles: u32) [64]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(report.workload_id);
    var cycle_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &cycle_bytes, cycles, .little);
    hash.update(&cycle_bytes);
    const count = cycles * 3;
    for (0..count) |ordinal| hash.update(@tagName(familyAt(ordinal)));
    return std.fmt.bytesToHex(hash.finalResult(), .lower);
}

fn proveShape(family: Family) cli.Prove {
    return .{
        .air = switch (family) {
            .wide_fibonacci => .wide_fibonacci,
            .poseidon => .poseidon,
            .state_machine => .state_machine,
        },
        .log_n_rows = switch (family) {
            .wide_fibonacci => 18,
            .state_machine => 16,
            .poseidon => null,
        },
        .sequence_len = if (family == .wide_fibonacci) 37 else null,
        .n_rounds = null,
        .log_n_instances = if (family == .poseidon) 13 else null,
        .log_size = null,
        .log_step = null,
        .offset = null,
        .initial_x = if (family == .state_machine) 9 else null,
        .initial_y = if (family == .state_machine) 3 else null,
        .output = "",
        .report_out = null,
        .repeat = 1,
        .execution_mode = .graphs,
    };
}

fn statementReport(geometry: Geometry) report.Statement {
    return switch (geometry) {
        .wide_fibonacci => |value| .{
            .family = "wide_fibonacci",
            .log_n_rows = value.statement.log_n_rows,
            .sequence_len = value.statement.sequence_len,
            .trace_rows = value.trace_rows,
            .trace_cells = value.trace_cells,
        },
        .poseidon => |value| .{
            .family = "poseidon",
            .log_n_instances = value.statement.log_n_instances,
            .trace_rows = value.trace_rows,
            .trace_cells = value.main_cells,
        },
        .state_machine => |value| .{
            .family = "state_machine",
            .log_n_rows = value.statement.log_n_rows,
            .initial_x = value.statement.initial_state[0].toU32(),
            .initial_y = value.statement.initial_state[1].toU32(),
            .trace_rows = value.trace_rows,
            .trace_cells = value.trace_elements,
        },
    };
}

fn add(left: u64, right: u64) !u64 {
    return std.math.add(u64, left, right) catch error.SizeOverflow;
}

test "mixed workload order and identity are deterministic" {
    try std.testing.expectEqual(Family.wide_fibonacci, familyAt(0));
    try std.testing.expectEqual(Family.poseidon, familyAt(1));
    try std.testing.expectEqual(Family.state_machine, familyAt(2));
    try std.testing.expectEqual(Family.wide_fibonacci, familyAt(3));
    try std.testing.expectEqualSlices(
        u8,
        &queueDigest(2),
        &queueDigest(2),
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &queueDigest(1),
        &queueDigest(2),
    ));
}
