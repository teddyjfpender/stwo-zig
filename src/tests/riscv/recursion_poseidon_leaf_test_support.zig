//! Focused measurement, mutation, and captured-FRI helpers for the Poseidon leaf gate.

const std = @import("std");
const postcard = @import("interop_postcard");
const frontend = @import("stwo_riscv_frontend");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const riscv_cpu = @import("stwo_riscv_cpu_integration");

const recursion = frontend.recursion;
const prover = frontend.prover_mod;
const Engine = recursion.engine.ScheduledProverEngineForBackend(CpuBackend);
const PcsConfig = @TypeOf(recursion.protocol.PCS_CONFIG);
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

pub const FRONTIER_COLUMN_LOG_DEGREE = recursion.segment_profile.COLUMN_LOG_DEGREE;
pub const FRONTIER_ENV = "STWO_RECURSION_FRI_FRONTIER_BLOWUP";
pub const ACTIVE_OUTER_ENV = "STWO_RECURSION_ACTIVE_FRI_OUTER";
pub const TUPLE_FRONTIER_ENV = "STWO_RECURSION_OUTER_TUPLE_FRONTIER";
pub const DISABLE_OUTER_MUTATIONS_ENV =
    "STWO_RECURSION_OUTER_DISABLE_MUTATION_PROBES";

pub const ProfileSelection = struct {
    config: PcsConfig,
    candidate: recursion.fri_profile_frontier.Candidate,
    measurement_mode: bool,
};

pub const LEAF_DIMENSIONS = recursion.segment_profile.DIMENSIONS;
pub const LeafWire = recursion.fixed_wire.FixedStarkProofWire(LEAF_DIMENSIONS);

pub fn validateAndReportMeasurement(
    selection: anytype,
    output: anytype,
    proof_capture: anytype,
    resources_before: anytype,
    metrics: anytype,
) !usize {
    try std.testing.expect(metrics.proof_size != 0);
    try std.testing.expect(metrics.proof_bytes_len != 0);
    try std.testing.expect(metrics.transcript_draws != 0);
    try std.testing.expectEqual(
        metrics.transcript_draws,
        metrics.verifier_draws,
    );
    try std.testing.expectEqual(
        selection.config.fri_config.n_queries,
        proof_capture.queries.raw.len,
    );
    try std.testing.expect(
        proof_capture.queries.unique.len <= proof_capture.queries.raw.len,
    );
    try std.testing.expect(proof_capture.queries.unique.len != 0);
    try std.testing.expectEqual(@as(usize, 4), proof_capture.commitments.len);
    try std.testing.expectEqual(@as(usize, 4), proof_capture.trace_paths.len);
    try std.testing.expect(proof_capture.sampled_values.len != 0);
    try std.testing.expect(proof_capture.queried_values.len != 0);
    try std.testing.expect(proof_capture.fri.layers.len != 0);
    try std.testing.expect(proof_capture.last_layer_coefficients.len != 0);
    for (proof_capture.trace_paths) |path_capture| {
        try std.testing.expectEqual(
            selection.config.fri_config.n_queries,
            path_capture.positions.len,
        );
    }
    for (proof_capture.fri.layers) |layer| {
        try std.testing.expectEqual(
            selection.config.fri_config.n_queries,
            layer.query_count,
        );
        try std.testing.expectEqual(
            layer.query_count * @as(usize, @intCast(layer.fold_width)),
            layer.values.len,
        );
    }

    const measured_dimensions = try measurementDimensions(
        &output.statement,
        output.interaction_claim,
        proof_capture,
    );
    const measured_wire_bytes = try recursion.fixed_wire.serializedByteCountRuntime(
        measured_dimensions,
    );
    const column_log_degree = std.math.sub(
        u32,
        proof_capture.trace_paths[3].path_depth,
        selection.config.fri_config.log_blowup_factor,
    ) catch return error.InvalidMeasuredProfile;
    try std.testing.expectEqual(FRONTIER_COLUMN_LOG_DEGREE, column_log_degree);

    var trace_siblings: usize = 0;
    for (proof_capture.trace_paths) |path| {
        trace_siblings = try std.math.add(usize, trace_siblings, path.siblings.len);
    }
    var fri_siblings: usize = 0;
    var fri_values: usize = 0;
    for (proof_capture.fri.layers) |layer| {
        fri_siblings = try std.math.add(usize, fri_siblings, layer.siblings.len);
        fri_values = try std.math.add(usize, fri_values, layer.values.len);
    }

    const resources_after = try frontend.process_usage.sample();
    const resources = try frontend.process_usage.difference(
        resources_before,
        resources_after,
    );
    std.debug.print(
        "\n  A1_REAL mode={s} blowup_log={d} expansion={d} queries={d} " ++
            "security={d} column_log={d} proof_estimate={d} postcard={d} " ++
            "fixed_wire={d} sampled={d} queried={d} trace_siblings={d} " ++
            "fri_layers={d} fri_siblings={d} fri_values={d} terminal={d} " ++
            "prove_ns={d} serialize_ns={d} ingress_ns={d} decode_ns={d} " ++
            "verify_ns={d} total_ns={d} counters={any} peak_bytes={d} " ++
            "cpu_ns={d} energy_nj={d} instructions={d} cycles={d}\n",
        .{
            if (selection.measurement_mode) "frontier" else "regression",
            selection.candidate.log_blowup_factor,
            selection.candidate.domain_expansion,
            selection.candidate.n_queries,
            selection.candidate.configured_security_bits,
            column_log_degree,
            metrics.proof_size,
            metrics.proof_bytes_len,
            measured_wire_bytes,
            proof_capture.sampled_values.len,
            proof_capture.queried_values.len,
            trace_siblings,
            proof_capture.fri.layers.len,
            fri_siblings,
            fri_values,
            proof_capture.last_layer_coefficients.len,
            metrics.prove_ns,
            metrics.serialize_ns,
            metrics.ingress_ns,
            metrics.decode_ns,
            metrics.verify_ns,
            metrics.total_ns,
            resources.available(),
            resources.lifetime_peak_physical_footprint_bytes orelse 0,
            resources.process_cpu_ns orelse 0,
            resources.energy_nj orelse 0,
            resources.instructions orelse 0,
            resources.cycles orelse 0,
        },
    );
    return measured_wire_bytes;
}

pub fn recursionOuterWorkerCount(allocator: std.mem.Allocator) !usize {
    const value = std.process.getEnvVarOwned(
        allocator,
        "STWO_RECURSION_OUTER_WORKERS",
    ) catch return 4;
    defer allocator.free(value);
    return std.fmt.parseInt(usize, value, 10);
}

pub fn environmentFlag(allocator: std.mem.Allocator, name: []const u8) !bool {
    const value = std.process.getEnvVarOwned(allocator, name) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return false,
        else => return err,
    };
    defer allocator.free(value);
    return std.mem.eql(u8, value, "1") or
        std.ascii.eqlIgnoreCase(value, "true") or
        std.ascii.eqlIgnoreCase(value, "yes");
}

pub fn selectProfile(allocator: std.mem.Allocator) !ProfileSelection {
    const raw: ?[]u8 = std.process.getEnvVarOwned(
        allocator,
        FRONTIER_ENV,
    ) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (raw) |owned| allocator.free(owned);

    const selected_blowup = if (raw) |encoded|
        try std.fmt.parseUnsigned(u32, encoded, 10)
    else
        recursion.protocol.FRI_LOG_BLOWUP_FACTOR;
    const frontier = try recursion.fri_profile_frontier.v1Comparison(
        FRONTIER_COLUMN_LOG_DEGREE,
    );
    for (frontier.active()) |candidate| {
        if (candidate.log_blowup_factor != selected_blowup) continue;
        var config = recursion.protocol.PCS_CONFIG;
        config.fri_config.log_blowup_factor = candidate.log_blowup_factor;
        config.fri_config.n_queries = candidate.n_queries;
        return .{
            .config = config,
            .candidate = candidate,
            .measurement_mode = raw != null,
        };
    }
    return error.FriFrontierCandidateNotFound;
}

pub fn measurementDimensions(
    statement: *const prover.RiscVStatement,
    claim: *const prover.RiscVInteractionClaim,
    capture: *const prover.ProofCaptureForEngine(Engine),
) !recursion.fixed_wire.Dimensions {
    const canonical_claim = try claim.canonical(statement);
    var trace_path_count: usize = 0;
    var maximum_merkle_depth: usize = 0;
    for (capture.trace_paths) |path| {
        trace_path_count = try std.math.add(
            usize,
            trace_path_count,
            path.positions.len,
        );
        maximum_merkle_depth = @max(
            maximum_merkle_depth,
            @as(usize, @intCast(path.path_depth)),
        );
    }
    var maximum_fold_width: usize = 0;
    for (capture.fri.layers) |layer| {
        maximum_fold_width = @max(
            maximum_fold_width,
            @as(usize, @intCast(layer.fold_width)),
        );
        maximum_merkle_depth = @max(
            maximum_merkle_depth,
            @as(usize, @intCast(layer.path_depth)),
        );
    }
    return .{
        .commitment_count = capture.commitments.len,
        .claimed_sum_count = canonical_claim.claimed_sums.len,
        .sampled_value_count = capture.sampled_values.len,
        .queried_value_count = capture.queried_values.len,
        .trace_path_count = trace_path_count,
        .fri_layer_count = capture.fri.layers.len,
        .query_count = capture.queries.raw.len,
        .maximum_fold_width = maximum_fold_width,
        .last_layer_coefficient_count = capture.last_layer_coefficients.len,
        .maximum_merkle_depth = maximum_merkle_depth,
    };
}

pub fn runAdapterMutationFleet(
    destination: *LeafWire,
    shape: recursion.fixed_profile.ProofShapeV1,
    statement: *const prover.RiscVStatement,
    claim: *const prover.RiscVInteractionClaim,
    capture: *prover.ProofCaptureForEngine(Engine),
) !void {
    const modulus = @import("stwo_core").fields.m31.Modulus;

    {
        const original = capture.trace_paths[0].path_depth;
        defer capture.trace_paths[0].path_depth = original;
        capture.trace_paths[0].path_depth = original + 1;
        try expectAtomicAdapterRejection(
            error.CaptureShapeMismatch,
            destination,
            shape,
            statement,
            claim,
            capture,
        );
    }
    {
        const original = capture.column_log_sizes[0][0];
        defer capture.column_log_sizes[0][0] = original;
        capture.column_log_sizes[0][0] = original + 1;
        try expectAtomicAdapterRejection(
            error.CaptureShapeMismatch,
            destination,
            shape,
            statement,
            claim,
            capture,
        );
    }
    {
        const original = capture.column_log_sizes[0];
        defer capture.column_log_sizes[0] = original;
        capture.column_log_sizes[0] = original[0 .. original.len - 1];
        try expectAtomicAdapterRejection(
            error.CaptureShapeMismatch,
            destination,
            shape,
            statement,
            claim,
            capture,
        );
    }
    {
        const original = capture.oods_seed;
        defer capture.oods_seed = original;
        capture.oods_seed = QM31.fromM31(
            M31.fromU32Unchecked(modulus),
            M31.zero(),
            M31.zero(),
            M31.zero(),
        );
        try expectAtomicAdapterRejection(
            error.NonCanonicalCapture,
            destination,
            shape,
            statement,
            claim,
            capture,
        );
    }
    {
        const original = capture.oods_seed;
        defer capture.oods_seed = original;
        // sqrt(-1) makes the rational circle map denominator zero. This is a
        // canonical field value and must be rejected, never panic.
        capture.oods_seed = QM31.fromU32Unchecked(0, 1, 0, 0);
        try expectAtomicAdapterRejection(
            error.CaptureShapeMismatch,
            destination,
            shape,
            statement,
            claim,
            capture,
        );
    }
    {
        const original = capture.sampled_points;
        defer capture.sampled_points = original;
        capture.sampled_points = original[0 .. original.len - 1];
        try expectAtomicAdapterRejection(
            error.CaptureShapeMismatch,
            destination,
            shape,
            statement,
            claim,
            capture,
        );
    }
    sample_point_mutation: {
        for (capture.sampled_points) |columns| {
            for (columns) |points| {
                if (points.len == 0) continue;
                const original = points[0];
                defer points[0] = original;
                points[0].x = points[0].x.add(QM31.one());
                try expectAtomicAdapterRejection(
                    error.CaptureShapeMismatch,
                    destination,
                    shape,
                    statement,
                    claim,
                    capture,
                );
                break :sample_point_mutation;
            }
        }
        return error.MissingSamplePointMutationTarget;
    }
    {
        const original = capture.trace_paths[0].positions[0];
        defer capture.trace_paths[0].positions[0] = original;
        capture.trace_paths[0].positions[0] ^= 1;
        try expectAtomicAdapterRejection(
            error.InvalidQuerySchedule,
            destination,
            shape,
            statement,
            claim,
            capture,
        );
    }
    {
        const original = capture.commitments[0][0];
        defer capture.commitments[0][0] = original;
        capture.commitments[0][0] = modulus;
        try expectAtomicAdapterRejection(
            error.NonCanonicalCapture,
            destination,
            shape,
            statement,
            claim,
            capture,
        );
    }
    {
        const original = capture.trace_paths[0].siblings[0][0];
        defer capture.trace_paths[0].siblings[0][0] = original;
        capture.trace_paths[0].siblings[0][0] = modulus;
        try expectAtomicAdapterRejection(
            error.NonCanonicalCapture,
            destination,
            shape,
            statement,
            claim,
            capture,
        );
    }
    {
        const original = capture.queries.raw[0];
        defer capture.queries.raw[0] = original;
        capture.queries.raw[0] ^= 1;
        try expectAtomicAdapterRejection(
            error.InvalidQuerySchedule,
            destination,
            shape,
            statement,
            claim,
            capture,
        );
    }
    {
        std.debug.assert(capture.queries.unique.len > 1);
        defer std.mem.swap(
            usize,
            &capture.queries.unique[0],
            &capture.queries.unique[1],
        );
        std.mem.swap(
            usize,
            &capture.queries.unique[0],
            &capture.queries.unique[1],
        );
        try expectAtomicAdapterRejection(
            error.InvalidQuerySchedule,
            destination,
            shape,
            statement,
            claim,
            capture,
        );
    }
    {
        const original = capture.fri.layers[0].positions[0];
        defer capture.fri.layers[0].positions[0] = original;
        capture.fri.layers[0].positions[0] ^= 1;
        try expectAtomicAdapterRejection(
            error.InvalidQuerySchedule,
            destination,
            shape,
            statement,
            claim,
            capture,
        );
    }
    {
        const original = capture.fri.layers[0].path_depth;
        defer capture.fri.layers[0].path_depth = original;
        capture.fri.layers[0].path_depth = original + 1;
        try expectAtomicAdapterRejection(
            error.CaptureShapeMismatch,
            destination,
            shape,
            statement,
            claim,
            capture,
        );
    }
    {
        const original = capture.fri.layers[0].siblings[0][0];
        defer capture.fri.layers[0].siblings[0][0] = original;
        capture.fri.layers[0].siblings[0][0] = modulus;
        try expectAtomicAdapterRejection(
            error.NonCanonicalCapture,
            destination,
            shape,
            statement,
            claim,
            capture,
        );
    }
    {
        const original = capture.fri.layers[0].siblings;
        defer capture.fri.layers[0].siblings = original;
        capture.fri.layers[0].siblings = original[0 .. original.len - 1];
        try expectAtomicAdapterRejection(
            error.CaptureShapeMismatch,
            destination,
            shape,
            statement,
            claim,
            capture,
        );
    }
    {
        const original = capture.last_layer_coefficients;
        defer capture.last_layer_coefficients = original;
        capture.last_layer_coefficients = original[0..0];
        try expectAtomicAdapterRejection(
            error.CaptureShapeMismatch,
            destination,
            shape,
            statement,
            claim,
            capture,
        );
    }
    {
        const original = capture.sampled_values;
        defer capture.sampled_values = original;
        capture.sampled_values = original[0 .. original.len - 1];
        try expectAtomicAdapterRejection(
            error.CaptureShapeMismatch,
            destination,
            shape,
            statement,
            claim,
            capture,
        );
    }
    {
        const original = capture.deep_answers;
        defer capture.deep_answers = original;
        capture.deep_answers = original[0 .. original.len - 1];
        try expectAtomicAdapterRejection(
            error.CaptureShapeMismatch,
            destination,
            shape,
            statement,
            claim,
            capture,
        );
    }
    {
        const original = capture.queried_values;
        defer capture.queried_values = original;
        capture.queried_values = original[0 .. original.len - 1];
        try expectAtomicAdapterRejection(
            error.CaptureShapeMismatch,
            destination,
            shape,
            statement,
            claim,
            capture,
        );
    }
    {
        const original = capture.trace_paths;
        defer capture.trace_paths = original;
        capture.trace_paths = original[0 .. original.len - 1];
        try expectAtomicAdapterRejection(
            error.CaptureShapeMismatch,
            destination,
            shape,
            statement,
            claim,
            capture,
        );
    }
    std.debug.print(
        "  fixed adapter mutation fleet: 21/21 rejected, destination atomic\n",
        .{},
    );
}

pub fn expectAtomicAdapterRejection(
    expected_error: anyerror,
    destination: *LeafWire,
    shape: recursion.fixed_profile.ProofShapeV1,
    statement: *const prover.RiscVStatement,
    claim: *const prover.RiscVInteractionClaim,
    capture: *const prover.ProofCaptureForEngine(Engine),
) !void {
    const sentinel: u8 = 0xa5;
    @memset(std.mem.asBytes(destination), sentinel);
    recursion.fixed_wire_adapter.populate(
        LEAF_DIMENSIONS,
        destination,
        shape,
        statement,
        claim,
        capture,
    ) catch |actual_error| {
        if (actual_error != expected_error) {
            std.debug.print(
                "  adapter mutation error mismatch: expected={s} actual={s}\n",
                .{ @errorName(expected_error), @errorName(actual_error) },
            );
            return error.AdapterMutationWrongError;
        }
        for (std.mem.asBytes(destination)) |byte| {
            if (byte != sentinel) return error.AdapterMutationWasNotAtomic;
        }
        return;
    };
    return error.AdapterMutationAccepted;
}

pub const FriCircuitEvidence = struct {
    node_count: usize,
    input_count: usize,
    output_count: usize,
    build_ns: u64,
    evaluate_ns: u64,
};

pub fn evaluateCapturedFriCircuit(
    allocator: std.mem.Allocator,
    config: PcsConfig,
    capture: *prover.ProofCaptureForEngine(Engine),
) !FriCircuitEvidence {
    var build_timer = try std.time.Timer.start();
    var captured = try recursion.captured_fri.Owned.init(
        allocator,
        recursion.captured_fri.ProfileConfig.fromPcs(config),
        capture,
    );
    defer captured.deinit();
    const build_ns = build_timer.read();
    var evaluation_timer = try std.time.Timer.start();
    var evaluation = try captured.circuit.evaluate(allocator, captured.witness());
    const evaluate_ns = evaluation_timer.read();
    defer evaluation.deinit();
    try evaluation.validateAgainst(&captured.circuit);

    {
        const deep_answers = @constCast(captured.deep_answers);
        const original = deep_answers[0];
        defer deep_answers[0] = original;
        deep_answers[0] = original.add(QM31.one());
        try std.testing.expectError(
            error.UnsatisfiedCircuit,
            captured.circuit.evaluate(allocator, captured.witness()),
        );
    }
    var inactive = try captured.evaluateInactive();
    defer inactive.deinit();
    try inactive.validateAgainst(&captured.circuit);
    return .{
        .node_count = captured.circuit.nodes.len,
        .input_count = captured.circuit.bindings.len,
        .output_count = captured.circuit.outputs.len,
        .build_ns = build_ns,
        .evaluate_ns = evaluate_ns,
    };
}
