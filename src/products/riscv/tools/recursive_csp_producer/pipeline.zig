//! One-workload native-leaf to verified outer-wire production pipeline.
//!
//! Every recursive value originates in the successful native verifier capture.
//! The retained artifact is the canonical outer-child wire published by the
//! independent outer verifier's receipt/capture/seal transaction.

const std = @import("std");
const builtin = @import("builtin");
const stwo = @import("stwo");
const contract = @import("contract.zig");
const profile_registry = @import("recursive_csp_profile_registry");

const postcard = stwo.interop.postcard;
const frontend = stwo.frontends.riscv;
const riscv_cpu = stwo.integrations.riscv_cpu;
const recursion = frontend.recursion;
const prover = frontend.prover_mod;
const Engine = recursion.engine.ScheduledProverEngineForBackend(
    riscv_cpu.CpuProverEngine.Backend,
);
const M31 = stwo.core.fields.m31.M31;
const LEAF_DIMENSIONS = recursion.segment_profile.DIMENSIONS;
const LeafWire = recursion.fixed_wire.FixedStarkProofWire(LEAF_DIMENSIONS);

pub const ImplementationIdentity = struct {
    commit: []const u8,
    dirty: bool,
};

pub const Phase = struct {
    duration_ns: u64,
    /// Exact count of Poseidon2 rows materialized into the authenticated
    /// recursive AIR. This deliberately does not claim to count native PCS
    /// hashing; the report names the narrower scope explicitly.
    poseidon2_permutations: u64,
};

/// Last authority boundary entered by `produce`. The caller owns this value so
/// a failed attempt can publish a useful failure record without manufacturing
/// phase timings that were never observed.
pub const Stage = enum {
    request_validation,
    source_admission,
    resource_capture,
    guest_execution,
    public_statement,
    profile_admission,
    base_prove,
    base_verify,
    recursive_prepare,
    recursive_prove_verify,
    artifact_encoding,
};

pub const Phases = struct {
    guest_execution: Phase,
    base_witness: Phase,
    base_prove: Phase,
    base_verify: Phase,
    recursive_prepare: Phase,
    recursive_witness: Phase,
    recursive_prove: Phase,
    recursive_verify: Phase,
};

pub const Identities = struct {
    request_sha256: [32]u8,
    public_values_sha256: [32]u8,
    leaf_statement_words_sha256: [32]u8,
    base_proof_sha256: [32]u8,
    payload_sha256: [32]u8,
    outer_statement_id: recursion.poseidon2_channel.Digest,
    outer_verification_key_id: recursion.poseidon2_channel.Digest,
    profile_id: recursion.poseidon2_channel.Digest,
    capture_id: recursion.poseidon2_channel.Digest,
    receipt_id: recursion.poseidon2_channel.Digest,
    transcript_id: recursion.poseidon2_channel.Digest,
    claimed_sums_id: recursion.poseidon2_channel.Digest,
    proof_id: recursion.poseidon2_channel.Digest,
    recursive_profile_shape_sha256: [32]u8,
    profile_registry_sha256: [32]u8,
};

pub const ResourceReceipt = struct {
    source: frontend.process_usage.Source,
    peak_rss_bytes: ?u64,
    lifetime_peak_physical_footprint_bytes: ?u64,
    process_cpu_ns: ?u64,
    energy_nj: ?u64,
    instructions: ?u64,
    cycles: ?u64,
    unavailable_reason: ?[]const u8,
};

pub const Produced = struct {
    payload: []u8,
    phases: Phases,
    identities: Identities,
    resources: ResourceReceipt,
    outer: riscv_cpu.recursive_fri_outer.Receipt,
    verified_end_to_end_ns: u64,
    execution_cycles: u64,
    worker_count: usize,
    proof_scope: recursion.outer_parent_child_admission.ProofScope,
    production_ready: bool,

    pub fn deinit(self: *Produced, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        self.* = undefined;
    }
};

pub fn produce(
    allocator: std.mem.Allocator,
    request: contract.Request,
    request_raw: []const u8,
    implementation: ImplementationIdentity,
    stage_out: *Stage,
) !Produced {
    comptime @import("stwo_prover_api").assertProverEngine(Engine);
    stage_out.* = .request_validation;
    try request.validate();

    // A public-values diagnostic binds the implementation commit and dirty
    // bit. Reject a historical or dirty producer before running attacker-
    // selected guest code: a paired benchmark requires a newly captured,
    // clean native cohort from this exact implementation commit.
    stage_out.* = .source_admission;
    if (!std.mem.eql(
        u8,
        request.native_measurement_commit,
        implementation.commit,
    )) return error.NativeMeasurementCommitMismatch;
    if (implementation.dirty) return error.DirtyProducerNotComparable;
    const registry_sha256 = profile_registry.registrySha256();
    try requireDigestEqual(
        registry_sha256,
        request.expected_profile_registry_sha256,
        error.ProfileRegistryDigestMismatch,
    );

    var request_sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(request_raw, &request_sha256, .{});

    const elf_bytes = try std.fs.cwd().readFileAlloc(
        allocator,
        request.guest_path,
        contract.MAX_ELF_BYTES,
    );
    defer allocator.free(elf_bytes);
    try frontend.runner.elf_loader.validateReleaseAbi(elf_bytes);
    try requireSha256(elf_bytes, request.guest_sha256);

    const input_bytes = try std.fs.cwd().readFileAlloc(
        allocator,
        request.input_path,
        contract.MAX_INPUT_BYTES,
    );
    defer allocator.free(input_bytes);
    try requireSha256(input_bytes, request.input_sha256);

    stage_out.* = .resource_capture;
    const resources_before = try frontend.process_usage.sample();
    var end_to_end_timer = try std.time.Timer.start();

    stage_out.* = .guest_execution;
    var guest_timer = try std.time.Timer.start();
    var run = try frontend.runner.runWithInput(
        allocator,
        elf_bytes,
        input_bytes,
        request.max_steps,
    );
    defer run.deinit();
    try prover.admitRunForProving(&run);
    const expected_cycles = std.math.cast(
        usize,
        request.expected_cycles,
    ) orelse return error.ExecutionCycleOverflow;
    if (run.step_count != expected_cycles) {
        return error.ExecutionCycleMismatch;
    }
    try validatePublicOutput(allocator, &run, request.expected_output_digest);
    const guest_execution_ns = guest_timer.read();

    // Public-data derivation and verifier-plan construction are witness setup.
    // The same derived value is then passed into the production prover, which
    // revalidates its commitment roots while building the committed witness.
    stage_out.* = .public_statement;
    var base_setup_timer = try std.time.Timer.start();
    var public = try frontend.diagnostics.public_values.derive(allocator, &run);
    defer public.deinit(allocator);
    const diagnostic = try frontend.diagnostics.public_values.encode(
        allocator,
        public.data,
        implementation.commit,
        implementation.dirty,
        elf_bytes,
        input_bytes,
    );
    defer allocator.free(diagnostic);
    const public_values_sha256 = hashWithTrailingNewline(diagnostic);
    try requireDigestEqual(
        public_values_sha256,
        request.expected_public_values_sha256,
        error.PublicValuesDigestMismatch,
    );

    // Admission runs inside the production prover after its one statement
    // derivation and before transcript/trace construction. Keeping the result
    // in caller-owned context avoids a second commitment-witness build.
    var statement_admission = ProfileStatementAdmissionContext{
        .request = &request,
        .stage_out = stage_out,
    };

    const input_capacity = std.math.cast(
        u32,
        public.data.io_entries.input_words.len,
    ) orelse return error.PublicCapacityOverflow;
    const output_capacity = std.math.cast(
        u32,
        public.data.io_entries.output_words.len,
    ) orelse return error.PublicCapacityOverflow;
    const claim_shape = try recursion.vm_public_claim.Shape.init(
        input_capacity,
        output_capacity,
    );
    var leaf_preprocessing = try recursion.segment_leaf_authority.Preprocessing.init(
        allocator,
        claim_shape,
    );
    defer leaf_preprocessing.deinit();
    var leaf_authority = try recursion.segment_leaf_authority.Prepared.init(
        allocator,
        &leaf_preprocessing,
        &public.data,
    );
    defer leaf_authority.deinit();
    var transcript_plans = try recursion.segment_profile.initPlans(
        allocator,
        claim_shape.max_input_words,
        claim_shape.max_output_words,
    );
    defer transcript_plans.recursion.deinit();
    defer transcript_plans.vm.deinit();
    const base_setup_ns = base_setup_timer.read();

    stage_out.* = .base_prove;
    var recorder = stwo.prover.stage_profile.Recorder.initWithOptions(
        allocator,
        @tagName(@import("builtin").mode),
        "riscv_recursive_csp_leaf",
        .{ .capture_tasks = false },
    );
    defer recorder.deinit();
    var base_prove_timer = try std.time.Timer.start();
    var proving_channel = try Engine.Channel.init(
        &transcript_plans.vm,
        &leaf_authority,
    );
    stage_out.* = .profile_admission;
    var output = try prover.proveRiscVWithEngineAndPublicDataUsingChannelAndExecution(
        Engine,
        allocator,
        recursion.protocol.PCS_CONFIG,
        &run.execution_trace,
        &run.state_chain_tracker,
        &run.rw_memory,
        &recorder,
        public.data,
        &proving_channel,
        .{
            .cpu = .{
                .worker_count = request.worker_count,
                // This preserves the predecessor's uncapped allocation policy;
                // the exact worker count is nevertheless strict and shared by all
                // execution-aware native proving stages.
                .host_byte_budget = std.math.maxInt(usize),
                .contention_policy = .strict,
            },
            .statement_admission = .{
                .context = &statement_admission,
                .admit_fn = admitRecursiveProfile,
            },
        },
    );
    const selected_profile = statement_admission.selected orelse
        return error.StatementAdmissionNotInvoked;
    const selected_profile_sha256 = selected_profile.shapeSha256();
    var base_proof_owned = true;
    defer if (base_proof_owned)
        output.deinit(allocator)
    else
        output.deinitAfterProofMoved(allocator);
    const base_prove_total_ns = base_prove_timer.read();
    var stage_profile = try recorder.snapshot(allocator);
    defer stage_profile.deinit(allocator);
    const internal_witness_ns = try witnessNanoseconds(stage_profile.stages);
    if (internal_witness_ns > base_prove_total_ns)
        return error.InvalidStageTiming;
    const base_witness_ns = try std.math.add(
        u64,
        base_setup_ns,
        internal_witness_ns,
    );
    const base_prove_ns = base_prove_total_ns - internal_witness_ns;

    // Serialization belongs to the verifier-custody boundary. The allocating
    // decoder is unreachable until statement-derived preflight has accepted
    // the complete postcard shape.
    stage_out.* = .base_verify;
    var base_verify_timer = try std.time.Timer.start();
    var proof_bytes: std.ArrayList(u8) = .empty;
    defer proof_bytes.deinit(allocator);
    try postcard.serializeProof(
        recursion.engine.Hasher,
        proof_bytes.writer(allocator),
        output.proof,
    );
    var base_proof_sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(
        proof_bytes.items,
        &base_proof_sha256,
        .{},
    );
    output.proof.deinit(allocator);
    base_proof_owned = false;

    try recursion.proof_ingress.validateForVerifierConfig(
        proof_bytes.items,
        output.statement,
        recursion.protocol.PCS_CONFIG,
        recursion.proof_ingress.DEFAULT_MAX_PROOF_BYTES,
    );
    var proof_stream = std.io.fixedBufferStream(proof_bytes.items);
    var decoded = try postcard.deserializeProof(
        recursion.engine.Hasher,
        allocator,
        proof_stream.reader(),
    );
    var decoded_owned = true;
    defer if (decoded_owned) decoded.deinit(allocator);
    if (proof_stream.pos != proof_bytes.items.len)
        return error.TrailingProofBytes;
    var verifier_channel = try Engine.Channel.init(
        &transcript_plans.vm,
        &leaf_authority,
    );
    var recursive_capture: prover.RecursiveLeafCaptureForEngine(Engine) = undefined;
    var recursive_capture_owned = false;
    defer if (recursive_capture_owned) recursive_capture.deinit(allocator);
    decoded_owned = false;
    try prover.verifyRiscVWithEngineUsingChannelAndRecursiveLeafCapture(
        Engine,
        allocator,
        recursion.protocol.PCS_CONFIG,
        output.statement,
        decoded,
        output.interaction_claim,
        &verifier_channel,
        &recursive_capture,
    );
    recursive_capture_owned = true;
    const base_verify_ns = base_verify_timer.read();
    if (!std.meta.eql(
        proving_channel.digestWords(),
        verifier_channel.digestWords(),
    ) or proving_channel.n_draws != verifier_channel.n_draws) {
        return error.LeafTranscriptMismatch;
    }

    stage_out.* = .recursive_prepare;
    var recursive_prepare_timer = try std.time.Timer.start();
    try recursive_capture.vm_air.validate();
    const proof_capture = &recursive_capture.proof;
    var prepared_vm_air = try recursion.vm_air_composition_circuit.Prepared.init(
        allocator,
        &recursive_capture.vm_air,
        proof_capture,
    );
    defer prepared_vm_air.deinit();

    const leaf_shape = try recursion.leaf_profile.deriveShape(
        LEAF_DIMENSIONS,
        &output.statement,
        proof_capture,
    );
    const leaf_wire = try allocator.create(LeafWire);
    defer allocator.destroy(leaf_wire);
    try recursion.fixed_wire_adapter.populate(
        LEAF_DIMENSIONS,
        leaf_wire,
        leaf_shape,
        &output.statement,
        output.interaction_claim,
        proof_capture,
    );
    try leaf_wire.validateAgainstShape(leaf_shape);

    var transcript_preprocessing =
        try recursion.segment_transcript_witness.Preprocessing.init(
            allocator,
            &transcript_plans.vm,
            &transcript_plans.recursion,
        );
    defer transcript_preprocessing.deinit();
    var public_claim_words: [recursion.poseidon2_channel.RATE]M31 = undefined;
    for (&public_claim_words, leaf_authority.claim.digest) |*destination, raw|
        destination.* = M31.fromCanonical(raw);
    var transcript_rows = try recursion.segment_transcript_witness.Prepared(
        LEAF_DIMENSIONS,
    ).init(
        allocator,
        &transcript_preprocessing,
        &transcript_plans.vm,
        &transcript_plans.recursion,
        &leaf_authority.statement.words,
        .{ .vm = public_claim_words },
        leaf_wire,
    );
    defer transcript_rows.deinit();
    try transcript_rows.execution.replayNative(&transcript_plans.vm);
    if (!std.meta.eql(
        proving_channel.digestWords(),
        m31DigestToU32(transcript_rows.execution.final_digest),
    ) or proving_channel.n_draws != transcript_rows.execution.final_draw_count) {
        return error.RecursiveTranscriptMismatch;
    }

    const native_relations = frontend.air.relation_challenges.Relations.fromDrawSequence(
        &recursive_capture.vm_air.relation_draws,
    );
    const canonical_claim = try output.interaction_claim.canonical(&output.statement);
    var statement_authority = try recursion.segment_statement_outer_source.Authority.init(
        allocator,
        &leaf_preprocessing,
    );
    defer statement_authority.deinit();
    var statement_workspace = try recursion.segment_statement_outer_source.Workspace.init(
        allocator,
    );
    defer statement_workspace.deinit();
    var statement_rows = try recursion.segment_statement_outer_source.Prepared.init(
        allocator,
        &statement_authority,
        &statement_workspace,
        &leaf_preprocessing,
        &public.data,
        &leaf_authority,
    );
    defer statement_rows.deinit();
    var public_source = try recursion.segment_public_outer_source.Source.init(
        allocator,
        &transcript_plans.vm,
        &transcript_plans.recursion,
        &leaf_preprocessing,
        @intCast(canonical_claim.claimed_sums.len),
    );
    defer public_source.deinit();
    var public_rows = try recursion.segment_public_outer_source.Prepared.init(
        allocator,
        &public_source,
        &leaf_preprocessing,
        &leaf_authority,
        &public.data,
        &native_relations,
        &canonical_claim.claimed_sums,
    );
    defer public_rows.deinit();
    var captured_fri = try recursion.captured_fri.Owned.init(
        allocator,
        recursion.captured_fri.ProfileConfig.fromPcs(recursion.protocol.PCS_CONFIG),
        proof_capture,
    );
    defer captured_fri.deinit();
    const recursive_prepare_ns = recursive_prepare_timer.read();

    stage_out.* = .recursive_prove_verify;
    var verified_outer: riscv_cpu.recursive_fri_outer.VerifiedOuterProofV1 = undefined;
    var verified_outer_owned = false;
    defer if (verified_outer_owned) verified_outer.deinit(allocator);
    const outer = try riscv_cpu.recursive_fri_outer.proveAndVerifyCapturedWithVmAirExecutionAndAdmission(
        allocator,
        &captured_fri,
        &prepared_vm_air,
        .{
            .vm = &transcript_plans.vm,
            .recursion = &transcript_plans.recursion,
        },
        .{
            .preprocessing = &transcript_preprocessing,
            .prepared = &transcript_rows,
            .statement = .{
                .authority = &statement_authority,
                .workspace = &statement_workspace,
                .prepared = &statement_rows,
            },
            .public = .{
                .source = &public_source,
                .prepared = &public_rows,
                .leaf_preprocessing = &leaf_preprocessing,
                .leaf = &leaf_authority,
                .data = &public.data,
            },
        },
        .{
            .worker_count = request.worker_count,
            .mutation_probes = .disabled,
        },
        &verified_outer,
    );
    verified_outer_owned = true;
    try verified_outer.validate();
    if (verified_outer.receipt.scope != .verifier_subsystem)
        return error.UnexpectedOuterProofScope;
    if (outer.roster_count != 36 or outer.active_verifier_rows != 34 or
        outer.active_provider_rows != 2)
    {
        return error.IncompleteOuterRoster;
    }
    if (outer.mutation_probe_mode != .disabled or outer.mutation_rejections != 0)
        return error.BenchmarkMutationProbeContamination;

    stage_out.* = .artifact_encoding;
    const payload_byte_count = try recursion.outer_parent_child_admission.runtimeCanonicalByteCount(
        verified_outer.seal,
        &verified_outer.receipt,
        &verified_outer.capture,
    );
    const payload = try allocator.alloc(u8, payload_byte_count);
    errdefer allocator.free(payload);
    const admission = try recursion.outer_parent_child_admission.admitRuntime(
        payload,
        verified_outer.seal,
        &verified_outer.receipt,
        &verified_outer.capture,
    );
    try admission.validate();
    if (admission.canonical_byte_count != payload.len)
        return error.CanonicalPayloadLengthMismatch;

    const recursive_witness_ns = std.math.sub(
        u64,
        outer.prove_ns,
        outer.stark_prove_ns,
    ) catch return error.InvalidStageTiming;
    stage_out.* = .resource_capture;
    const resources_after = try frontend.process_usage.sample();
    const resource_delta = try frontend.process_usage.difference(
        resources_before,
        resources_after,
    );
    var payload_sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &payload_sha256, .{});

    return .{
        .payload = payload,
        .phases = .{
            .guest_execution = phase(guest_execution_ns, 0),
            .base_witness = phase(base_witness_ns, 0),
            .base_prove = phase(base_prove_ns, 0),
            .base_verify = phase(base_verify_ns, 0),
            .recursive_prepare = phase(recursive_prepare_ns, 0),
            .recursive_witness = phase(
                recursive_witness_ns,
                outer.poseidon2_call_count,
            ),
            .recursive_prove = phase(outer.stark_prove_ns, 0),
            .recursive_verify = phase(outer.verify_ns, 0),
        },
        .identities = .{
            .request_sha256 = request_sha256,
            .public_values_sha256 = public_values_sha256,
            .leaf_statement_words_sha256 = hashM31Words(
                &leaf_authority.statement.words,
            ),
            .base_proof_sha256 = base_proof_sha256,
            .payload_sha256 = payload_sha256,
            .outer_statement_id = verified_outer.receipt.statement_id,
            .outer_verification_key_id = verified_outer.receipt.verification_key_id,
            .profile_id = admission.candidate.profile_id,
            .capture_id = admission.candidate.capture_id,
            .receipt_id = admission.candidate.receipt_id,
            .transcript_id = admission.candidate.transcript_id,
            .claimed_sums_id = admission.candidate.claimed_sums_id,
            .proof_id = admission.candidate.proof_id,
            .recursive_profile_shape_sha256 = selected_profile_sha256,
            .profile_registry_sha256 = registry_sha256,
        },
        .resources = .{
            .source = resource_delta.source,
            .peak_rss_bytes = try peakRssBytes(),
            .lifetime_peak_physical_footprint_bytes = resource_delta.lifetime_peak_physical_footprint_bytes,
            .process_cpu_ns = resource_delta.process_cpu_ns,
            .energy_nj = resource_delta.energy_nj,
            .instructions = resource_delta.instructions,
            .cycles = resource_delta.cycles,
            .unavailable_reason = resource_delta.unavailable_reason,
        },
        .outer = outer,
        .verified_end_to_end_ns = end_to_end_timer.read(),
        .execution_cycles = @intCast(run.step_count),
        .worker_count = request.worker_count,
        .proof_scope = verified_outer.receipt.scope,
        .production_ready = verified_outer.productionReady(),
    };
}

const ProfileStatementAdmissionContext = struct {
    request: *const contract.Request,
    stage_out: *Stage,
    /// Published only after shape, request identities, and implementation
    /// readiness all validate.
    selected: ?profile_registry.Entry = null,
};

fn admitRecursiveProfile(
    raw_context: *anyopaque,
    statement: *const prover.RiscVStatement,
) anyerror!void {
    const context: *ProfileStatementAdmissionContext = @ptrCast(
        @alignCast(raw_context),
    );
    var maximum_log: u32 = 0;
    for (statement.component_descs[0..statement.n_components]) |descriptor|
        maximum_log = @max(maximum_log, descriptor.log_size);
    for (statement.infra_descs[0..statement.n_infra]) |descriptor|
        maximum_log = @max(maximum_log, descriptor.log_size);
    const selected = try profile_registry.select(.{
        .component_count = statement.n_components,
        .infrastructure_count = statement.n_infra,
        .preprocessed_column_count = std.math.cast(
            u32,
            statement.nPreprocessedColumns(),
        ) orelse return error.StatementGeometryOverflow,
        .main_column_count = std.math.cast(
            u32,
            statement.nMainColumns(),
        ) orelse return error.StatementGeometryOverflow,
        .interaction_column_count = std.math.cast(
            u32,
            statement.nInteractionColumns(),
        ) orelse return error.StatementGeometryOverflow,
        .maximum_column_log_degree = maximum_log,
    });
    if (!std.mem.eql(
        u8,
        selected.name(),
        context.request.expected_recursive_profile_id,
    )) return error.RecursiveProfileIdMismatch;
    try requireDigestEqual(
        selected.shapeSha256(),
        context.request.expected_recursive_profile_shape_sha256,
        error.RecursiveProfileShapeDigestMismatch,
    );
    if (!selected.outerExecutable())
        return error.RecursiveProfileOuterUnavailable;
    context.selected = selected;
    context.stage_out.* = .base_prove;
}

fn phase(duration_ns: u64, permutations: u64) Phase {
    return .{
        .duration_ns = duration_ns,
        .poseidon2_permutations = permutations,
    };
}

fn requireSha256(bytes: []const u8, expected_hex: []const u8) !void {
    var actual: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &actual, .{});
    try requireDigestEqual(actual, expected_hex, error.SourceDigestMismatch);
}

fn requireDigestEqual(
    actual: [32]u8,
    expected_hex: []const u8,
    mismatch: anyerror,
) !void {
    var expected: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&expected, expected_hex) catch
        return error.InvalidExpectedDigest;
    if (!std.mem.eql(u8, &actual, &expected)) return mismatch;
}

fn hashWithTrailingNewline(bytes: []const u8) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(bytes);
    hasher.update("\n");
    var result: [32]u8 = undefined;
    hasher.final(&result);
    return result;
}

fn hashM31Words(words: []const M31) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var encoded: [4]u8 = undefined;
    for (words) |word| {
        std.mem.writeInt(u32, &encoded, word.toU32(), .little);
        hasher.update(&encoded);
    }
    var result: [32]u8 = undefined;
    hasher.final(&result);
    return result;
}

fn witnessNanoseconds(nodes: []const stwo.prover.stage_profile.StageNode) !u64 {
    const seconds = witnessSeconds(nodes);
    if (!std.math.isFinite(seconds) or seconds < 0)
        return error.InvalidStageTiming;
    const nanoseconds = @round(seconds * std.time.ns_per_s);
    if (nanoseconds > @as(f64, @floatFromInt(std.math.maxInt(u64))))
        return error.InvalidStageTiming;
    return @intFromFloat(nanoseconds);
}

fn witnessSeconds(nodes: []const stwo.prover.stage_profile.StageNode) f64 {
    var seconds: f64 = 0;
    for (nodes) |node| {
        if (std.mem.eql(u8, node.id, "riscv_opcode_trace_generation") or
            std.mem.eql(u8, node.id, "riscv_infrastructure_trace_generation"))
        {
            seconds += node.seconds;
        }
        if (node.children) |children|
            seconds += witnessSeconds(children);
    }
    return seconds;
}

fn validatePublicOutput(
    allocator: std.mem.Allocator,
    run: *const frontend.runner.RunResult,
    expected_hex: []const u8,
) !void {
    if (run.output_words.len == 0 or expected_hex.len % 2 != 0)
        return error.InvalidPublicOutput;
    if (run.output_words[0].addr != run.output_len_addr or
        run.output_words[0].value != run.output_len)
    {
        return error.InvalidPublicOutput;
    }
    const output_len: usize = @intCast(run.output_len);
    const expected_word_count = std.math.divCeil(
        usize,
        output_len,
        @sizeOf(u32),
    ) catch return error.InvalidPublicOutput;
    if (run.output_words.len != expected_word_count + 1 or
        expected_hex.len / 2 != output_len)
    {
        return error.InvalidPublicOutput;
    }
    const output = try allocator.alloc(u8, output_len);
    defer allocator.free(output);
    for (run.output_words[1..], 0..) |word, index| {
        if (word.addr != run.output_data_addr + index * @sizeOf(u32))
            return error.InvalidPublicOutput;
        var encoded: [4]u8 = undefined;
        std.mem.writeInt(u32, &encoded, word.value, .little);
        const start = index * encoded.len;
        const count = @min(encoded.len, output.len - start);
        @memcpy(output[start..][0..count], encoded[0..count]);
        for (encoded[count..]) |padding| {
            if (padding != 0) return error.InvalidPublicOutput;
        }
    }
    const expected = try allocator.alloc(u8, expected_hex.len / 2);
    defer allocator.free(expected);
    _ = std.fmt.hexToBytes(expected, expected_hex) catch
        return error.InvalidExpectedDigest;
    if (!std.mem.eql(u8, output, expected))
        return error.PublicOutputMismatch;
}

/// `getrusage(RUSAGE_SELF).ru_maxrss` is a true lifetime resident-set peak.
/// Linux reports KiB and Darwin reports bytes. Unsupported targets retain a
/// null value rather than relabelling the physical-footprint counter as RSS.
fn peakRssBytes() !?u64 {
    return switch (builtin.os.tag) {
        .linux => linux: {
            const usage = std.posix.getrusage(std.posix.rusage.SELF);
            if (usage.maxrss < 0) return error.InvalidPeakRss;
            const kib: u64 = @intCast(usage.maxrss);
            break :linux std.math.mul(u64, kib, 1024) catch
                return error.PeakRssOverflow;
        },
        .macos, .ios => darwin: {
            const usage = std.posix.getrusage(std.posix.rusage.SELF);
            if (usage.maxrss < 0) return error.InvalidPeakRss;
            break :darwin @as(u64, @intCast(usage.maxrss));
        },
        else => null,
    };
}

fn m31DigestToU32(
    digest: [recursion.poseidon2_channel.RATE]M31,
) recursion.poseidon2_channel.Digest {
    var result: recursion.poseidon2_channel.Digest = undefined;
    for (&result, digest) |*destination, source|
        destination.* = source.toU32();
    return result;
}
