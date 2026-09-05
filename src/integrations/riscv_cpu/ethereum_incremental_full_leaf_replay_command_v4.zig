//! One-shot VM-free producer for a retained real Ethereum leaf.
//!
//! This command exists as the production adapter precursor for stage 101. It
//! cold-opens all retained capture authorities, replays without VM execution,
//! proves with the Poseidon/q193 engine, destroys producer ownership, and
//! independently cold-verifies STWIEF04 before create-only publication.

const std = @import("std");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
const prover_api = @import("stwo_prover_api");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const compact_manifest = @import("ethereum_block_leaf_compact_manifest.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const capture_publication =
    @import("ethereum_incremental_capture_publication_v4.zig");
const postprocess_authority =
    @import("ethereum_incremental_capture_postprocess_authority_v4.zig");
const raw_recovery =
    @import("ethereum_incremental_capture_raw_recovery_v4.zig");
const retained_authority =
    @import("ethereum_incremental_capture_retained_authority_v4.zig");
const wire_publication =
    @import("ethereum_incremental_public_wire_publication_v4.zig");
const producer =
    @import("ethereum_incremental_full_leaf_replay_producer_v4.zig");
const prepared_producer =
    @import("ethereum_incremental_full_leaf_prepared_replay_producer_v4.zig");
const throughput_execution =
    @import("ethereum_incremental_full_leaf_throughput_execution_v1.zig");
const stage102_input =
    @import("recursive_common_ethereum_incremental_leaf_input_v4.zig");
const node_artifact = @import("recursive_node_artifact_v1.zig");

pub const CpuEngine = frontend.recursion.engine.ProverEngineForBackend(CpuBackend);
pub const PreparedProofTransactionV4 =
    prepared_producer.PreparedProofTransactionV4;
pub const PreparedProviderCallViewV1 = prepared_producer.ProviderCallViewV1;
pub const PreparedVisitorEvidenceV1 =
    prepared_producer.PreparedVisitorEvidenceV1;

pub const command_name = "ethereum-incremental-full-leaf-replay-produce-v4";
pub const PRODUCTION_ACTIVE = false;
pub const TimingReceiptV1 = producer.TimingReceiptV1;

/// Borrowed evidence presented immediately before create-only publication.
/// A backend-specific diagnostic may reject release, but it cannot replace
/// the independent CPU cold verifier or serialize a process-local capability.
pub const ReleaseEvidenceV1 = struct {
    artifact_bytes: []const u8,
    timing: TimingReceiptV1,
    producer_elapsed_ns: u64,
    cold_verify_elapsed_ns: u64,
    fri_query_count: u32,
    execution_policy: ?throughput_execution.PolicyV1 = null,
    producer_resources: ?throughput_execution.ResourceReceiptV1 = null,
    cold_verifier_resources: ?throughput_execution.ResourceReceiptV1 = null,
    preparation: ?prepared_producer.PreparationCounterSnapshotV1 = null,
};

pub const ReleaseGuardV1 = struct {
    context: *anyopaque,
    validate_fn: *const fn (*anyopaque, ReleaseEvidenceV1) anyerror!void,

    pub fn validate(self: ReleaseGuardV1, evidence: ReleaseEvidenceV1) !void {
        return self.validate_fn(self.context, evidence);
    }
};

pub const PreparedVisitorCustodyV1 = struct {
    segment_index: u32,
    public_wire: wire_publication.CommittedSegmentV4,
    elf: capture_publication.ArtifactIdentityV4,
    program_source_identity_sha256: [32]u8,

    pub fn validateAgainst(
        self: PreparedVisitorCustodyV1,
        calls: prepared_producer.ProviderCallViewV1,
    ) !void {
        try self.public_wire.validate();
        try self.elf.validate(false);
        if (self.public_wire.segment.coordinate.segment_index !=
            self.segment_index or !std.meta.eql(
            self.public_wire.segment.wire_id,
            calls.segment_public_wire_id,
        ) or !std.mem.eql(
            u8,
            &self.program_source_identity_sha256,
            &calls.program_source_identity_sha256,
        )) return error.InvalidIncrementalPreparedVisitorCustodyV4;
    }
};

pub const RetainedPreparedVisitorV1 = struct {
    context: *anyopaque,
    visit_fn: *const fn (
        *anyopaque,
        PreparedVisitorCustodyV1,
        *const PreparedProofTransactionV4,
        PreparedProviderCallViewV1,
        PreparedVisitorEvidenceV1,
    ) anyerror!void,

    pub fn visit(
        self: RetainedPreparedVisitorV1,
        custody: PreparedVisitorCustodyV1,
        transaction: *const PreparedProofTransactionV4,
        calls: PreparedProviderCallViewV1,
        evidence: PreparedVisitorEvidenceV1,
    ) !void {
        try calls.validateAgainst(transaction);
        try custody.validateAgainst(calls);
        try evidence.validate();
        return self.visit_fn(
            self.context,
            custody,
            transaction,
            calls,
            evidence,
        );
    }
};

const PreparedVisitorBridgeV1 = struct {
    retained: RetainedPreparedVisitorV1,
    custody: PreparedVisitorCustodyV1,

    fn visitOpaque(
        context: *anyopaque,
        transaction: *const PreparedProofTransactionV4,
        calls: PreparedProviderCallViewV1,
        evidence: PreparedVisitorEvidenceV1,
    ) anyerror!void {
        const self: *PreparedVisitorBridgeV1 = @ptrCast(@alignCast(context));
        return self.retained.visit(
            self.custody,
            transaction,
            calls,
            evidence,
        );
    }
};

pub const Options = struct {
    retained_materialization_result: []const u8,
    publication_root: []const u8,
    segment_index: u32,
    output: []const u8,

    pub fn parse(arguments: []const []const u8) !Options {
        var retained: ?[]const u8 = null;
        var root: ?[]const u8 = null;
        var segment_index: ?u32 = null;
        var output: ?[]const u8 = null;
        var at: usize = 0;
        while (at < arguments.len) : (at += 2) {
            if (at + 1 == arguments.len) return error.InvalidArguments;
            const key = arguments[at];
            const value = arguments[at + 1];
            if (std.mem.eql(u8, key, "--retained-materialization-result")) {
                if (retained != null) return error.DuplicateArgument;
                retained = value;
            } else if (std.mem.eql(u8, key, "--publication-root")) {
                if (root != null) return error.DuplicateArgument;
                root = value;
            } else if (std.mem.eql(u8, key, "--segment-index")) {
                if (segment_index != null) return error.DuplicateArgument;
                segment_index = std.fmt.parseInt(u32, value, 10) catch
                    return error.InvalidArguments;
            } else if (std.mem.eql(u8, key, "--output")) {
                if (output != null) return error.DuplicateArgument;
                output = value;
            } else return error.InvalidArguments;
        }
        return .{
            .retained_materialization_result = retained orelse
                return error.MissingArgument,
            .publication_root = root orelse return error.MissingArgument,
            .segment_index = segment_index orelse return error.MissingArgument,
            .output = output orelse return error.MissingArgument,
        };
    }
};

pub fn run(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !void {
    return runWithEngines(
        CpuEngine,
        CpuEngine,
        allocator,
        arguments,
        null,
    );
}

/// Isolated backend-autoresearch entry point. Producer and verifier engines
/// are separate compile-time authorities; the production CPU command above
/// remains the exact same CPU/CPU transaction with no release guard.
pub fn runWithEngines(
    comptime ProducerEngine: type,
    comptime VerifierEngine: type,
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
    release_guard: ?ReleaseGuardV1,
) !void {
    return runWithEnginesInternal(
        ProducerEngine,
        VerifierEngine,
        .legacy,
        allocator,
        arguments,
        release_guard,
        .{},
        null,
        null,
    );
}

/// Autoresearch-only one-pass sibling. Scheduling is a strict, validated
/// process policy and never enters the statement, transcript, or artifact.
pub fn runPreparedWithEnginesAndExecution(
    comptime ProducerEngine: type,
    comptime VerifierEngine: type,
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
    release_guard: ?ReleaseGuardV1,
    policy: throughput_execution.PolicyV1,
) !void {
    try policy.validate();
    return runWithEnginesInternal(
        ProducerEngine,
        VerifierEngine,
        .prepared,
        allocator,
        arguments,
        release_guard,
        try policy.executionOptions(),
        policy,
        null,
    );
}

/// Candidate-only custody route. It performs the same sealed-root/STWIPR04
/// cold admission as the leaf producer, then lends the one-pass prepared
/// transaction to a nonserializable visitor without minting a leaf artifact.
pub fn runPreparedVisitor(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
    visitor: RetainedPreparedVisitorV1,
) !void {
    return runWithEnginesInternal(
        CpuEngine,
        CpuEngine,
        .provider_visit,
        allocator,
        arguments,
        null,
        .{},
        null,
        visitor,
    );
}

const ProducerPathV1 = enum { legacy, prepared, provider_visit };

fn runWithEnginesInternal(
    comptime ProducerEngine: type,
    comptime VerifierEngine: type,
    comptime producer_path: ProducerPathV1,
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
    release_guard: ?ReleaseGuardV1,
    proof_execution: frontend.testing.incremental_ethereum_orchestration_v4_internal
        .ExecutionOptions,
    execution_policy: ?throughput_execution.PolicyV1,
    prepared_visitor: ?RetainedPreparedVisitorV1,
) !void {
    const parsed = try Options.parse(arguments);
    const retained_path = try artifact_io.resolveAbsolute(
        allocator,
        parsed.retained_materialization_result,
    );
    defer allocator.free(retained_path);
    const root_path = try artifact_io.resolveAbsolute(
        allocator,
        parsed.publication_root,
    );
    defer allocator.free(root_path);
    const output_path = try artifact_io.resolveAbsolute(
        allocator,
        parsed.output,
    );
    defer allocator.free(output_path);

    var retained = try retained_authority.RetainedAuthorityV4.open(
        allocator,
        retained_path,
    );
    defer retained.deinit();
    const campaign_execution = try retained.executionAuthority();
    if (parsed.segment_index >= campaign_execution.segment_count)
        return error.SegmentIndexMismatch;
    const sealed = try coldOpenSealedSelection(
        allocator,
        &retained,
        root_path,
        campaign_execution,
        parsed.segment_index,
    );

    var program = try producer.ProgramV4.init(allocator, retained.elf_bytes);
    defer program.deinit();
    const compact_path = try capture_publication.compactTapePathAlloc(
        allocator,
        root_path,
        parsed.segment_index,
    );
    defer allocator.free(compact_path);
    const compact_bytes = try artifact_io.readFileBounded(
        allocator,
        compact_path,
        frontend.runner.minimal_trace.ethereum_wire.MAX_ENCODED_BYTES,
    );
    defer allocator.free(compact_bytes);
    const wire_path = try wire_publication.wirePathAlloc(
        allocator,
        root_path,
        parsed.segment_index,
    );
    defer allocator.free(wire_path);
    const wire_bytes = try artifact_io.readFileBounded(
        allocator,
        wire_path,
        wire_publication.max_wire_bytes,
    );
    defer allocator.free(wire_bytes);
    var mint_input = try postprocess_authority.OwnedMintInputV4
        .openCanonicalBytes(
        allocator,
        campaign_execution,
        retained.elf_bytes,
        retained.input_bytes,
        retained.output_bytes,
        &retained.sources[parsed.segment_index].value,
        compact_bytes,
        wire_bytes,
    );
    defer mint_input.deinit();
    try mint_input.validate(campaign_execution);
    if (!std.meta.eql(program.layout, mint_input.layout) or
        !std.mem.eql(
            u8,
            &program.program.identity,
            &mint_input.compact.leaf.source.program,
        )) return error.IncrementalFullLeafProgramAuthorityMismatchV4;

    var proof_public = mint_input.role_public.value;
    const retained_completion = proof_public.completion orelse
        return error.MissingIncrementalFullLeafCompletionV4;
    proof_public.completion = try program.completionForProof(
        .{
            .is_first = parsed.segment_index == 0,
            .is_last = parsed.segment_index + 1 == campaign_execution.segment_count,
        },
        retained_completion,
    );
    try proof_public.validate();
    var proof_public_authority = mint_input.publicAuthority();
    proof_public_authority.public_data = &proof_public;
    try proof_public_authority.validate();

    var opened = try capture_publication.coldOpenSegment(
        allocator,
        root_path,
        parsed.segment_index,
        false,
    );
    defer opened.deinit();
    if (!std.meta.eql(opened.reference, sealed.transition) or
        !std.meta.eql(
            opened.reference.segment.compact_tape,
            mint_input.compact_identity,
        ) or !std.meta.eql(
        opened.reference.segment.source,
        mint_input.source_identity,
    ) or !std.mem.eql(
        u8,
        &opened.reference.segment.journal_record_sha256,
        &mint_input.journal_record_sha256,
    ) or !std.meta.eql(
        opened.reference.segment.segment_public_wire_id,
        mint_input.wire.data.wireId(),
    )) return error.IncrementalFullLeafCaptureAuthorityMismatchV4;

    var opened_wire = try wire_publication.coldOpenSegment(
        allocator,
        root_path,
        parsed.segment_index,
        sealed.transition,
    );
    defer opened_wire.deinit();
    if (!std.meta.eql(opened_wire.reference, sealed.public_wire) or
        !std.meta.eql(
            opened_wire.reference.segment.wire_artifact,
            mint_input.wire_identity,
        ) or !std.meta.eql(
        opened_wire.wire.data.wireId(),
        mint_input.wire.data.wireId(),
    )) return error.IncrementalFullLeafCaptureAuthorityMismatchV4;

    const replay_authority = producer.ReplayAuthorityV4{
        .source = mint_input.compact.leaf.source,
        .global_first_cycle = std.math.add(
            u64,
            retained.sources[parsed.segment_index].value.metadata
                .global_cycle_start,
            1,
        ) catch return error.IncrementalFullLeafCycleAuthorityOverflowV4,
        .entry_cpu_sha256 = minimalCpuIdentity(
            mint_input.compact.leaf.entry_cpu,
        ),
        .exit_cpu_sha256 = minimalCpuIdentity(
            mint_input.compact.leaf.exit_cpu,
        ),
        .completion = mint_input.compact.leaf.completion,
    };
    const profile_stages = std.process.hasEnvVarConstant(
        "STWO_ZIG_STAGE101_STAGE_PROFILE",
    );
    var stage_recorder: prover_api.stage_profile.Recorder = undefined;
    if (profile_stages) stage_recorder =
        prover_api.stage_profile.Recorder.initWithOptions(
            allocator,
            @tagName(@import("builtin").mode),
            "ethereum_incremental_stage101_v4",
            .{ .capture_tasks = false, .capture_work = false },
        );
    defer if (profile_stages) stage_recorder.deinit();

    var producer_resource_measurement: ?throughput_execution.MeasurementV1 =
        if (comptime producer_path == .prepared)
            try throughput_execution.MeasurementV1.begin()
        else
            null;
    var producer_timer = try std.time.Timer.start();
    var timing: producer.TimingReceiptV1 = undefined;
    var preparation: prepared_producer.PreparationCounterSnapshotV1 = undefined;
    var producer_validation = frontend.air.public_data_v2.PublicDataV2
        .ValidationCountersV2{};
    const cold_input = producer.ColdInputV4{
        .compact = &mint_input.compact,
        .public_wire = &mint_input.wire.data,
        .role_aware_public = &proof_public,
        .public_authority = proof_public_authority,
        .boundary = &opened.artifact,
        .program = &program,
        .replay_authority = replay_authority,
        .validation_counters = &producer_validation,
    };
    if (comptime producer_path == .provider_visit) {
        const retained_visitor = prepared_visitor orelse
            return error.MissingIncrementalPreparedVisitorV4;
        var bridge = PreparedVisitorBridgeV1{
            .retained = retained_visitor,
            .custody = .{
                .segment_index = parsed.segment_index,
                .public_wire = opened_wire.reference,
                .elf = retained.elf_identity,
                .program_source_identity_sha256 = program.program.identity,
            },
        };
        try prepared_producer.visitPreparedTransaction(
            allocator,
            cold_input,
            if (profile_stages) &stage_recorder else null,
            .{
                .context = &bridge,
                .visit_fn = PreparedVisitorBridgeV1.visitOpaque,
            },
        );
        const validation = producer_validation.snapshot();
        if (validation.retained_root_authentications != 1 or
            validation.legacy_full_authentications != 0)
        {
            return error.IncrementalFullLeafValidationBudgetMismatchV4;
        }
        return;
    }
    const encoded = if (comptime producer_path == .prepared)
        try prepared_producer.produceAllocWithRecorderAndTiming(
            ProducerEngine,
            allocator,
            cold_input,
            .{},
            proof_execution,
            if (profile_stages) &stage_recorder else null,
            &timing,
            &preparation,
        )
    else
        try producer.produceAllocWithRecorderAndTiming(
            ProducerEngine,
            allocator,
            cold_input,
            .{},
            proof_execution,
            if (profile_stages) &stage_recorder else null,
            &timing,
        );
    const producer_elapsed_ns = producer_timer.read();
    defer allocator.free(encoded);
    if (profile_stages) {
        var profile = try stage_recorder.snapshot(allocator);
        defer profile.deinit(allocator);
        printStageProfile(profile.stages, 0);
    }
    const producer_validation_snapshot = producer_validation.snapshot();
    if (producer_validation_snapshot.retained_root_authentications != 1 or
        producer_validation_snapshot.legacy_full_authentications != 0)
    {
        return error.IncrementalFullLeafValidationBudgetMismatchV4;
    }
    const producer_resources = if (producer_resource_measurement) |*measurement|
        try measurement.finish(1)
    else
        null;

    const coordinate = try node_artifact.TaskCoordinateV1.init(
        0,
        parsed.segment_index,
    );
    const retained_snapshots = mint_input.wire.data.retained_snapshots orelse
        return error.IncrementalFullLeafValidationAuthorityMissingV4;
    var cold_validation = frontend.air.public_data_v2.PublicDataV2
        .ValidationCountersV2{};
    var cold_resource_measurement: ?throughput_execution.MeasurementV1 =
        if (comptime producer_path == .prepared)
            try throughput_execution.MeasurementV1.begin()
        else
            null;
    var cold_timer = try std.time.Timer.start();
    var fresh = try stage102_input.FreshInputV4(VerifierEngine)
        .coldOpenWithRetainedSnapshots(
        allocator,
        encoded,
        coordinate,
        .{},
        retained_snapshots,
        &cold_validation,
    );
    defer fresh.deinit();
    try fresh.validateAgainstArtifact(encoded);
    const cold_elapsed_ns = cold_timer.read();
    const query_count = fresh.stage101.profile.protocol.pcs.query_count;
    if (query_count != frontend.recursion.protocol.FRI_QUERY_COUNT or
        query_count != 193)
    {
        return error.IncrementalFullLeafFriQueryCountMismatchV4;
    }
    const cold_validation_snapshot = cold_validation.snapshot();
    if (cold_validation_snapshot.retained_root_authentications != 1 or
        cold_validation_snapshot.legacy_full_authentications != 0)
    {
        return error.IncrementalFullLeafValidationBudgetMismatchV4;
    }
    std.debug.print(
        "INCREMENTAL_FULL_LEAF_VALIDATION_V2 producer_ns={} " ++
            "producer_auth_count={} producer_auth_ns={} producer_reuses={} " ++
            "cold_ns={} cold_auth_count={} cold_auth_ns={} cold_reuses={}\n",
        .{
            producer_elapsed_ns,
            producer_validation_snapshot.retained_root_authentications,
            producer_validation_snapshot.retained_root_authentication_ns,
            producer_validation_snapshot.cached_view_reuses,
            cold_elapsed_ns,
            cold_validation_snapshot.retained_root_authentications,
            cold_validation_snapshot.retained_root_authentication_ns,
            cold_validation_snapshot.cached_view_reuses,
        },
    );
    const cold_verifier_resources = if (cold_resource_measurement) |*measurement|
        try measurement.finish(1)
    else
        null;
    if (release_guard) |guard| try guard.validate(.{
        .artifact_bytes = encoded,
        .timing = timing,
        .producer_elapsed_ns = producer_elapsed_ns,
        .cold_verify_elapsed_ns = cold_elapsed_ns,
        .fri_query_count = @intCast(query_count),
        .execution_policy = execution_policy,
        .producer_resources = producer_resources,
        .cold_verifier_resources = cold_verifier_resources,
        .preparation = if (comptime producer_path == .prepared)
            preparation
        else
            null,
    });
    try artifact_io.publishCreateOnlyDurable(output_path, encoded);
}

fn minimalCpuIdentity(cpu: frontend.runner.Cpu) [32]u8 {
    return frontend.runner.minimal_trace.ethereumCpuIdentity(cpu);
}

fn printStageProfile(
    stages: []const prover_api.stage_profile.StageNode,
    depth: usize,
) void {
    for (stages) |stage| {
        std.debug.print(
            "STAGE101_PROFILE depth={} id={s} seconds={d:.9}\n",
            .{ depth, stage.id, stage.seconds },
        );
        if (stage.children) |children| printStageProfile(children, depth + 1);
    }
}

const SealedSelectionV4 = struct {
    transition: capture_publication.CommittedSegmentV4,
    public_wire: wire_publication.CommittedSegmentV4,
};

/// Opens only the two sealed aggregate manifests and the authority object they
/// bind, then returns the selected immutable leaf records by value. The later
/// segment cold opens must match these exact records. This avoids the
/// postprocessor's intentionally unsealed-only constructor without weakening
/// the sealed-root admission boundary or rescanning all 210 large artifacts.
fn coldOpenSealedSelection(
    allocator: std.mem.Allocator,
    retained: *const retained_authority.RetainedAuthorityV4,
    root: []const u8,
    execution: capture_publication.ExecutionAuthorityV4,
    segment_index: u32,
) !SealedSelectionV4 {
    const transition_path = try capture_publication.manifestPathAlloc(
        allocator,
        root,
    );
    defer allocator.free(transition_path);
    const transition_bytes = try artifact_io.readFileBounded(
        allocator,
        transition_path,
        capture_publication.manifest_max_byte_count,
    );
    defer allocator.free(transition_bytes);
    var transition = try capture_publication.decodeManifestAlloc(
        allocator,
        transition_bytes,
    );
    defer transition.deinit();
    transition.file = capture_publication.ArtifactIdentityV4.fromBytes(
        transition_bytes,
    );
    try transition.value.validateAgainst(
        execution,
        transition.value.final_bindings,
    );

    const public_path = try wire_publication.manifestPathAlloc(allocator, root);
    defer allocator.free(public_path);
    const public_bytes = try artifact_io.readFileBounded(
        allocator,
        public_path,
        wire_publication.manifest_max_byte_count,
    );
    defer allocator.free(public_bytes);
    var public_wire = try wire_publication.decodeManifestAlloc(
        allocator,
        public_bytes,
    );
    defer public_wire.deinit();
    try public_wire.value.validateAgainst(
        execution,
        transition.value.final_bindings,
        transition.file,
    );
    if (segment_index >= transition.value.segments.len or
        segment_index >= public_wire.value.segments.len)
    {
        return error.SegmentIndexMismatch;
    }
    const result = SealedSelectionV4{
        .transition = transition.value.segments[segment_index],
        .public_wire = public_wire.value.segments[segment_index],
    };
    try validateBoundFinalAuthority(
        allocator,
        retained,
        root,
        execution,
        transition.value.final_bindings,
        result,
        segment_index,
    );
    return result;
}

fn validateBoundFinalAuthority(
    allocator: std.mem.Allocator,
    retained: *const retained_authority.RetainedAuthorityV4,
    root: []const u8,
    execution: capture_publication.ExecutionAuthorityV4,
    bindings: capture_publication.FinalBindingsV4,
    selected: SealedSelectionV4,
    segment_index: u32,
) !void {
    const recovery_path = try std.fs.path.join(
        allocator,
        &.{ root, raw_recovery.manifest_basename },
    );
    defer allocator.free(recovery_path);
    if (artifact_io.readFileBounded(
        allocator,
        recovery_path,
        raw_recovery.manifest_max_byte_count,
    )) |bytes| {
        defer allocator.free(bytes);
        if (std.meta.eql(
            capture_publication.ArtifactIdentityV4.fromBytes(bytes),
            bindings.compact_manifest,
        )) {
            var recovery = try raw_recovery.decodeManifestAlloc(
                allocator,
                bytes,
            );
            defer recovery.deinit();
            const record = recovery.value.records[@intCast(segment_index)];
            if (!std.meta.eql(recovery.value.execution, execution) or
                !std.meta.eql(
                    recovery.value.materialization_result,
                    bindings.materialization_result,
                ) or !std.meta.eql(
                recovery.value.source_request,
                bindings.source_request,
            ) or !std.meta.eql(recovery.value.journal, bindings.journal) or
                !std.meta.eql(
                    recovery.value.execution_profile_receipt,
                    bindings.execution_profile_receipt,
                ) or !std.meta.eql(
                record.compact_tape,
                selected.transition.segment.compact_tape,
            ) or !std.meta.eql(
                record.public_wire,
                selected.public_wire.segment.wire_artifact,
            ) or !std.meta.eql(record.source, selected.transition.segment.source) or
                !std.mem.eql(
                    u8,
                    &record.journal_record_sha256,
                    &selected.transition.segment.journal_record_sha256,
                )) return error.IncrementalFullLeafSealedAuthorityMismatchV4;
            return;
        }
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }

    const compact_path = try std.fs.path.join(
        allocator,
        &.{ root, "compact-capture-manifest.json" },
    );
    defer allocator.free(compact_path);
    const compact_bytes = try artifact_io.readFileBounded(
        allocator,
        compact_path,
        compact_manifest.max_manifest_bytes,
    );
    defer allocator.free(compact_bytes);
    if (!std.meta.eql(
        capture_publication.ArtifactIdentityV4.fromBytes(compact_bytes),
        bindings.compact_manifest,
    )) return error.IncrementalFullLeafSealedAuthorityMismatchV4;
    var compact = try compact_manifest.parse(allocator, compact_bytes);
    defer compact.deinit();
    if (segment_index >= compact.value.artifacts.len or
        compact.value.segment_count != selected.transition.segment.segment_count or
        !contractIdentityMatches(
            compact.value.artifacts[segment_index].artifact,
            selected.transition.segment.compact_tape,
        ) or !contractIdentityMatches(
        compact.value.elf,
        retained.elf_identity,
    ) or !contractIdentityMatches(
        compact.value.input,
        retained.input_identity,
    ) or !contractIdentityMatches(
        compact.value.expected_output,
        retained.output_identity,
    ) or !contractIdentityMatches(
        compact.value.execution_journal,
        bindings.journal,
    ) or !contractIdentityMatches(
        compact.value.materialization_result,
        bindings.materialization_result,
    ) or !contractIdentityMatches(
        compact.value.source_request,
        bindings.source_request,
    ) or !contractIdentityMatches(
        compact.value.execution_profile_receipt,
        bindings.execution_profile_receipt,
    )) return error.IncrementalFullLeafSealedAuthorityMismatchV4;
}

fn contractIdentityMatches(
    actual: contract.Identity,
    expected: capture_publication.ArtifactIdentityV4,
) bool {
    const digest = contract.parseSha256(actual.sha256) catch return false;
    return actual.bytes == expected.byte_count and
        std.mem.eql(u8, &digest, &expected.sha256);
}

comptime {
    if (PRODUCTION_ACTIVE)
        @compileError("VM-free incremental full-leaf command activated");
}
