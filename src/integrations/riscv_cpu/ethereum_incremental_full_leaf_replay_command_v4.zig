//! One-shot VM-free producer for a retained real Ethereum leaf.
//!
//! This command exists as the production adapter precursor for stage 101. It
//! cold-opens all retained capture authorities, replays without VM execution,
//! proves with the Poseidon/q193 engine, destroys producer ownership, and
//! independently cold-verifies STWIEF04 before create-only publication.

const std = @import("std");
const profile_mod = @import("ethereum_incremental_full_leaf_profile_v4.zig");
const fixed_program_mod = @import("ethereum_fixed_program_admission_v1.zig");
const campaign_geometry = @import("ethereum_incremental_campaign_geometry_v1.zig");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
const prover_api = @import("stwo_prover_api");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const compact_manifest = @import("ethereum_block_leaf_compact_manifest.zig");
const selected_leaf = @import("ethereum_selected_leaf_admission_v1.zig");
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
    claim_admission: profile_mod.ClaimAdmissionV4 = .legacy_aggregate_v2,
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
    claim_admission: profile_mod.ClaimAdmissionV4 = .legacy_aggregate_v2,
    campaign_geometry: campaign_geometry.SelectionV1 = .legacy_210,
    retained_materialization_result: []const u8,
    publication_root: []const u8,
    segment_index: u32,
    output: []const u8,
    global_metadata_output: ?[]const u8 = null,
    selected_leaf_admission_root: ?[]const u8 = null,
    pcs_retained_byte_budget: ?usize = null,

    pub fn parse(arguments: []const []const u8) !Options {
        var retained: ?[]const u8 = null;
        var root: ?[]const u8 = null;
        var segment_index: ?u32 = null;
        var output: ?[]const u8 = null;
        var global_metadata_output: ?[]const u8 = null;
        var selected_leaf_admission_root: ?[]const u8 = null;
        var pcs_retained_byte_budget: ?usize = null;
        var geometry: ?campaign_geometry.SelectionV1 = null;
        var claim_admission: ?profile_mod.ClaimAdmissionV4 = null;
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
            } else if (std.mem.eql(u8, key, "--selected-leaf-admission-root")) {
                if (selected_leaf_admission_root != null) return error.DuplicateArgument;
                if (value.len == 0) return error.InvalidArguments;
                selected_leaf_admission_root = value;
            } else if (std.mem.eql(u8, key, "--pcs-retained-byte-budget")) {
                if (pcs_retained_byte_budget != null) return error.DuplicateArgument;
                pcs_retained_byte_budget = std.fmt.parseUnsigned(usize, value, 10) catch return error.InvalidArguments;
                if (pcs_retained_byte_budget.? == 0) return error.InvalidArguments;
            } else if (std.mem.eql(u8, key, "--global-metadata-output")) {
                if (global_metadata_output != null) return error.DuplicateArgument;
                global_metadata_output = value;
            } else if (std.mem.eql(u8, key, "--claim-admission")) {
                if (claim_admission != null) return error.DuplicateArgument;
                claim_admission = std.meta.stringToEnum(profile_mod.ClaimAdmissionV4, value) orelse
                    return error.UnsupportedIncrementalClaimAdmissionV4;
            } else if (std.mem.eql(u8, key, "--campaign-geometry")) {
                if (geometry != null) return error.DuplicateArgument;
                geometry = try campaign_geometry.SelectionV1.parse(value);
            } else return error.InvalidArguments;
        }
        return .{
            .campaign_geometry = geometry orelse .legacy_210,
            .claim_admission = claim_admission orelse .legacy_aggregate_v2,
            .global_metadata_output = global_metadata_output,
            .selected_leaf_admission_root = selected_leaf_admission_root,
            .pcs_retained_byte_budget = pcs_retained_byte_budget,
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

/// Explicit CPU sibling using the same prepared transaction as Metal A/B.
/// The host budget limits Stage101 composition admission, not process RSS.
pub const prepared_cpu_command_name = "ethereum-incremental-full-leaf-replay-prepared-cpu-v1";

pub const PreparedCpuOptionsV1 = struct {
    replay_arguments: [18][]const u8 = undefined,
    replay_argument_count: usize = 0,
    worker_count: usize,
    host_byte_budget: usize,
    host_byte_limit: usize,

    pub fn parse(arguments: []const []const u8) !PreparedCpuOptionsV1 {
        var workers: ?usize = null;
        var budget: ?usize = null;
        var limit: ?usize = null;
        var result = PreparedCpuOptionsV1{
            .worker_count = undefined,
            .host_byte_budget = undefined,
            .host_byte_limit = undefined,
        };
        var index: usize = 0;
        while (index < arguments.len) : (index += 2) {
            if (index + 1 == arguments.len) return error.InvalidArguments;
            const key = arguments[index];
            const value = arguments[index + 1];
            const destination: ?*?usize = if (std.mem.eql(u8, key, "--workers")) &workers else if (std.mem.eql(u8, key, "--host-byte-budget")) &budget else if (std.mem.eql(u8, key, "--host-byte-limit")) &limit else null;
            if (destination) |slot| {
                if (slot.* != null) return error.DuplicateArgument;
                slot.* = std.fmt.parseUnsigned(usize, value, 10) catch return error.InvalidArguments;
            } else {
                if (result.replay_argument_count + 2 > result.replay_arguments.len)
                    return error.InvalidArguments;
                result.replay_arguments[result.replay_argument_count] = key;
                result.replay_arguments[result.replay_argument_count + 1] = value;
                result.replay_argument_count += 2;
            }
        }
        result.worker_count = workers orelse return error.MissingArgument;
        result.host_byte_budget = budget orelse return error.MissingArgument;
        result.host_byte_limit = limit orelse return error.MissingArgument;
        _ = try Options.parse(result.replay_arguments[0..result.replay_argument_count]);
        return result;
    }
};

pub fn runPreparedCpu(allocator: std.mem.Allocator, arguments: []const []const u8) !void {
    const options = try PreparedCpuOptionsV1.parse(arguments);
    const policy = try throughput_execution.PolicyV1.init(
        options.worker_count,
        options.host_byte_budget,
        try throughput_execution.HostCapacityV1.detect(options.host_byte_limit),
    );
    return runPreparedWithEnginesAndExecution(
        CpuEngine,
        CpuEngine,
        allocator,
        options.replay_arguments[0..options.replay_argument_count],
        null,
        policy,
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
    var request_measurement = try throughput_execution.MeasurementV1.begin();
    const parsed = try Options.parse(arguments);
    if (comptime producer_path != .prepared) {
        if (parsed.pcs_retained_byte_budget != null) return error.PcsBudgetRequiresPreparedLeaf;
    }
    const pcs_retained_byte_budget = parsed.pcs_retained_byte_budget orelse
        if (execution_policy) |policy| policy.host.host_byte_limit else null;
    if (execution_policy) |policy| {
        if (pcs_retained_byte_budget.? > policy.host.host_byte_limit) return error.PcsBudgetExceedsHostAdmissionLimit;
        std.debug.print("INCREMENTAL_FULL_LEAF_RESOURCE_POLICY_V1 composition_allocation_budget_bytes={} pcs_retained_byte_budget_bytes={} host_admission_limit_bytes={} process_cap_enforced=false\n", .{ policy.host_byte_budget, pcs_retained_byte_budget.?, policy.host.host_byte_limit });
    }
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
    const selected_root = if (parsed.selected_leaf_admission_root) |path|
        try artifact_io.resolveAbsolute(allocator, path)
    else
        null;
    defer if (selected_root) |path| allocator.free(path);
    if (selected_root) |path| {
        if (std.mem.eql(u8, path, root_path)) return error.SelectedLeafRootMustBeSeparate;
    }
    const leaf_publication_root = selected_root orelse root_path;

    const output_path = try artifact_io.resolveAbsolute(
        allocator,
        parsed.output,
    );
    defer allocator.free(output_path);

    var preparation_timer = try std.time.Timer.start();
    var retained = try retained_authority.RetainedAuthorityV4.openWithCampaignGeometryV1(
        allocator,
        retained_path,
        parsed.campaign_geometry,
    );
    defer retained.deinit();
    const retained_open_ns = preparation_timer.lap();
    const campaign_execution = try retained.executionAuthority();
    if (parsed.segment_index >= campaign_execution.segment_count)
        return error.SegmentIndexMismatch;
    var selection: ?LeafSelectionV4 = if (selected_root == null)
        try coldOpenSealedSelection(allocator, &retained, root_path, campaign_execution, parsed.segment_index)
    else
        null;

    const selection_ns = preparation_timer.lap();
    var program = try producer.ProgramV4.init(allocator, retained.elf_bytes);
    defer program.deinit();
    const replay_program_ns = preparation_timer.lap();
    // This authority is independent of the compact tape and proof. Callers of
    // the prepared producer can retain the same owner across multiple leaves.
    const fixed_program = if (parsed.claim_admission == .fixed_program_narrow_v5)
        try fixed_program_mod.OwnedV1.createFromElf(allocator, retained.elf_bytes, retained.elf_identity.sha256)
    else
        null;
    defer if (fixed_program) |owner| owner.deinit();
    const fixed_program_admission_ns = preparation_timer.lap();
    if (comptime producer_path == .legacy) {
        if (fixed_program != null) return error.FixedProgramRequiresPreparedProducer;
    }

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

    if (selected_root) |path| selection = try selected_leaf.openOrMint(
        allocator,
        &retained,
        &mint_input,
        path,
        compact_bytes,
        wire_bytes,
    );
    const admitted_selection = selection orelse return error.MissingSelectedEthereumLeafAdmissionV1;
    var opened = try capture_publication.coldOpenSegment(
        allocator,
        leaf_publication_root,
        parsed.segment_index,
        false,
    );
    defer opened.deinit();
    if (!std.meta.eql(opened.reference, admitted_selection.transition) or
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
        leaf_publication_root,
        parsed.segment_index,
        admitted_selection.transition,
    );
    defer opened_wire.deinit();
    if (!std.meta.eql(opened_wire.reference, admitted_selection.public_wire) or
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

    const capture_admission_ns = preparation_timer.lap();
    std.debug.print("INCREMENTAL_FULL_LEAF_INPUT_PHASES_V1 retained_open_ns={} selection_ns={} replay_program_ns={} fixed_program_admission_ns={} capture_admission_ns={}\n", .{ retained_open_ns, selection_ns, replay_program_ns, fixed_program_admission_ns, capture_admission_ns });
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
        .pcs_retained_byte_budget = pcs_retained_byte_budget,
        .claim_admission = parsed.claim_admission,
        .compact = &mint_input.compact,
        .public_wire = &mint_input.wire.data,
        .role_aware_public = &proof_public,
        .public_authority = proof_public_authority,
        .boundary = &opened.artifact,
        .program = &program,
        .fixed_program = fixed_program,
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
    var verification_scope: @import("ethereum_native_verification_scope_v1.zig").ScopeV1 = undefined;
    if (execution_policy) |policy| try verification_scope.initInPlace(policy.worker_count);
    defer if (execution_policy != null) verification_scope.deinit();
    if (execution_policy) |policy| std.debug.print("INCREMENTAL_FULL_LEAF_VERIFY_POLICY_V1 workers={}\n", .{policy.worker_count});
    var cold_timer = try std.time.Timer.start();
    var fresh = if (fixed_program) |owner|
        try stage102_input.FreshInputV4(VerifierEngine).coldOpenWithRetainedSnapshotsAndProgramAdmission(
            allocator,
            encoded,
            coordinate,
            .{},
            retained_snapshots,
            &cold_validation,
            owner,
        )
    else
        try stage102_input.FreshInputV4(VerifierEngine)
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
    if (try fresh.stage101.profile.claimAdmission() != parsed.claim_admission)
        return error.IncrementalFullLeafClaimAdmissionMismatchV4;
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
    std.debug.print("INCREMENTAL_FULL_LEAF_CLAIM_ADMISSION schema={} profile={s}\n", .{
        @intFromEnum(parsed.claim_admission), @tagName(parsed.claim_admission),
    });
    std.debug.print(
        "INCREMENTAL_FULL_LEAF_PHASES_V1 transaction_ns={} admission_ns={} replay_ns={} witness_ns={} profile_ns={} prove_ns={} encode_ns={}\n",
        .{ timing.transaction_ns, timing.input_admission_ns, timing.compact_replay_ns, timing.witness_prepare_ns, timing.statement_profile_prepare_ns, timing.prove_ns, timing.encode_ns },
    );
    const cold_verifier_resources = if (cold_resource_measurement) |*measurement|
        try measurement.finish(1)
    else
        null;
    if (producer_resources) |resources| std.debug.print(
        "INCREMENTAL_FULL_LEAF_RESOURCES_V1 phase=producer wall_ns={} cpu_ns={?} lifetime_peak_footprint_bytes={?}\n",
        .{ resources.wall_ns, resources.process_cpu_ns, resources.lifetime_peak_physical_footprint_bytes },
    );
    if (cold_verifier_resources) |resources| std.debug.print(
        "INCREMENTAL_FULL_LEAF_RESOURCES_V1 phase=fresh_verifier wall_ns={} cpu_ns={?} lifetime_peak_footprint_bytes={?}\n",
        .{ resources.wall_ns, resources.process_cpu_ns, resources.lifetime_peak_physical_footprint_bytes },
    );
    if (release_guard) |guard| try guard.validate(.{
        .artifact_bytes = encoded,
        .claim_admission = parsed.claim_admission,
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
    if (parsed.global_metadata_output) |sidecar| {
        // Use the retained, admitted global source authority, never a local-clock
        // reconstruction from the proof. Publication follows fresh verification.
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(encoded, &digest, .{});
        const leaf = @import("ethereum_full_leaf_bundle_verifier_v1.zig").LeafV1{
            .metadata = retained.sources[parsed.segment_index].value.metadata,
            .proof_bytes = encoded.len,
            .proof_sha256 = digest,
        };
        const json = try std.json.Stringify.valueAlloc(allocator, leaf, .{ .whitespace = .indent_2 });
        defer allocator.free(json);
        const sidecar_path = try artifact_io.resolveAbsolute(allocator, sidecar);
        defer allocator.free(sidecar_path);
        try artifact_io.publishCreateOnlyDurable(sidecar_path, json);
    }
    const request_resources = try request_measurement.finish(1);
    std.debug.print(
        "INCREMENTAL_FULL_LEAF_RESOURCES_V1 phase=complete_request wall_ns={} cpu_ns={?} lifetime_peak_footprint_bytes={?}\n",
        .{ request_resources.wall_ns, request_resources.process_cpu_ns, request_resources.lifetime_peak_physical_footprint_bytes },
    );
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

const LeafSelectionV4 = selected_leaf.SelectionV1;

/// Opens only the two sealed aggregate manifests and the authority object they
/// bind, then returns the selected immutable leaf records by value. The later
/// segment cold opens must match these exact records. This avoids the
/// postprocessor's intentionally unsealed-only constructor without weakening
/// the sealed-root admission boundary or rescanning the campaign’s large artifacts.
fn coldOpenSealedSelection(
    allocator: std.mem.Allocator,
    retained: *const retained_authority.RetainedAuthorityV4,
    root: []const u8,
    execution: capture_publication.ExecutionAuthorityV4,
    segment_index: u32,
) !LeafSelectionV4 {
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
    const result = LeafSelectionV4{
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
    selected: LeafSelectionV4,
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
