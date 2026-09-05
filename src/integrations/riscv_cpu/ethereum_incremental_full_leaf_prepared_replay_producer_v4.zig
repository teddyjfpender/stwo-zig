//! Experimental one-pass VM-free Stage101 producer.
//!
//! The durable proof/artifact encoder is identical to the legacy producer.
//! Only process-local preparation changes: the populated statement workspace,
//! incremental witness, Ethereum witness, extension, and profile remain owned
//! by one `PreparedProofTransactionV4` through proof completion.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const stage_profile = @import("stwo_prover_api").stage_profile;

const legacy = @import("ethereum_incremental_full_leaf_replay_producer_v4.zig");
const prepared_mod =
    @import("ethereum_incremental_full_leaf_prepared_proof_transaction_v4.zig");
const prepared_parity =
    @import("ethereum_incremental_full_leaf_prepared_authority_parity_v4.zig");
const proof_artifact =
    @import("ethereum_incremental_full_leaf_proof_artifact_v4.zig");

const minimal = frontend.runner.minimal_trace;
const public_data_v2 = frontend.air.public_data_v2;

pub const FORMAT_VERSION: u16 = 4;
pub const PRODUCTION_ACTIVE = false;
pub const DEFAULT_PRODUCER_CHANGED = false;
pub const TimingReceiptV1 = legacy.TimingReceiptV1;
pub const PreparationCounterSnapshotV1 = prepared_mod.CounterSnapshotV1;
pub const PreparedProofTransactionV4 = prepared_mod.PreparedProofTransactionV4;
pub const ProviderCallViewV1 = prepared_mod.ProviderCallViewV1;

pub const PreparedVisitorEvidenceV1 = struct {
    input_admission_ns: u64,
    compact_replay_ns: u64,
    snapshot_ns: u64,
    preparation: PreparationCounterSnapshotV1,

    pub fn validate(self: PreparedVisitorEvidenceV1) !void {
        try self.preparation.construction.validate();
        try self.preparation.phase_timing.validate();
        if (self.input_admission_ns == 0 or self.compact_replay_ns == 0 or
            self.snapshot_ns == 0)
        {
            return error.InvalidIncrementalPreparedVisitorEvidenceV4;
        }
    }
};

pub const PreparedVisitorV1 = struct {
    context: *anyopaque,
    visit_fn: *const fn (
        *anyopaque,
        *const prepared_mod.PreparedProofTransactionV4,
        prepared_mod.ProviderCallViewV1,
        PreparedVisitorEvidenceV1,
    ) anyerror!void,

    pub fn visit(
        self: PreparedVisitorV1,
        transaction: *const prepared_mod.PreparedProofTransactionV4,
        calls: prepared_mod.ProviderCallViewV1,
        evidence: PreparedVisitorEvidenceV1,
    ) !void {
        try calls.validateAgainst(transaction);
        try evidence.validate();
        return self.visit_fn(self.context, transaction, calls, evidence);
    }
};

pub fn produceAllocWithRecorderAndTiming(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    source_input: legacy.ColdInputV4,
    proof_limits: proof_artifact.Limits,
    execution: frontend.testing.incremental_ethereum_orchestration_v4_internal
        .ExecutionOptions,
    recorder: ?*stage_profile.Recorder,
    timing_out: ?*TimingReceiptV1,
    preparation_out: ?*PreparationCounterSnapshotV1,
) ![]u8 {
    var transaction_timer = try std.time.Timer.start();
    var transaction_stage = try stage_profile.StageScope.begin(
        recorder,
        "stage101_leaf_transaction",
        "Stage101 leaf transaction",
    );
    defer transaction_stage.end();

    var admission_stage = try stage_profile.StageScope.begin(
        recorder,
        "stage101_input_admission",
        "Stage101 input admission",
    );
    var admission_timer = try std.time.Timer.start();
    errdefer admission_stage.end();
    try source_input.replay_authority.validate();
    var public_lease: ?public_data_v2.PublicDataV2.OwnedValidatedLeaseV2 = null;
    defer if (public_lease) |*lease| lease.deinit();
    var input = source_input;
    if (source_input.public_wire.validated_lease != null) {
        // Borrow the caller's already-owned immutable frontend authority.
    } else if (source_input.public_wire.retained_snapshots) |retained| {
        public_lease = try public_data_v2.PublicDataV2.OwnedValidatedLeaseV2
            .initRetained(
            allocator,
            source_input.public_wire,
            retained,
            source_input.validation_counters,
        );
        input.public_wire = public_lease.?.data();
    } else if (source_input.validation_counters) |counters| {
        counters.recordLegacyFullAuthentication();
    }
    try input.validate();
    admission_stage.end();
    const admission_ns = admission_timer.read();

    var replay_stage = try stage_profile.StageScope.begin(
        recorder,
        "stage101_compact_replay",
        "Stage101 compact replay",
    );
    var replay_timer = try std.time.Timer.start();
    errdefer replay_stage.end();
    var replay_boundary = try minimal.SliceBoundary.init(
        input.compact.boundary_words,
    );
    var replay = try minimal.replayEthereumLeaf(allocator, .{
        .leaf = &input.compact.leaf,
        .program = input.program.program.source(),
        .boundary = replay_boundary.source(),
        .expected_memory_layout = input.program.layout,
        .expected_source = input.replay_authority.source,
        .expected_entry_cpu_sha256 = input.replay_authority.entry_cpu_sha256,
        .expected_exit_cpu_sha256 = input.replay_authority.exit_cpu_sha256,
        .expected_completion = input.replay_authority.completion,
    });
    defer replay.deinit();
    replay_stage.end();
    const replay_ns = replay_timer.read();

    var prepare_stage = try stage_profile.StageScope.begin(
        recorder,
        "stage101_prepared_proof_transaction",
        "Stage101 one-pass witness, statement, and profile",
    );
    var prepare_timer = try std.time.Timer.start();
    errdefer prepare_stage.end();
    const completion = input.role_aware_public.completion orelse
        return error.MissingIncrementalFullLeafCompletionV4;
    var snapshot = try input.program.snapshotForCompletion(
        allocator,
        input.public_authority.segment_role,
        completion,
    );
    defer snapshot.deinit();
    const snapshot_ns = prepare_timer.lap();
    var prepared = try prepared_mod.PreparedProofTransactionV4.initOwned(
        allocator,
        .{
            .replay = &replay,
            .memory_snapshot = &snapshot.value,
            .program_source_identity_sha256 = input.replay_authority.source.program,
            .completion = completion,
            .boundary_artifact = input.boundary,
            .public_wire = input.public_wire,
            .role_aware_public = input.role_aware_public,
            .public_authority = input.public_authority,
        },
    );
    defer prepared.deinit();
    prepare_stage.end();
    const preparation = prepared.counterSnapshot();
    try preparation.construction.validate();
    try preparation.phase_timing.validate();
    const witness_ns = std.math.add(
        u64,
        snapshot_ns,
        preparation.phase_timing.witness_prepare_ns,
    ) catch return error.IncrementalPreparedResourceOverflowV4;
    const profile_ns = preparation.phase_timing.statement_profile_prepare_ns;

    var prove_stage = try stage_profile.StageScope.begin(
        recorder,
        "stage101_prove",
        "Stage101 prove",
    );
    var prove_timer = try std.time.Timer.start();
    errdefer prove_stage.end();
    const view = try prepared.proofView();
    if (prepared_parity.enabled()) {
        const parity_result = try prepared_parity.comparePreparedAgainstLegacy(
            allocator,
            view,
        );
        switch (parity_result) {
            .exact => |receipt| std.debug.print(
                "STAGE101_PREPARED_AUTHORITY_PARITY=exact trace={x} statement={any} profile={x}\n",
                .{
                    receipt.snapshot.core_trace_sha256,
                    receipt.snapshot.statement_authority_id,
                    receipt.snapshot.profile_identity_sha256,
                },
            ),
            .mismatch => |difference| {
                std.debug.print(
                    "STAGE101_PREPARED_AUTHORITY_PARITY=mismatch field={s}\n",
                    .{@tagName(difference.field)},
                );
                return error.Stage101PreparedAuthorityParityMismatchV4;
            },
        }
    }
    var prove_channel = Engine.Channel{};
    var output = try prepared.proveWithEngineUsingChannel(
        Engine,
        allocator,
        recorder,
        &prove_channel,
        execution,
    );
    defer output.deinit(allocator);
    prove_stage.end();
    const prove_ns = prove_timer.read();

    var encode_stage = try stage_profile.StageScope.begin(
        recorder,
        "stage101_encode",
        "Stage101 canonical encode",
    );
    var encode_timer = try std.time.Timer.start();
    errdefer encode_stage.end();
    const encoded = try proof_artifact.encodeAlloc(
        Engine,
        allocator,
        .{
            .statement = &output.statement,
            .role_aware_public = input.role_aware_public,
            .extension = &output.extension,
            .profile = view.profile,
            .base_claim = output.claims.base,
            .extension_claim = &output.claims.ethereum,
            .bridge_claim = output.claims.bridge,
            .proof = &output.proof,
        },
        proof_limits,
    );
    encode_stage.end();
    if (timing_out) |timing| timing.* = .{
        .transaction_ns = transaction_timer.read(),
        .input_admission_ns = admission_ns,
        .compact_replay_ns = replay_ns,
        .witness_prepare_ns = witness_ns,
        .statement_profile_prepare_ns = profile_ns,
        .prove_ns = prove_ns,
        .encode_ns = encode_timer.read(),
    };
    if (preparation_out) |counters| counters.* = prepared.counterSnapshot();
    return encoded;
}

/// Opens the same one-pass transaction as the prepared Stage101 producer and
/// lends its exact ordered provider calls to one process-local visitor. No
/// proof artifact is encoded or published by this research-only boundary.
pub fn visitPreparedTransaction(
    allocator: std.mem.Allocator,
    source_input: legacy.ColdInputV4,
    recorder: ?*stage_profile.Recorder,
    visitor: PreparedVisitorV1,
) !void {
    var transaction_stage = try stage_profile.StageScope.begin(
        recorder,
        "stage101_provider_transaction",
        "Stage101 provider-call transaction",
    );
    defer transaction_stage.end();

    var admission_stage = try stage_profile.StageScope.begin(
        recorder,
        "stage101_input_admission",
        "Stage101 input admission",
    );
    var admission_timer = try std.time.Timer.start();
    errdefer admission_stage.end();
    try source_input.replay_authority.validate();
    var public_lease: ?public_data_v2.PublicDataV2.OwnedValidatedLeaseV2 = null;
    defer if (public_lease) |*lease| lease.deinit();
    var input = source_input;
    if (source_input.public_wire.validated_lease != null) {
        // Borrow the caller's already-owned immutable frontend authority.
    } else if (source_input.public_wire.retained_snapshots) |retained| {
        public_lease = try public_data_v2.PublicDataV2.OwnedValidatedLeaseV2
            .initRetained(
            allocator,
            source_input.public_wire,
            retained,
            source_input.validation_counters,
        );
        input.public_wire = public_lease.?.data();
    } else if (source_input.validation_counters) |counters| {
        counters.recordLegacyFullAuthentication();
    }
    try input.validate();
    admission_stage.end();
    const admission_ns = admission_timer.read();

    var replay_stage = try stage_profile.StageScope.begin(
        recorder,
        "stage101_compact_replay",
        "Stage101 compact replay",
    );
    var replay_timer = try std.time.Timer.start();
    errdefer replay_stage.end();
    var replay_boundary = try minimal.SliceBoundary.init(
        input.compact.boundary_words,
    );
    var replay = try minimal.replayEthereumLeaf(allocator, .{
        .leaf = &input.compact.leaf,
        .program = input.program.program.source(),
        .boundary = replay_boundary.source(),
        .expected_memory_layout = input.program.layout,
        .expected_source = input.replay_authority.source,
        .expected_entry_cpu_sha256 = input.replay_authority.entry_cpu_sha256,
        .expected_exit_cpu_sha256 = input.replay_authority.exit_cpu_sha256,
        .expected_completion = input.replay_authority.completion,
    });
    defer replay.deinit();
    replay_stage.end();
    const replay_ns = replay_timer.read();

    var prepare_stage = try stage_profile.StageScope.begin(
        recorder,
        "stage101_prepared_provider_transaction",
        "Stage101 provider witness and statement",
    );
    var prepare_timer = try std.time.Timer.start();
    errdefer prepare_stage.end();
    const completion = input.role_aware_public.completion orelse
        return error.MissingIncrementalFullLeafCompletionV4;
    var snapshot = try input.program.snapshotForCompletion(
        allocator,
        input.public_authority.segment_role,
        completion,
    );
    defer snapshot.deinit();
    const snapshot_ns = prepare_timer.lap();
    var prepared = try prepared_mod.PreparedProofTransactionV4.initOwned(
        allocator,
        .{
            .replay = &replay,
            .memory_snapshot = &snapshot.value,
            .program_source_identity_sha256 = input.replay_authority.source.program,
            .completion = completion,
            .boundary_artifact = input.boundary,
            .public_wire = input.public_wire,
            .role_aware_public = input.role_aware_public,
            .public_authority = input.public_authority,
        },
    );
    defer prepared.deinit();
    prepare_stage.end();
    const call_view = try prepared.providerCallView();
    const evidence = PreparedVisitorEvidenceV1{
        .input_admission_ns = admission_ns,
        .compact_replay_ns = replay_ns,
        .snapshot_ns = snapshot_ns,
        .preparation = prepared.counterSnapshot(),
    };
    try visitor.visit(&prepared, call_view, evidence);
}

comptime {
    if (FORMAT_VERSION != 4 or PRODUCTION_ACTIVE or DEFAULT_PRODUCER_CHANGED)
        @compileError("prepared Stage101 producer activated");
}
