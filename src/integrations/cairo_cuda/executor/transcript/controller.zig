//! Checked device execution for the authenticated Cairo transcript schedule.
//!
//! Challenge destinations are resident CUDA buffers. The controller never
//! accepts challenge values from the host. Input and output snapshots alias
//! their immutable source/destination buffers; only the 16-word boundary
//! snapshot needs dedicated storage.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const field = @import("stwo_cuda_backend").abi.field;
const common = @import("stwo_cuda_backend").runtime.stages.common;
const transcript_stage = @import("stwo_cuda_backend").runtime.stages.transcript;
const telemetry = @import("stwo_cuda_backend").runtime.telemetry;
const schedule_mod = @import("schedule.zig");

pub const state_words: usize = 16;
pub const boundary_snapshot_words: usize = 16;
pub const minimum_storage_words =
    state_words + boundary_snapshot_words;
pub const pow_search_end: u64 = @as(u64, 0x7fff_ffff) << 20;

pub const View = struct {
    state: common.Words,
    boundary_snapshot: common.Words,

    pub fn bind(storage: common.Words) !View {
        if (storage.len < minimum_storage_words)
            return error.InvalidTranscriptStorage;
        return .{
            .state = try storage.sub(0, state_words),
            .boundary_snapshot = try storage.sub(
                state_words,
                boundary_snapshot_words,
            ),
        };
    }
};

pub const Cursor = struct {
    initialized: bool = false,
    next_step: u32 = 0,

    pub fn complete(
        self: Cursor,
        schedule: schedule_mod.Schedule,
    ) bool {
        return self.initialized and
            self.next_step == schedule.operation_count;
    }
};

pub fn initialize(
    comptime Transcript: type,
    session: anytype,
    schedule: schedule_mod.Schedule,
    cursor: *Cursor,
    view: View,
) !void {
    if (cursor.initialized or cursor.next_step != 0)
        return error.InvalidTranscriptCursor;
    try Transcript.initialize(
        session,
        .trace_commit,
        view.state,
        null,
        null,
        schedule.initialChain(),
    );
    cursor.initialized = true;
}

pub fn mixInput(
    comptime Transcript: type,
    session: anytype,
    stage: telemetry.Stage,
    schedule: schedule_mod.Schedule,
    cursor: *Cursor,
    view: View,
    ordinal: u32,
    source: common.Words,
) !void {
    const step = try requireStep(schedule, cursor, stage);
    const scheduled_ordinal = (try schedule.inputOrdinal(step)) orelse
        return error.InvalidTranscriptOperation;
    if (scheduled_ordinal != ordinal)
        return error.InvalidTranscriptOperation;
    try schedule.validateInputWords(step, source.len);
    try Transcript.mixWords(
        session,
        stage,
        view.state,
        try boundary(schedule, step, view),
        source,
        try schedule.validateM31(step),
        source,
    );
    cursor.next_step += 1;
}

pub fn drawSecure(
    comptime Transcript: type,
    session: anytype,
    stage: telemetry.Stage,
    schedule: schedule_mod.Schedule,
    cursor: *Cursor,
    view: View,
    ordinal: u32,
    output: common.SecureFields,
) !void {
    const step = try requireStep(schedule, cursor, stage);
    const scheduled_ordinal = (try schedule.outputOrdinal(step)) orelse
        return error.InvalidTranscriptOperation;
    const felt_count = (try schedule.secureFeltCount(step)) orelse
        return error.InvalidTranscriptOperation;
    if (scheduled_ordinal != ordinal or output.len != felt_count)
        return error.InvalidTranscriptPayload;
    try schedule.validateOutputWords(step, output.len * 4);
    try Transcript.drawSecure(
        session,
        stage,
        view.state,
        try boundary(schedule, step, view),
        felt_count,
        schedule_mod.max_rejection_rounds,
        output,
        output,
    );
    cursor.next_step += 1;
}

pub const PowView = struct {
    prefix_digest: common.Words,
    best_nonce: common.Nonce,
    completed_blocks: common.Words,
    transcript_nonce: common.Words,
};

/// Grinds and absorbs either Cairo PoW boundary on the owning CUDA stage.
///
/// Both nonce search and channel mutation remain on device. The explicit
/// stage methods distinguish interaction PoW in `.trace_commit` from query
/// PoW in `.pow`; callers cannot inject a host-selected nonce.
pub fn executePow(
    comptime Fri: type,
    comptime Transcript: type,
    session: anytype,
    stage: telemetry.Stage,
    schedule: schedule_mod.Schedule,
    cursor: *Cursor,
    view: View,
    pow: PowView,
) !void {
    const step = try requireStep(schedule, cursor, stage);
    const ordinal = (try schedule.inputOrdinal(step)) orelse
        return error.InvalidTranscriptOperation;
    if (ordinal != 21 and ordinal != 31)
        return error.InvalidTranscriptOperation;
    try schedule.validateInputWords(step, pow.transcript_nonce.len);
    const pow_bits = (try schedule.powBits(step)) orelse
        return error.InvalidTranscriptOperation;
    const sealed = try boundary(schedule, step, view);
    try Fri.grindPowAtStage(
        session,
        stage,
        view.state,
        pow_bits,
        pow_search_end,
        pow.prefix_digest,
        pow.best_nonce,
        pow.completed_blocks,
        pow.transcript_nonce,
    );
    try Transcript.absorbPowAtStage(
        session,
        stage,
        view.state,
        sealed,
        pow.transcript_nonce,
        pow_bits,
        pow.transcript_nonce,
    );
    cursor.next_step += 1;
}

pub fn drawQueries(
    comptime Transcript: type,
    session: anytype,
    schedule: schedule_mod.Schedule,
    cursor: *Cursor,
    view: View,
    ordinal: u32,
    output: common.Words,
) !void {
    const stage = telemetry.Stage.decommit;
    const step = try requireStep(schedule, cursor, stage);
    const scheduled_ordinal = (try schedule.outputOrdinal(step)) orelse
        return error.InvalidTranscriptOperation;
    if (scheduled_ordinal != ordinal)
        return error.InvalidTranscriptOperation;
    try schedule.validateOutputWords(step, output.len);
    try Transcript.drawQueries(
        session,
        view.state,
        try boundary(schedule, step, view),
        schedule.protocol.max_log_degree_bound,
        output,
        output,
    );
    cursor.next_step += 1;
}

pub const AotAuthority = struct {
    manifest_identity: proof_ir.Digest,
    binary_identity: proof_ir.Digest,
};

pub const Measurement = struct {
    measured: bool,
    observed_manifest_identity: proof_ir.Digest,
    observed_binary_identity: proof_ir.Digest,
    runtime_compile_attempts: u64,
    cpu_fallback_attempts: u64,
};

pub const Evidence = struct {
    schedule_identity: proof_ir.Digest,
    semantic_proof_identity: proof_ir.Digest,
    executable_program_identity: proof_ir.Digest,
    aot_manifest_identity: proof_ir.Digest,
    aot_binary_identity: proof_ir.Digest,
    completed_operations: u32,
    runtime_compile_attempts: u64,
    cpu_fallback_attempts: u64,
    evidence_identity: proof_ir.Digest,

    pub fn seal(
        schedule: schedule_mod.Schedule,
        cursor: Cursor,
        authority: AotAuthority,
        measurement: Measurement,
    ) !Evidence {
        if (!cursor.complete(schedule) or
            !measurement.measured or
            digestEmpty(authority.manifest_identity) or
            digestEmpty(authority.binary_identity) or
            !std.mem.eql(
                u8,
                &authority.manifest_identity,
                &measurement.observed_manifest_identity,
            ) or
            !std.mem.eql(
                u8,
                &authority.binary_identity,
                &measurement.observed_binary_identity,
            ) or
            measurement.runtime_compile_attempts != 0 or
            measurement.cpu_fallback_attempts != 0)
        {
            return error.InvalidTranscriptExecutionEvidence;
        }
        var result = Evidence{
            .schedule_identity = schedule.schedule_identity,
            .semantic_proof_identity = schedule.semantic_proof_identity,
            .executable_program_identity = schedule.executable_program_identity,
            .aot_manifest_identity = authority.manifest_identity,
            .aot_binary_identity = authority.binary_identity,
            .completed_operations = cursor.next_step,
            .runtime_compile_attempts = measurement.runtime_compile_attempts,
            .cpu_fallback_attempts = measurement.cpu_fallback_attempts,
            .evidence_identity = undefined,
        };
        result.evidence_identity = evidenceIdentity(result);
        return result;
    }

    pub fn validate(
        self: Evidence,
        schedule: schedule_mod.Schedule,
    ) !void {
        if (!std.mem.eql(
            u8,
            &self.schedule_identity,
            &schedule.schedule_identity,
        ) or
            !std.mem.eql(
                u8,
                &self.semantic_proof_identity,
                &schedule.semantic_proof_identity,
            ) or
            !std.mem.eql(
                u8,
                &self.executable_program_identity,
                &schedule.executable_program_identity,
            ) or
            digestEmpty(self.aot_manifest_identity) or
            digestEmpty(self.aot_binary_identity) or
            self.completed_operations != schedule.operation_count or
            self.runtime_compile_attempts != 0 or
            self.cpu_fallback_attempts != 0 or
            !std.mem.eql(
                u8,
                &self.evidence_identity,
                &evidenceIdentity(self),
            ))
        {
            return error.InvalidTranscriptExecutionEvidence;
        }
    }
};

fn requireStep(
    schedule: schedule_mod.Schedule,
    cursor: *const Cursor,
    stage: telemetry.Stage,
) !u32 {
    if (!cursor.initialized or
        cursor.next_step >= schedule.operation_count)
    {
        return error.InvalidTranscriptCursor;
    }
    if (try schedule.stage(cursor.next_step) != stage)
        return error.InvalidTranscriptStage;
    return cursor.next_step;
}

fn boundary(
    schedule: schedule_mod.Schedule,
    step: u32,
    view: View,
) !transcript_stage.Boundary {
    const value = try schedule.boundary(step);
    return .{
        .expected_step = value.expected_step,
        .expected_chain = value.expected_chain,
        .next_chain = value.next_chain,
        .snapshot = view.boundary_snapshot,
    };
}

fn evidenceIdentity(value: Evidence) proof_ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/transcript-evidence/v1\x00");
    hash.update(&value.schedule_identity);
    hash.update(&value.semantic_proof_identity);
    hash.update(&value.executable_program_identity);
    hash.update(&value.aot_manifest_identity);
    hash.update(&value.aot_binary_identity);
    hashInt(&hash, u32, value.completed_operations);
    hashInt(&hash, u64, value.runtime_compile_attempts);
    hashInt(&hash, u64, value.cpu_fallback_attempts);
    return hash.finalResult();
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: T,
) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

fn digestEmpty(value: proof_ir.Digest) bool {
    return std.mem.allEqual(u8, &value, 0);
}

comptime {
    if (@sizeOf(field.SecureField) != 4 * @sizeOf(u32))
        @compileError("Cairo transcript assumes four-word secure fields");
}
