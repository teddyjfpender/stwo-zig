//! Internal binary pair authority authority shard; use binary_pair_authority.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");

pub const M31 = stwo_core.fields.m31.M31;
pub const QM31 = stwo_core.fields.qm31.QM31;

pub const fixed_profile = @import("fixed_profile.zig");
pub const fixed_wire = @import("fixed_wire.zig");
pub const pair_node = @import("pair_node.zig");
pub const protocol = @import("protocol.zig");
pub const span_statement = @import("span_statement.zig");
pub const statement_circuit = @import("statement_semantics_circuit.zig");
pub const transcript_program = @import("transcript_program.zig");
pub const transcript_owner = @import("segment_transcript_witness.zig");

pub const schedule = @import("air/verifier_schedule.zig");
pub const proof_kind = @import("air/proof_kind.zig");
pub const statement_input = @import("air/statement_input_witness.zig");
pub const transcript_air = @import("air/transcript_air_witness.zig");
pub const transcript_binding = @import("air/transcript_binding_witness.zig");
pub const transcript_state = @import("air/transcript_state_witness.zig");
pub const transcript_word = @import("air/transcript_word_witness.zig");
pub const transcript_payload = @import("air/transcript_payload_witness.zig");
pub const pow_check = @import("air/pow_check_witness.zig");
pub const pow_frame = @import("air/pow_frame_witness.zig");
pub const relation_challenge = @import("air/relation_challenge_witness.zig");
pub const verifier_randomness = @import("air/verifier_randomness_witness.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const PROOF_KIND = proof_kind.ProofKind.binary_node;
pub const FIRST_AUTHORITY_ROW: usize = 0;
pub const LAST_SNAPSHOTTED_ROW: usize = 11;
pub const FIRST_INACTIVE_VM_ROW: usize = 12;
pub const LAST_INACTIVE_VM_ROW: usize = 16;
pub const BINARY_PUBLIC_LOGUP_CONTROL_ROW: usize = 17;
pub const SHARED_RANGE_ROW: usize = 35;
pub const SHARED_RANGE_LOG_SIZE: u32 = 16;
pub const VALIDATION_SCRATCH_LEN: usize =
    statement_circuit.INPUT_COUNT + statement_circuit.NODE_COUNT;

/// This source closes custody and exact binary witness derivation. It does not
/// itself instantiate the 36 components or make a parent proof.
pub const RECURSIVE_PROOF_PRODUCTION = false;

pub const Error = error{
    ChildCaptureMismatch,
    ChildOmitted,
    EmptyProofSummary,
    ExecutionStatementMismatch,
    NonCanonicalTranscriptDigest,
    PlanMismatch,
    PlanNotFrozenV1,
    StatementIndexMismatch,
    StatementNotLeaf,
    TranscriptSnapshotMismatch,
    ValidationWorkspaceMismatch,
};

/// Whether the supplied plans must be the exact frozen V1 reconstruction.
/// `sealed_candidate` exists only for separately domain-reviewed profiling and
/// tests; production callers use `frozen_v1`.
pub const PlanAdmission = enum(u8) {
    frozen_v1,
    sealed_candidate,
};

/// Proof-independent preprocessing shared with the segment path. The native
/// universal layout intentionally contains one VM lane and two recursion
/// lanes, so the same authenticated preprocessing is the single source of
/// truth for both modes.
pub const TranscriptPreprocessing = transcript_owner.Preprocessing;

pub const PairInputs = struct {
    context: pair_node.VerifierContextV1,
    root_pin: pair_node.RootVkPinV1,
};

/// Exact branch contract consumed by rows 0--17 and the shared range provider.
/// Rows 12--16 are inactive for a binary node by protocol, not placeholders.
/// Row 17 is schedule control, not a VM-public witness: it must consume both
/// binary recursion lanes or row 0's exact schedule tuples cannot close.
pub const RowContract = struct {
    proof_kind: proof_kind.ProofKind = PROOF_KIND,
    active_transcript_lanes: u8 = 2,
    active_statement_scopes: u8 = 2,
    vm_rows_active: bool = false,
    active_public_logup_control_lanes: u8 = 2,
    range_provider_log_size: u32 = SHARED_RANGE_LOG_SIZE,

    pub fn validate(self: RowContract) Error!void {
        if (self.proof_kind != .binary_node or
            self.active_transcript_lanes != 2 or
            self.active_statement_scopes != 2 or
            self.vm_rows_active or
            self.active_public_logup_control_lanes != 2 or
            self.range_provider_log_size != SHARED_RANGE_LOG_SIZE)
        {
            return error.TranscriptSnapshotMismatch;
        }
    }
};

pub fn validatePlans(
    allocator: std.mem.Allocator,
    admission: PlanAdmission,
    vm_plan: *const schedule.Plan,
    recursion_plans: [2]*const schedule.Plan,
    left_shape: fixed_profile.ProofShapeV1,
    right_shape: fixed_profile.ProofShapeV1,
) !void {
    try vm_plan.validate();
    if (vm_plan.schema != .vm) return error.PlanMismatch;
    try validateSealedPlanPair(recursion_plans);
    if (!std.meta.eql(recursion_plans[0].shape_id, try left_shape.id()) or
        !std.meta.eql(recursion_plans[1].shape_id, try right_shape.id()))
    {
        return error.PlanMismatch;
    }
    if (admission == .sealed_candidate) return;
    var left_expected = try schedule.Plan.init(
        allocator,
        schedule.RECURSION_PROGRAM_SPEC_V1,
        left_shape,
    );
    defer left_expected.deinit();
    var right_expected = try schedule.Plan.init(
        allocator,
        schedule.RECURSION_PROGRAM_SPEC_V1,
        right_shape,
    );
    defer right_expected.deinit();
    if (!planEql(recursion_plans[0], &left_expected) or
        !planEql(recursion_plans[1], &right_expected))
    {
        return error.PlanNotFrozenV1;
    }
}

pub fn validateSealedPlanPair(plans: [2]*const schedule.Plan) !void {
    for (plans) |plan| {
        try plan.validate();
        if (plan.schema != .recursion or
            !std.meta.eql(plan.protocol_id, protocol.PROTOCOL_ID_WORDS))
        {
            return error.PlanMismatch;
        }
    }
    if (!planEql(plans[0], plans[1])) return error.PlanMismatch;
}

pub fn planEql(left: *const schedule.Plan, right: *const schedule.Plan) bool {
    if (left.schema != right.schema or
        !std.meta.eql(left.spec, right.spec) or
        !std.meta.eql(left.protocol_id, right.protocol_id) or
        !std.meta.eql(left.shape_id, right.shape_id) or
        !std.meta.eql(left.authority_digest, right.authority_digest) or
        left.steps.len != right.steps.len)
    {
        return false;
    }
    for (left.steps, right.steps) |left_step, right_step| {
        if (!std.meta.eql(left_step, right_step)) return false;
    }
    return true;
}

pub fn validateStatementPositions(pair_index: u32, children: anytype) Error!void {
    const first = std.math.mul(u32, pair_index, 2) catch
        return error.StatementIndexMismatch;
    for (children, 0..) |child, index| {
        if (child.capture.statement.slots.height != 0)
            return error.StatementNotLeaf;
        if (child.capture.statement.slots.first != first + index)
            return error.StatementIndexMismatch;
    }
}

pub fn recordFromAuthority(
    authority: *const pair_node.VerifierAuthorityV1,
) !pair_node.PairNodeRecordV1 {
    const context_id = try authority.context.contextId();
    var children: [2]pair_node.ChildEvidenceV1 = undefined;
    for (&children, authority.children) |*target, child| target.* = .{
        .position = child.position,
        .role = child.role,
        .leaf_index = child.leaf_index,
        .pair_index = child.pair_index,
        .leaf_count = child.leaf_count,
        .protocol_id = child.protocol_id,
        .session_id = child.session_id,
        .challenge_context_id = child.challenge_context_id,
        .authority_context_id = child.authority_context_id,
        .parent_vk_id = child.parent_vk_id,
        .statement_id = child.statement_id,
        .proof_id = child.proof_id,
        .transcript_id = child.transcript_id,
        .summary_id = child.summary_id,
        .event_count = child.event_count,
        .signed_relation_total = child.signed_relation_total,
    };
    return .{
        .pair_index = authority.context.pair_index,
        .first_leaf_index = authority.context.pair_index * 2,
        .aggregator_vk_id = authority.context.aggregator_vk_id,
        .authority_context_id = context_id,
        .children = children,
    };
}

pub fn statementId(words: *const span_statement.StatementWords) protocol.Digest {
    var canonical: [span_statement.SPAN_STATEMENT_CANONICAL_WORDS]u32 = undefined;
    for (&canonical, words) |*target, word| target.* = word.toU32();
    return protocol.statementId(&canonical);
}

pub fn executionDigest(words: [transcript_program.RATE]M31) Error!protocol.Digest {
    var result: protocol.Digest = undefined;
    for (&result, words) |*target, word| {
        const value = word.toU32();
        if (value >= stwo_core.fields.m31.Modulus)
            return error.NonCanonicalTranscriptDigest;
        target.* = value;
    }
    return result;
}

pub fn verifierRandomnessCount(execution: *const transcript_program.Execution) usize {
    var count: usize = 0;
    for (execution.operations) |operation|
        count += @intFromBool(isVerifierRandomness(operation.step));
    return count;
}

pub fn writeVerifierRandomness(
    execution: *const transcript_program.Execution,
    destination: []verifier_randomness.Draw,
) Error!void {
    if (destination.len != verifierRandomnessCount(execution))
        return error.TranscriptSnapshotMismatch;
    var at: usize = 0;
    for (execution.operations) |operation| {
        if (!isVerifierRandomness(operation.step)) continue;
        destination[at] = operation.draw orelse
            return error.TranscriptSnapshotMismatch;
        at += 1;
    }
}

pub fn isVerifierRandomness(step: schedule.VerifierStep) bool {
    return switch (step) {
        .draw_composition_randomness,
        .draw_oods_point,
        .draw_deep_randomness,
        .draw_fri_alpha,
        .draw_query_block,
        => true,
        else => false,
    };
}

pub fn validateRelationSnapshot(
    executions: *const [2]transcript_program.Execution,
    preprocessing: *const relation_challenge.Preprocessed,
    witness: *const relation_challenge.MainWitness,
) !void {
    try witness.validateAgainst(preprocessing);
    for (preprocessing.rows, witness.rows) |metadata, row| {
        const lane: ?usize = switch (metadata.verifier_id) {
            relation_challenge.LEFT_RECURSION_VERIFIER_ID => 0,
            relation_challenge.RIGHT_RECURSION_VERIFIER_ID => 1,
            else => null,
        };
        const lane_index = lane orelse {
            if (row.enabler != 0) return error.TranscriptSnapshotMismatch;
            continue;
        };
        const operation = findOperation(&executions[lane_index], metadata.sequence) orelse
            return error.TranscriptSnapshotMismatch;
        const expected = operation.draw orelse return error.TranscriptSnapshotMismatch;
        if (operation.step != .draw_relation_challenge or
            operation.step.draw_relation_challenge.challenge != metadata.challenge or
            !std.meta.eql(row.outputs, expected))
        {
            return error.TranscriptSnapshotMismatch;
        }
    }
}

pub fn validateRandomnessSnapshot(
    executions: *const [2]transcript_program.Execution,
    preprocessing: *const verifier_randomness.Preprocessed,
    witness: *const verifier_randomness.MainWitness,
) !void {
    try witness.validateAgainst(preprocessing);
    for (preprocessing.rows, witness.rows) |metadata, row| {
        const lane: ?usize = switch (metadata.verifier_id) {
            verifier_randomness.LEFT_RECURSION_VERIFIER_ID => 0,
            verifier_randomness.RIGHT_RECURSION_VERIFIER_ID => 1,
            else => null,
        };
        const lane_index = lane orelse {
            if (row.enabler != 0) return error.TranscriptSnapshotMismatch;
            continue;
        };
        const operation = findOperation(&executions[lane_index], metadata.sequence) orelse
            return error.TranscriptSnapshotMismatch;
        const expected = operation.draw orelse return error.TranscriptSnapshotMismatch;
        if (!isVerifierRandomness(operation.step) or
            !std.meta.eql(row.outputs, expected))
        {
            return error.TranscriptSnapshotMismatch;
        }
    }
}

pub fn findOperation(
    execution: *const transcript_program.Execution,
    sequence: u32,
) ?transcript_program.Operation {
    for (execution.operations) |operation|
        if (operation.sequence == sequence) return operation;
    return null;
}

pub fn traceLogSize(row_count: usize) u32 {
    return @max(
        @as(u32, 4),
        @as(u32, @intCast(std.math.log2_int_ceil(usize, @max(row_count, 1)))),
    );
}

pub fn secureSlicesEql(left: []const QM31, right: []const QM31) bool {
    if (left.len != right.len) return false;
    for (left, right) |left_value, right_value|
        if (!left_value.eql(right_value)) return false;
    return true;
}

pub fn slicesOverlap(left: []const QM31, right: []const QM31) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_bytes = std.math.mul(usize, left.len, @sizeOf(QM31)) catch return true;
    const right_bytes = std.math.mul(usize, right.len, @sizeOf(QM31)) catch return true;
    const left_end = std.math.add(usize, left_start, left_bytes) catch return true;
    const right_end = std.math.add(usize, right_start, right_bytes) catch return true;
    return left_start < right_end and right_start < left_end;
}
