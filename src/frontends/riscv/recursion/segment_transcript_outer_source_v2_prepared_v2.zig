//! Internal segment transcript outer source v2 authority shard; use segment_transcript_outer_source_v2.zig publicly.

const dependency_0 = @import("segment_transcript_outer_source_v2_contract.zig");

const AuthorityBindingV2 = dependency_0.AuthorityBindingV2;
const ControlRowV2 = dependency_0.ControlRowV2;
const CountsV2 = dependency_0.CountsV2;
const Digest = dependency_0.Digest;
const Error = dependency_0.Error;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const IdentityHasher = dependency_0.IdentityHasher;
const M31 = dependency_0.M31;
const ManifestV2 = dependency_0.ManifestV2;
const PRODUCTION_ACTIVATION = dependency_0.PRODUCTION_ACTIVATION;
const PcsConfig = dependency_0.PcsConfig;
const ProviderCall = dependency_0.ProviderCall;
const RANGE_ID_DOMAIN = dependency_0.RANGE_ID_DOMAIN;
const ROW_COUNT = dependency_0.ROW_COUNT;
const SCHEMA_VERSION = dependency_0.SCHEMA_VERSION;
const SOURCE_ID_DOMAIN = dependency_0.SOURCE_ID_DOMAIN;
const TranscriptAirRowV2 = dependency_0.TranscriptAirRowV2;
const VERIFIER_ID = dependency_0.VERIFIER_ID;
const binding_witness = dependency_0.binding_witness;
const channel = dependency_0.channel;
const countsFromManifest = dependency_0.countsFromManifest;
const deriveCounts = dependency_0.deriveCounts;
const manifestFor = dependency_0.manifestFor;
const overlap = dependency_0.overlap;
const payload_air = dependency_0.payload_air;
const pow_check_air = dependency_0.pow_check_air;
const provider = dependency_0.provider;
const public_data_v2 = dependency_0.public_data_v2;
const randomness_witness = dependency_0.randomness_witness;
const relation = dependency_0.relation;
const relation_witness = dependency_0.relation_witness;
const schedule = dependency_0.schedule;
const state_witness = dependency_0.state_witness;
const statement_v1 = dependency_0.statement_v1;
const std = dependency_0.std;
const transcript = dependency_0.transcript;
const typedTag = dependency_0.typedTag;
const universal = dependency_0.universal;
const validateProgramWords = dependency_0.validateProgramWords;
const validateRawQuerySchedule = dependency_0.validateRawQuerySchedule;
const word_witness = dependency_0.word_witness;

/// Pointer-free source receipt retained by the outer integration bundle.
pub const PreparedV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    manifest: ManifestV2,
    authority: AuthorityBindingV2,
    execution_id: Digest,
    evidence_id: Digest,
    trace_receipt: [32]u8,
    final_digest: Digest,
    final_draw_count: u32,
    source_id: Digest,

    pub fn validateAgainst(
        self: *const PreparedV2,
        program: *const transcript.Program,
        execution: *const transcript.Execution,
        evidence: *const transcript.Evidence,
        plan: *const schedule.Plan,
        pcs_config: PcsConfig,
        data: *const public_data_v2.PublicDataV2,
        component_descs: []const statement_v1.FamilyComponentDesc,
        infra_descs: []const statement_v1.InfraComponentDesc,
    ) Error!void {
        const expected = try derivePrepared(
            program,
            execution,
            evidence,
            plan,
            pcs_config,
            data,
            component_descs,
            infra_descs,
        );
        if (!std.meta.eql(self.*, expected)) return error.SourceMismatch;
    }

    pub fn counts(self: *const PreparedV2) CountsV2 {
        return countsFromManifest(self.manifest);
    }

    pub fn productionReady(_: *const PreparedV2) bool {
        return PRODUCTION_ACTIVATION;
    }

    /// Copies the complete, unmasked Fiat--Shamir query words authenticated
    /// by the V2 transcript. Merkle positions retain only verifier-selected
    /// low bits, so feeding those positions back into row 20 would sever the
    /// proof from row 9 whenever a discarded high bit is non-zero.
    ///
    /// Validation is a dry pass: the destination remains untouched unless the
    /// source receipt, execution, plan, query-block order, and exact length all
    /// agree. The subsequent copy is allocation-free and infallible.
    pub fn writeRawQueryWords(
        self: *const PreparedV2,
        destination: []M31,
        program: *const transcript.Program,
        execution: *const transcript.Execution,
        plan: *const schedule.Plan,
    ) Error!void {
        try validateExecutionSnapshot(self, program, execution, plan);
        try rejectRawQueryAliases(destination, self, program, execution, plan);
        const query_count = try validateRawQuerySchedule(program, execution);
        if (destination.len != query_count)
            return error.DestinationLengthMismatch;

        var at: usize = 0;
        for (program.instructions, execution.operations) |instruction, operation| {
            if (instruction.kind != .query_draw) continue;
            const draw = operation.draw.?;
            const width: usize = @intCast(instruction.args[2]);
            @memcpy(destination[at..][0..width], draw[0..width]);
            at += width;
        }
        std.debug.assert(at == destination.len);
    }
};

/// Checked half-open ownership range in the single shared row-34 provider.
pub const PoseidonRequestRangeV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    source_id: Digest,
    program_id: Digest,
    first: u32,
    count: u32,
    end: u32,
    identity: Digest,

    pub fn init(prepared: *const PreparedV2, first: usize) Error!PoseidonRequestRangeV2 {
        try prepared.manifest.validate();
        const first_u32 = std.math.cast(u32, first) orelse
            return error.ArithmeticOverflow;
        const end = std.math.add(
            u32,
            first_u32,
            prepared.manifest.poseidon_request_count,
        ) catch return error.ArithmeticOverflow;
        var result = PoseidonRequestRangeV2{
            .source_id = prepared.source_id,
            .program_id = prepared.authority.program_id,
            .first = first_u32,
            .count = prepared.manifest.poseidon_request_count,
            .end = end,
            .identity = undefined,
        };
        result.identity = rangeId(&result);
        return result;
    }

    pub fn validateAgainst(
        self: *const PoseidonRequestRangeV2,
        prepared: *const PreparedV2,
    ) Error!void {
        const expected = try PoseidonRequestRangeV2.init(prepared, self.first);
        if (!std.meta.eql(self.*, expected)) return error.PoseidonRangeMismatch;
    }
};

pub const TranscriptBindingRowV2 = struct {
    preprocessing: binding_witness.PreprocessedRow,
    main: binding_witness.MainRow,
};

pub const TranscriptStateRowV2 = struct {
    preprocessing: state_witness.PreprocessedRow,
    main: state_witness.MainRow,
};

pub const TranscriptWordRowV2 = struct {
    preprocessing: word_witness.Row,
    value: M31,
};

pub const PayloadSourceKindV2 = enum(u32) {
    protocol = @intFromEnum(payload_air.VerifierInputKind.protocol),
    statement = @intFromEnum(payload_air.VerifierInputKind.statement),
    pcs_parameters = @intFromEnum(payload_air.VerifierInputKind.pcs_parameters),
    commitment = @intFromEnum(payload_air.VerifierInputKind.commitment),
    claimed_sum = @intFromEnum(payload_air.VerifierInputKind.claimed_sum),
    sampled_value = @intFromEnum(payload_air.VerifierInputKind.sampled_value),
    fri_commitment = @intFromEnum(payload_air.VerifierInputKind.fri_commitment),
    last_layer_coefficient = @intFromEnum(payload_air.VerifierInputKind.last_layer_coefficient),
    interaction_pow_nonce = @intFromEnum(payload_air.VerifierInputKind.interaction_pow_nonce),
    pcs_pow_nonce = @intFromEnum(payload_air.VerifierInputKind.pcs_pow_nonce),
    public_geometry = 13,
};

/// V2 replacement for frozen row 5's fixed statement-source metadata.
pub const TranscriptPayloadRowV2 = struct {
    verifier_id: u32,
    instruction_index: u32,
    tag: u32,
    args: [4]u32,
    payload_index: u32,
    source_kind: PayloadSourceKindV2,
    item_index: u32,
    limb_index: u32,
    constant_mask: u32,
    input_use_count: u32,
    source_hash_id: u32,
    source_word_index: u32,
    value: M31,
};

pub const PowCheckRowV2 = struct {
    enabler: u32 = 1,
    verifier_id: u32 = VERIFIER_ID,
    pow_kind: pow_check_air.PowKind,
    call_id: u32,
    bits: u32,
    word: M31,
    word_bits: [31]u32,
    active_bits: [31]u32,
};

pub const PowFrameRowV2 = struct {
    enabler: u32 = 1,
    verifier_id: u32 = VERIFIER_ID,
    instruction_index: u32,
    pow_kind: pow_check_air.PowKind,
    hash_id: u32,
    call_id: u32,
    bits: u32,
    words: transcript.Draw,
};

pub const RelationChallengeRowV2 = struct {
    preprocessing: relation_witness.PreprocessedRow,
    main: relation_witness.MainRow,
};

pub const VerifierRandomnessRowV2 = struct {
    preprocessing: randomness_witness.PreprocessedRow,
    main: randomness_witness.MainRow,
};

/// One exact universal relation event.  `arity` is checked against the pinned
/// registry; unused tuple lanes are canonical zero.  `multiplicity` retains
/// zero-weight AIR events so event ordinal/order stays identical to the typed
/// component definition.
pub const RelationEventV2 = struct {
    roster_row: u8,
    logical_row: u32,
    event_ordinal: u8,
    domain: relation.Domain,
    role: relation.Role,
    multiplicity: u32,
    arity: u8,
    tuple: [universal.MAX_ARITY]M31,

    pub fn validate(self: RelationEventV2) Error!void {
        if (self.roster_row >= ROW_COUNT or
            self.arity != relation.universalDescriptor(self.domain).arity)
        {
            return error.InvalidRelationEvent;
        }
        for (self.tuple[self.arity..]) |word| if (!word.isZero())
            return error.InvalidRelationEvent;
    }
};

pub const DestinationsV2 = struct {
    control: []ControlRowV2,
    transcript_air: []TranscriptAirRowV2,
    transcript_binding: []TranscriptBindingRowV2,
    transcript_state: []TranscriptStateRowV2,
    transcript_word: []TranscriptWordRowV2,
    transcript_payload: []TranscriptPayloadRowV2,
    pow_check: []PowCheckRowV2,
    pow_frame: []PowFrameRowV2,
    relation_challenge: []RelationChallengeRowV2,
    verifier_randomness: []VerifierRandomnessRowV2,
    relation_events: []RelationEventV2,
    poseidon_requests: []ProviderCall,
};

pub fn preflight(
    program: *const transcript.Program,
    execution: *const transcript.Execution,
    evidence: *const transcript.Evidence,
    plan: *const schedule.Plan,
    pcs_config: PcsConfig,
    data: *const public_data_v2.PublicDataV2,
    component_descs: []const statement_v1.FamilyComponentDesc,
    infra_descs: []const statement_v1.InfraComponentDesc,
) Error!PreparedV2 {
    return derivePrepared(
        program,
        execution,
        evidence,
        plan,
        pcs_config,
        data,
        component_descs,
        infra_descs,
    );
}

/// Fail-atomic pointer-free publication into caller storage.
pub fn prepareInto(
    destination: *PreparedV2,
    program: *const transcript.Program,
    execution: *const transcript.Execution,
    evidence: *const transcript.Evidence,
    plan: *const schedule.Plan,
    pcs_config: PcsConfig,
    data: *const public_data_v2.PublicDataV2,
    component_descs: []const statement_v1.FamilyComponentDesc,
    infra_descs: []const statement_v1.InfraComponentDesc,
) Error!void {
    const output = std.mem.asBytes(destination);
    try rejectSourceAlias(
        output,
        program,
        execution,
        evidence,
        plan,
        data,
        component_descs,
        infra_descs,
    );
    const staged = try derivePrepared(
        program,
        execution,
        evidence,
        plan,
        pcs_config,
        data,
        component_descs,
        infra_descs,
    );
    destination.* = staged;
}

pub fn derivePrepared(
    program: *const transcript.Program,
    execution: *const transcript.Execution,
    evidence: *const transcript.Evidence,
    plan: *const schedule.Plan,
    pcs_config: PcsConfig,
    data: *const public_data_v2.PublicDataV2,
    component_descs: []const statement_v1.FamilyComponentDesc,
    infra_descs: []const statement_v1.InfraComponentDesc,
) Error!PreparedV2 {
    try program.validateAgainst(
        plan,
        pcs_config,
        data,
        component_descs,
        infra_descs,
    );
    try execution.validateAgainst(program);
    try evidence.validateAgainst(execution, program);
    try validateProgramWords(program, plan);

    const counts = try deriveCounts(program, execution, plan);
    const manifest = try manifestFor(program, counts);
    var result = PreparedV2{
        .manifest = manifest,
        .authority = .{
            .program_id = program.identity,
            .wire_id = program.wire_id,
            .statement_authority_id = program.statement_authority_id,
        },
        .execution_id = execution.identity,
        .evidence_id = evidence.identity,
        .trace_receipt = evidence.trace_receipt,
        .final_digest = evidence.final_digest,
        .final_draw_count = evidence.final_draw_count,
        .source_id = undefined,
    };
    result.source_id = sourceId(&result);
    return result;
}

/// A mix frame advances the externally retained channel digest exactly once.
/// Every following draw reuses that digest, and the next mix consumes it once
/// before replacing it.  Returning the exact number of those consumers keeps
/// the digest-state lookup closed without inventing a state transition for a
/// draw.  The scan ranges between adjacent mix frames, so total work across a
/// transcript remains linear and the hot writer retains zero allocations.
pub fn stateConsumerCount(frames: []const transcript.HashFrame, mix_index: usize) u32 {
    std.debug.assert(mix_index < frames.len);
    std.debug.assert(frames[mix_index].purpose == .mix);
    var result: u32 = 0;
    for (frames[mix_index + 1 ..]) |frame| {
        result += 1;
        if (frame.purpose == .mix) break;
    }
    return result;
}

pub fn transcriptCallRow(
    execution: *const transcript.Execution,
    call_index: usize,
    frame: transcript.HashFrame,
) TranscriptAirRowV2 {
    const call = execution.poseidon_calls[call_index];
    const previous = if (call.id.step == 0)
        [_]M31{M31.zero()} ** transcript.WIDTH
    else
        execution.poseidon_calls[call_index - 1].output;
    var chunk: [channel.RATE]M31 = undefined;
    for (&chunk, call.input[0..channel.RATE], previous[0..channel.RATE]) |
        *target,
        input,
        prior,
    | target.* = input.sub(prior);
    return .{
        .enabler = 1,
        .verifier_id = VERIFIER_ID,
        .call_id = @intCast(call_index),
        .hash_id = frame.hash_id,
        .step = call.id.step,
        .is_first = @intFromBool(call.id.step == 0),
        .is_last = @intFromBool(call.id.step + 1 == frame.call_count),
        .is_draw = @intFromBool(frame.purpose == .draw),
        .previous = previous,
        .chunk = chunk,
        .output = call.output,
    };
}

pub const PayloadMetadata = struct {
    source_kind: PayloadSourceKindV2,
    item_index: u32,
    limb_index: u32,
    constant_mask: u32,
    input_use_count: u32,
};

pub fn payloadRow(
    instruction: transcript.Instruction,
    instruction_index: u32,
    hash_id: u32,
    payload_index: u32,
    source_word_index: u32,
    value: M31,
) TranscriptPayloadRowV2 {
    const metadata = payloadMetadata(instruction, payload_index);
    return .{
        .verifier_id = VERIFIER_ID,
        .instruction_index = instruction_index,
        .tag = typedTag(instruction.kind),
        .args = instruction.args,
        .payload_index = payload_index,
        .source_kind = metadata.source_kind,
        .item_index = metadata.item_index,
        .limb_index = metadata.limb_index,
        .constant_mask = metadata.constant_mask,
        .input_use_count = metadata.input_use_count,
        .source_hash_id = hash_id,
        .source_word_index = source_word_index,
        .value = value,
    };
}

pub fn payloadMetadata(
    instruction: transcript.Instruction,
    payload_index: u32,
) PayloadMetadata {
    return switch (instruction.kind) {
        .pcs_config => constantPayload(.pcs_parameters, 0, payload_index),
        .statement_header => dynamicPayload(.statement, 0, payload_index, 1),
        .statement_wire_id => dynamicPayload(.statement, 1, payload_index, 1),
        .statement_words => dynamicPayload(.statement, 2, payload_index, 1),
        .trace_commitment => dynamicPayload(
            .commitment,
            instruction.args[0],
            payload_index,
            1,
        ),
        .interaction_pow => dynamicPayload(
            .interaction_pow_nonce,
            0,
            payload_index,
            0,
        ),
        .claimed_sum => dynamicPayload(
            .claimed_sum,
            instruction.args[0],
            payload_index,
            1,
        ),
        .sampled_values => dynamicPayload(
            .sampled_value,
            payload_index / 4,
            payload_index % 4,
            2,
        ),
        .fri_commitment => dynamicPayload(
            .fri_commitment,
            instruction.args[0],
            payload_index,
            1,
        ),
        .last_layer_coefficients => dynamicPayload(
            .last_layer_coefficient,
            payload_index / 4,
            payload_index % 4,
            1,
        ),
        .pcs_pow => dynamicPayload(.pcs_pow_nonce, 0, payload_index, 0),
        .main_log_size,
        .shard_header,
        .shard_component,
        .shard_infra,
        .interaction_log_count,
        .interaction_log_size,
        => constantPayload(.public_geometry, instruction.sub_index, payload_index),
        else => unreachable,
    };
}

pub fn constantPayload(
    kind: PayloadSourceKindV2,
    item_index: u32,
    limb_index: u32,
) PayloadMetadata {
    return .{
        .source_kind = kind,
        .item_index = item_index,
        .limb_index = limb_index,
        .constant_mask = 1,
        .input_use_count = 0,
    };
}

pub fn dynamicPayload(
    kind: PayloadSourceKindV2,
    item_index: u32,
    limb_index: u32,
    input_use_count: u32,
) PayloadMetadata {
    return .{
        .source_kind = kind,
        .item_index = item_index,
        .limb_index = limb_index,
        .constant_mask = 0,
        .input_use_count = input_use_count,
    };
}

pub fn rejectSourceAlias(
    output: []const u8,
    program: *const transcript.Program,
    execution: *const transcript.Execution,
    evidence: *const transcript.Evidence,
    plan: *const schedule.Plan,
    data: *const public_data_v2.PublicDataV2,
    component_descs: []const statement_v1.FamilyComponentDesc,
    infra_descs: []const statement_v1.InfraComponentDesc,
) Error!void {
    const sources = [_][]const u8{
        std.mem.asBytes(program),
        std.mem.sliceAsBytes(program.instructions),
        std.mem.asBytes(execution),
        std.mem.sliceAsBytes(execution.poseidon_calls),
        std.mem.sliceAsBytes(execution.hash_frames),
        std.mem.sliceAsBytes(execution.pow_checks),
        std.mem.sliceAsBytes(execution.word_storage),
        std.mem.sliceAsBytes(execution.operations),
        std.mem.asBytes(evidence),
        std.mem.asBytes(plan),
        std.mem.sliceAsBytes(plan.steps),
        std.mem.asBytes(data),
        std.mem.sliceAsBytes(data.words()),
        std.mem.sliceAsBytes(component_descs),
        std.mem.sliceAsBytes(infra_descs),
    };
    for (sources) |source| if (overlap(output, source))
        return error.AliasedDestination;
}

pub fn validateExecutionSnapshot(
    prepared: *const PreparedV2,
    program: *const transcript.Program,
    execution: *const transcript.Execution,
    plan: *const schedule.Plan,
) Error!void {
    try plan.validate();
    try execution.validateAgainst(program);
    try validateProgramWords(program, plan);
    const evidence = try execution.evidence(program);
    const counts = try deriveCounts(program, execution, plan);
    const manifest = try manifestFor(program, counts);
    if (prepared.format_version != FORMAT_VERSION or
        prepared.schema_version != SCHEMA_VERSION or
        !std.meta.eql(prepared.manifest, manifest) or
        !std.meta.eql(prepared.authority.program_id, program.identity) or
        !std.meta.eql(prepared.authority.wire_id, program.wire_id) or
        !std.meta.eql(
            prepared.authority.statement_authority_id,
            program.statement_authority_id,
        ) or
        !std.meta.eql(prepared.execution_id, execution.identity) or
        !std.meta.eql(prepared.evidence_id, evidence.identity) or
        !std.mem.eql(u8, &prepared.trace_receipt, &evidence.trace_receipt) or
        !std.meta.eql(prepared.final_digest, execution.final_digest) or
        prepared.final_draw_count != execution.final_draw_count or
        !std.meta.eql(prepared.source_id, sourceId(prepared)))
    {
        return error.SourceMismatch;
    }
}

pub fn rejectRawQueryAliases(
    destination: []M31,
    prepared: *const PreparedV2,
    program: *const transcript.Program,
    execution: *const transcript.Execution,
    plan: *const schedule.Plan,
) Error!void {
    const output = std.mem.sliceAsBytes(destination);
    const sources = [_][]const u8{
        std.mem.asBytes(prepared),
        std.mem.asBytes(program),
        std.mem.sliceAsBytes(program.instructions),
        std.mem.asBytes(execution),
        std.mem.sliceAsBytes(execution.poseidon_calls),
        std.mem.sliceAsBytes(execution.hash_frames),
        std.mem.sliceAsBytes(execution.pow_checks),
        std.mem.sliceAsBytes(execution.word_storage),
        std.mem.sliceAsBytes(execution.operations),
        std.mem.asBytes(plan),
        std.mem.sliceAsBytes(plan.steps),
    };
    for (sources) |source| if (overlap(output, source))
        return error.AliasedDestination;
}

pub fn sourceId(prepared: *const PreparedV2) Digest {
    var hash = IdentityHasher.init(SOURCE_ID_DOMAIN);
    hash.scalar(prepared.format_version);
    hash.scalar(prepared.schema_version);
    hash.digest(prepared.manifest.identity);
    hash.digest(prepared.authority.program_id);
    hash.digest(prepared.authority.wire_id);
    hash.digest(prepared.authority.statement_authority_id);
    hash.digest(prepared.execution_id);
    hash.digest(prepared.evidence_id);
    hash.bytes(&prepared.trace_receipt);
    hash.digest(prepared.final_digest);
    hash.u32Value(prepared.final_draw_count);
    return hash.finalize();
}

pub fn rangeId(range: *const PoseidonRequestRangeV2) Digest {
    var hash = IdentityHasher.init(RANGE_ID_DOMAIN);
    hash.scalar(range.format_version);
    hash.scalar(range.schema_version);
    hash.digest(range.source_id);
    hash.digest(range.program_id);
    hash.u32Value(range.first);
    hash.u32Value(range.count);
    hash.u32Value(range.end);
    return hash.finalize();
}
