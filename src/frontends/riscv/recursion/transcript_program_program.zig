//! Internal transcript program v2 authority shard; use transcript_program_v2.zig publicly.

const dependency_0 = @import("transcript_program_v2_contract.zig");

const Check = dependency_0.Check;
const Digest = dependency_0.Digest;
const Draw = dependency_0.Draw;
const EVIDENCE_ID_DOMAIN = dependency_0.EVIDENCE_ID_DOMAIN;
const Error = dependency_0.Error;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const HashFrame = dependency_0.HashFrame;
const IdentityHasher = dependency_0.IdentityHasher;
const Instruction = dependency_0.Instruction;
const lookup_physical_v2 = dependency_0.lookup_physical_v2;
const M31 = dependency_0.M31;
const PROGRAM_ID_DOMAIN = dependency_0.PROGRAM_ID_DOMAIN;
const PcsConfig = dependency_0.PcsConfig;
const PoseidonCall = dependency_0.PoseidonCall;
const QM31 = dependency_0.QM31;
const RATE = dependency_0.RATE;
const SCHEMA_VERSION = dependency_0.SCHEMA_VERSION;
const TranscriptTrace = dependency_0.TranscriptTrace;
const add = dependency_0.add;
const buildInstructions = dependency_0.buildInstructions;
const channel = dependency_0.channel;
const countKind = dependency_0.countKind;
const hashPcsConfig = dependency_0.hashPcsConfig;
const m31 = dependency_0.m31;
const pcsConfigEql = dependency_0.pcsConfigEql;
const public_data_v2 = dependency_0.public_data_v2;
const relation_challenges = dependency_0.relation_challenges;
const schedule = dependency_0.schedule;
const statement_v1 = dependency_0.statement_v1;
const statement_v2 = dependency_0.statement_v2;
const std = dependency_0.std;
const validatePcsAgainstPlan = dependency_0.validatePcsAgainstPlan;
const validatePlanPrefix = dependency_0.validatePlanPrefix;

/// Verifier-owned expansion of one admitted V2 VM transcript shape.
pub const Program = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    plan_id: Digest,
    wire_id: Digest,
    statement_authority_id: Digest,
    wire_word_count: u32,
    pcs_config: PcsConfig,
    lookup_activation: ?lookup_physical_v2.AuthenticatedStatement = null,
    instructions: []Instruction,
    identity: Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        plan: *const schedule.Plan,
        pcs_config: PcsConfig,
        data: *const public_data_v2.PublicDataV2,
        component_descs: []const statement_v1.FamilyComponentDesc,
        infra_descs: []const statement_v1.InfraComponentDesc,
    ) Error!Program {
        return initForLookupLayout(
            allocator,
            plan,
            pcs_config,
            data,
            component_descs,
            infra_descs,
            false,
        );
    }

    /// Exact default SegmentV2 transcript, including its four authenticated
    /// physical-lookup V2 mixes and selected Tree-2 column geometry.
    pub fn initAuthenticatedLookupV2(
        allocator: std.mem.Allocator,
        plan: *const schedule.Plan,
        pcs_config: PcsConfig,
        data: *const public_data_v2.PublicDataV2,
        component_descs: []const statement_v1.FamilyComponentDesc,
        infra_descs: []const statement_v1.InfraComponentDesc,
    ) Error!Program {
        return initForLookupLayout(
            allocator,
            plan,
            pcs_config,
            data,
            component_descs,
            infra_descs,
            true,
        );
    }

    fn initForLookupLayout(
        allocator: std.mem.Allocator,
        plan: *const schedule.Plan,
        pcs_config: PcsConfig,
        data: *const public_data_v2.PublicDataV2,
        component_descs: []const statement_v1.FamilyComponentDesc,
        infra_descs: []const statement_v1.InfraComponentDesc,
        authenticated_lookup_v2: bool,
    ) Error!Program {
        try plan.validate();
        try data.validate();
        try validatePlanPrefix(plan);
        try validatePcsAgainstPlan(pcs_config, plan);
        if (component_descs.len > statement_v1.MAX_COMPONENTS or
            infra_descs.len > statement_v1.MAX_INFRA_COMPONENTS)
        {
            return error.ProgramShapeMismatch;
        }

        const wire_word_count = std.math.cast(u32, data.words().len) orelse
            return error.WordCountOutOfRange;
        const statement_authority_id = try statement_v2.authorityIdentityFromGeometry(
            data,
            component_descs,
            infra_descs,
        );
        var lookup_manifest = lookup_physical_v2.Manifest.native();
        const lookup_activation = if (authenticated_lookup_v2)
            try lookupActivation(component_descs, &lookup_manifest)
        else
            null;
        if (authenticated_lookup_v2)
            lookup_manifest.validate() catch return error.ProgramShapeMismatch;
        var instructions: std.ArrayList(Instruction) = .empty;
        errdefer instructions.deinit(allocator);
        try buildInstructions(
            allocator,
            &instructions,
            plan,
            pcs_config,
            wire_word_count,
            component_descs,
            infra_descs,
            lookup_activation,
            if (authenticated_lookup_v2) &lookup_manifest else null,
        );
        const owned = try instructions.toOwnedSlice(allocator);
        errdefer allocator.free(owned);
        var result = Program{
            .allocator = allocator,
            .plan_id = plan.authority_digest,
            .wire_id = data.wireId(),
            .statement_authority_id = statement_authority_id,
            .wire_word_count = wire_word_count,
            .pcs_config = pcs_config,
            .lookup_activation = lookup_activation,
            .instructions = owned,
            .identity = undefined,
        };
        result.identity = programIdentity(&result);
        try result.validateAgainst(
            plan,
            pcs_config,
            data,
            component_descs,
            infra_descs,
        );
        return result;
    }

    pub fn deinit(self: *Program) void {
        self.allocator.free(self.instructions);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const Program,
        plan: *const schedule.Plan,
        pcs_config: PcsConfig,
        data: *const public_data_v2.PublicDataV2,
        component_descs: []const statement_v1.FamilyComponentDesc,
        infra_descs: []const statement_v1.InfraComponentDesc,
    ) Error!void {
        try plan.validate();
        try data.validate();
        try validatePlanPrefix(plan);
        try validatePcsAgainstPlan(pcs_config, plan);
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION)
        {
            return error.UnsupportedVersion;
        }
        const authority_id = try statement_v2.authorityIdentityFromGeometry(
            data,
            component_descs,
            infra_descs,
        );
        var lookup_manifest = lookup_physical_v2.Manifest.native();
        const expected_lookup = if (self.lookup_activation != null)
            try lookupActivation(component_descs, &lookup_manifest)
        else
            null;
        if (!std.meta.eql(self.plan_id, plan.authority_digest) or
            !std.meta.eql(self.wire_id, data.wireId()) or
            !std.meta.eql(self.statement_authority_id, authority_id) or
            self.wire_word_count != data.words().len or
            !pcsConfigEql(self.pcs_config, pcs_config) or
            !std.meta.eql(self.lookup_activation, expected_lookup) or
            self.instructions.len == 0 or
            !std.meta.eql(self.identity, programIdentity(self)))
        {
            return error.AuthorityMismatch;
        }
        try validateInstructionShape(self);
    }

    pub fn relationDrawCount(self: *const Program) usize {
        return countKind(self.instructions, .relation_draw);
    }

    pub fn traceCommitmentCount(self: *const Program) usize {
        return countKind(self.instructions, .trace_commitment);
    }

    pub fn friCommitmentCount(self: *const Program) usize {
        return countKind(self.instructions, .fri_commitment);
    }
};

/// Dynamic proof values consumed in verifier-program order. Statement and VM
/// geometry are deliberately absent: those come from authenticated authority.
pub const Inputs = struct {
    trace_commitments: []const Digest,
    interaction_pow: u64,
    claimed_sums: []const QM31,
    sampled_values: []const QM31,
    fri_commitments: []const Digest,
    last_layer_coefficients: []const QM31,
    pcs_pow: u64,

    pub fn validate(self: Inputs, program: *const Program) Error!void {
        if (self.trace_commitments.len != program.traceCommitmentCount() or
            self.fri_commitments.len != program.friCommitmentCount())
        {
            return error.InvalidInputCount;
        }
        for (program.instructions) |instruction| switch (instruction.kind) {
            .claimed_sum => if (instruction.args[0] >= self.claimed_sums.len)
                return error.InvalidInputCount,
            .sampled_values => if (instruction.args[0] != self.sampled_values.len)
                return error.InvalidInputCount,
            .last_layer_coefficients => if (instruction.args[0] !=
                self.last_layer_coefficients.len) return error.InvalidInputCount,
            else => {},
        };
        for (self.trace_commitments) |digest| try validateDigest(digest);
        for (self.fri_commitments) |digest| try validateDigest(digest);
        for (self.claimed_sums) |value| try validateQm31(value);
        for (self.sampled_values) |value| try validateQm31(value);
        for (self.last_layer_coefficients) |value| try validateQm31(value);
    }
};

pub const Operation = struct {
    instruction_index: u32,
    first_hash_id: u32,
    hash_count: u32,
    first_call_id: u32,
    call_count: u32,
    draw: ?Draw,
};

/// Value-only recursive handoff for rows 0--9 and the shared Poseidon provider.
pub const Evidence = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    program_id: Digest,
    wire_id: Digest,
    statement_authority_id: Digest,
    frame_count: u32,
    poseidon_call_count: u32,
    pow_check_count: u32,
    final_digest: Digest,
    final_draw_count: u32,
    trace_receipt: [32]u8,
    identity: Digest,

    pub fn validateAgainst(
        self: *const Evidence,
        execution: *const Execution,
        program: *const Program,
    ) Error!void {
        const expected = try evidenceFor(execution, program);
        if (!std.meta.eql(self.*, expected)) return error.AuthorityMismatch;
    }
};

/// Exact raw sponge evidence. Construction owns five retained allocations and
/// publishes nothing on failure.
pub const Execution = struct {
    allocator: std.mem.Allocator,
    program_id: Digest,
    wire_id: Digest,
    statement_authority_id: Digest,
    poseidon_calls: []PoseidonCall,
    hash_frames: []HashFrame,
    pow_checks: []Check,
    word_storage: []M31,
    operations: []Operation,
    final_digest: Digest,
    final_draw_count: u32,
    identity: Digest,

    pub fn deinit(self: *Execution) void {
        self.allocator.free(self.operations);
        self.allocator.free(self.word_storage);
        self.allocator.free(self.pow_checks);
        self.allocator.free(self.hash_frames);
        self.allocator.free(self.poseidon_calls);
        self.* = undefined;
    }

    pub fn trace(self: *const Execution) TranscriptTrace {
        return .{
            .poseidon_calls = self.poseidon_calls,
            .hash_frames = self.hash_frames,
            .pow_checks = self.pow_checks,
        };
    }

    pub fn poseidonCalls(self: *const Execution) []const PoseidonCall {
        return self.poseidon_calls;
    }

    pub fn evidence(self: *const Execution, program: *const Program) Error!Evidence {
        return evidenceFor(self, program);
    }

    pub fn validateAgainst(self: *const Execution, program: *const Program) Error!void {
        if (!std.meta.eql(self.program_id, program.identity) or
            !std.meta.eql(self.wire_id, program.wire_id) or
            !std.meta.eql(self.statement_authority_id, program.statement_authority_id) or
            self.operations.len != program.instructions.len)
        {
            return error.AuthorityMismatch;
        }
        self.trace().validate() catch return error.InvalidTranscriptTrace;
        try validateWordOwnership(self);
        try validateOperations(self, program);
        if (!std.meta.eql(self.identity, executionIdentity(self)))
            return error.AuthorityMismatch;
    }

    /// Replays recorded raw frames through the ordinary production channel.
    pub fn replayNative(self: *const Execution, program: *const Program) Error!void {
        try self.validateAgainst(program);
        var native = channel.Channel{};
        var frame_at: usize = 0;
        var draw_count: u32 = 0;
        for (program.instructions) |instruction| {
            switch (instruction.effect()) {
                .mix => {
                    const frame = self.hash_frames[frame_at];
                    try expectDigestPrefix(native.digestWords(), frame.words);
                    native.mixCanonicalM31Words(frame.words[RATE..]);
                    try expectDigest(native.digestWords(), frame.output[0..RATE].*);
                    draw_count = 0;
                    frame_at += 1;
                },
                .draw => {
                    const frame = self.hash_frames[frame_at];
                    try expectDigestPrefix(native.digestWords(), frame.words);
                    const actual = native.drawU32s();
                    try expectDigest(actual, frame.output[0..RATE].*);
                    draw_count += 1;
                    frame_at += 1;
                },
                .pow => {
                    const mix_frame = self.hash_frames[frame_at];
                    try expectDigestPrefix(native.digestWords(), mix_frame.words);
                    native.mixCanonicalM31Words(mix_frame.words[RATE..]);
                    try expectDigest(native.digestWords(), mix_frame.output[0..RATE].*);
                    const draw_frame = self.hash_frames[frame_at + 1];
                    const actual = native.drawU32s();
                    try expectDigest(actual, draw_frame.output[0..RATE].*);
                    native.n_draws = 0;
                    draw_count = 0;
                    frame_at += 2;
                },
            }
        }
        if (frame_at != self.hash_frames.len or
            draw_count != self.final_draw_count or
            !std.meta.eql(native.digestWords(), self.final_digest))
        {
            return error.InvalidTranscriptTrace;
        }
    }
};

pub const Layout = struct {
    call_count: usize = 0,
    frame_count: usize = 0,
    pow_count: usize = 0,
    word_count: usize = 0,

    pub fn init(program: *const Program) Error!Layout {
        var result = Layout{};
        for (program.instructions) |instruction| {
            const effect = instruction.effect();
            if (effect != .draw) {
                const words = try add(RATE, try instruction.payloadWordCount());
                result.word_count = try add(result.word_count, words);
                result.frame_count = try add(result.frame_count, 1);
                result.call_count = try add(result.call_count, try frameCallCount(words));
            }
            if (effect != .mix) {
                const words = RATE + 2;
                result.word_count = try add(result.word_count, words);
                result.frame_count = try add(result.frame_count, 1);
                result.call_count = try add(result.call_count, try frameCallCount(words));
            }
            result.pow_count = try add(result.pow_count, @intFromBool(effect == .pow));
        }
        if (result.call_count >= m31.Modulus) return error.CallCountOutOfRange;
        if (result.frame_count >= m31.Modulus) return error.FrameCountOutOfRange;
        if (program.instructions.len >= m31.Modulus)
            return error.OperationCountOutOfRange;
        if (result.word_count >= std.math.maxInt(u32))
            return error.WordCountOutOfRange;
        return result;
    }
};

pub fn writePayload(
    destination: []M31,
    program: *const Program,
    data: *const public_data_v2.PublicDataV2,
    inputs: Inputs,
    instruction: Instruction,
) Error!void {
    if (destination.len != try instruction.payloadWordCount())
        return error.DestinationLengthMismatch;
    switch (instruction.kind) {
        .pcs_config => writePcsFelts(destination, program.pcs_config),
        .statement_header => writeU32s(destination, &.{
            public_data_v2.STATEMENT_TRANSCRIPT_DOMAIN,
            public_data_v2.STATEMENT_TRANSCRIPT_VERSION,
            public_data_v2.STATEMENT_TRANSCRIPT_SCHEMA_VERSION,
            program.wire_word_count,
        }),
        .statement_wire_id => writeU32s(destination, &program.wire_id),
        .statement_words => @memcpy(destination, data.words()),
        .lookup_activation_header => {
            const activation = program.lookup_activation orelse
                return error.ProgramShapeMismatch;
            writeU32s(destination, &.{
                lookup_physical_v2.TRANSCRIPT_TAG,
                lookup_physical_v2.FORMAT_VERSION,
                activation.format_version,
                activation.component_count,
                activation.opcode_main_columns,
                activation.opcode_interaction_columns,
                activation.detailed_claim_count,
            });
        },
        .lookup_manifest_identity => try writeSha256Digest(
            destination,
            (program.lookup_activation orelse
                return error.ProgramShapeMismatch).manifest_identity,
        ),
        .lookup_statement_identity => try writeSha256Digest(
            destination,
            (program.lookup_activation orelse
                return error.ProgramShapeMismatch).statement_identity,
        ),
        .lookup_activation_identity => try writeSha256Digest(
            destination,
            (program.lookup_activation orelse
                return error.ProgramShapeMismatch).activation_identity,
        ),
        .trace_commitment => try writeDigest(
            destination,
            inputs.trace_commitments[instruction.args[0]],
        ),
        .main_log_size => writeU64(destination, instruction.args[1]),
        .shard_header => writeU32s(destination, &.{
            0x5348_5244,
            instruction.args[0],
            instruction.args[1],
        }),
        .shard_component, .shard_infra => writeU32s(destination, &instruction.args),
        .claimed_sum => writeQm31(destination, inputs.claimed_sums[instruction.args[0]]),
        .interaction_log_count => writeU64(destination, instruction.args[0]),
        .interaction_log_size => writeU64(destination, instruction.args[1]),
        .sampled_values => writeQm31s(destination, inputs.sampled_values),
        .fri_commitment => try writeDigest(
            destination,
            inputs.fri_commitments[instruction.args[0]],
        ),
        .last_layer_coefficients => writeQm31s(
            destination,
            inputs.last_layer_coefficients,
        ),
        .interaction_pow,
        .pcs_pow,
        .relation_draw,
        .composition_draw,
        .oods_draw,
        .deep_draw,
        .fri_alpha_draw,
        .query_draw,
        => return error.ProgramShapeMismatch,
    }
}

pub fn validateInstructionShape(program: *const Program) Error!void {
    var saw_header = false;
    var saw_wire = false;
    var saw_words = false;
    var saw_pcs = false;
    var lookup_mix_count: usize = 0;
    for (program.instructions) |instruction| {
        _ = try instruction.payloadWordCount();
        switch (instruction.kind) {
            .pcs_config => saw_pcs = true,
            .statement_header => saw_header = true,
            .statement_wire_id => saw_wire = true,
            .statement_words => {
                saw_words = instruction.args[0] == program.wire_word_count;
            },
            .lookup_activation_header,
            .lookup_manifest_identity,
            .lookup_statement_identity,
            .lookup_activation_identity,
            => {
                if (instruction.verifier_sequence != 1)
                    return error.ProgramShapeMismatch;
                lookup_mix_count += 1;
            },
            else => {},
        }
    }
    const expected_lookup_mix_count: usize =
        if (program.lookup_activation != null) 4 else 0;
    if (!saw_pcs or !saw_header or !saw_wire or !saw_words or
        lookup_mix_count != expected_lookup_mix_count or
        program.relationDrawCount() != relation_challenges.RELATION_COUNT or
        program.traceCommitmentCount() != 4)
    {
        return error.ProgramShapeMismatch;
    }
}

pub fn programIdentity(program: *const Program) Digest {
    var hash = IdentityHasher.init(PROGRAM_ID_DOMAIN);
    hash.scalar(program.format_version);
    hash.scalar(program.schema_version);
    hash.digest(program.plan_id);
    hash.digest(program.wire_id);
    hash.digest(program.statement_authority_id);
    hash.u32Value(program.wire_word_count);
    hashPcsConfig(&hash, program.pcs_config);
    if (program.lookup_activation) |activation| {
        hash.scalar(lookup_physical_v2.FORMAT_VERSION);
        hash.scalar(activation.format_version);
        hash.bytes(&activation.manifest_identity);
        hash.bytes(&activation.statement_identity);
        hash.bytes(&activation.activation_identity);
        hash.u32Value(activation.component_count);
        hash.u32Value(activation.opcode_main_columns);
        hash.u32Value(activation.opcode_interaction_columns);
        hash.u32Value(activation.detailed_claim_count);
    }
    hash.u32Value(@intCast(program.instructions.len));
    for (program.instructions) |instruction| {
        hash.scalar(@intFromEnum(instruction.kind));
        hash.u32Value(instruction.verifier_sequence);
        hash.u32Value(instruction.sub_index);
        for (instruction.args) |value| hash.u32Value(value);
    }
    return hash.finalize();
}

pub fn executionIdentity(execution: *const Execution) Digest {
    var hash = IdentityHasher.init(EVIDENCE_ID_DOMAIN);
    hash.digest(execution.program_id);
    hash.digest(execution.wire_id);
    hash.digest(execution.statement_authority_id);
    hash.u32Value(@intCast(execution.poseidon_calls.len));
    hash.u32Value(@intCast(execution.hash_frames.len));
    hash.u32Value(@intCast(execution.pow_checks.len));
    hash.u32Value(@intCast(execution.operations.len));
    hash.digest(execution.final_digest);
    hash.u32Value(execution.final_draw_count);
    hash.bytes(&execution.trace().receiptDigest());
    return hash.finalize();
}

pub fn evidenceFor(execution: *const Execution, program: *const Program) Error!Evidence {
    try execution.validateAgainst(program);
    const result = Evidence{
        .program_id = program.identity,
        .wire_id = program.wire_id,
        .statement_authority_id = program.statement_authority_id,
        .frame_count = @intCast(execution.hash_frames.len),
        .poseidon_call_count = @intCast(execution.poseidon_calls.len),
        .pow_check_count = @intCast(execution.pow_checks.len),
        .final_digest = execution.final_digest,
        .final_draw_count = execution.final_draw_count,
        .trace_receipt = execution.trace().receiptDigest(),
        .identity = execution.identity,
    };
    return result;
}

pub fn validateWordOwnership(execution: *const Execution) Error!void {
    var at: usize = 0;
    for (execution.hash_frames) |frame| {
        const end = try add(at, frame.words.len);
        if (end > execution.word_storage.len or
            frame.words.ptr != execution.word_storage[at..end].ptr)
        {
            return error.AuthorityMismatch;
        }
        at = end;
    }
    if (at != execution.word_storage.len) return error.AuthorityMismatch;
}

pub fn validateOperations(execution: *const Execution, program: *const Program) Error!void {
    var frame_at: usize = 0;
    var call_at: usize = 0;
    var draw_count: u32 = 0;
    var final_digest = [_]M31{M31.zero()} ** RATE;
    for (program.instructions, execution.operations, 0..) |instruction, operation, index| {
        const expected_frames: usize = if (instruction.effect() == .pow) 2 else 1;
        if (frame_at > execution.hash_frames.len or
            expected_frames > execution.hash_frames.len - frame_at)
        {
            return error.AuthorityMismatch;
        }
        if (operation.instruction_index != index or
            operation.first_hash_id != frame_at or
            operation.first_call_id != call_at or
            operation.hash_count != expected_frames or
            (operation.draw != null) != (instruction.effect() == .draw))
        {
            return error.AuthorityMismatch;
        }
        var calls: usize = 0;
        for (execution.hash_frames[frame_at .. frame_at + expected_frames]) |frame|
            calls = try add(calls, frame.call_count);
        if (operation.call_count != calls) return error.AuthorityMismatch;
        switch (instruction.effect()) {
            .mix => {
                final_digest = execution.hash_frames[frame_at].output[0..RATE].*;
                draw_count = 0;
            },
            .draw => {
                const expected_draw = execution.hash_frames[frame_at].output[0..RATE].*;
                const actual_draw = operation.draw orelse
                    return error.AuthorityMismatch;
                if (!fieldArrayEql(RATE, actual_draw, expected_draw))
                    return error.AuthorityMismatch;
                draw_count += 1;
            },
            .pow => {
                final_digest = execution.hash_frames[frame_at].output[0..RATE].*;
                draw_count = 0;
            },
        }
        frame_at += expected_frames;
        call_at += calls;
    }
    if (frame_at != execution.hash_frames.len or call_at != execution.poseidon_calls.len or
        draw_count != execution.final_draw_count or
        !fieldArrayEql(RATE, final_digest, digestFields(execution.final_digest)))
    {
        return error.AuthorityMismatch;
    }
}

pub fn writePcsFelts(destination: []M31, config: PcsConfig) void {
    const first = QM31.fromU32Unchecked(
        config.pow_bits,
        config.fri_config.log_blowup_factor,
        @intCast(config.fri_config.n_queries),
        config.fri_config.log_last_layer_degree_bound,
    );
    writeQm31(destination[0..4], first);
    if (destination.len == 8) writeQm31(destination[4..8], QM31.fromU32Unchecked(
        config.fri_config.fold_step,
        config.lifting_log_size orelse 0,
        0,
        0,
    ));
}

pub fn writeU32s(destination: []M31, values: []const u32) void {
    std.debug.assert(destination.len == 2 * values.len);
    for (values, 0..) |value, index| {
        destination[2 * index] = M31.fromCanonical(value & 0xffff);
        destination[2 * index + 1] = M31.fromCanonical(value >> 16);
    }
}

pub fn writeU64(destination: []M31, value: u64) void {
    std.debug.assert(destination.len == 4);
    writeU32s(destination, &.{ @truncate(value), @truncate(value >> 32) });
}

pub fn writeQm31(destination: []M31, value: QM31) void {
    std.debug.assert(destination.len == 4);
    destination[0..4].* = value.toM31Array();
}

pub fn writeQm31s(destination: []M31, values: []const QM31) void {
    std.debug.assert(destination.len == 4 * values.len);
    for (values, 0..) |value, index| writeQm31(destination[4 * index ..][0..4], value);
}

pub fn writeDigest(destination: []M31, value: Digest) Error!void {
    if (destination.len != RATE) return error.DestinationLengthMismatch;
    for (destination, value) |*word, raw| word.* = try canonical(raw);
}

fn writeSha256Digest(
    destination: []M31,
    value: lookup_physical_v2.Digest,
) Error!void {
    if (destination.len != 16) return error.DestinationLengthMismatch;
    var limbs: [8]u32 = undefined;
    for (&limbs, 0..) |*limb, index| {
        limb.* = std.mem.readInt(
            u32,
            value[index * @sizeOf(u32) ..][0..@sizeOf(u32)],
            .little,
        );
    }
    writeU32s(destination, &limbs);
}

fn lookupActivation(
    component_descs: []const statement_v1.FamilyComponentDesc,
    manifest: *const lookup_physical_v2.Manifest,
) Error!lookup_physical_v2.AuthenticatedStatement {
    var core: statement_v1.RiscVStatement = undefined;
    core.n_components = @intCast(component_descs.len);
    @memcpy(core.component_descs[0..component_descs.len], component_descs);
    return lookup_physical_v2.AuthenticatedStatement.init(
        &core,
        manifest,
    ) catch error.ProgramShapeMismatch;
}

pub fn validateDigest(value: Digest) Error!void {
    for (value) |word| if (word >= m31.Modulus) return error.InvalidFieldElement;
}

pub fn validateQm31(value: QM31) Error!void {
    for (value.toM31Array()) |word| if (word.toU32() >= m31.Modulus)
        return error.InvalidFieldElement;
}

pub fn canonical(value: u32) Error!M31 {
    if (value >= m31.Modulus) return error.InvalidFieldElement;
    return M31.fromCanonical(value);
}

pub fn rawDigest(value: Draw) Digest {
    var result: Digest = undefined;
    for (&result, value) |*destination, word| destination.* = word.toU32();
    return result;
}

pub fn digestFields(value: Digest) Draw {
    var result: Draw = undefined;
    for (&result, value) |*destination, word|
        destination.* = M31.fromCanonical(word);
    return result;
}

pub fn frameCallCount(word_count: usize) Error!usize {
    return std.math.divCeil(usize, try add(word_count, 1), RATE) catch
        return error.ArithmeticOverflow;
}

pub fn expectDigestPrefix(expected: Digest, words: []const M31) Error!void {
    if (words.len < RATE) return error.InvalidTranscriptTrace;
    try expectDigest(expected, words[0..RATE].*);
}

pub fn expectDigest(expected: Digest, actual: Draw) Error!void {
    for (expected, actual) |left, right|
        if (left != right.toU32()) return error.InvalidTranscriptTrace;
}

pub fn fieldArrayEql(comptime count: usize, left: [count]M31, right: [count]M31) bool {
    for (left, right) |a, b| if (!a.eql(b)) return false;
    return true;
}
