//! Internal segment transcript outer source v2 authority shard; use segment_transcript_outer_source_v2.zig publicly.

const dependency_0 = @import("segment_transcript_outer_source_v2_contract.zig");
const dependency_1 = @import("segment_transcript_outer_source_v2_prepared_v2.zig");
const dependency_2 = @import("segment_transcript_outer_source_v2_write_rows_assume_valid.zig");

const CountsV2 = dependency_0.CountsV2;
const DestinationsV2 = dependency_1.DestinationsV2;
const Error = dependency_0.Error;
const EventSink = dependency_2.EventSink;
const FIRST_ROW = dependency_0.FIRST_ROW;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const LAST_ROW = dependency_0.LAST_ROW;
const M31 = dependency_0.M31;
const MANIFEST_VERSION = dependency_0.MANIFEST_VERSION;
const PcsConfig = dependency_0.PcsConfig;
const PreparedV2 = dependency_1.PreparedV2;
const ProviderCall = dependency_0.ProviderCall;
const ROW_COUNT = dependency_0.ROW_COUNT;
const VerifierRandomnessRowV2 = dependency_1.VerifierRandomnessRowV2;
const channel = dependency_0.channel;
const felt = dependency_0.felt;
const feltArgs = dependency_2.feltArgs;
const overlap = dependency_0.overlap;
const preflight = dependency_1.preflight;
const provider = dependency_0.provider;
const public_data_v2 = dependency_0.public_data_v2;
const rejectSourceAlias = dependency_1.rejectSourceAlias;
const relation = dependency_0.relation;
const schedule = dependency_0.schedule;
const statement_v1 = dependency_0.statement_v1;
const std = dependency_0.std;
const transcript = dependency_0.transcript;
const writeBindingEvents = dependency_2.writeBindingEvents;
const writePayloadEvents = dependency_2.writePayloadEvents;
const writePowCheckEvents = dependency_2.writePowCheckEvents;
const writePowFrameEvents = dependency_2.writePowFrameEvents;
const writeRelationChallengeEvents = dependency_2.writeRelationChallengeEvents;
const writeRowsAssumeValid = dependency_2.writeRowsAssumeValid;
const writeStateEvents = dependency_2.writeStateEvents;
const writeTranscriptAirEvents = dependency_2.writeTranscriptAirEvents;
const writeWordEvents = dependency_2.writeWordEvents;

/// Revalidates every authority and destination before writing any row, event,
/// or provider request.  The post-preflight loops are allocation-free and
/// infallible over the admitted geometry.
pub fn writeInto(
    prepared: *const PreparedV2,
    destinations: DestinationsV2,
    program: *const transcript.Program,
    execution: *const transcript.Execution,
    evidence: *const transcript.Evidence,
    plan: *const schedule.Plan,
    pcs_config: PcsConfig,
    data: *const public_data_v2.PublicDataV2,
    component_descs: []const statement_v1.FamilyComponentDesc,
    infra_descs: []const statement_v1.InfraComponentDesc,
) Error!void {
    try validateDestinationGeometry(destinations, prepared.counts());
    try rejectDestinationAliases(
        destinations,
        prepared,
        program,
        execution,
        evidence,
        plan,
        data,
        component_descs,
        infra_descs,
    );
    try prepared.validateAgainst(
        program,
        execution,
        evidence,
        plan,
        pcs_config,
        data,
        component_descs,
        infra_descs,
    );

    writeRowsAssumeValid(destinations, program, execution, plan);
    writeEventsAssumeValid(destinations);
    writeProviderAssumeValid(destinations.poseidon_requests, execution);
}

pub fn writeEventsAssumeValid(destinations: DestinationsV2) void {
    var sink = EventSink{ .events = destinations.relation_events };

    for (destinations.control, 0..) |row, logical_row| {
        const tuple = [_]M31{
            felt(row.verifier_id),
            felt(row.sequence),
            felt(row.tag),
        } ++ feltArgs(row.args);
        sink.put(.control, logical_row, 0, .recursion_step, .emit, 1, &tuple);
        sink.put(
            .control,
            logical_row,
            1,
            .recursion_step,
            .consume,
            row.terminal_mask,
            &tuple,
        );
    }

    for (destinations.transcript_air, 0..) |row, logical_row|
        writeTranscriptAirEvents(&sink, logical_row, row);
    for (destinations.transcript_binding, 0..) |row, logical_row|
        writeBindingEvents(&sink, logical_row, row);
    for (destinations.transcript_state, 0..) |row, logical_row|
        writeStateEvents(&sink, logical_row, row);
    for (destinations.transcript_word, 0..) |row, logical_row|
        writeWordEvents(&sink, logical_row, row);
    for (destinations.transcript_payload, 0..) |row, logical_row|
        writePayloadEvents(&sink, logical_row, row);
    for (destinations.pow_check, 0..) |row, logical_row|
        writePowCheckEvents(&sink, logical_row, row);
    for (destinations.pow_frame, 0..) |row, logical_row|
        writePowFrameEvents(&sink, logical_row, row);
    for (destinations.relation_challenge, 0..) |row, logical_row|
        writeRelationChallengeEvents(&sink, logical_row, row);
    for (destinations.verifier_randomness, 0..) |row, logical_row|
        writeRandomnessEvents(&sink, logical_row, row);

    std.debug.assert(sink.at == destinations.relation_events.len);
}

pub fn writeRandomnessEvents(
    sink: *EventSink,
    logical_row: usize,
    row: VerifierRandomnessRowV2,
) void {
    const pp = row.preprocessing;
    const draw_tuple = [_]M31{
        felt(pp.verifier_id), felt(pp.sequence), felt(pp.tag),
    } ++ feltArgs(pp.args) ++ row.main.outputs;
    sink.put(.verifier_randomness, logical_row, 0, .recursion_transcript_draw_output, .consume, row.main.enabler, &draw_tuple);
    for (row.main.outputs, 0..) |value, word| {
        const item_index = pp.item_base + pp.query_items * @as(u32, @intCast(word));
        const limb_index = (1 - pp.query_items) * @as(u32, @intCast(word));
        const tuple = [_]M31{
            felt(pp.verifier_id),
            felt(@intFromEnum(pp.kind)),
            felt(item_index),
            felt(limb_index),
            value,
        };
        sink.put(
            .verifier_randomness,
            logical_row,
            @intCast(1 + word),
            .recursion_verifier_randomness_word,
            .emit,
            row.main.enabler * pp.multiplicities[word],
            &tuple,
        );
    }
}

pub fn writeProviderAssumeValid(
    destination: []ProviderCall,
    execution: *const transcript.Execution,
) void {
    for (destination, execution.poseidon_calls) |*target, call| {
        var input: [transcript.WIDTH]u32 = undefined;
        for (&input, call.input) |*raw, value| raw.* = value.toU32();
        target.* = .{
            .input = input,
            .wide = false,
            .io = true,
            .narrow_output = null,
        };
    }
}

pub fn validateDestinationGeometry(
    destinations: DestinationsV2,
    counts: CountsV2,
) Error!void {
    if (destinations.control.len != counts.control or
        destinations.transcript_air.len != counts.transcript_air or
        destinations.transcript_binding.len != counts.transcript_binding or
        destinations.transcript_state.len != counts.transcript_state or
        destinations.transcript_word.len != counts.transcript_word or
        destinations.transcript_payload.len != counts.transcript_payload or
        destinations.pow_check.len != counts.pow_check or
        destinations.pow_frame.len != counts.pow_frame or
        destinations.relation_challenge.len != counts.relation_challenge or
        destinations.verifier_randomness.len != counts.verifier_randomness or
        destinations.relation_events.len != counts.relation_events or
        destinations.poseidon_requests.len != counts.poseidon_requests)
    {
        return error.DestinationLengthMismatch;
    }
}

pub fn rejectDestinationAliases(
    destinations: DestinationsV2,
    prepared: *const PreparedV2,
    program: *const transcript.Program,
    execution: *const transcript.Execution,
    evidence: *const transcript.Evidence,
    plan: *const schedule.Plan,
    data: *const public_data_v2.PublicDataV2,
    component_descs: []const statement_v1.FamilyComponentDesc,
    infra_descs: []const statement_v1.InfraComponentDesc,
) Error!void {
    const outputs = [_][]u8{
        std.mem.sliceAsBytes(destinations.control),
        std.mem.sliceAsBytes(destinations.transcript_air),
        std.mem.sliceAsBytes(destinations.transcript_binding),
        std.mem.sliceAsBytes(destinations.transcript_state),
        std.mem.sliceAsBytes(destinations.transcript_word),
        std.mem.sliceAsBytes(destinations.transcript_payload),
        std.mem.sliceAsBytes(destinations.pow_check),
        std.mem.sliceAsBytes(destinations.pow_frame),
        std.mem.sliceAsBytes(destinations.relation_challenge),
        std.mem.sliceAsBytes(destinations.verifier_randomness),
        std.mem.sliceAsBytes(destinations.relation_events),
        std.mem.sliceAsBytes(destinations.poseidon_requests),
    };
    for (outputs, 0..) |left, left_index| {
        for (outputs[left_index + 1 ..]) |right|
            if (overlap(left, right)) return error.AliasedDestination;
        try rejectSourceAlias(
            left,
            program,
            execution,
            evidence,
            plan,
            data,
            component_descs,
            infra_descs,
        );
        if (overlap(left, std.mem.asBytes(prepared)))
            return error.AliasedDestination;
    }
}

comptime {
    if (FORMAT_VERSION == 1 or MANIFEST_VERSION == 1 or
        FIRST_ROW != 0 or LAST_ROW != 9 or ROW_COUNT != 10 or
        channel.RATE != 8 or transcript.WIDTH != 16)
    {
        @compileError("V2 transcript outer-source geometry drifted");
    }
    const expected = .{
        .{ relation.Domain.poseidon2_io, 32 },
        .{ relation.Domain.recursion_step, 7 },
        .{ relation.Domain.recursion_hash_state, 19 },
        .{ relation.Domain.recursion_hash_data, 11 },
        .{ relation.Domain.recursion_hash_output, 12 },
        .{ relation.Domain.recursion_hash_call_control, 7 },
        .{ relation.Domain.recursion_transcript_frame_word, 4 },
        .{ relation.Domain.recursion_transcript_frame_output, 10 },
        .{ relation.Domain.recursion_transcript_pow_frame, 14 },
        .{ relation.Domain.recursion_transcript_digest_state, 10 },
        .{ relation.Domain.recursion_transcript_draw_output, 15 },
        .{ relation.Domain.recursion_transcript_payload_word, 9 },
        .{ relation.Domain.recursion_verifier_input_word, 5 },
        .{ relation.Domain.recursion_pow_check, 5 },
        .{ relation.Domain.recursion_relation_challenge_word, 5 },
        .{ relation.Domain.recursion_verifier_randomness_word, 5 },
    };
    for (expected) |item| if (relation.universalDescriptor(item[0]).arity != item[1])
        @compileError("V2 transcript relation ABI drifted");
}
