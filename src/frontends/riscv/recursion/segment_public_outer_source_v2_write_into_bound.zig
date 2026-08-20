//! Internal segment public outer source v2 authority shard; use segment_public_outer_source_v2.zig publicly.

const dependency_0 = @import("segment_public_outer_source_v2_contract.zig");
const dependency_1 = @import("segment_public_outer_source_v2_arithmetic_graph_binding_v2.zig");

const ARITHMETIC_PUBLICATION_WORD_COUNT = dependency_0.ARITHMETIC_PUBLICATION_WORD_COUNT;
const ArithmeticGraphBindingV2 = dependency_1.ArithmeticGraphBindingV2;
const BOUNDARY_BRIDGE_CIRCUIT_ID = dependency_0.BOUNDARY_BRIDGE_CIRCUIT_ID;
const CHALLENGE_WORD_COUNT = dependency_0.CHALLENGE_WORD_COUNT;
const CONTROL_LOGICAL_ROW_COUNT = dependency_0.CONTROL_LOGICAL_ROW_COUNT;
const CONTROL_PUBLICATION_INDEX = dependency_0.CONTROL_PUBLICATION_INDEX;
const CONTROL_RELATION_EVENT_COUNT = dependency_0.CONTROL_RELATION_EVENT_COUNT;
const CONTROL_RELAY_CIRCUIT_ID = dependency_0.CONTROL_RELAY_CIRCUIT_ID;
const ChallengeWord = dependency_1.ChallengeWord;
const DestinationsV2 = dependency_1.DestinationsV2;
const Error = dependency_0.Error;
const EventSink = dependency_1.EventSink;
const FIRST_ROW = dependency_0.FIRST_ROW;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const FROZEN_V1_ROW_COMPATIBLE = dependency_0.FROZEN_V1_ROW_COMPATIBLE;
const HOT_HEAP_ALLOCATIONS = dependency_0.HOT_HEAP_ALLOCATIONS;
const InputsV2 = dependency_1.InputsV2;
const LAST_ROW = dependency_0.LAST_ROW;
const M31 = dependency_0.M31;
const MANIFEST_VERSION = dependency_0.MANIFEST_VERSION;
const MISSING_INTEGRATION_CAPABILITIES = dependency_0.MISSING_INTEGRATION_CAPABILITIES;
const NATIVE_PUBLIC_SUM_WORD_COUNT = dependency_0.NATIVE_PUBLIC_SUM_WORD_COUNT;
const NATIVE_TOTAL_WORD_COUNT = dependency_0.NATIVE_TOTAL_WORD_COUNT;
const PRODUCTION_ACTIVATION = dependency_0.PRODUCTION_ACTIVATION;
const PUBLICATION_BRIDGE_CIRCUIT_ID = dependency_0.PUBLICATION_BRIDGE_CIRCUIT_ID;
const PUBLICATION_HEADER_WORD_COUNT = dependency_0.PUBLICATION_HEADER_WORD_COUNT;
const PUBLICATION_SEAL_START = dependency_0.PUBLICATION_SEAL_START;
const PUBLICATION_SEAL_WORD_COUNT = dependency_0.PUBLICATION_SEAL_WORD_COUNT;
const PUBLICATION_SUM_START = dependency_0.PUBLICATION_SUM_START;
const PUBLICATION_WORD_COUNT = dependency_0.PUBLICATION_WORD_COUNT;
const PreparedV2 = dependency_1.PreparedV2;
const ROW_COUNT = dependency_0.ROW_COUNT;
const RelayRowV2 = dependency_1.RelayRowV2;
const SOURCE_37_PUBLICATION_BRIDGE_AVAILABLE = dependency_0.SOURCE_37_PUBLICATION_BRIDGE_AVAILABLE;
const Sha256Digest = dependency_0.Sha256Digest;
const TRANSCRIPT_VERIFIER_ID = dependency_0.TRANSCRIPT_VERIFIER_ID;
const arithmeticGraphBindingId = dependency_1.arithmeticGraphBindingId;
const challengeWords = dependency_1.challengeWords;
const control_v2 = dependency_0.control_v2;
const control_witness_v2 = dependency_0.control_witness_v2;
const destinationBytes = dependency_1.destinationBytes;
const felt = dependency_1.felt;
const inputUseCount = dependency_1.inputUseCount;
const overlap = dependency_1.overlap;
const publicationEvents = dependency_0.publicationEvents;
const rejectDestinationAliases = dependency_1.rejectDestinationAliases;
const relation = dependency_0.relation;
const relation_challenge_witness = dependency_0.relation_challenge_witness;
const roster = dependency_0.roster;
const source_v2 = dependency_0.source_v2;
const std = dependency_0.std;
const universal = dependency_0.universal;
const validateDestinationGeometry = dependency_1.validateDestinationGeometry;
const wireTuple = dependency_1.wireTuple;
const writeRelayEvents = dependency_1.writeRelayEvents;

/// Exact-size, failure-atomic and allocation-free hot materialization.
pub fn writeInto(
    prepared: *const PreparedV2,
    destinations: DestinationsV2,
    inputs: InputsV2,
) Error!void {
    try validateDestinationGeometry(destinations, prepared.counts());
    try rejectDestinationAliases(destinations, prepared, inputs);
    try prepared.validateAgainst(inputs);

    const data = &inputs.owned_public_data.data;
    const publication_events = try publicationEvents(inputs.publication);
    const challenge_words = challengeWords(inputs.relations);

    try control_witness_v2.writeInto(&prepared.control, destinations.control);

    writeAssumeValid(
        destinations,
        prepared,
        data.words(),
        &publication_events,
        &challenge_words,
        null,
    );
}

/// Production row materialization with exact graph-derived input
/// multiplicities.  The binding and all of its backing storage are admitted
/// before the first destination write; zero-use graph inputs remain explicit
/// source rows but emit no arithmetic-wire multiplicity.
pub fn writeIntoBound(
    prepared: *const PreparedV2,
    destinations: DestinationsV2,
    inputs: InputsV2,
    arithmetic: ArithmeticGraphBindingV2,
) Error!void {
    try validateDestinationGeometry(destinations, prepared.counts());
    try rejectDestinationAliases(destinations, prepared, inputs);
    try rejectArithmeticBindingAliases(destinations, &arithmetic);
    try prepared.validateAgainst(inputs);
    try arithmetic.validateAgainst(prepared);

    const data = &inputs.owned_public_data.data;
    const publication_events = try publicationEvents(inputs.publication);
    const challenge_words = challengeWords(inputs.relations);
    try control_witness_v2.writeInto(&prepared.control, destinations.control);
    writeAssumeValid(
        destinations,
        prepared,
        data.words(),
        &publication_events,
        &challenge_words,
        arithmetic.input_use_counts,
    );
}

pub fn writeAssumeValid(
    destinations: DestinationsV2,
    prepared: *const PreparedV2,
    wire: []const M31,
    publication_events: *const [PUBLICATION_WORD_COUNT]source_v2.VerifierInputEventV2,
    challenges: *const [CHALLENGE_WORD_COUNT]ChallengeWord,
    arithmetic_use_counts: ?[]const u32,
) void {
    var sink = EventSink{ .events = destinations.relation_events };
    for (publication_events, 0..) |source_event, publication_index| {
        const local = if (publication_index < PUBLICATION_SUM_START)
            publication_index
        else if (publication_index < PUBLICATION_SEAL_START)
            publication_index - PUBLICATION_SUM_START
        else
            publication_index - PUBLICATION_SEAL_START;
        const destination = if (publication_index < PUBLICATION_SUM_START)
            &destinations.publication_header[local]
        else if (publication_index < PUBLICATION_SEAL_START)
            &destinations.native_public_sums[local]
        else
            &destinations.publication_seal[local];
        const component: roster.Component = if (publication_index < PUBLICATION_SUM_START)
            .vm_public_claim_input
        else if (publication_index < PUBLICATION_SEAL_START)
            .vm_public_claim_hash
        else
            .vm_public_io_hash;
        const arithmetic = publication_index >= PUBLICATION_SUM_START and
            publication_index < PUBLICATION_SEAL_START + NATIVE_TOTAL_WORD_COUNT;
        const control = publication_index == CONTROL_PUBLICATION_INDEX;
        const arithmetic_node = if (arithmetic)
            wire.len + publication_index - PUBLICATION_SUM_START
        else
            0;
        destination.* = .{
            .source_kind = .publication_bridge,
            .source_fields = .{
                PUBLICATION_BRIDGE_CIRCUIT_ID,
                @intCast(publication_index),
                0,
                0,
                0,
            },
            .value = source_event.tuple[4],
            .arithmetic_mask = @intFromBool(arithmetic),
            .arithmetic_node_id = if (arithmetic) @intCast(arithmetic_node) else 0,
            .arithmetic_use_count = if (arithmetic)
                inputUseCount(arithmetic_use_counts, arithmetic_node)
            else
                0,
            .control_mask = @intFromBool(control),
            .control_node_id = 0,
            .control_use_count = @intFromBool(control),
        };
        const source_tuple = wireTuple(
            PUBLICATION_BRIDGE_CIRCUIT_ID,
            @intCast(publication_index),
            source_event.tuple[4],
        );
        writeRelayEvents(&sink, component, local, destination.*, .recursion_wire, &source_tuple);
    }

    for (wire, 0..) |value, index| {
        const row = RelayRowV2{
            .source_kind = .boundary_bridge,
            .source_fields = .{
                BOUNDARY_BRIDGE_CIRCUIT_ID,
                @intCast(index),
                0,
                0,
                0,
            },
            .value = value,
            .arithmetic_mask = 1,
            .arithmetic_node_id = @intCast(index),
            .arithmetic_use_count = inputUseCount(arithmetic_use_counts, index),
        };
        destinations.boundary_bridge[index] = row;
        const source_tuple = wireTuple(
            BOUNDARY_BRIDGE_CIRCUIT_ID,
            @intCast(index),
            value,
        );
        writeRelayEvents(
            &sink,
            .vm_public_claim_semantics_input,
            index,
            row,
            .recursion_wire,
            &source_tuple,
        );
    }

    for (challenges, 0..) |challenge, index| {
        const node = wire.len + ARITHMETIC_PUBLICATION_WORD_COUNT + index;
        const row = RelayRowV2{
            .source_kind = .native_challenge,
            .source_fields = .{
                TRANSCRIPT_VERIFIER_ID,
                relation_challenge_witness.VM_PUBLIC_LOGUP_CHALLENGE_SCOPE,
                challenge.challenge,
                challenge.limb,
                0,
            },
            .value = challenge.value,
            .arithmetic_mask = 1,
            .arithmetic_node_id = @intCast(node),
            .arithmetic_use_count = inputUseCount(arithmetic_use_counts, node),
        };
        destinations.native_challenges[index] = row;
        const source_tuple = [_]M31{
            felt(TRANSCRIPT_VERIFIER_ID),
            felt(relation_challenge_witness.VM_PUBLIC_LOGUP_CHALLENGE_SCOPE),
            felt(challenge.challenge),
            felt(challenge.limb),
            challenge.value,
        };
        writeRelayEvents(
            &sink,
            .vm_public_logup_input,
            index,
            row,
            .recursion_relation_challenge_word,
            &source_tuple,
        );
    }

    std.debug.assert(sink.at == destinations.relation_events.len);
    _ = prepared;
}

pub fn rejectArithmeticBindingAliases(
    destinations: DestinationsV2,
    binding: *const ArithmeticGraphBindingV2,
) Error!void {
    const outputs = destinationBytes(destinations);
    const binding_bytes = std.mem.asBytes(binding);
    const counts_bytes = std.mem.sliceAsBytes(binding.input_use_counts);
    for (outputs) |output| {
        if (overlap(output, binding_bytes) or overlap(output, counts_bytes))
            return error.AliasedDestination;
    }
}

pub fn sealArithmeticGraphBinding(
    prepared: *const PreparedV2,
    graph_identity: Sha256Digest,
    circuit_identity: Sha256Digest,
    input_use_counts: []const u32,
) Error!ArithmeticGraphBindingV2 {
    var result = ArithmeticGraphBindingV2{
        .input_count = std.math.cast(u32, input_use_counts.len) orelse
            return error.ArithmeticOverflow,
        .prepared_source_id = prepared.source_id,
        .lowering_obligation_id = prepared.lowering_obligation.identity,
        .graph_identity = graph_identity,
        .circuit_identity = circuit_identity,
        .input_use_counts = input_use_counts,
        .identity = undefined,
    };
    result.identity = arithmeticGraphBindingId(result);
    try result.validateAgainst(prepared);
    return result;
}

comptime {
    if (FORMAT_VERSION == 1 or MANIFEST_VERSION == 1 or
        FROZEN_V1_ROW_COMPATIBLE or PRODUCTION_ACTIVATION)
    {
        @compileError("V2 public spine must remain version-separated and fail closed");
    }
    if (FIRST_ROW != 12 or LAST_ROW != 17 or ROW_COUNT != 6)
        @compileError("universal public-spine roster placement drifted");
    if (PUBLICATION_WORD_COUNT != 55 or CHALLENGE_WORD_COUNT != 32 or
        CONTROL_LOGICAL_ROW_COUNT != 71 or CONTROL_RELATION_EVENT_COUNT != 72 or
        control_v2.CONTROL_RELAY_CIRCUIT_ID != CONTROL_RELAY_CIRCUIT_ID)
        @compileError("V2 public-spine input geometry drifted");
    if (PUBLICATION_HEADER_WORD_COUNT + NATIVE_PUBLIC_SUM_WORD_COUNT +
        PUBLICATION_SEAL_WORD_COUNT != PUBLICATION_WORD_COUNT or
        relation.universalDescriptor(.recursion_relation_challenge_word).arity != 5 or
        relation.universalDescriptor(.recursion_wire).arity != 6)
    {
        @compileError("V2 public spine universal relation ABI drifted");
    }
    if (HOT_HEAP_ALLOCATIONS != 0 or
        MISSING_INTEGRATION_CAPABILITIES.len != 10 or
        !SOURCE_37_PUBLICATION_BRIDGE_AVAILABLE)
        @compileError("V2 public-spine performance/capability ledger drifted");
}
