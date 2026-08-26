//! Internal segment statement outer source v2 authority shard; use segment_statement_outer_source_v2.zig publicly.

const dependency_0 = @import("segment_statement_outer_source_v2_contract.zig");
const dependency_1 = @import("segment_statement_outer_source_v2_prepared_v2.zig");

const Air = dependency_0.Air;
const AuthorityV2 = dependency_0.AuthorityV2;
const ClosureLedgerV2 = dependency_0.ClosureLedgerV2;
const DestinationsV2 = dependency_0.DestinationsV2;
const Digest = dependency_0.Digest;
const EVENT_COUNT_PER_ROW = dependency_0.EVENT_COUNT_PER_ROW;
const Error = dependency_0.Error;
const Framework = dependency_0.Framework;
const HEADER_LIMB_COUNT = dependency_0.HEADER_LIMB_COUNT;
const M31 = dependency_0.M31;
const PreparedV2 = dependency_1.PreparedV2;
const QM31 = dependency_0.QM31;
const WIRE_ID_LIMB_COUNT = dependency_0.WIRE_ID_LIMB_COUNT;
const WorkspaceV2 = dependency_0.WorkspaceV2;
const add = dependency_0.add;
const addU32 = dependency_0.addU32;
const deriveManifest = dependency_1.deriveManifest;
const logicalRowsSha = dependency_1.logicalRowsSha;
const preparedId = dependency_1.preparedId;
const public_data_v2 = dependency_0.public_data_v2;
const rejectAliases = dependency_1.rejectAliases;
const rowAt = dependency_1.rowAt;
const segment_statement_v2 = dependency_0.segment_statement_v2;
const source_v2 = dependency_0.source_v2;
const std = dependency_0.std;
const traceSha = dependency_1.traceSha;
const transcript_source_v2 = dependency_0.transcript_source_v2;
const universal = dependency_0.universal;
const validateContextWireId = dependency_1.validateContextWireId;
const validateDestinationGeometry = dependency_1.validateDestinationGeometry;
const validateDirectRow = dependency_1.validateDirectRow;
const writeEvents = dependency_1.writeEvents;
const writeRangeRequests = dependency_1.writeRangeRequests;
const writeTraceRow = dependency_1.writeTraceRow;
const zeroTracePadding = dependency_1.zeroTracePadding;

/// Fail-atomic, allocation-free row publication. Every authority, shape,
/// alias, and direct-constraint check completes in a dry pass before the first
/// caller-owned destination cell is changed.
pub fn prepareInto(
    destination: *PreparedV2,
    workspace: *WorkspaceV2,
    authority: *const AuthorityV2,
    outputs: DestinationsV2,
    data: *const public_data_v2.PublicDataV2,
    source: *const source_v2.PreparedV2,
    transcript_source: *const transcript_source_v2.PreparedV2,
    expected_statement_authority_id: Digest,
) Error!void {
    try authority.validate();
    const manifest = try deriveManifest(
        data,
        source,
        transcript_source,
        expected_statement_authority_id,
    );
    try validateDestinationGeometry(outputs, &manifest);
    try rejectAliases(
        destination,
        workspace,
        authority,
        outputs,
        data,
        source,
        transcript_source,
    );
    const view = try segment_statement_v2.authenticateCanonicalWire(data.words());
    if (!std.meta.eql(view.wire_id, data.wireId()))
        return error.SourceMismatch;
    const context_words = try source.context.canonicalWords();
    try validateContextWireId(&context_words, data.wireId());

    // Dry pass: constraints and exact request count before any destination
    // mutation. The workspace is private scratch and may change on failure.
    var range_count: usize = 0;
    for (0..manifest.logical_row_count) |logical_row| {
        const row = try rowAt(
            &view,
            &context_words,
            logical_row,
            manifest.logical_row_count,
        );
        try validateDirectRow(workspace, authority, row.runtime());
        range_count = add(
            range_count,
            row.preprocessing.source_u16_mask +
                row.preprocessing.verifier_a_u16_mask +
                row.preprocessing.verifier_b_u16_mask,
        ) catch return error.ArithmeticOverflow;
    }
    if (range_count != manifest.range_request_count)
        return error.InvalidManifest;

    var range_at: usize = 0;
    var event_at: usize = 0;
    for (0..manifest.logical_row_count) |logical_row| {
        const row = rowAt(
            &view,
            &context_words,
            logical_row,
            manifest.logical_row_count,
        ) catch unreachable;
        const runtime = row.runtime();
        outputs.logical_rows[logical_row] = runtime;
        writeTraceRow(outputs.trace, logical_row, row);
        writeEvents(
            outputs.relation_events[event_at..][0..EVENT_COUNT_PER_ROW],
            logical_row,
            row,
        );
        event_at += EVENT_COUNT_PER_ROW;
        writeRangeRequests(outputs.range_requests, &range_at, logical_row, row);
    }
    zeroTracePadding(outputs.trace, manifest.logical_row_count, manifest.trace_row_count);
    std.debug.assert(event_at == outputs.relation_events.len);
    std.debug.assert(range_at == outputs.range_requests.len);

    var result = PreparedV2{
        .manifest = manifest,
        .source_id = source.source_id,
        .transcript_source_id = transcript_source.source_id,
        .trace_sha_id = traceSha(outputs.trace),
        .logical_rows_sha_id = logicalRowsSha(outputs.logical_rows),
        .identity = undefined,
    };
    result.identity = preparedId(&result);
    try result.validate();
    destination.* = result;
}

pub fn generateInteractionInto(
    workspace: *Framework.Workspace,
    authority: *const AuthorityV2,
    prepared: *const PreparedV2,
    logical_rows: []const Air.Row,
    relations: *const universal.UniversalRelations,
    destination: *[Air.INTERACTION_COLUMN_COUNT][]M31,
) !QM31 {
    try authority.validate();
    try prepared.validate();
    if (logical_rows.len != prepared.manifest.logical_row_count or
        !std.mem.eql(
            u8,
            &prepared.logical_rows_sha_id,
            &logicalRowsSha(logical_rows),
        ))
    {
        return error.TraceMutation;
    }
    return Framework.generatePreparedInto(
        workspace,
        &authority.relation_plan,
        logical_rows,
        prepared.manifest.trace_log_size,
        relations,
        destination,
    );
}

/// Re-authenticates the immutable row array carried by `PreparedV2`. This is
/// the zero-allocation custody seam used by the partial shared-row-35 ledger.
pub fn validateLogicalRows(
    prepared: *const PreparedV2,
    logical_rows: []const Air.Row,
) Error!void {
    try prepared.validate();
    if (logical_rows.len != prepared.manifest.logical_row_count or
        !std.mem.eql(
            u8,
            &prepared.logical_rows_sha_id,
            &logicalRowsSha(logical_rows),
        ))
    {
        return error.TraceMutation;
    }
}

pub fn closureLedger(prepared: *const PreparedV2) Error!ClosureLedgerV2 {
    try prepared.validate();
    const source_count = addU32(
        prepared.manifest.wire_word_count,
        prepared.manifest.context_word_count,
    ) catch return error.ArithmeticOverflow;
    const transcript_count = addU32(
        addU32(HEADER_LIMB_COUNT, WIRE_ID_LIMB_COUNT) catch
            return error.ArithmeticOverflow,
        prepared.manifest.wire_word_count,
    ) catch return error.ArithmeticOverflow;
    const result = ClosureLedgerV2{
        .source36_statement_emits = source_count,
        .row11_statement_consumes = source_count,
        .program_statement_payload_emits = transcript_count,
        .row11_statement_payload_consumes = transcript_count,
        .row11_boundary_wire_emits = prepared.manifest.wire_word_count,
        .row15_boundary_wire_consumes = prepared.manifest.wire_word_count,
    };
    try result.validate();
    return result;
}
