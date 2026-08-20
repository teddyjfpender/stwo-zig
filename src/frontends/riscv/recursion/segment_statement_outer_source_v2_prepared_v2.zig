//! Internal segment statement outer source v2 authority shard; use segment_statement_outer_source_v2.zig publicly.

const dependency_0 = @import("segment_statement_outer_source_v2_contract.zig");

const AUTHORITY_HASH_AIR_VERIFIED = dependency_0.AUTHORITY_HASH_AIR_VERIFIED;
const Air = dependency_0.Air;
const AuthorityV2 = dependency_0.AuthorityV2;
const DestinationsV2 = dependency_0.DestinationsV2;
const Digest = dependency_0.Digest;
const EVENT_COUNT_PER_ROW = dependency_0.EVENT_COUNT_PER_ROW;
const Error = dependency_0.Error;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const FROZEN_ROW_10_ACTIVE = dependency_0.FROZEN_ROW_10_ACTIVE;
const HEADER_LIMB_COUNT = dependency_0.HEADER_LIMB_COUNT;
const LogicalRowV2 = dependency_0.LogicalRowV2;
const M31 = dependency_0.M31;
const ManifestV2 = dependency_0.ManifestV2;
const NativeHasher = dependency_0.NativeHasher;
const PREPARED_ID_DOMAIN = dependency_0.PREPARED_ID_DOMAIN;
const PRODUCTION_ACTIVATION = dependency_0.PRODUCTION_ACTIVATION;
const QM31 = dependency_0.QM31;
const ROW_11_BOUNDARY_BRIDGE_CLOSED = dependency_0.ROW_11_BOUNDARY_BRIDGE_CLOSED;
const ROW_11_SOURCE_TUPLES_CLOSED = dependency_0.ROW_11_SOURCE_TUPLES_CLOSED;
const ROW_11_TRANSCRIPT_STATEMENT_INPUTS_CLOSED = dependency_0.ROW_11_TRANSCRIPT_STATEMENT_INPUTS_CLOSED;
const ROW_35_REQUEST_SET_COMPLETE = dependency_0.ROW_35_REQUEST_SET_COMPLETE;
const ROW_SHA_DOMAIN = dependency_0.ROW_SHA_DOMAIN;
const RangeRequestV2 = dependency_0.RangeRequestV2;
const RelationEventV2 = dependency_0.RelationEventV2;
const SCHEMA_VERSION = dependency_0.SCHEMA_VERSION;
const Sha256Digest = dependency_0.Sha256Digest;
const TRACE_SHA_DOMAIN = dependency_0.TRACE_SHA_DOMAIN;
const TraceColumnsV2 = dependency_0.TraceColumnsV2;
const WIRE_HASH_AIR_VERIFIED = dependency_0.WIRE_HASH_AIR_VERIFIED;
const WIRE_ID_LIMB_COUNT = dependency_0.WIRE_ID_LIMB_COUNT;
const WIRE_ID_WORD_COUNT = dependency_0.WIRE_ID_WORD_COUNT;
const WorkspaceV2 = dependency_0.WorkspaceV2;
const addU32 = dependency_0.addU32;
const felt = dependency_0.felt;
const isZeroSha = dependency_0.isZeroSha;
const manifestId = dependency_0.manifestId;
const mulU32 = dependency_0.mulU32;
const public_data_v2 = dependency_0.public_data_v2;
const relation = dependency_0.relation;
const requireDigest = dependency_0.requireDigest;
const segment_statement_v2 = dependency_0.segment_statement_v2;
const source_v2 = dependency_0.source_v2;
const span_statement = dependency_0.span_statement;
const std = dependency_0.std;
const transcript_source_v2 = dependency_0.transcript_source_v2;

pub const PreparedV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    manifest: ManifestV2,
    source_id: Digest,
    transcript_source_id: Digest,
    row10_claim: QM31 = QM31.zero(),
    row10_active: bool = FROZEN_ROW_10_ACTIVE,
    row11_source_tuples_closed: bool = ROW_11_SOURCE_TUPLES_CLOSED,
    row11_transcript_statement_inputs_closed: bool =
        ROW_11_TRANSCRIPT_STATEMENT_INPUTS_CLOSED,
    row11_boundary_bridge_closed: bool = ROW_11_BOUNDARY_BRIDGE_CLOSED,
    row35_request_set_complete: bool = ROW_35_REQUEST_SET_COMPLETE,
    wire_hash_air_verified: bool = WIRE_HASH_AIR_VERIFIED,
    authority_hash_air_verified: bool = AUTHORITY_HASH_AIR_VERIFIED,
    trace_sha_id: Sha256Digest,
    logical_rows_sha_id: Sha256Digest,
    identity: Digest,

    pub fn validate(self: *const PreparedV2) Error!void {
        try self.manifest.validate();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or self.row10_active or
            !self.row10_claim.isZero() or
            !self.row11_source_tuples_closed or
            !self.row11_transcript_statement_inputs_closed or
            !self.row11_boundary_bridge_closed or
            !self.row35_request_set_complete or
            self.wire_hash_air_verified or self.authority_hash_air_verified or
            isZeroSha(self.trace_sha_id) or isZeroSha(self.logical_rows_sha_id) or
            !std.meta.eql(self.identity, preparedId(self)))
        {
            return error.SourceMismatch;
        }
        inline for (.{ self.source_id, self.transcript_source_id, self.identity }) |
            value,
        | try requireDigest(value);
    }

    pub fn validateRow35RequestSource(self: *const PreparedV2) Error!void {
        try self.validate();
        if (!self.row35_request_set_complete)
            return error.SourceMismatch;
    }

    pub fn productionReady(_: *const PreparedV2) bool {
        return PRODUCTION_ACTIVATION;
    }
};

pub fn preflight(
    data: *const public_data_v2.PublicDataV2,
    source: *const source_v2.PreparedV2,
    transcript_source: *const transcript_source_v2.PreparedV2,
    expected_statement_authority_id: Digest,
) Error!ManifestV2 {
    return deriveManifest(
        data,
        source,
        transcript_source,
        expected_statement_authority_id,
    );
}

pub fn deriveManifest(
    data: *const public_data_v2.PublicDataV2,
    source: *const source_v2.PreparedV2,
    transcript_source: *const transcript_source_v2.PreparedV2,
    expected_statement_authority_id: Digest,
) Error!ManifestV2 {
    try source.validateAgainst(data, &source.verifier_keys);
    try transcript_source.manifest.validate();
    try requireDigest(expected_statement_authority_id);
    if (!std.meta.eql(source.context.segment_wire_id, data.wireId()) or
        !std.meta.eql(transcript_source.authority.wire_id, data.wireId()) or
        !std.meta.eql(
            transcript_source.authority.statement_authority_id,
            expected_statement_authority_id,
        ))
    {
        return error.SourceMismatch;
    }
    const view = try segment_statement_v2.authenticateCanonicalWire(data.words());
    if (!std.meta.eql(view.wire_id, data.wireId()))
        return error.SourceMismatch;
    const wire_count = std.math.cast(u32, data.words().len) orelse
        return error.ArithmeticOverflow;
    var wire_u16_count: u32 = 0;
    for (0..data.words().len) |index| wire_u16_count = addU32(
        wire_u16_count,
        @intFromBool(wireWordIsU16(&view, index)),
    ) catch return error.ArithmeticOverflow;
    const source_rows = addU32(wire_count, source_v2.CONTEXT_WORD_COUNT) catch
        return error.ArithmeticOverflow;
    const logical_rows = addU32(source_rows, HEADER_LIMB_COUNT) catch
        return error.ArithmeticOverflow;
    const log_size = ceilLog2(logical_rows);
    if (log_size >= 31) return error.InvalidManifest;
    var result = ManifestV2{
        .wire_word_count = wire_count,
        .logical_row_count = logical_rows,
        .trace_log_size = log_size,
        .trace_row_count = @as(u32, 1) << @intCast(log_size),
        .relation_event_count = mulU32(logical_rows, EVENT_COUNT_PER_ROW) catch
            return error.ArithmeticOverflow,
        .wire_u16_request_count = wire_u16_count,
        .range_request_count = addU32(wire_u16_count, WIRE_ID_LIMB_COUNT) catch
            return error.ArithmeticOverflow,
        .source_manifest_id = source.manifest.identity,
        .transcript_manifest_id = transcript_source.manifest.identity,
        .wire_id = data.wireId(),
        .statement_authority_id = expected_statement_authority_id,
        .identity = undefined,
    };
    result.identity = manifestId(&result);
    try result.validate();
    return result;
}

pub fn rowAt(
    view: *const segment_statement_v2.CanonicalWireViewV2,
    context_words: *const [source_v2.CONTEXT_WORD_COUNT]M31,
    logical_row: usize,
    logical_row_count: u32,
) Error!LogicalRowV2 {
    if (logical_row >= logical_row_count) return error.InvalidTraceShape;
    if (logical_row < HEADER_LIMB_COUNT)
        return headerRow(view.words.len, logical_row);
    const source_row = logical_row - HEADER_LIMB_COUNT;
    if (source_row < view.words.len)
        return wireRow(view, source_row);
    const context_index = source_row - view.words.len;
    if (context_index >= context_words.len) return error.InvalidTraceShape;
    return contextRow(context_words, view.wire_id, context_index);
}

pub fn headerRow(wire_word_count: usize, index: usize) Error!LogicalRowV2 {
    const count = std.math.cast(u32, wire_word_count) orelse
        return error.ArithmeticOverflow;
    const values = [_]u32{
        public_data_v2.STATEMENT_TRANSCRIPT_DOMAIN & 0xffff,
        public_data_v2.STATEMENT_TRANSCRIPT_DOMAIN >> 16,
        public_data_v2.STATEMENT_TRANSCRIPT_VERSION & 0xffff,
        public_data_v2.STATEMENT_TRANSCRIPT_VERSION >> 16,
        public_data_v2.STATEMENT_TRANSCRIPT_SCHEMA_VERSION & 0xffff,
        public_data_v2.STATEMENT_TRANSCRIPT_SCHEMA_VERSION >> 16,
        count & 0xffff,
        count >> 16,
    };
    return .{
        .preprocessing = .{
            .row_mask = 1,
            .source_mask = 0,
            .verifier_a_mask = 1,
            .verifier_b_mask = 0,
            .header_mask = 1,
            .recombine_mask = 0,
            .source_u16_mask = 0,
            .verifier_a_u16_mask = 0,
            .verifier_b_u16_mask = 0,
            .source_scope = 0,
            .source_index = 0,
            .verifier_item = Air.HEADER_ITEM,
            .verifier_a_index = @intCast(index),
            .verifier_b_index = 0,
            .expected_header = values[index],
            .boundary_bridge_mask = 0,
        },
        .main = .{
            .enabler = M31.one(),
            .source_value = M31.zero(),
            .verifier_a = felt(values[index]),
            .verifier_b = M31.zero(),
            .source_low_byte = M31.zero(),
            .source_high_byte = M31.zero(),
            .verifier_a_low_byte = M31.zero(),
            .verifier_a_high_byte = M31.zero(),
            .verifier_b_low_byte = M31.zero(),
            .verifier_b_high_byte = M31.zero(),
        },
    };
}

pub fn wireRow(
    view: *const segment_statement_v2.CanonicalWireViewV2,
    index: usize,
) LogicalRowV2 {
    const value = view.words[index];
    const is_u16 = wireWordIsU16(view, index);
    const bytes = if (is_u16) bytesOfU16(value) else .{ M31.zero(), M31.zero() };
    return .{
        .preprocessing = .{
            .row_mask = 1,
            .source_mask = 1,
            .verifier_a_mask = 1,
            .verifier_b_mask = 0,
            .header_mask = 0,
            .recombine_mask = 0,
            .source_u16_mask = @intFromBool(is_u16),
            .verifier_a_u16_mask = 0,
            .verifier_b_u16_mask = 0,
            .source_scope = source_v2.WIRE_SCOPE,
            .source_index = @intCast(index),
            .verifier_item = Air.WIRE_WORD_ITEM,
            .verifier_a_index = @intCast(index),
            .verifier_b_index = 0,
            .expected_header = 0,
            .boundary_bridge_mask = 1,
        },
        .main = .{
            .enabler = M31.one(),
            .source_value = value,
            .verifier_a = value,
            .verifier_b = M31.zero(),
            .source_low_byte = bytes[0],
            .source_high_byte = bytes[1],
            .verifier_a_low_byte = M31.zero(),
            .verifier_a_high_byte = M31.zero(),
            .verifier_b_low_byte = M31.zero(),
            .verifier_b_high_byte = M31.zero(),
        },
    };
}

pub fn contextRow(
    context_words: *const [source_v2.CONTEXT_WORD_COUNT]M31,
    wire_id: Digest,
    index: usize,
) LogicalRowV2 {
    const is_wire_id = index >= source_v2.CONTEXT_SEGMENT_WIRE_ID_START and
        index < source_v2.CONTEXT_SEGMENT_WIRE_ID_START + WIRE_ID_WORD_COUNT;
    const digest_index = index -| source_v2.CONTEXT_SEGMENT_WIRE_ID_START;
    const low: u32 = if (is_wire_id) wire_id[digest_index] & 0xffff else 0;
    const high: u32 = if (is_wire_id) wire_id[digest_index] >> 16 else 0;
    const low_bytes = bytesOfU16(felt(low));
    const high_bytes = bytesOfU16(felt(high));
    return .{
        .preprocessing = .{
            .row_mask = 1,
            .source_mask = 1,
            .verifier_a_mask = @intFromBool(is_wire_id),
            .verifier_b_mask = @intFromBool(is_wire_id),
            .header_mask = 0,
            .recombine_mask = @intFromBool(is_wire_id),
            .source_u16_mask = 0,
            .verifier_a_u16_mask = @intFromBool(is_wire_id),
            .verifier_b_u16_mask = @intFromBool(is_wire_id),
            .source_scope = source_v2.CONTEXT_SCOPE,
            .source_index = @intCast(index),
            .verifier_item = if (is_wire_id) Air.WIRE_ID_ITEM else 0,
            .verifier_a_index = if (is_wire_id)
                @intCast(2 * digest_index)
            else
                0,
            .verifier_b_index = if (is_wire_id)
                @intCast(2 * digest_index + 1)
            else
                0,
            .expected_header = 0,
            .boundary_bridge_mask = 0,
        },
        .main = .{
            .enabler = M31.one(),
            .source_value = context_words[index],
            .verifier_a = felt(low),
            .verifier_b = felt(high),
            .source_low_byte = M31.zero(),
            .source_high_byte = M31.zero(),
            .verifier_a_low_byte = low_bytes[0],
            .verifier_a_high_byte = low_bytes[1],
            .verifier_b_low_byte = high_bytes[0],
            .verifier_b_high_byte = high_bytes[1],
        },
    };
}

pub fn validateDirectRow(
    workspace: *WorkspaceV2,
    authority: *const AuthorityV2,
    row: Air.Row,
) Error!void {
    authority.direct.evaluateBaseInto(
        &row,
        &workspace.direct_scratch,
        &workspace.roots,
    ) catch return error.InvalidTraceShape;
    for (workspace.roots) |root| if (!root.isZero())
        return error.DirectConstraintFailure;
}

pub fn writeTraceRow(trace: TraceColumnsV2, index: usize, row: LogicalRowV2) void {
    for (trace.preprocessed, row.preprocessing.values()) |column, value|
        column[index] = value;
    for (trace.main, row.main.values()) |column, value| column[index] = value;
}

pub fn zeroTracePadding(trace: TraceColumnsV2, logical: usize, size: usize) void {
    for (trace.preprocessed) |column| @memset(column[logical..size], M31.zero());
    for (trace.main) |column| @memset(column[logical..size], M31.zero());
}

pub fn writeEvents(
    destination: *[EVENT_COUNT_PER_ROW]RelationEventV2,
    logical_row: usize,
    row: LogicalRowV2,
) void {
    const pp = row.preprocessing;
    const main = row.main;
    destination.* = .{
        event(logical_row, 0, .recursion_statement_word, .consume, pp.source_mask, &.{
            felt(pp.source_scope), felt(pp.source_index), main.source_value,
        }),
        event(logical_row, 1, .recursion_verifier_input_word, .consume, pp.verifier_a_mask, &.{
            felt(Air.TRANSCRIPT_VERIFIER_ID), felt(Air.TRANSCRIPT_STATEMENT_KIND),
            felt(pp.verifier_item),           felt(pp.verifier_a_index),
            main.verifier_a,
        }),
        event(logical_row, 2, .recursion_verifier_input_word, .consume, pp.verifier_b_mask, &.{
            felt(Air.TRANSCRIPT_VERIFIER_ID), felt(Air.TRANSCRIPT_STATEMENT_KIND),
            felt(pp.verifier_item),           felt(pp.verifier_b_index),
            main.verifier_b,
        }),
        event(logical_row, 3, .range_check_8_8, .request, pp.source_u16_mask, &.{
            main.source_low_byte, main.source_high_byte,
        }),
        event(logical_row, 4, .range_check_8_8, .request, pp.verifier_a_u16_mask, &.{
            main.verifier_a_low_byte, main.verifier_a_high_byte,
        }),
        event(logical_row, 5, .range_check_8_8, .request, pp.verifier_b_u16_mask, &.{
            main.verifier_b_low_byte, main.verifier_b_high_byte,
        }),
        event(logical_row, 6, .recursion_wire, .emit, pp.boundary_bridge_mask, &.{
            felt(Air.BOUNDARY_BRIDGE_CIRCUIT_ID), felt(pp.source_index),
            main.source_value,                    M31.zero(),
            M31.zero(),                           M31.zero(),
        }),
    };
}

pub fn event(
    logical_row: usize,
    ordinal: u8,
    domain: relation.Domain,
    role: relation.Role,
    multiplicity: u32,
    values: []const M31,
) RelationEventV2 {
    var tuple = [_]M31{M31.zero()} ** 6;
    @memcpy(tuple[0..values.len], values);
    return .{
        .logical_row = @intCast(logical_row),
        .ordinal = ordinal,
        .domain = domain,
        .role = role,
        .multiplicity = multiplicity,
        .arity = @intCast(values.len),
        .tuple = tuple,
    };
}

pub fn writeRangeRequests(
    destination: []RangeRequestV2,
    at: *usize,
    logical_row: usize,
    row: LogicalRowV2,
) void {
    const masks = [_]u32{
        row.preprocessing.source_u16_mask,
        row.preprocessing.verifier_a_u16_mask,
        row.preprocessing.verifier_b_u16_mask,
    };
    const pairs = [_][2]M31{
        .{ row.main.source_low_byte, row.main.source_high_byte },
        .{ row.main.verifier_a_low_byte, row.main.verifier_a_high_byte },
        .{ row.main.verifier_b_low_byte, row.main.verifier_b_high_byte },
    };
    for (masks, pairs, 0..) |mask, pair, local_event| {
        if (mask == 0) continue;
        destination[at.*] = .{
            .logical_row = @intCast(logical_row),
            .event_ordinal = @intCast(3 + local_event),
            .low_byte = pair[0],
            .high_byte = pair[1],
        };
        at.* += 1;
    }
}

pub fn wireWordIsU16(
    view: *const segment_statement_v2.CanonicalWireViewV2,
    index: usize,
) bool {
    if (index == segment_statement_v2.fixed_layout.format_version or
        index == segment_statement_v2.fixed_layout.schema_version or
        index == segment_statement_v2.fixed_layout.flags)
    {
        return true;
    }
    const base_start = segment_statement_v2.fixed_layout.base_statement;
    if (index >= base_start and
        index < base_start + span_statement.SPAN_STATEMENT_CANONICAL_WORDS)
    {
        return span_statement.isIntegerWord(index - base_start);
    }
    inline for (.{
        .{ segment_statement_v2.fixed_layout.entry_snapshot_count, 4 },
        .{ segment_statement_v2.fixed_layout.exit_snapshot_count, 4 },
        .{ segment_statement_v2.fixed_layout.entry_memory_clock_count, 2 },
        .{ segment_statement_v2.fixed_layout.exit_memory_clock_count, 2 },
        .{ segment_statement_v2.fixed_layout.entry_register_clocks, 64 },
        .{ segment_statement_v2.fixed_layout.exit_register_clocks, 64 },
        .{ segment_statement_v2.fixed_layout.completion + 2, 6 },
    }) |range| if (inRange(index, range[0], range[1])) return true;
    inline for (.{
        view.entry_snapshot,
        view.exit_snapshot,
        view.entry_memory_clocks,
        view.exit_memory_clocks,
    }) |section| {
        const header = section.payload_start - segment_statement_v2.SECTION_HEADER_WORDS;
        if (inRange(index, header + 1, 2) or
            inRange(
                index,
                section.payload_start,
                @as(usize, section.count) *
                    segment_statement_v2.RETAINED_ENTRY_WORDS,
            )) return true;
    }
    return false;
}

pub fn validateContextWireId(
    context_words: *const [source_v2.CONTEXT_WORD_COUNT]M31,
    wire_id: Digest,
) Error!void {
    for (wire_id, 0..) |word, index| if (!context_words[
        source_v2.CONTEXT_SEGMENT_WIRE_ID_START + index
    ].eql(felt(word))) return error.SourceMismatch;
}

pub fn validateDestinationGeometry(
    outputs: DestinationsV2,
    manifest: *const ManifestV2,
) Error!void {
    for (outputs.trace.preprocessed) |column| if (column.len != manifest.trace_row_count)
        return error.DestinationLengthMismatch;
    for (outputs.trace.main) |column| if (column.len != manifest.trace_row_count)
        return error.DestinationLengthMismatch;
    if (outputs.logical_rows.len != manifest.logical_row_count or
        outputs.relation_events.len != manifest.relation_event_count or
        outputs.range_requests.len != manifest.range_request_count)
    {
        return error.DestinationLengthMismatch;
    }
}

pub fn rejectAliases(
    destination: *PreparedV2,
    workspace: *WorkspaceV2,
    authority: *const AuthorityV2,
    outputs: DestinationsV2,
    data: *const public_data_v2.PublicDataV2,
    source: *const source_v2.PreparedV2,
    transcript_source: *const transcript_source_v2.PreparedV2,
) Error!void {
    var ranges: [
        Air.PREPROCESSED_COLUMN_COUNT + Air.PHYSICAL_MAIN_COLUMN_COUNT + 4
    ]ByteRange = undefined;
    var count: usize = 0;
    for (outputs.trace.preprocessed) |column| {
        ranges[count] = byteRange(std.mem.sliceAsBytes(column));
        count += 1;
    }
    for (outputs.trace.main) |column| {
        ranges[count] = byteRange(std.mem.sliceAsBytes(column));
        count += 1;
    }
    inline for (.{
        std.mem.sliceAsBytes(outputs.logical_rows),
        std.mem.sliceAsBytes(outputs.relation_events),
        std.mem.sliceAsBytes(outputs.range_requests),
        std.mem.asBytes(destination),
    }) |bytes| {
        ranges[count] = byteRange(bytes);
        count += 1;
    }
    for (ranges[0..count], 0..) |left, index| {
        if (left.empty()) return error.DestinationLengthMismatch;
        for (ranges[index + 1 .. count]) |right| if (left.overlaps(right))
            return error.AliasedDestination;
        inline for (.{
            std.mem.asBytes(workspace),
            std.mem.asBytes(authority),
            std.mem.asBytes(data),
            std.mem.sliceAsBytes(data.words()),
            std.mem.asBytes(source),
            std.mem.asBytes(transcript_source),
        }) |input| if (left.overlaps(byteRange(input)))
            return error.AliasedDestination;
    }
}

pub const ByteRange = struct {
    start: usize,
    end: usize,

    fn empty(self: ByteRange) bool {
        return self.start == self.end;
    }

    fn overlaps(self: ByteRange, other: ByteRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

pub fn byteRange(bytes: []const u8) ByteRange {
    const start = @intFromPtr(bytes.ptr);
    return .{ .start = start, .end = start + bytes.len };
}

pub fn traceSha(trace: TraceColumnsV2) Sha256Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(TRACE_SHA_DOMAIN);
    for (trace.preprocessed) |column| for (column) |value|
        hashU32(&hash, value.toU32());
    for (trace.main) |column| for (column) |value|
        hashU32(&hash, value.toU32());
    return hash.finalResult();
}

pub fn logicalRowsSha(rows: []const Air.Row) Sha256Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(ROW_SHA_DOMAIN);
    for (rows) |row| for (row) |value| hashU32(&hash, value.toU32());
    return hash.finalResult();
}

pub fn preparedId(prepared: *const PreparedV2) Digest {
    var hash = NativeHasher.init(PREPARED_ID_DOMAIN);
    hash.scalar(prepared.format_version);
    hash.scalar(prepared.schema_version);
    hash.digest(prepared.manifest.identity);
    hash.digest(prepared.source_id);
    hash.digest(prepared.transcript_source_id);
    hash.qm31(prepared.row10_claim);
    hash.scalar(@intFromBool(prepared.row10_active));
    hash.scalar(@intFromBool(prepared.row11_source_tuples_closed));
    hash.scalar(@intFromBool(prepared.row11_transcript_statement_inputs_closed));
    hash.scalar(@intFromBool(prepared.row11_boundary_bridge_closed));
    hash.scalar(@intFromBool(prepared.row35_request_set_complete));
    hash.scalar(@intFromBool(prepared.wire_hash_air_verified));
    hash.scalar(@intFromBool(prepared.authority_hash_air_verified));
    hash.bytesDigest(prepared.trace_sha_id);
    hash.bytesDigest(prepared.logical_rows_sha_id);
    return hash.finalize();
}

pub fn bytesOfU16(value: M31) [2]M31 {
    const word = value.toU32();
    std.debug.assert(word <= std.math.maxInt(u16));
    return .{ felt(word & 0xff), felt(word >> 8) };
}

pub fn ceilLog2(value: u32) u8 {
    std.debug.assert(value != 0);
    return @intCast(32 - @clz(value - 1));
}

pub fn inRange(index: usize, start: usize, len: usize) bool {
    return index >= start and index < start + len;
}

pub fn hashU32(hash: anytype, value: u32) void {
    var encoded: [4]u8 = undefined;
    std.mem.writeInt(u32, &encoded, value, .little);
    hash.update(&encoded);
}
