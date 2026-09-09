//! Capture-backed witness for the SegmentV2 publication-input publisher.
//!
//! The V3 source schema binds a ContextV2 to the exact boundary publication.
//! Its trace geometry follows the authenticated physical claim inventory.
//! Preparation borrows immutable claims until materialization completes; the
//! committed authority retains pointer-free identities and trace commitments.
//! Hot materialization is allocation-free, exact-size, and alias-safe.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const m31 = stwo_core.fields.m31;

const relation = @import("../../air/lang/relation.zig");
const air = @import("segment_publication_input_provider_v2.zig");
const universal = @import("universal_challenges.zig");
const leaf_source = @import("../segment_leaf_authority_v2.zig");
const boundary = @import("../segment_leaf_outer_authority_v2.zig");
const vm_leaf_context = @import("../vm_leaf_context_v2.zig");

pub const FORMAT_VERSION: u16 = 3;
pub const SCHEMA_VERSION: u16 = 1;
pub const PROPOSED_ROSTER_ROW: u8 = 38;
pub const LUP2_WORD_COUNT: usize = leaf_source.LOGUP_PUBLICATION_WORD_COUNT;
pub const SECURE_LIMB_COUNT: usize = 4;

pub const Shape = struct {
    claim_count: u32,
    logical_row_count: u32,
    trace_log_size: u32,

    pub fn init(claim_count: usize) Error!Shape {
        if (claim_count == 0) return error.InvalidInputPair;
        const limbs = std.math.mul(usize, claim_count, SECURE_LIMB_COUNT) catch
            return error.InvalidInputPair;
        const rows = std.math.add(usize, LUP2_WORD_COUNT, limbs) catch
            return error.InvalidInputPair;
        if (rows > (1 << 30)) return error.InvalidInputPair;
        return .{
            .claim_count = @intCast(claim_count),
            .logical_row_count = @intCast(rows),
            .trace_log_size = std.math.log2_int_ceil(u32, @intCast(rows)),
        };
    }

    pub fn validate(self: Shape) Error!void {
        if (!std.meta.eql(self, try init(self.claim_count)))
            return error.InvalidPreparedSource;
    }

    pub fn traceRowCount(self: Shape) usize {
        return @as(usize, 1) << @intCast(self.trace_log_size);
    }
};

/// Frozen small-fixture geometry. Live captures use PreparedV2.shape.
pub const DETAILED_CLAIM_COUNT: usize = 21;
pub const LEGACY_SHAPE = Shape.init(DETAILED_CLAIM_COUNT) catch unreachable;
pub const DETAILED_LIMB_COUNT = DETAILED_CLAIM_COUNT * SECURE_LIMB_COUNT;
pub const LOGICAL_ROW_COUNT = LEGACY_SHAPE.logical_row_count;
pub const TRACE_LOG_SIZE = LEGACY_SHAPE.trace_log_size;
pub const TRACE_ROW_COUNT = LEGACY_SHAPE.traceRowCount();
pub const ACTIVE_RELATION_EVENT_COUNT = LOGICAL_ROW_COUNT;

pub const HOT_HEAP_ALLOCATIONS: usize = 0;
pub const LogicalRow = [air.LOGICAL_INPUT_COUNT]M31;

pub const Error = boundary.Error || vm_leaf_context.Error || error{
    AliasedDestination,
    CaptureMismatch,
    DestinationLengthMismatch,
    InvalidInputPair,
    InvalidPreparedSource,
    InvalidRelationEvent,
    NonCanonicalWord,
};

pub const InputsV2 = struct {
    capture: *const boundary.PreparedNativeVerifierOuterAuthorityV2,
    vm_context: *const vm_leaf_context.ContextV2,

    pub fn validate(self: InputsV2) Error!void {
        try self.capture.validate();
        try self.vm_context.validate();
        const publication = &self.capture.public_logup;
        if (!std.meta.eql(publication.statement_authority_id, self.vm_context.statement_authority_id) or
            !std.meta.eql(publication.statement_wire_id, self.vm_context.public_wire_id) or
            !std.meta.eql(publication.receipt.identity, self.vm_context.verified_receipt_identity) or
            !std.meta.eql(publication.native_public_sums_identity, self.vm_context.native_public_sums_identity) or
            self.vm_context.detailed_claims.len != self.vm_context.profile.input_profile.claimed_sum_count or
            self.capture.authority_hash_plan.component_count !=
                self.vm_context.component_descs.len or
            self.capture.authority_hash_plan.infra_count !=
                self.vm_context.infra_descs.len)
        {
            return error.InvalidInputPair;
        }
    }
};

pub const RowV2 = struct {
    value: M31,
    lup2_class: bool,
    index_0: u32,
    index_1: u32,

    pub fn values(self: RowV2) LogicalRow {
        return .{
            self.value,
            M31.one(),
            felt(@intFromBool(self.lup2_class)),
            felt(self.index_0),
            felt(self.index_1),
        };
    }
};

/// Immutable source view. The ContextV2 must outlive materialization. Mutation
/// of its borrowed claims is rejected by the source seal before output writes.
/// Tuple classes, coordinates and relation roles remain source-owned.
pub const PreparedV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    capture_format_version: u16 = boundary.FORMAT_VERSION,
    capture_schema_version: u16 = boundary.SCHEMA_VERSION,
    context_schema_version: u16 = vm_leaf_context.SCHEMA_VERSION,
    air_semantic_digest: [32]u8 = air.SEMANTIC_DIGEST,
    capture_identity: boundary.NativeDigest,
    capture_manifest_id: boundary.NativeDigest,
    capture_committed_trace_sha_id: boundary.Sha256Digest,
    publication_id: leaf_source.Digest,
    receipt_id: leaf_source.Digest,
    native_public_sums_identity: leaf_source.Digest,
    statement_authority_id: leaf_source.Digest,
    outer_relation_context_sha_id: boundary.Sha256Digest,
    context_identity_digest: [32]u8,
    context_profile_manifest_digest: [32]u8,
    lup2_words: [LUP2_WORD_COUNT]M31,
    shape: Shape,
    detailed_claims: []const QM31,
    identity: [32]u8,

    pub fn validate(self: *const PreparedV2) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.capture_format_version != boundary.FORMAT_VERSION or
            self.capture_schema_version != boundary.SCHEMA_VERSION or
            self.context_schema_version != vm_leaf_context.SCHEMA_VERSION or
            !std.mem.eql(u8, &self.air_semantic_digest, &air.SEMANTIC_DIGEST))
        {
            return error.InvalidPreparedSource;
        }
        try self.shape.validate();
        if (self.detailed_claims.len != self.shape.claim_count)
            return error.InvalidPreparedSource;
        inline for (.{
            self.capture_identity,
            self.capture_manifest_id,
            self.publication_id,
            self.receipt_id,
            self.native_public_sums_identity,
            self.statement_authority_id,
        }) |value| try requireNativeDigest(value);
        try requireShaDigest(self.capture_committed_trace_sha_id);
        try requireShaDigest(self.outer_relation_context_sha_id);
        try requireShaDigest(self.context_identity_digest);
        try requireShaDigest(self.context_profile_manifest_digest);
        for (self.lup2_words) |word| try requireCanonicalWord(word);
        for (self.detailed_claims) |claim| {
            for (claim.toM31Array()) |word| try requireCanonicalWord(word);
        }
        if (!std.mem.eql(u8, &self.identity, &preparedIdentity(self)))
            return error.InvalidPreparedSource;
    }

    pub fn validateAgainst(self: *const PreparedV2, inputs: InputsV2) Error!void {
        const expected = try derivePrepared(inputs);
        try self.validate();
        if (!std.mem.eql(u8, &self.identity, &expected.identity))
            return error.CaptureMismatch;
    }
};

pub const RelationEventV2 = struct {
    roster_row: u8 = PROPOSED_ROSTER_ROW,
    logical_row: u32,
    event_ordinal: u8 = 0,
    domain: relation.Domain = .recursion_verifier_input_word,
    role: relation.Role = .emit,
    multiplicity: u32 = 1,
    arity: u8 = 5,
    tuple: [universal.MAX_ARITY]M31,

    pub fn validate(self: RelationEventV2, shape: Shape) Error!void {
        try shape.validate();
        if (self.roster_row != PROPOSED_ROSTER_ROW or
            self.logical_row >= shape.logical_row_count or self.event_ordinal != 0 or
            self.domain != .recursion_verifier_input_word or self.role != .emit or
            self.multiplicity != 1 or self.arity != 5 or
            self.arity != relation.universalDescriptor(self.domain).arity)
        {
            return error.InvalidRelationEvent;
        }
        const row: usize = self.logical_row;
        if (row < LUP2_WORD_COUNT) {
            if (self.tuple[0].toU32() != air.LUP2_VERIFIER_ID or
                self.tuple[1].toU32() != air.LUP2_SOURCE_KIND or
                self.tuple[2].toU32() != row or !self.tuple[3].isZero())
            {
                return error.InvalidRelationEvent;
            }
        } else {
            const offset = row - LUP2_WORD_COUNT;
            if (self.tuple[0].toU32() != air.DETAILED_VERIFIER_ID or
                self.tuple[1].toU32() != air.DETAILED_SOURCE_KIND or
                self.tuple[2].toU32() != offset / SECURE_LIMB_COUNT or
                self.tuple[3].toU32() != offset % SECURE_LIMB_COUNT)
            {
                return error.InvalidRelationEvent;
            }
        }
        for (self.tuple[self.arity..]) |word| if (!word.isZero())
            return error.InvalidRelationEvent;
    }
};

pub const DestinationsV2 = struct {
    main: [air.PHYSICAL_MAIN_COLUMN_COUNT][]M31,
    preprocessed: [air.PREPROCESSED_COLUMN_COUNT][]M31,
    logical_rows: []LogicalRow,
    relation_events: []RelationEventV2,
};

pub fn preflight(inputs: InputsV2) Error!PreparedV2 {
    return derivePrepared(inputs);
}

pub fn prepareInto(destination: *PreparedV2, inputs: InputsV2) Error!void {
    try rejectInputAlias(std.mem.asBytes(destination), inputs);
    const staged = try derivePrepared(inputs);
    destination.* = staged;
}

/// Exact-size, failure-atomic and allocation-free trace materialization.
pub fn writeInto(
    prepared: *const PreparedV2,
    destinations: DestinationsV2,
) Error!void {
    try prepared.validate();
    try validateDestinationGeometry(destinations, prepared.shape);
    try rejectDestinationAliases(destinations, prepared);

    for (destinations.main) |column| @memset(column, M31.zero());
    for (destinations.preprocessed) |column| @memset(column, M31.zero());
    var row_index: usize = 0;
    for (prepared.lup2_words, 0..) |word, index| {
        writeActiveRow(destinations, row_index, .{
            .value = word,
            .lup2_class = true,
            .index_0 = @intCast(index),
            .index_1 = 0,
        });
        row_index += 1;
    }
    for (prepared.detailed_claims, 0..) |claim, item| {
        for (claim.toM31Array(), 0..) |word, limb| {
            writeActiveRow(destinations, row_index, .{
                .value = word,
                .lup2_class = false,
                .index_0 = @intCast(item),
                .index_1 = @intCast(limb),
            });
            row_index += 1;
        }
    }
    std.debug.assert(row_index == prepared.shape.logical_row_count);
}

fn writeActiveRow(
    destinations: DestinationsV2,
    row_index: usize,
    row: RowV2,
) void {
    const values = row.values();
    destinations.main[0][row_index] = values[0];
    inline for (0..air.PREPROCESSED_COLUMN_COUNT) |column|
        destinations.preprocessed[column][row_index] = values[column + 1];
    destinations.logical_rows[row_index] = values;
    destinations.relation_events[row_index] = providerEvent(row_index, row);
}

fn derivePrepared(inputs: InputsV2) Error!PreparedV2 {
    try inputs.validate();
    const publication = &inputs.capture.public_logup;
    var result = PreparedV2{
        .capture_identity = inputs.capture.identity,
        .capture_manifest_id = inputs.capture.manifest.identity,
        .capture_committed_trace_sha_id = inputs.capture.committed_trace_sha_id,
        .publication_id = publication.identity,
        .receipt_id = publication.receipt.identity,
        .native_public_sums_identity = publication.native_public_sums_identity,
        .statement_authority_id = publication.statement_authority_id,
        .outer_relation_context_sha_id = inputs.capture.outer_relation_context_sha_id,
        .context_identity_digest = inputs.vm_context.identity_digest,
        .context_profile_manifest_digest = inputs.vm_context.profile.identity_digest,
        .lup2_words = try publication.canonicalWords(),
        .shape = try Shape.init(inputs.vm_context.detailed_claims.len),
        .detailed_claims = inputs.vm_context.detailed_claims,
        .identity = undefined,
    };
    result.identity = preparedIdentity(&result);
    try result.validate();
    return result;
}

fn providerEvent(row_index: usize, row: RowV2) RelationEventV2 {
    var tuple = [_]M31{M31.zero()} ** universal.MAX_ARITY;
    const values = if (row.lup2_class) [_]M31{
        felt(air.LUP2_VERIFIER_ID),
        felt(air.LUP2_SOURCE_KIND),
        felt(row.index_0),
        M31.zero(),
        row.value,
    } else [_]M31{
        felt(air.DETAILED_VERIFIER_ID),
        felt(air.DETAILED_SOURCE_KIND),
        felt(row.index_0),
        felt(row.index_1),
        row.value,
    };
    @memcpy(tuple[0..values.len], &values);
    return .{ .logical_row = @intCast(row_index), .tuple = tuple };
}

fn validateDestinationGeometry(destinations: DestinationsV2, shape: Shape) Error!void {
    for (destinations.main) |column| if (column.len != shape.traceRowCount())
        return error.DestinationLengthMismatch;
    for (destinations.preprocessed) |column| if (column.len != shape.traceRowCount())
        return error.DestinationLengthMismatch;
    if (destinations.logical_rows.len != shape.logical_row_count or
        destinations.relation_events.len != shape.logical_row_count)
    {
        return error.DestinationLengthMismatch;
    }
}

fn rejectDestinationAliases(
    destinations: DestinationsV2,
    prepared: *const PreparedV2,
) Error!void {
    var outputs: [
        air.PHYSICAL_MAIN_COLUMN_COUNT + air.PREPROCESSED_COLUMN_COUNT + 2
    ][]u8 = undefined;
    var at: usize = 0;
    for (destinations.main) |column| {
        outputs[at] = std.mem.sliceAsBytes(column);
        at += 1;
    }
    for (destinations.preprocessed) |column| {
        outputs[at] = std.mem.sliceAsBytes(column);
        at += 1;
    }
    outputs[at] = std.mem.sliceAsBytes(destinations.logical_rows);
    at += 1;
    outputs[at] = std.mem.sliceAsBytes(destinations.relation_events);
    at += 1;
    std.debug.assert(at == outputs.len);

    const prepared_bytes = std.mem.asBytes(prepared);
    for (outputs, 0..) |left, left_index| {
        if (overlap(left, prepared_bytes) or
            overlap(left, std.mem.sliceAsBytes(prepared.detailed_claims)))
            return error.AliasedDestination;
        for (outputs[left_index + 1 ..]) |right| if (overlap(left, right))
            return error.AliasedDestination;
    }
}

fn rejectInputAlias(output: []const u8, inputs: InputsV2) Error!void {
    inline for (.{
        std.mem.asBytes(inputs.capture),
        std.mem.asBytes(inputs.vm_context),
        std.mem.sliceAsBytes(inputs.vm_context.component_descs),
        std.mem.sliceAsBytes(inputs.vm_context.infra_descs),
        std.mem.sliceAsBytes(inputs.vm_context.detailed_claims),
        std.mem.sliceAsBytes(inputs.vm_context.profile.entries),
    }) |input| if (overlap(output, input)) return error.AliasedDestination;
}

fn preparedIdentity(prepared: *const PreparedV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(
        "stwo-zig/riscv/recursion/segment-publication-input-provider/v3\x00",
    );
    hashInt(&hash, u16, prepared.format_version);
    hashInt(&hash, u16, prepared.schema_version);
    hashInt(&hash, u16, prepared.capture_format_version);
    hashInt(&hash, u16, prepared.capture_schema_version);
    hashInt(&hash, u16, prepared.context_schema_version);
    hash.update(&prepared.air_semantic_digest);
    hashNativeDigest(&hash, prepared.capture_identity);
    hashNativeDigest(&hash, prepared.capture_manifest_id);
    hash.update(&prepared.capture_committed_trace_sha_id);
    hashNativeDigest(&hash, prepared.publication_id);
    hashNativeDigest(&hash, prepared.receipt_id);
    hashNativeDigest(&hash, prepared.native_public_sums_identity);
    hashNativeDigest(&hash, prepared.statement_authority_id);
    hash.update(&prepared.outer_relation_context_sha_id);
    hash.update(&prepared.context_identity_digest);
    hash.update(&prepared.context_profile_manifest_digest);
    hashInt(&hash, u16, prepared.lup2_words.len);
    for (prepared.lup2_words) |word| hashInt(&hash, u32, word.toU32());
    hashInt(&hash, u32, prepared.shape.claim_count);
    hashInt(&hash, u32, prepared.shape.logical_row_count);
    hashInt(&hash, u32, prepared.shape.trace_log_size);
    for (prepared.detailed_claims) |claim| {
        for (claim.toM31Array()) |word| hashInt(&hash, u32, word.toU32());
    }
    return hash.finalResult();
}

fn hashNativeDigest(
    hash: *std.crypto.hash.sha2.Sha256,
    value: boundary.NativeDigest,
) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: anytype,
) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn requireNativeDigest(value: boundary.NativeDigest) Error!void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= m31.Modulus) return error.InvalidPreparedSource;
        aggregate |= word;
    }
    if (aggregate == 0) return error.InvalidPreparedSource;
}

fn requireShaDigest(value: boundary.Sha256Digest) Error!void {
    if (std.mem.allEqual(u8, &value, 0)) return error.InvalidPreparedSource;
}

fn requireCanonicalWord(word: M31) Error!void {
    if (word.toU32() >= m31.Modulus) return error.NonCanonicalWord;
}

fn felt(value: u32) M31 {
    std.debug.assert(value < m31.Modulus);
    return M31.fromCanonical(value);
}

fn overlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

comptime {
    if (LUP2_WORD_COUNT != 55 or SECURE_LIMB_COUNT != 4 or
        HOT_HEAP_ALLOCATIONS != 0 or PROPOSED_ROSTER_ROW != 38 or
        air.LOGICAL_INPUT_COUNT != 5)
        @compileError("publication-input provider tuple contract drifted");
}
