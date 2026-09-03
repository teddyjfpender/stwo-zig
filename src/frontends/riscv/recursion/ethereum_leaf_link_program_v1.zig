//! Proof-independent AIR schedule for the recursive Ethereum leaf-link wrapper.
//!
//! The program is reconstructed from fixed typed semantics.  It routes the
//! exact 608-word MetadataV3 and 50-word VerifiedLinkV3 preimages, derives the
//! unique local-clock Span projection, consumes all 42 transcript claimed
//! sums, and schedules the two domain-separated Poseidon hashes (84 calls).
//! Program, preprocessed-root, and provider digests enter only through
//! verifier-produced field lanes; this module never converts SHA bytes into
//! field authority and cannot mint a verified leaf.

const std = @import("std");
const core = @import("stwo_core");

const hash_witness = @import("air/vm_public_claim_hash_witness.zig");
const projection_air = @import("air/ethereum_leaf_link_projection_v1.zig");
const source_air = @import("air/ethereum_leaf_link_source_v1.zig");
const metadata_v3 = @import("segment_leaf_local_authority_v3.zig");
const link_v3 = @import("segment_leaf_local_verified_link_v3.zig");
const leaf_v2 = @import("segment_leaf_authority_v2.zig");
const segment_v2 = @import("segment_statement_v2.zig");
const span = @import("span_statement.zig");

const M31 = core.fields.m31.M31;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const TRANSCRIPT_CLAIM_COUNT: usize = 42;
pub const SECURE_VALUE_WORD_COUNT: usize = 4;
pub const TRANSCRIPT_WORD_COUNT: usize =
    TRANSCRIPT_CLAIM_COUNT * SECURE_VALUE_WORD_COUNT;
pub const DIGEST_WORD_COUNT: usize = 8;
pub const METADATA_HASH_ROW_COUNT: usize =
    (metadata_v3.METADATA_IDENTITY_WORDS + 1 + 7) / 8;
pub const LINK_HASH_ROW_COUNT: usize = (link_v3.IDENTITY_WORDS + 1 + 7) / 8;
pub const METADATA_HASH_STEP_BASE: u32 = 0;
pub const LINK_HASH_STEP_BASE: u32 = 128;
pub const POSEIDON_CALL_COUNT: usize =
    METADATA_HASH_ROW_COUNT + LINK_HASH_ROW_COUNT;
pub const SOURCE_ROW_COUNT: usize =
    metadata_v3.METADATA_IDENTITY_WORDS + link_v3.IDENTITY_WORDS +
    TRANSCRIPT_WORD_COUNT + 2 * DIGEST_WORD_COUNT;
pub const PUBLIC_AUTHORITY_DIGEST_COUNT: usize = 7;
pub const PUBLIC_AUTHORITY_WORD_COUNT: usize =
    PUBLIC_AUTHORITY_DIGEST_COUNT * DIGEST_WORD_COUNT;
pub const PROJECTION_ROW_COUNT: usize =
    2 * span.SPAN_STATEMENT_CANONICAL_WORDS + link_v3.IDENTITY_WORDS +
    PUBLIC_AUTHORITY_WORD_COUNT;

pub const METADATA_BASE_START: usize = 4;
pub const METADATA_SEGMENT_INDEX_START: usize = 416;
pub const METADATA_SEGMENT_COUNT_START: usize = 418;
pub const METADATA_GLOBAL_START: usize = 420;
pub const METADATA_GLOBAL_END: usize = 424;
pub const METADATA_LOCAL_COUNT_START: usize = 428;
pub const METADATA_ENTRY_CONTINUATION_ROOT: usize = 440;
pub const METADATA_EXIT_CONTINUATION_ROOT: usize = 525;

pub const SourceScheduleRowV1 = struct {
    active: u32,
    raw_mask: u32,
    verifier_mask: u32,
    transcript_mask: u32,
    statement_mask: u32,
    scope: u32,
    kind: u32,
    index_0: u32,
    index_1: u32,
    use_count: u32,

    pub fn logical(self: SourceScheduleRowV1, value: M31) source_air.Row {
        return source_air.logicalRow(
            value,
            self.active,
            self.raw_mask,
            self.verifier_mask,
            self.transcript_mask,
            self.statement_mask,
            self.scope,
            self.kind,
            self.index_0,
            self.index_1,
            self.use_count,
        );
    }
};

pub const ProjectionScheduleRowV1 = struct {
    active: u32,
    raw_mask: u32,
    verifier_mask: u32,
    constant_source_mask: u32,
    global_statement_mask: u32,
    local_statement_mask: u32,
    expected_mask: u32,
    raw_scope: u32,
    raw_index: u32,
    raw_join_mask: u32,
    raw_join_scope: u32,
    raw_join_index: u32,
    verifier_kind: u32,
    verifier_index_0: u32,
    verifier_index_1: u32,
    statement_scope: u32,
    statement_index: u32,
    expected: u32,

    pub fn logical(
        self: ProjectionScheduleRowV1,
        value: M31,
    ) projection_air.Row {
        return projection_air.logicalRow(
            value,
            self.active,
            self.raw_mask,
            self.verifier_mask,
            self.constant_source_mask,
            self.global_statement_mask,
            self.local_statement_mask,
            self.expected_mask,
            self.raw_scope,
            self.raw_index,
            self.raw_join_mask,
            self.raw_join_scope,
            self.raw_join_index,
            self.verifier_kind,
            self.verifier_index_0,
            self.verifier_index_1,
            self.statement_scope,
            self.statement_index,
            self.expected,
        );
    }
};

pub const HashScheduleV1 = struct {
    word_count: usize,
    log_size: u32,
    step_base: u32,
    domain: u32,
    scope: u32,
    digest_kind: u32,
    rows: []hash_witness.PreprocessedRow,

    fn deinit(self: *HashScheduleV1, allocator: std.mem.Allocator) void {
        allocator.free(self.rows);
        self.* = undefined;
    }
};

pub const ProgramV1 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    source_log_size: u32,
    projection_log_size: u32,
    source_rows: []SourceScheduleRowV1,
    projection_rows: []ProjectionScheduleRowV1,
    metadata_hash: HashScheduleV1,
    link_hash: HashScheduleV1,

    pub fn init(allocator: std.mem.Allocator) !ProgramV1 {
        var result = try buildUnchecked(allocator);
        errdefer result.deinit();
        try result.validate();
        return result;
    }

    pub fn deinit(self: *ProgramV1) void {
        self.link_hash.deinit(self.allocator);
        self.metadata_hash.deinit(self.allocator);
        self.allocator.free(self.projection_rows);
        self.allocator.free(self.source_rows);
        self.* = undefined;
    }

    /// Cold reconstruction from the fixed compiler. Retained rows cannot
    /// select their own verifier program, even after being consistently
    /// resealed by a transport layer.
    pub fn validate(self: *const ProgramV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.source_log_size != try traceLogSize(SOURCE_ROW_COUNT) or
            self.projection_log_size != try traceLogSize(PROJECTION_ROW_COUNT))
        {
            return error.InvalidEthereumLeafLinkProgram;
        }
        var expected = try buildUnchecked(self.allocator);
        defer expected.deinit();
        if (!metaSliceEqual(
            SourceScheduleRowV1,
            self.source_rows,
            expected.source_rows,
        ) or !metaSliceEqual(
            ProjectionScheduleRowV1,
            self.projection_rows,
            expected.projection_rows,
        ) or !hashSchedulesEqual(&self.metadata_hash, &expected.metadata_hash) or
            !hashSchedulesEqual(&self.link_hash, &expected.link_hash))
        {
            return error.InvalidEthereumLeafLinkProgram;
        }
    }
};

fn buildUnchecked(allocator: std.mem.Allocator) !ProgramV1 {
    const source_rows = try allocator.alloc(SourceScheduleRowV1, SOURCE_ROW_COUNT);
    errdefer allocator.free(source_rows);
    const projection_rows = try allocator.alloc(
        ProjectionScheduleRowV1,
        PROJECTION_ROW_COUNT,
    );
    errdefer allocator.free(projection_rows);
    var metadata_hash = try buildHashSchedule(
        allocator,
        metadata_v3.METADATA_IDENTITY_WORDS,
        metadata_v3.METADATA_ID_DOMAIN,
        source_air.METADATA_SCOPE,
        source_air.METADATA_DIGEST_KIND,
        METADATA_HASH_STEP_BASE,
    );
    errdefer metadata_hash.deinit(allocator);
    var link_hash = try buildHashSchedule(
        allocator,
        link_v3.IDENTITY_WORDS,
        link_v3.IDENTITY_DOMAIN,
        source_air.LINK_SCOPE,
        source_air.LINK_DIGEST_KIND,
        LINK_HASH_STEP_BASE,
    );
    errdefer link_hash.deinit(allocator);

    var metadata_uses = [_]u32{1} ** metadata_v3.METADATA_IDENTITY_WORDS;
    var link_uses = [_]u32{1} ** link_v3.IDENTITY_WORDS;
    try fillProjectionRows(projection_rows, &metadata_uses, &link_uses);
    fillSourceRows(source_rows, metadata_uses, link_uses);
    return .{
        .allocator = allocator,
        .source_log_size = try traceLogSize(SOURCE_ROW_COUNT),
        .projection_log_size = try traceLogSize(PROJECTION_ROW_COUNT),
        .source_rows = source_rows,
        .projection_rows = projection_rows,
        .metadata_hash = metadata_hash,
        .link_hash = link_hash,
    };
}

fn buildHashSchedule(
    allocator: std.mem.Allocator,
    word_count: usize,
    domain: u32,
    scope: u32,
    digest_kind: u32,
    step_base: u32,
) !HashScheduleV1 {
    const row_count = (word_count + 1 + 7) / 8;
    const rows = try allocator.alloc(hash_witness.PreprocessedRow, row_count);
    errdefer allocator.free(rows);
    for (rows, 0..) |*row, step| {
        row.* = try hash_witness.expectedRow(word_count, row_count, step);
        row.step = std.math.add(
            u32,
            step_base,
            row.step,
        ) catch return error.InvalidEthereumLeafLinkProgram;
    }
    return .{
        .word_count = word_count,
        .log_size = try hash_witness.traceLogSize(row_count),
        .step_base = step_base,
        .domain = domain,
        .scope = scope,
        .digest_kind = digest_kind,
        .rows = rows,
    };
}

fn fillSourceRows(
    destination: []SourceScheduleRowV1,
    metadata_uses: [metadata_v3.METADATA_IDENTITY_WORDS]u32,
    link_uses: [link_v3.IDENTITY_WORDS]u32,
) void {
    var at: usize = 0;
    for (metadata_uses, 0..) |uses, index| {
        destination[at] = rawRow(source_air.METADATA_SCOPE, index, uses);
        at += 1;
    }
    for (link_uses, 0..) |uses, index| {
        destination[at] = rawRow(source_air.LINK_SCOPE, index, uses);
        at += 1;
    }
    for (0..TRANSCRIPT_CLAIM_COUNT) |claim| {
        for (0..SECURE_VALUE_WORD_COUNT) |limb| {
            destination[at] = verifierRow(
                source_air.TRANSCRIPT_CLAIM_KIND,
                claim,
                limb,
                1,
                true,
            );
            at += 1;
        }
    }
    for (0..DIGEST_WORD_COUNT) |limb| {
        destination[at] = verifierRow(
            source_air.METADATA_DIGEST_KIND,
            0,
            limb,
            2,
            false,
        );
        at += 1;
    }
    for (0..DIGEST_WORD_COUNT) |limb| {
        destination[at] = verifierRow(
            source_air.LINK_DIGEST_KIND,
            0,
            limb,
            2,
            false,
        );
        at += 1;
    }
    std.debug.assert(at == destination.len);
}

fn fillProjectionRows(
    destination: []ProjectionScheduleRowV1,
    metadata_uses: *[metadata_v3.METADATA_IDENTITY_WORDS]u32,
    link_uses: *[link_v3.IDENTITY_WORDS]u32,
) !void {
    var at: usize = 0;
    for (0..span.SPAN_STATEMENT_CANONICAL_WORDS) |index| {
        const metadata_index = METADATA_BASE_START + index;
        destination[at] = rawStatementRow(
            source_air.METADATA_SCOPE,
            metadata_index,
            source_air.GLOBAL_STATEMENT_SCOPE,
            index,
            true,
        );
        metadata_uses[metadata_index] += 1;
        at += 1;
    }
    for (0..span.SPAN_STATEMENT_CANONICAL_WORDS) |index| {
        const statement_index = segment_v2.fixed_layout.base_statement + index;
        if (localCountLimb(index)) |limb| {
            const metadata_index = METADATA_LOCAL_COUNT_START + limb;
            destination[at] = rawStatementRow(
                source_air.METADATA_SCOPE,
                metadata_index,
                leaf_v2.WIRE_SCOPE,
                statement_index,
                false,
            );
            metadata_uses[metadata_index] += 1;
        } else if (localZeroWord(index)) {
            destination[at] = constantStatementRow(
                leaf_v2.WIRE_SCOPE,
                statement_index,
            );
        } else {
            const metadata_index = METADATA_BASE_START + index;
            destination[at] = rawStatementRow(
                source_air.METADATA_SCOPE,
                metadata_index,
                leaf_v2.WIRE_SCOPE,
                statement_index,
                false,
            );
            metadata_uses[metadata_index] += 1;
        }
        at += 1;
    }
    for (0..link_v3.IDENTITY_WORDS) |index| {
        destination[at] = try linkProjectionRow(index, metadata_uses);
        link_uses[index] += 1;
        at += 1;
    }
    const public_kinds = [_]u32{
        source_air.LINK_DIGEST_KIND,
        source_air.PROGRAM_AUTHORITY_KIND,
        source_air.PREPROCESSED_ROOT_KIND,
        source_air.PROVIDER_RELATION_CONTEXT_KIND,
        source_air.PROVIDER_CORE_CLAIM_KIND,
        source_air.PROVIDER_MANIFEST_KIND,
        source_air.PROVIDER_CANCELLATION_KIND,
    };
    for (public_kinds, 0..) |kind, digest_index| {
        for (0..DIGEST_WORD_COUNT) |limb| {
            destination[at] = verifierStatementRow(
                kind,
                0,
                limb,
                source_air.LEAF_AUTHORITY_SCOPE,
                digest_index * DIGEST_WORD_COUNT + limb,
            );
            at += 1;
        }
    }
    std.debug.assert(at == destination.len);
}

fn linkProjectionRow(
    index: usize,
    metadata_uses: *[metadata_v3.METADATA_IDENTITY_WORDS]u32,
) !ProjectionScheduleRowV1 {
    if (index < 2) return rawExpectedRow(
        source_air.LINK_SCOPE,
        index,
        if (index == 0) link_v3.FORMAT_VERSION else link_v3.SCHEMA_VERSION,
    );
    if (index < 10) return verifierRawJoinRow(
        source_air.LINK_SCOPE,
        index,
        source_air.METADATA_DIGEST_KIND,
        0,
        index - 2,
    );
    if (index < 18) return verifierRawJoinRow(
        source_air.LINK_SCOPE,
        index,
        source_air.LOCAL_AUTHORITY_DIGEST_KIND,
        0,
        index - 10,
    );
    if (index < 26) return verifierRawJoinRow(
        source_air.LINK_SCOPE,
        index,
        source_air.LOCAL_WIRE_DIGEST_KIND,
        0,
        index - 18,
    );
    if (index < 34) return verifierRawJoinRow(
        source_air.LINK_SCOPE,
        index,
        source_air.LOCAL_RECEIPT_DIGEST_KIND,
        0,
        index - 26,
    );
    const metadata_index: usize = switch (index) {
        34...35 => METADATA_SEGMENT_INDEX_START + index - 34,
        36...37 => METADATA_SEGMENT_COUNT_START + index - 36,
        38...41 => METADATA_GLOBAL_START + index - 38,
        42...45 => METADATA_GLOBAL_END + index - 42,
        46...47 => METADATA_LOCAL_COUNT_START + index - 46,
        48 => METADATA_ENTRY_CONTINUATION_ROOT,
        49 => METADATA_EXIT_CONTINUATION_ROOT,
        else => return error.InvalidEthereumLeafLinkProgram,
    };
    metadata_uses[metadata_index] += 1;
    return rawRawJoinRow(
        source_air.LINK_SCOPE,
        index,
        source_air.METADATA_SCOPE,
        metadata_index,
    );
}

fn rawRow(scope: u32, index: usize, use_count: u32) SourceScheduleRowV1 {
    return .{
        .active = 1,
        .raw_mask = 1,
        .verifier_mask = 0,
        .transcript_mask = 0,
        .statement_mask = 0,
        .scope = scope,
        .kind = 0,
        .index_0 = @intCast(index),
        .index_1 = 0,
        .use_count = use_count,
    };
}

fn verifierRow(
    kind: u32,
    index_0: usize,
    index_1: usize,
    use_count: u32,
    transcript: bool,
) SourceScheduleRowV1 {
    return .{
        .active = 1,
        .raw_mask = 0,
        .verifier_mask = @intFromBool(!transcript),
        .transcript_mask = @intFromBool(transcript),
        .statement_mask = 0,
        .scope = 0,
        .kind = kind,
        .index_0 = @intCast(index_0),
        .index_1 = @intCast(index_1),
        .use_count = use_count,
    };
}

fn projectionBase() ProjectionScheduleRowV1 {
    return .{
        .active = 1,
        .raw_mask = 0,
        .verifier_mask = 0,
        .constant_source_mask = 0,
        .global_statement_mask = 0,
        .local_statement_mask = 0,
        .expected_mask = 0,
        .raw_scope = 0,
        .raw_index = 0,
        .raw_join_mask = 0,
        .raw_join_scope = 0,
        .raw_join_index = 0,
        .verifier_kind = 0,
        .verifier_index_0 = 0,
        .verifier_index_1 = 0,
        .statement_scope = 0,
        .statement_index = 0,
        .expected = 0,
    };
}

fn rawStatementRow(
    raw_scope: u32,
    raw_index: usize,
    statement_scope: u32,
    statement_index: usize,
    global: bool,
) ProjectionScheduleRowV1 {
    var result = projectionBase();
    result.raw_mask = 1;
    result.raw_scope = raw_scope;
    result.raw_index = @intCast(raw_index);
    result.global_statement_mask = @intFromBool(global);
    result.local_statement_mask = @intFromBool(!global);
    result.statement_scope = statement_scope;
    result.statement_index = @intCast(statement_index);
    return result;
}

fn constantStatementRow(
    statement_scope: u32,
    statement_index: usize,
) ProjectionScheduleRowV1 {
    var result = projectionBase();
    result.constant_source_mask = 1;
    result.local_statement_mask = 1;
    result.statement_scope = statement_scope;
    result.statement_index = @intCast(statement_index);
    return result;
}

fn rawExpectedRow(
    raw_scope: u32,
    raw_index: usize,
    expected: u32,
) ProjectionScheduleRowV1 {
    var result = projectionBase();
    result.raw_mask = 1;
    result.raw_scope = raw_scope;
    result.raw_index = @intCast(raw_index);
    result.expected_mask = 1;
    result.expected = expected;
    return result;
}

fn verifierRawJoinRow(
    raw_scope: u32,
    raw_index: usize,
    verifier_kind: u32,
    verifier_index_0: usize,
    verifier_index_1: usize,
) ProjectionScheduleRowV1 {
    var result = projectionBase();
    result.raw_mask = 1;
    result.verifier_mask = 1;
    // A join deliberately has two sources for one value. The AIR source
    // partition permits exactly one primary source, so use the raw preimage as
    // primary and consume the verifier tuple as an additional equality.
    result.constant_source_mask = 0;
    result.raw_scope = raw_scope;
    result.raw_index = @intCast(raw_index);
    result.verifier_kind = verifier_kind;
    result.verifier_index_0 = @intCast(verifier_index_0);
    result.verifier_index_1 = @intCast(verifier_index_1);
    return result;
}

fn rawRawJoinRow(
    left_scope: u32,
    left_index: usize,
    right_scope: u32,
    right_index: usize,
) ProjectionScheduleRowV1 {
    var result = projectionBase();
    result.raw_mask = 1;
    result.raw_scope = left_scope;
    result.raw_index = @intCast(left_index);
    result.raw_join_mask = 1;
    result.raw_join_scope = right_scope;
    result.raw_join_index = @intCast(right_index);
    return result;
}

fn verifierStatementRow(
    kind: u32,
    index_0: usize,
    index_1: usize,
    statement_scope: u32,
    statement_index: usize,
) ProjectionScheduleRowV1 {
    var result = projectionBase();
    result.verifier_mask = 1;
    result.verifier_kind = kind;
    result.verifier_index_0 = @intCast(index_0);
    result.verifier_index_1 = @intCast(index_1);
    result.global_statement_mask = 1;
    result.statement_scope = statement_scope;
    result.statement_index = @intCast(statement_index);
    return result;
}

fn localCountLimb(index: usize) ?usize {
    inline for (.{
        span.canonical_layout.total_cycles_start,
        span.canonical_layout.executed_cycle_count_start,
    }) |start| if (index >= start and index < start + 2) return index - start;
    return null;
}

fn localZeroWord(index: usize) bool {
    return (index >= span.canonical_layout.total_cycles_start + 2 and
        index < span.canonical_layout.total_cycles_start + 4) or
        (index >= span.canonical_layout.first_cycle_start and
            index < span.canonical_layout.first_cycle_start + 4) or
        (index >= span.canonical_layout.executed_cycle_count_start + 2 and
            index < span.canonical_layout.executed_cycle_count_start + 4);
}

fn hashSchedulesEqual(left: *const HashScheduleV1, right: *const HashScheduleV1) bool {
    return left.word_count == right.word_count and
        left.log_size == right.log_size and left.domain == right.domain and
        left.step_base == right.step_base and left.scope == right.scope and
        left.digest_kind == right.digest_kind and
        metaSliceEqual(hash_witness.PreprocessedRow, left.rows, right.rows);
}

fn metaSliceEqual(
    comptime T: type,
    left: []const T,
    right: []const T,
) bool {
    if (left.len != right.len) return false;
    for (left, right) |left_value, right_value| {
        if (!std.meta.eql(left_value, right_value)) return false;
    }
    return true;
}

fn traceLogSize(row_count: usize) !u32 {
    const padded = std.math.ceilPowerOfTwo(usize, @max(row_count, 1)) catch
        return error.InvalidEthereumLeafLinkProgram;
    return @max(@as(u32, 4), std.math.log2_int(usize, padded));
}

comptime {
    if (metadata_v3.METADATA_IDENTITY_WORDS != 608 or
        link_v3.IDENTITY_WORDS != 50 or span.SPAN_STATEMENT_CANONICAL_WORDS != 412 or
        TRANSCRIPT_WORD_COUNT != 168 or METADATA_HASH_ROW_COUNT != 77 or
        LINK_HASH_ROW_COUNT != 7 or POSEIDON_CALL_COUNT != 84 or
        SOURCE_ROW_COUNT != 842 or PROJECTION_ROW_COUNT != 930 or
        LINK_HASH_STEP_BASE <= METADATA_HASH_ROW_COUNT or
        METADATA_BASE_START + span.SPAN_STATEMENT_CANONICAL_WORDS !=
            METADATA_SEGMENT_INDEX_START)
    {
        @compileError("Ethereum leaf-link program geometry drifted");
    }
}
