//! Internal segment statement v2 authority shard; use segment_statement_v2.zig publicly.

const dependency_0 = @import("segment_statement_v2_contract.zig");
const dependency_1 = @import("segment_statement_v2_canonical_wire_view_v2.zig");
const dependency_2 = @import("segment_statement_v2_source_v2.zig");

const ADJACENCY_ID_DOMAIN = dependency_0.ADJACENCY_ID_DOMAIN;
const AdjacentReceiptV2 = dependency_2.AdjacentReceiptV2;
const BOUNDARY_LINEAGE_ID_DOMAIN = dependency_0.BOUNDARY_LINEAGE_ID_DOMAIN;
const CanonicalWireViewV2 = dependency_1.CanonicalWireViewV2;
const CompletionV2 = dependency_0.CompletionV2;
const Digest = dependency_0.Digest;
const Error = dependency_0.Error;
const FIXED_CANONICAL_WORDS = dependency_0.FIXED_CANONICAL_WORDS;
const FORMAT_ID_DOMAIN = dependency_0.FORMAT_ID_DOMAIN;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const IdentityHasher = dependency_0.IdentityHasher;
const JOB_ID_DOMAIN = dependency_0.JOB_ID_DOMAIN;
const KNOWN_FLAGS = dependency_0.KNOWN_FLAGS;
const M31 = dependency_0.M31;
const MAX_GLOBAL_CYCLES = dependency_0.MAX_GLOBAL_CYCLES;
const MAX_RW_ADDRESS_EXCLUSIVE = dependency_0.MAX_RW_ADDRESS_EXCLUSIVE;
const MAX_SPARSE_BOUNDARY_ENTRIES = dependency_0.MAX_SPARSE_BOUNDARY_ENTRIES;
const MEMORY_CLOCK_ID_DOMAIN = dependency_0.MEMORY_CLOCK_ID_DOMAIN;
const MEMORY_STATE_ID_DOMAIN = dependency_0.MEMORY_STATE_ID_DOMAIN;
const MIN_CANONICAL_WORDS = dependency_0.MIN_CANONICAL_WORDS;
const POSITION_ID_DOMAIN = dependency_0.POSITION_ID_DOMAIN;
const RETAINED_ENTRY_WORDS = dependency_0.RETAINED_ENTRY_WORDS;
const Reader = dependency_2.Reader;
const RetainedSectionV2 = dependency_0.RetainedSectionV2;
const SCHEMA_VERSION = dependency_0.SCHEMA_VERSION;
const SEGMENT_LINEAGE_ID_DOMAIN = dependency_0.SEGMENT_LINEAGE_ID_DOMAIN;
const SnapshotSide = dependency_1.SnapshotSide;
const SourceV2 = dependency_2.SourceV2;
const StatementV2 = dependency_0.StatementV2;
const Tag = dependency_0.Tag;
const V1_PROJECTION_WORD_COUNT = dependency_0.V1_PROJECTION_WORD_COUNT;
const WIRE_ID_DOMAIN = dependency_0.WIRE_ID_DOMAIN;
const WireByteIterator = dependency_2.WireByteIterator;
const channel = dependency_0.channel;
const continuationRoot = dependency_1.continuationRoot;
const executedLeaf = dependency_0.executedLeaf;
const memory_state = dependency_0.memory_state;
const protocol = dependency_0.protocol;
const readFixed = dependency_2.readFixed;
const readRetainedSection = dependency_2.readRetainedSection;
const runner_result = dependency_0.runner_result;
const snapshotSectionIdentity = dependency_2.snapshotSectionIdentity;
const span_statement = dependency_0.span_statement;
const statementRange = dependency_0.statementRange;
const std = dependency_0.std;
const validateWireClockProgress = dependency_2.validateWireClockProgress;

/// Authenticate an untrusted canonical wire without allocation.  All retained
/// tuples are checked for strict order, nonzero sparse normalization, bounds,
/// count/header agreement, and digest agreement before a view is returned.
pub fn authenticateCanonicalWire(words: []const M31) Error!CanonicalWireViewV2 {
    if (words.len < MIN_CANONICAL_WORDS) return error.CanonicalLengthMismatch;
    var fixed: [FIXED_CANONICAL_WORDS]M31 = undefined;
    @memcpy(&fixed, words[0..FIXED_CANONICAL_WORDS]);
    const statement_v2 = try readFixed(&fixed);

    var reader = Reader{ .words = words, .at = FIXED_CANONICAL_WORDS };
    const entry_snapshot = try readRetainedSection(
        &reader,
        .entry_memory_state,
        statement_v2.entry_snapshot_count,
        .sparse_state,
        0,
    );
    const exit_snapshot = try readRetainedSection(
        &reader,
        .exit_memory_state,
        statement_v2.exit_snapshot_count,
        .sparse_state,
        0,
    );
    const base = try statement_v2.base();
    const executed = try executedLeaf(base);
    const range = try statementRange(base, executed);
    const entry_memory_clocks = try readRetainedSection(
        &reader,
        .entry_memory_clocks,
        statement_v2.entry_memory_clock_count,
        .memory_clock,
        range.start,
    );
    const exit_memory_clocks = try readRetainedSection(
        &reader,
        .exit_memory_clocks,
        statement_v2.exit_memory_clock_count,
        .memory_clock,
        range.end,
    );
    if (reader.at != words.len) return error.CanonicalLengthMismatch;

    var view = CanonicalWireViewV2{
        .words = words,
        .statement = statement_v2,
        .entry_snapshot = entry_snapshot,
        .exit_snapshot = exit_snapshot,
        .entry_memory_clocks = entry_memory_clocks,
        .exit_memory_clocks = exit_memory_clocks,
        .wire_id = channel.hashCanonicalWords(words, WIRE_ID_DOMAIN),
    };
    try validateRetainedIdentities(&view);
    try validateWireClockProgress(&view);
    try validateWireCompletionLink(&view);
    return view;
}

/// Exact adjacent-span authentication over the retained canonical wires.
/// This re-authenticates both inputs so a mutation after an earlier decode
/// cannot reuse a stale view.
pub fn authenticateAdjacentCanonicalWires(
    left_words: []const M31,
    right_words: []const M31,
) Error!AdjacentReceiptV2 {
    const left = try authenticateCanonicalWire(left_words);
    const right = try authenticateCanonicalWire(right_words);
    try requireAdjacentViews(&left, &right);
    var hasher = IdentityHasher.init(ADJACENCY_ID_DOMAIN);
    hasher.scalar(FORMAT_VERSION);
    hasher.digest(left.statement.session_id);
    hasher.digest(left.statement.job_id);
    hasher.digest(left.statement.exit_lineage_id);
    hasher.digest(left.wire_id);
    hasher.digest(right.wire_id);
    return .{
        .session_id = left.statement.session_id,
        .job_id = left.statement.job_id,
        .shared_boundary_lineage_id = left.statement.exit_lineage_id,
        .left_wire_id = left.wire_id,
        .right_wire_id = right.wire_id,
        .identity = hasher.finalize(),
    };
}

/// Exact source-side check used before encoding two adjacent runner results.
/// Sparse memory equality treats an omitted address as zero, matching the
/// sparse Merkle default.  Clock maps are cumulative and therefore compare as
/// exact retained slices.
pub fn requireAdjacentSources(
    left: *const SourceV2,
    right: *const SourceV2,
) Error!void {
    try left.validate();
    try right.validate();
    if (!std.meta.eql(left.session_id, right.session_id))
        return error.CrossSession;
    const left_statement = try left.statement();
    const right_statement = try right.statement();
    if (!std.meta.eql(left_statement.job_id, right_statement.job_id))
        return error.JobMismatch;
    if (left.segment_index == std.math.maxInt(u32) or
        left.segment_index + 1 != right.segment_index)
    {
        return error.NonAdjacentPosition;
    }
    const left_span = try executedLeaf(left.base_statement);
    const right_span = try executedLeaf(right.base_statement);
    if (left_span.endCycle() != right_span.first_cycle)
        return error.CycleDiscontinuity;
    if (!std.meta.eql(left.exit_cpu, right.entry_cpu))
        return error.StateDiscontinuity;
    try requireSparseSourceEquality(
        left.memory_words,
        .final_word,
        right.memory_words,
        .initial_word,
    );
    if (!std.mem.eql(
        u32,
        &left.exit_register_clocks,
        &right.entry_register_clocks,
    ) or !clockSlicesEqual(
        left.exit_memory_clocks,
        right.entry_memory_clocks,
    )) return error.BoundaryClockMismatch;
    if (!std.meta.eql(
        left_statement.exit_lineage_id,
        right_statement.entry_lineage_id,
    )) return error.LineageMismatch;
    _ = try span_statement.SpanStatement.fold(
        left.base_statement,
        right.base_statement,
    );
}

pub fn formatId() Digest {
    var hasher = IdentityHasher.init(FORMAT_ID_DOMAIN);
    hasher.scalar(FORMAT_VERSION);
    hasher.scalar(SCHEMA_VERSION);
    hasher.scalar(KNOWN_FLAGS);
    hasher.scalar(V1_PROJECTION_WORD_COUNT);
    hasher.scalar(FIXED_CANONICAL_WORDS);
    hasher.scalar(RETAINED_ENTRY_WORDS);
    hasher.u32Value(MAX_GLOBAL_CYCLES);
    hasher.u32Value(MAX_SPARSE_BOUNDARY_ENTRIES);
    hasher.u32Value(MAX_RW_ADDRESS_EXCLUSIVE);
    inline for (.{
        FORMAT_ID_DOMAIN,
        JOB_ID_DOMAIN,
        POSITION_ID_DOMAIN,
        MEMORY_STATE_ID_DOMAIN,
        MEMORY_CLOCK_ID_DOMAIN,
        BOUNDARY_LINEAGE_ID_DOMAIN,
        SEGMENT_LINEAGE_ID_DOMAIN,
        WIRE_ID_DOMAIN,
        ADJACENCY_ID_DOMAIN,
    }) |domain| hasher.scalar(domain);
    inline for (std.meta.tags(Tag)) |tag| hasher.scalar(@intFromEnum(tag));
    hasher.digest(protocol.PROTOCOL_ID_WORDS);
    return hasher.finalize();
}

pub fn validateRetainedIdentities(view: *const CanonicalWireViewV2) Error!void {
    const entry_snapshot = snapshotSectionIdentity(view, view.entry_snapshot);
    const exit_snapshot = snapshotSectionIdentity(view, view.exit_snapshot);
    const entry_clocks = clockSectionIdentity(view, view.entry_memory_clocks);
    const exit_clocks = clockSectionIdentity(view, view.exit_memory_clocks);
    var entry_root_iterator = WireByteIterator.init(view, view.entry_snapshot);
    var exit_root_iterator = WireByteIterator.init(view, view.exit_snapshot);
    const entry_root = continuationRoot(&entry_root_iterator);
    const exit_root = continuationRoot(&exit_root_iterator);
    if (!std.meta.eql(entry_snapshot, view.statement.entry_snapshot_id) or
        !std.meta.eql(exit_snapshot, view.statement.exit_snapshot_id) or
        entry_root != view.statement.entry_continuation_root or
        exit_root != view.statement.exit_continuation_root or
        !std.meta.eql(entry_clocks, view.statement.entry_memory_clock_id) or
        !std.meta.eql(exit_clocks, view.statement.exit_memory_clock_id))
    {
        return error.BoundaryIdentityMismatch;
    }
}

pub fn clockSectionIdentity(
    view: *const CanonicalWireViewV2,
    section: RetainedSectionV2,
) Digest {
    var hasher = IdentityHasher.init(MEMORY_CLOCK_ID_DOMAIN);
    hasher.scalar(FORMAT_VERSION);
    hasher.u32Value(section.count);
    for (0..section.count) |index| {
        const entry = view.clockEntry(section, index);
        hasher.u32Value(entry.address);
        hasher.u32Value(entry.clock);
    }
    return hasher.finalize();
}

pub fn validateWireCompletionLink(view: *const CanonicalWireViewV2) Error!void {
    const completion = view.statement.completion orelse return;
    if (completion.kind != .halt_flag) return;

    var value_matches = false;
    for (0..view.exit_snapshot.count) |index| {
        const entry = view.sparseEntry(view.exit_snapshot, index);
        if (entry.address < completion.address) continue;
        if (entry.address == completion.address and entry.value == completion.value)
            value_matches = true;
        break;
    }
    var clock_matches = false;
    for (0..view.exit_memory_clocks.count) |index| {
        const entry = view.clockEntry(view.exit_memory_clocks, index);
        if (entry.address < completion.address) continue;
        if (entry.address == completion.address and entry.clock == completion.clock)
            clock_matches = true;
        break;
    }
    if (!value_matches or !clock_matches) return error.CompletionMismatch;
}

pub fn requireAdjacentViews(
    left: *const CanonicalWireViewV2,
    right: *const CanonicalWireViewV2,
) Error!void {
    if (!std.meta.eql(left.statement.session_id, right.statement.session_id))
        return error.CrossSession;
    if (!std.meta.eql(left.statement.job_id, right.statement.job_id))
        return error.JobMismatch;
    const left_base = try left.statement.base();
    const right_base = try right.statement.base();
    const left_span = try executedLeaf(left_base);
    const right_span = try executedLeaf(right_base);
    if (left_span.first_segment == std.math.maxInt(u32) or
        left_span.first_segment + 1 != right_span.first_segment)
    {
        return error.NonAdjacentPosition;
    }
    if (left_span.endCycle() != right_span.first_cycle)
        return error.CycleDiscontinuity;
    if (!std.meta.eql(left_span.exit, right_span.entry))
        return error.StateDiscontinuity;
    if (!sectionsEqualSparse(left, left.exit_snapshot, right, right.entry_snapshot))
        return error.MemorySnapshotMismatch;
    if (!std.mem.eql(
        u32,
        &left.statement.exit_register_clocks,
        &right.statement.entry_register_clocks,
    ) or !sectionsEqualClocks(
        left,
        left.exit_memory_clocks,
        right,
        right.entry_memory_clocks,
    )) return error.BoundaryClockMismatch;
    if (!std.meta.eql(
        left.statement.exit_lineage_id,
        right.statement.entry_lineage_id,
    )) return error.LineageMismatch;
    _ = try span_statement.SpanStatement.fold(left_base, right_base);
}

pub fn sectionsEqualSparse(
    left: *const CanonicalWireViewV2,
    left_section: RetainedSectionV2,
    right: *const CanonicalWireViewV2,
    right_section: RetainedSectionV2,
) bool {
    if (left_section.count != right_section.count) return false;
    for (0..left_section.count) |index| {
        if (!std.meta.eql(
            left.sparseEntry(left_section, index),
            right.sparseEntry(right_section, index),
        )) return false;
    }
    return true;
}

pub fn sectionsEqualClocks(
    left: *const CanonicalWireViewV2,
    left_section: RetainedSectionV2,
    right: *const CanonicalWireViewV2,
    right_section: RetainedSectionV2,
) bool {
    if (left_section.count != right_section.count) return false;
    for (0..left_section.count) |index| {
        if (!std.meta.eql(
            left.clockEntry(left_section, index),
            right.clockEntry(right_section, index),
        )) return false;
    }
    return true;
}

pub fn clockSlicesEqual(
    left: []const runner_result.MemoryAccessClock,
    right: []const runner_result.MemoryAccessClock,
) bool {
    if (left.len != right.len) return false;
    for (left, right) |lhs, rhs| if (!std.meta.eql(lhs, rhs)) return false;
    return true;
}

pub fn requireSparseSourceEquality(
    left: []const memory_state.WordState,
    comptime left_side: SnapshotSide,
    right: []const memory_state.WordState,
    comptime right_side: SnapshotSide,
) Error!void {
    var left_at: usize = 0;
    var right_at: usize = 0;
    while (true) {
        while (left_at < left.len and
            @field(left[left_at], @tagName(left_side)) == 0)
        {
            left_at += 1;
        }
        while (right_at < right.len and
            @field(right[right_at], @tagName(right_side)) == 0)
        {
            right_at += 1;
        }
        if (left_at == left.len or right_at == right.len) break;
        if (left[left_at].addr != right[right_at].addr or
            @field(left[left_at], @tagName(left_side)) !=
                @field(right[right_at], @tagName(right_side)))
        {
            return error.MemorySnapshotMismatch;
        }
        left_at += 1;
        right_at += 1;
    }
    while (left_at < left.len and
        @field(left[left_at], @tagName(left_side)) == 0) left_at += 1;
    while (right_at < right.len and
        @field(right[right_at], @tagName(right_side)) == 0) right_at += 1;
    if (left_at != left.len or right_at != right.len)
        return error.MemorySnapshotMismatch;
}

pub fn assertPointerFree(comptime T: type) void {
    switch (@typeInfo(T)) {
        .pointer => @compileError("segment statement V2 fixed authority contains a pointer"),
        .optional => |optional| assertPointerFree(optional.child),
        .array => |array| assertPointerFree(array.child),
        .@"struct" => |info| inline for (info.fields) |field|
            assertPointerFree(field.type),
        .@"union" => |info| inline for (info.fields) |field|
            assertPointerFree(field.type),
        else => {},
    }
}

comptime {
    assertPointerFree(CompletionV2);
    assertPointerFree(StatementV2);
    assertPointerFree(AdjacentReceiptV2);
}
