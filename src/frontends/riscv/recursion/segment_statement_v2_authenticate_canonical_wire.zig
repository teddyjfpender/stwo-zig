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
const SnapshotIdentity = dependency_0.SnapshotIdentity;
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
const memory_state = @import("../runner/memory_state.zig");
const protocol = dependency_0.protocol;
const readFixed = dependency_2.readFixed;
const readRetainedSection = dependency_2.readRetainedSection;
const runner_result = @import("../runner/result.zig");
const snapshotSectionIdentity = dependency_2.snapshotSectionIdentity;
const span_statement = dependency_0.span_statement;
const statementRange = dependency_0.statementRange;
const std = dependency_0.std;
const validateWireClockProgress = dependency_2.validateWireClockProgress;

/// Authenticate an untrusted canonical wire without allocation.  All retained
/// tuples are checked for strict order, nonzero sparse normalization, bounds,
/// count/header agreement, and digest agreement before a view is returned.
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
    // Consecutive execution segments need not be aligned binary siblings.
    // The recursive parent separately enforces SpanStatement.fold geometry.
    _ = try span_statement.foldExecuted(left_span, right_span);
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

const wire = @import("segment_statement_v2_wire.zig");
pub const authenticateCanonicalWire = wire.authenticateCanonicalWire;
pub const authenticateCanonicalWireReusingRoots = wire.authenticateCanonicalWireReusingRoots;
pub const authenticateAdjacentCanonicalWires = wire.authenticateAdjacentCanonicalWires;
pub const formatId = wire.formatId;
pub const validateRetainedIdentities = wire.validateRetainedIdentities;
pub const validateRetainedIdentitiesReusingRoots = wire.validateRetainedIdentitiesReusingRoots;
pub const clockSectionIdentity = wire.clockSectionIdentity;
pub const validateWireCompletionLink = wire.validateWireCompletionLink;
pub const requireAdjacentViews = wire.requireAdjacentViews;
pub const sectionsEqualSparse = wire.sectionsEqualSparse;
pub const sectionsEqualClocks = wire.sectionsEqualClocks;
pub const assertPointerFree = wire.assertPointerFree;
