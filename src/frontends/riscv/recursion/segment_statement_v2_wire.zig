//! Canonical segment wire decoding and authentication, without native source ownership.
const dependency_0 = @import("segment_statement_v2_contract.zig");
pub const CompletionV2 = dependency_0.CompletionV2;
pub const Digest = dependency_0.Digest;
pub const Error = dependency_0.Error;
pub const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
pub const IdentityHasher = dependency_0.IdentityHasher;
pub const MAX_RW_ADDRESS_EXCLUSIVE = dependency_0.MAX_RW_ADDRESS_EXCLUSIVE;
pub const MAX_SPARSE_BOUNDARY_ENTRIES = dependency_0.MAX_SPARSE_BOUNDARY_ENTRIES;
pub const MEMORY_CLOCK_ID_DOMAIN = dependency_0.MEMORY_CLOCK_ID_DOMAIN;
pub const MEMORY_STATE_ID_DOMAIN = dependency_0.MEMORY_STATE_ID_DOMAIN;
pub const MIN_CANONICAL_WORDS = dependency_0.MIN_CANONICAL_WORDS;
pub const RETAINED_ENTRY_WORDS = dependency_0.RETAINED_ENTRY_WORDS;
pub const SnapshotIdentity = dependency_0.SnapshotIdentity;
pub const Tag = dependency_0.Tag;
pub const Writer = dependency_0.Writer;
pub const clockWithinBoundary = dependency_0.clockWithinBoundary;
pub const memory_poseidon2 = dependency_0.memory_poseidon2;
pub const std = dependency_0.std;
pub const validateRegisterClocks = dependency_0.validateRegisterClocks;
pub const CanonicalWireViewV2 = dependency_0.CanonicalWireViewV2;
pub const BaseStatementWords = dependency_0.BaseStatementWords;
pub const CompletionKindV2 = dependency_0.CompletionKindV2;
pub const FIXED_CANONICAL_WORDS = dependency_0.FIXED_CANONICAL_WORDS;
pub const M31 = dependency_0.M31;
pub const MAX_GLOBAL_CYCLES = dependency_0.MAX_GLOBAL_CYCLES;
pub const RangeV2 = dependency_0.RangeV2;
pub const RetainedSectionV2 = dependency_0.RetainedSectionV2;
pub const SECTION_HEADER_WORDS = dependency_0.SECTION_HEADER_WORDS;
pub const StatementV2 = dependency_0.StatementV2;
pub const WIRE_ID_DOMAIN = dependency_0.WIRE_ID_DOMAIN;
pub const baseStatementIdAssumeCanonical = dependency_0.baseStatementIdAssumeCanonical;
pub const channel = dependency_0.channel;
pub const deriveBoundaryLineageId = dependency_0.deriveBoundaryLineageId;
pub const derivePositionId = dependency_0.derivePositionId;
pub const deriveSegmentLineageId = dependency_0.deriveSegmentLineageId;
pub const executedLeaf = dependency_0.executedLeaf;
pub const jobIdAssumeCanonical = dependency_0.jobIdAssumeCanonical;
pub const m31 = dependency_0.m31;
pub const requireDigest = dependency_0.requireDigest;
pub const span_statement = dependency_0.span_statement;
pub const ADJACENCY_ID_DOMAIN = dependency_0.ADJACENCY_ID_DOMAIN;
pub const BOUNDARY_LINEAGE_ID_DOMAIN = dependency_0.BOUNDARY_LINEAGE_ID_DOMAIN;
pub const FORMAT_ID_DOMAIN = dependency_0.FORMAT_ID_DOMAIN;
pub const JOB_ID_DOMAIN = dependency_0.JOB_ID_DOMAIN;
pub const KNOWN_FLAGS = dependency_0.KNOWN_FLAGS;
pub const POSITION_ID_DOMAIN = dependency_0.POSITION_ID_DOMAIN;
pub const SCHEMA_VERSION = dependency_0.SCHEMA_VERSION;
pub const SEGMENT_LINEAGE_ID_DOMAIN = dependency_0.SEGMENT_LINEAGE_ID_DOMAIN;
pub const V1_PROJECTION_WORD_COUNT = dependency_0.V1_PROJECTION_WORD_COUNT;
pub const protocol = dependency_0.protocol;
pub const statementRange = dependency_0.statementRange;

pub const ByteLeaf = struct {
    index: u32,
    value: u32,
};

pub fn continuationRoot(iterator: anytype) u32 {
    const root = continuationSubtreeRoot(
        iterator,
        0,
        0,
        MAX_RW_ADDRESS_EXCLUSIVE,
    );
    std.debug.assert(iterator.current == null);
    return root;
}

pub fn continuationSubtreeRoot(iterator: anytype, depth: u32, start: u32, width: u32) u32 {
    return continuationSubtreeRootWithHasher(iterator, depth, start, width, NativeContinuationHasher{});
}
const NativeContinuationHasher = struct {
    pub fn emptyRoot(_: NativeContinuationHasher, depth: u32) u32 {
        return memory_poseidon2.DEFAULT_HASHES[depth];
    }
    pub fn leaf(_: NativeContinuationHasher, value: u32) u32 {
        return value;
    }
    pub fn pair(_: NativeContinuationHasher, left: u32, right: u32) u32 {
        return memory_poseidon2.hashPair(left, right);
    }
};

/// Canonical byte-tree topology and default-subtree semantics. A recursive
/// caller supplies an independently admitted address iterator and a hasher
/// that records authenticated provider requests, retaining zero-byte leaves.
pub fn continuationSubtreeRootWithHasher(iterator: anytype, depth: u32, start: u32, width: u32, hasher: anytype) @TypeOf(hasher.emptyRoot(0)) {
    const leaf = iterator.current orelse
        return hasher.emptyRoot(depth);
    std.debug.assert(leaf.index >= start);
    const end = @as(u64, start) + width;
    if (leaf.index >= end) return hasher.emptyRoot(depth);
    if (depth == 30) {
        std.debug.assert(width == 1 and leaf.index == start);
        return hasher.leaf(iterator.consume().value);
    }
    const half = width / 2;
    const left = continuationSubtreeRootWithHasher(iterator, depth + 1, start, half, hasher);
    const right = continuationSubtreeRootWithHasher(iterator, depth + 1, start + half, half, hasher);
    return hasher.pair(left, right);
}

pub const AdjacentReceiptV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    session_id: Digest,
    job_id: Digest,
    shared_boundary_lineage_id: Digest,
    left_wire_id: Digest,
    right_wire_id: Digest,
    identity: Digest,
};

pub const WireByteIterator = struct {
    view: *const CanonicalWireViewV2,
    section: RetainedSectionV2,
    entry_index: usize = 0,
    byte_index: u3 = 0,
    current: ?ByteLeaf = null,

    pub fn init(
        view: *const CanonicalWireViewV2,
        section: RetainedSectionV2,
    ) WireByteIterator {
        var result = WireByteIterator{ .view = view, .section = section };
        result.advance();
        return result;
    }

    pub fn consume(self: *WireByteIterator) ByteLeaf {
        const result = self.current.?;
        self.advance();
        return result;
    }

    fn advance(self: *WireByteIterator) void {
        self.current = null;
        while (self.entry_index < self.section.count) {
            const entry = self.view.sparseEntry(self.section, self.entry_index);
            while (self.byte_index < 4) {
                const byte_index = self.byte_index;
                self.byte_index += 1;
                const shift: u5 = @as(u5, byte_index) * 8;
                const byte: u8 = @truncate(entry.value >> shift);
                if (byte == 0) continue;
                self.current = .{
                    .index = entry.address + @as(u32, byte_index),
                    .value = byte,
                };
                return;
            }
            self.entry_index += 1;
            self.byte_index = 0;
        }
    }
};

pub fn readFixed(words: *const [FIXED_CANONICAL_WORDS]M31) Error!StatementV2 {
    var reader = Reader{ .words = words };
    try reader.tag(.segment_statement_v2);
    const format_version = try reader.u16Value();
    const schema_version = try reader.u16Value();
    const flags = try reader.u16Value();
    const session_id = try reader.digest();
    const job_id = try reader.digest();
    const position_id = try reader.digest();
    const entry_lineage_id = try reader.digest();
    const exit_lineage_id = try reader.digest();
    const lineage_id = try reader.digest();
    const base_statement_id = try reader.digest();
    var base_statement_words: BaseStatementWords = undefined;
    for (&base_statement_words) |*destination| destination.* = try reader.canonicalM31();
    const entry_snapshot_id = try reader.digest();
    const entry_snapshot_count = try reader.u32Value();
    const entry_continuation_root = try reader.u32Value();
    const exit_snapshot_id = try reader.digest();
    const exit_snapshot_count = try reader.u32Value();
    const exit_continuation_root = try reader.u32Value();
    const entry_memory_clock_id = try reader.digest();
    const entry_memory_clock_count = try reader.u32Value();
    const exit_memory_clock_id = try reader.digest();
    const exit_memory_clock_count = try reader.u32Value();
    var entry_register_clocks: [32]u32 = undefined;
    for (&entry_register_clocks) |*clock| clock.* = try reader.u32Value();
    var exit_register_clocks: [32]u32 = undefined;
    for (&exit_register_clocks) |*clock| clock.* = try reader.u32Value();
    const completion = try readCompletion(&reader);
    std.debug.assert(reader.at == words.len);
    const result = StatementV2{
        .format_version = format_version,
        .schema_version = schema_version,
        .flags = flags,
        .session_id = session_id,
        .job_id = job_id,
        .position_id = position_id,
        .entry_lineage_id = entry_lineage_id,
        .exit_lineage_id = exit_lineage_id,
        .lineage_id = lineage_id,
        .base_statement_id = base_statement_id,
        .base_statement_words = base_statement_words,
        .entry_snapshot_id = entry_snapshot_id,
        .entry_snapshot_count = entry_snapshot_count,
        .entry_continuation_root = entry_continuation_root,
        .exit_snapshot_id = exit_snapshot_id,
        .exit_snapshot_count = exit_snapshot_count,
        .exit_continuation_root = exit_continuation_root,
        .entry_memory_clock_id = entry_memory_clock_id,
        .entry_memory_clock_count = entry_memory_clock_count,
        .exit_memory_clock_id = exit_memory_clock_id,
        .exit_memory_clock_count = exit_memory_clock_count,
        .entry_register_clocks = entry_register_clocks,
        .exit_register_clocks = exit_register_clocks,
        .completion = completion,
    };
    try result.validate();
    var canonical: [FIXED_CANONICAL_WORDS]M31 = undefined;
    var writer = Writer{ .words = &canonical };
    result.writeFixed(&writer);
    std.debug.assert(writer.at == canonical.len);
    if (!m31WordsEqual(&canonical, words)) return error.DigestMismatch;
    return result;
}

pub fn readCompletion(reader: *Reader) Error!?CompletionV2 {
    const raw_tag = try reader.word();
    if (raw_tag == @intFromEnum(Tag.completion_absent)) {
        try reader.zeroes(7);
        return null;
    }
    if (raw_tag != @intFromEnum(Tag.completion_present))
        return error.CanonicalTagMismatch;
    const kind_raw = try reader.word();
    const kind = std.meta.intToEnum(CompletionKindV2, kind_raw) catch
        return error.UnsupportedCompletion;
    return .{
        .kind = kind,
        .address = try reader.u32Value(),
        .value = try reader.u32Value(),
        .clock = try reader.u32Value(),
    };
}

pub const RetainedKind = enum { sparse_state, memory_clock };

pub fn readRetainedSection(
    reader: *Reader,
    expected_tag: Tag,
    expected_count: u32,
    kind: RetainedKind,
    clock_cycle: u32,
) Error!RetainedSectionV2 {
    try reader.tag(expected_tag);
    const count = try reader.u32Value();
    if (count != expected_count or count > MAX_SPARSE_BOUNDARY_ENTRIES)
        return error.RetainedBoundaryMismatch;
    const payload_start = reader.at;
    var previous: ?u32 = null;
    for (0..count) |_| {
        const address = try reader.u32Value();
        const value = try reader.u32Value();
        if ((address & 3) != 0 or address > MAX_RW_ADDRESS_EXCLUSIVE - 4)
            return error.InvalidMemoryAddress;
        if (previous) |prior| {
            if (address == prior) return error.DuplicateBoundaryAddress;
            if (address < prior) return error.RetainedBoundaryMismatch;
        }
        previous = address;
        switch (kind) {
            .sparse_state => if (value == 0) return error.NonCanonicalSparseZero,
            .memory_clock => if (!clockWithinBoundary(value, clock_cycle, false))
                return error.BoundaryClockOutOfRange,
        }
    }
    return .{ .payload_start = payload_start, .count = count };
}

pub fn snapshotSectionIdentity(
    view: *const CanonicalWireViewV2,
    section: RetainedSectionV2,
) Digest {
    var hasher = IdentityHasher.init(MEMORY_STATE_ID_DOMAIN);
    @import("segment_statement_v2_identity_preimage.zig").emitRetainedSection(
        &hasher,
        section.count,
        view.words[section.payload_start..][0 .. @as(usize, section.count) * 4],
    );
    return hasher.finalize();
}

pub fn validateWireClockProgress(view: *const CanonicalWireViewV2) Error!void {
    var exit_at: usize = 0;
    for (0..view.entry_memory_clocks.count) |index| {
        const entry = view.clockEntry(view.entry_memory_clocks, index);
        while (exit_at < view.exit_memory_clocks.count) {
            const exit = view.clockEntry(view.exit_memory_clocks, exit_at);
            if (exit.address >= entry.address) break;
            exit_at += 1;
        }
        if (exit_at == view.exit_memory_clocks.count)
            return error.BoundaryClockMismatch;
        const exit = view.clockEntry(view.exit_memory_clocks, exit_at);
        if (exit.address != entry.address or exit.clock < entry.clock)
            return error.BoundaryClockMismatch;
    }
}

pub fn m31WordsEqual(left: []const M31, right: []const M31) bool {
    if (left.len != right.len) return false;
    for (left, right) |lhs, rhs| if (!lhs.eql(rhs)) return false;
    return true;
}

pub const Reader = struct {
    words: []const M31,
    at: usize = 0,

    fn word(self: *Reader) Error!u32 {
        if (self.at >= self.words.len) return error.CanonicalLengthMismatch;
        const value = self.words[self.at].toU32();
        self.at += 1;
        if (value >= m31.Modulus) return error.CanonicalWordNonCanonical;
        return value;
    }

    fn canonicalM31(self: *Reader) Error!M31 {
        const value = try self.word();
        return M31.fromCanonical(value);
    }

    fn tag(self: *Reader, expected: Tag) Error!void {
        if (try self.word() != @intFromEnum(expected))
            return error.CanonicalTagMismatch;
    }

    fn limb(self: *Reader) Error!u32 {
        const value = try self.word();
        if (value > std.math.maxInt(u16))
            return error.CanonicalIntegerLimbOutOfRange;
        return value;
    }

    fn u16Value(self: *Reader) Error!u16 {
        return std.math.cast(u16, try self.word()) orelse
            error.CanonicalIntegerLimbOutOfRange;
    }

    fn u32Value(self: *Reader) Error!u32 {
        return try self.limb() | (try self.limb() << 16);
    }

    fn digest(self: *Reader) Error!Digest {
        var result: Digest = undefined;
        for (&result) |*destination| destination.* = try self.word();
        return result;
    }

    fn zeroes(self: *Reader, count: usize) Error!void {
        for (0..count) |_| if (try self.word() != 0)
            return error.CanonicalPaddingNonZero;
    }
};
pub fn authenticateCanonicalWire(words: []const M31) Error!CanonicalWireViewV2 {
    var view = try decodeCanonicalWire(words);
    try validateRetainedIdentities(&view);
    return view;
}

/// Cold-open twin of `authenticateCanonicalWire`. The retained snapshot
/// authorities must include the exact sparse identity, count, and continuation
/// root already authenticated by the enclosing segment source. The canonical
/// wire still replays every sparse tuple and clock identity; only the expensive
/// Poseidon continuation-root traversal is reused.
pub fn authenticateCanonicalWireReusingRoots(
    words: []const M31,
    retained_entry: SnapshotIdentity,
    retained_exit: SnapshotIdentity,
) Error!CanonicalWireViewV2 {
    var view = try decodeCanonicalWire(words);
    try validateRetainedIdentitiesReusingRoots(
        &view,
        retained_entry,
        retained_exit,
    );
    return view;
}

fn decodeCanonicalWire(words: []const M31) Error!CanonicalWireViewV2 {
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

    const view = CanonicalWireViewV2{
        .words = words,
        .statement = statement_v2,
        .entry_snapshot = entry_snapshot,
        .exit_snapshot = exit_snapshot,
        .entry_memory_clocks = entry_memory_clocks,
        .exit_memory_clocks = exit_memory_clocks,
        .wire_id = channel.hashCanonicalWords(words, WIRE_ID_DOMAIN),
    };
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

pub fn validateRetainedIdentitiesReusingRoots(
    view: *const CanonicalWireViewV2,
    retained_entry: SnapshotIdentity,
    retained_exit: SnapshotIdentity,
) Error!void {
    const entry_snapshot = snapshotSectionIdentity(view, view.entry_snapshot);
    const exit_snapshot = snapshotSectionIdentity(view, view.exit_snapshot);
    const entry_clocks = clockSectionIdentity(view, view.entry_memory_clocks);
    const exit_clocks = clockSectionIdentity(view, view.exit_memory_clocks);
    if (!std.meta.eql(entry_snapshot, view.statement.entry_snapshot_id) or
        !std.meta.eql(exit_snapshot, view.statement.exit_snapshot_id) or
        !std.meta.eql(entry_clocks, view.statement.entry_memory_clock_id) or
        !std.meta.eql(exit_clocks, view.statement.exit_memory_clock_id) or
        !std.meta.eql(retained_entry.id, entry_snapshot) or
        retained_entry.count != view.statement.entry_snapshot_count or
        retained_entry.root != view.statement.entry_continuation_root or
        !std.meta.eql(retained_exit.id, exit_snapshot) or
        retained_exit.count != view.statement.exit_snapshot_count or
        retained_exit.root != view.statement.exit_continuation_root)
    {
        return error.BoundaryIdentityMismatch;
    }
}

pub fn clockSectionIdentity(
    view: *const CanonicalWireViewV2,
    section: RetainedSectionV2,
) Digest {
    var hasher = IdentityHasher.init(MEMORY_CLOCK_ID_DOMAIN);
    @import("segment_statement_v2_identity_preimage.zig").emitRetainedSection(
        &hasher,
        section.count,
        view.words[section.payload_start..][0 .. @as(usize, section.count) * 4],
    );
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
    _ = try span_statement.foldExecuted(left_span, right_span);
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
