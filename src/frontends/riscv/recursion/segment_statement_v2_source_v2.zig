//! Internal segment statement v2 authority shard; use segment_statement_v2.zig publicly.

const dependency_0 = @import("segment_statement_v2_contract.zig");
const dependency_1 = @import("segment_statement_v2_canonical_wire_view_v2.zig");

const BaseStatementWords = dependency_0.BaseStatementWords;
const ByteLeaf = dependency_1.ByteLeaf;
const CanonicalWireViewV2 = dependency_1.CanonicalWireViewV2;
const CompletionKindV2 = dependency_0.CompletionKindV2;
const CompletionV2 = dependency_0.CompletionV2;
const Cpu = dependency_0.Cpu;
const Digest = dependency_0.Digest;
const Error = dependency_0.Error;
const FIXED_CANONICAL_WORDS = dependency_0.FIXED_CANONICAL_WORDS;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const IdentityHasher = dependency_0.IdentityHasher;
const M31 = dependency_0.M31;
const MAX_GLOBAL_CYCLES = dependency_0.MAX_GLOBAL_CYCLES;
const MAX_RW_ADDRESS_EXCLUSIVE = dependency_0.MAX_RW_ADDRESS_EXCLUSIVE;
const MAX_SPARSE_BOUNDARY_ENTRIES = dependency_0.MAX_SPARSE_BOUNDARY_ENTRIES;
const MEMORY_STATE_ID_DOMAIN = dependency_0.MEMORY_STATE_ID_DOMAIN;
const RangeV2 = dependency_0.RangeV2;
const RetainedSectionV2 = dependency_0.RetainedSectionV2;
const SECTION_HEADER_WORDS = dependency_0.SECTION_HEADER_WORDS;
const SnapshotIdentity = dependency_0.SnapshotIdentity;
const StatementV2 = dependency_0.StatementV2;
const Tag = dependency_0.Tag;
const WIRE_ID_DOMAIN = dependency_0.WIRE_ID_DOMAIN;
const Writer = dependency_0.Writer;
const baseStatementIdAssumeCanonical = dependency_0.baseStatementIdAssumeCanonical;
const channel = dependency_0.channel;
const checkedWireWordCount = dependency_1.checkedWireWordCount;
const clockWithinBoundary = dependency_0.clockWithinBoundary;
const completionFromRunner = dependency_1.completionFromRunner;
const deriveBoundaryLineageId = dependency_0.deriveBoundaryLineageId;
const derivePositionId = dependency_0.derivePositionId;
const deriveSegmentLineageId = dependency_0.deriveSegmentLineageId;
const executedLeaf = dependency_0.executedLeaf;
const jobIdAssumeCanonical = dependency_0.jobIdAssumeCanonical;
const m31 = dependency_0.m31;
const memoryClockIdentity = dependency_1.memoryClockIdentity;
const memory_state = dependency_0.memory_state;
const nonZeroWordCount = dependency_1.nonZeroWordCount;
const requireDigest = dependency_0.requireDigest;
const runner_result = dependency_0.runner_result;
const snapshotIdentity = dependency_1.snapshotIdentity;
const snapshotIdentityReusingRoot = dependency_1.snapshotIdentityReusingRoot;
const span_statement = dependency_0.span_statement;
const std = dependency_0.std;
const validateClockBoundary = dependency_1.validateClockBoundary;
const validateMemoryWords = dependency_1.validateMemoryWords;
const writeClockSection = dependency_1.writeClockSection;
const writeSnapshotSection = dependency_1.writeSnapshotSection;

/// Borrowed, exact native source for one segment statement.  The slices stay
/// owned by the runner result.  `encodeCanonical` retains their canonical
/// sparse projections in the wire before that result may be released.
pub const SourceV2 = struct {
    session_id: Digest,
    base_statement: span_statement.SpanStatement,
    segment_index: u32,
    segment_role: memory_state.SegmentRole,
    global_first_cycle: u64,
    cycle_count: usize,
    entry_cpu: Cpu,
    exit_cpu: Cpu,
    completion: ?CompletionV2,
    continuation_present: bool,
    public_input_custody: bool,
    public_output_custody: bool,
    memory_words: []const memory_state.WordState,
    entry_register_clocks: [32]u32,
    exit_register_clocks: [32]u32,
    entry_memory_clocks: []const runner_result.MemoryAccessClock,
    exit_memory_clocks: []const runner_result.MemoryAccessClock,

    /// Zero-copy adapter from the resumable runner.  Process-local FNV values
    /// in the continuation token are deliberately ignored; the canonical V2
    /// wire derives Poseidon identities from the exact retained boundaries.
    pub fn fromSegmentResult(
        session_id: Digest,
        base_statement: span_statement.SpanStatement,
        result: *const runner_result.SegmentResult,
    ) Error!SourceV2 {
        if (result.clock_frame != .global_continuous)
            return error.ClockFrameMismatch;
        if (!std.meta.eql(result.segment_role, result.rw_memory.segment_role))
            return error.InvalidSegmentRole;
        const completion = if (result.completion_reason) |reason|
            try completionFromRunner(
                reason,
                result.completion_address,
                result.completion_value,
                result.completion_clock,
            )
        else
            null;
        const source: SourceV2 = .{
            .session_id = session_id,
            .base_statement = base_statement,
            .segment_index = result.segment_index,
            .segment_role = result.segment_role,
            .global_first_cycle = result.global_first_cycle,
            .cycle_count = result.cycle_count,
            .entry_cpu = result.entry_cpu,
            .exit_cpu = result.exit_cpu,
            .completion = completion,
            .continuation_present = result.continuation != null,
            .public_input_custody = result.input != null,
            // Completion owns the public-output boundary even when the
            // logical output is empty and therefore has no allocated bytes.
            .public_output_custody = result.completion_reason != null,
            .memory_words = result.rw_memory.words,
            .entry_register_clocks = result.entry_access_clocks.register_clocks,
            .exit_register_clocks = result.exit_access_clocks.register_clocks,
            .entry_memory_clocks = result.entry_access_clocks.memory_clocks,
            .exit_memory_clocks = result.exit_access_clocks.memory_clocks,
        };
        try source.validate();
        return source;
    }

    pub fn validate(self: *const SourceV2) Error!void {
        try requireDigest(self.session_id);
        try self.base_statement.validate();
        const executed = try executedLeaf(self.base_statement);
        const range = try sourceRange(self, executed);
        const is_first = self.segment_index == 0;
        const is_final = self.segment_index + 1 == self.base_statement.job.segment_count;

        if (self.segment_role.is_first != is_first or
            self.segment_role.is_last != is_final)
        {
            return error.InvalidSegmentRole;
        }
        if (self.public_input_custody != is_first)
            return error.InputCustodyMismatch;
        if (self.public_output_custody != is_final)
            return error.OutputCustodyMismatch;
        if (self.continuation_present == is_final)
            return error.InvalidSegmentRole;
        if (is_final) {
            const completion = self.completion orelse return error.CompletionMissing;
            try completion.validate(self.exit_cpu.pc, range.end);
        } else if (self.completion != null) {
            return error.CompletionForbidden;
        }

        if (self.entry_cpu.pc != executed.entry.pc or
            !std.mem.eql(u32, &self.entry_cpu.regs, &executed.entry.registers) or
            self.exit_cpu.pc != executed.exit.pc or
            !std.mem.eql(u32, &self.exit_cpu.regs, &executed.exit.registers))
        {
            return error.BaseStatementMismatch;
        }

        try validateMemoryWords(self.memory_words, self.segment_role, range.end);
        try validateClockBoundary(
            self.entry_register_clocks,
            self.entry_memory_clocks,
            range.start,
        );
        try validateClockBoundary(
            self.exit_register_clocks,
            self.exit_memory_clocks,
            range.end,
        );
        try requireClockProgress(self);
        try requireSnapshotClockLink(self);
        try requireCompletionMemoryLink(self);
    }

    pub fn statement(self: *const SourceV2) Error!StatementV2 {
        try self.validate();
        const entry_snapshot = snapshotIdentity(
            self.memory_words,
            .initial_word,
        );
        const exit_snapshot = snapshotIdentity(
            self.memory_words,
            .final_word,
        );
        return self.statementFromSnapshots(entry_snapshot, exit_snapshot);
    }

    /// Reuses roots only after the exact current sparse projections reproduce
    /// both retained snapshot identities and counts. This is the restart path
    /// for a cold-authenticated STWESG31/PublicDataV2 boundary: it avoids an
    /// O(nonzero-bytes * tree-depth) Poseidon traversal without accepting a
    /// detached root or skipping any canonical tuple validation.
    pub fn statementReusingRoots(
        self: *const SourceV2,
        retained_entry: SnapshotIdentity,
        retained_exit: SnapshotIdentity,
    ) Error!StatementV2 {
        try self.validate();
        const entry_snapshot = try snapshotIdentityReusingRoot(
            retained_entry,
            self.memory_words,
            .initial_word,
        );
        const exit_snapshot = try snapshotIdentityReusingRoot(
            retained_exit,
            self.memory_words,
            .final_word,
        );
        return self.statementFromSnapshots(entry_snapshot, exit_snapshot);
    }

    fn statementFromSnapshots(
        self: *const SourceV2,
        entry_snapshot: SnapshotIdentity,
        exit_snapshot: SnapshotIdentity,
    ) Error!StatementV2 {
        const base_words = try self.base_statement.canonicalWords();
        const executed = try executedLeaf(self.base_statement);
        const range = try sourceRange(self, executed);
        const entry_memory_clock_id = memoryClockIdentity(self.entry_memory_clocks);
        const exit_memory_clock_id = memoryClockIdentity(self.exit_memory_clocks);
        const job_id = jobIdAssumeCanonical(&base_words);
        const base_statement_id = baseStatementIdAssumeCanonical(&base_words);
        const position_id = derivePositionId(
            self.session_id,
            job_id,
            self.segment_index,
            self.base_statement.job.segment_count,
            range,
            self.base_statement.slots,
        );
        const entry_lineage_id = deriveBoundaryLineageId(
            self.session_id,
            job_id,
            self.segment_index,
            range.start,
            base_words[span_statement.canonical_layout.entry_state_start..][0..span_statement.MACHINE_STATE_CANONICAL_WORDS],
            entry_snapshot,
            self.entry_register_clocks,
            entry_memory_clock_id,
            @intCast(self.entry_memory_clocks.len),
        );
        const exit_lineage_id = deriveBoundaryLineageId(
            self.session_id,
            job_id,
            self.segment_index + 1,
            range.end,
            base_words[span_statement.canonical_layout.exit_state_start..][0..span_statement.MACHINE_STATE_CANONICAL_WORDS],
            exit_snapshot,
            self.exit_register_clocks,
            exit_memory_clock_id,
            @intCast(self.exit_memory_clocks.len),
        );
        const lineage_id = deriveSegmentLineageId(
            self.session_id,
            job_id,
            position_id,
            entry_lineage_id,
            exit_lineage_id,
            base_statement_id,
        );
        const result = StatementV2{
            .session_id = self.session_id,
            .job_id = job_id,
            .position_id = position_id,
            .entry_lineage_id = entry_lineage_id,
            .exit_lineage_id = exit_lineage_id,
            .lineage_id = lineage_id,
            .base_statement_id = base_statement_id,
            .base_statement_words = base_words,
            .entry_snapshot_id = entry_snapshot.id,
            .entry_snapshot_count = entry_snapshot.count,
            .entry_continuation_root = entry_snapshot.root,
            .exit_snapshot_id = exit_snapshot.id,
            .exit_snapshot_count = exit_snapshot.count,
            .exit_continuation_root = exit_snapshot.root,
            .entry_memory_clock_id = entry_memory_clock_id,
            .entry_memory_clock_count = @intCast(self.entry_memory_clocks.len),
            .exit_memory_clock_id = exit_memory_clock_id,
            .exit_memory_clock_count = @intCast(self.exit_memory_clocks.len),
            .entry_register_clocks = self.entry_register_clocks,
            .exit_register_clocks = self.exit_register_clocks,
            .completion = self.completion,
        };
        try result.validate();
        return result;
    }

    pub fn canonicalWordCount(self: *const SourceV2) Error!usize {
        try self.validate();
        const entry_count = nonZeroWordCount(self.memory_words, .initial_word);
        const exit_count = nonZeroWordCount(self.memory_words, .final_word);
        return checkedWireWordCount(
            entry_count,
            exit_count,
            self.entry_memory_clocks.len,
            self.exit_memory_clocks.len,
        );
    }

    /// Canonical, fail-atomic encoding.  Every fallible source check and size
    /// computation completes before the first destination word is changed.
    pub fn encodeCanonical(
        self: *const SourceV2,
        destination: []M31,
    ) Error!CanonicalWireViewV2 {
        const statement_v2 = try self.statement();
        return self.encodeWithStatement(destination, statement_v2);
    }

    /// Canonical encoder paired with `statementReusingRoots`. The emitted
    /// bytes are identical to `encodeCanonical`; only the root derivation work
    /// is elided after exact sparse identity/count replay succeeds.
    pub fn encodeCanonicalReusingRoots(
        self: *const SourceV2,
        destination: []M31,
        retained_entry: SnapshotIdentity,
        retained_exit: SnapshotIdentity,
    ) Error!CanonicalWireViewV2 {
        const statement_v2 = try self.statementReusingRoots(
            retained_entry,
            retained_exit,
        );
        return self.encodeWithStatement(destination, statement_v2);
    }

    fn encodeWithStatement(
        self: *const SourceV2,
        destination: []M31,
        statement_v2: StatementV2,
    ) Error!CanonicalWireViewV2 {
        const expected = try checkedWireWordCount(
            statement_v2.entry_snapshot_count,
            statement_v2.exit_snapshot_count,
            statement_v2.entry_memory_clock_count,
            statement_v2.exit_memory_clock_count,
        );
        if (destination.len != expected) return error.CanonicalLengthMismatch;

        var writer = Writer{ .words = destination };
        statement_v2.writeFixed(&writer);
        const entry_snapshot = RetainedSectionV2{
            .payload_start = writer.at + SECTION_HEADER_WORDS,
            .count = statement_v2.entry_snapshot_count,
        };
        writeSnapshotSection(&writer, .entry_memory_state, self.memory_words, .initial_word);
        const exit_snapshot = RetainedSectionV2{
            .payload_start = writer.at + SECTION_HEADER_WORDS,
            .count = statement_v2.exit_snapshot_count,
        };
        writeSnapshotSection(&writer, .exit_memory_state, self.memory_words, .final_word);
        const entry_memory_clocks = RetainedSectionV2{
            .payload_start = writer.at + SECTION_HEADER_WORDS,
            .count = statement_v2.entry_memory_clock_count,
        };
        writeClockSection(&writer, .entry_memory_clocks, self.entry_memory_clocks);
        const exit_memory_clocks = RetainedSectionV2{
            .payload_start = writer.at + SECTION_HEADER_WORDS,
            .count = statement_v2.exit_memory_clock_count,
        };
        writeClockSection(&writer, .exit_memory_clocks, self.exit_memory_clocks);
        std.debug.assert(writer.at == destination.len);
        return .{
            .words = destination,
            .statement = statement_v2,
            .entry_snapshot = entry_snapshot,
            .exit_snapshot = exit_snapshot,
            .entry_memory_clocks = entry_memory_clocks,
            .exit_memory_clocks = exit_memory_clocks,
            .wire_id = channel.hashCanonicalWords(destination, WIRE_ID_DOMAIN),
        };
    }
};

pub const AdjacentReceiptV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    session_id: Digest,
    job_id: Digest,
    shared_boundary_lineage_id: Digest,
    left_wire_id: Digest,
    right_wire_id: Digest,
    identity: Digest,
};

pub fn sourceRange(self: *const SourceV2, executed: span_statement.ExecutedSpan) Error!RangeV2 {
    if (self.segment_index != executed.first_segment or
        self.segment_index != self.base_statement.slots.first)
    {
        return error.SegmentIndexMismatch;
    }
    if (self.global_first_cycle == 0) return error.ExecutionRangeOutOfBounds;
    const start_u64 = self.global_first_cycle - 1;
    const count_u64 = std.math.cast(u64, self.cycle_count) orelse
        return error.ExecutionRangeOutOfBounds;
    const end_u64 = std.math.add(u64, start_u64, count_u64) catch
        return error.ExecutionRangeOutOfBounds;
    if (count_u64 == 0 or end_u64 > MAX_GLOBAL_CYCLES or
        executed.first_cycle != start_u64 or
        executed.cycle_count != count_u64)
    {
        return error.ExecutionRangeOutOfBounds;
    }
    return .{ .start = @intCast(start_u64), .end = @intCast(end_u64) };
}

pub fn requireClockProgress(source: *const SourceV2) Error!void {
    for (source.entry_register_clocks, source.exit_register_clocks) |entry, exit| {
        if (exit < entry) return error.BoundaryClockMismatch;
    }
    var exit_at: usize = 0;
    for (source.entry_memory_clocks) |entry| {
        while (exit_at < source.exit_memory_clocks.len and
            source.exit_memory_clocks[exit_at].addr < entry.addr)
        {
            exit_at += 1;
        }
        if (exit_at == source.exit_memory_clocks.len or
            source.exit_memory_clocks[exit_at].addr != entry.addr or
            source.exit_memory_clocks[exit_at].clock < entry.clock)
        {
            return error.BoundaryClockMismatch;
        }
    }
}

pub fn requireSnapshotClockLink(source: *const SourceV2) Error!void {
    var clock_at: usize = 0;
    for (source.memory_words) |word| {
        while (clock_at < source.exit_memory_clocks.len and
            source.exit_memory_clocks[clock_at].addr < word.addr)
        {
            return error.MemoryClockMissing;
        }
        const expected = if (clock_at < source.exit_memory_clocks.len and
            source.exit_memory_clocks[clock_at].addr == word.addr)
            source.exit_memory_clocks[clock_at].clock
        else
            0;
        if (word.final_clock != expected) return error.MemoryClockMissing;
        if (expected != 0) clock_at += 1;
    }
    if (clock_at != source.exit_memory_clocks.len)
        return error.MemoryClockMissing;

    var word_at: usize = 0;
    for (source.entry_memory_clocks) |entry| {
        while (word_at < source.memory_words.len and
            source.memory_words[word_at].addr < entry.addr)
        {
            word_at += 1;
        }
        if (word_at == source.memory_words.len or
            source.memory_words[word_at].addr != entry.addr)
        {
            return error.MemoryClockMissing;
        }
    }
}

pub fn requireCompletionMemoryLink(source: *const SourceV2) Error!void {
    const completion = source.completion orelse return;
    if (completion.kind != .halt_flag) return;
    for (source.memory_words) |word| {
        if (word.addr != completion.address) continue;
        if (!word.role.is_public_completion or
            word.final_word != completion.value or
            word.final_clock != completion.clock)
        {
            return error.CompletionMismatch;
        }
        return;
    }
    return error.CompletionMismatch;
}

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
    hasher.scalar(FORMAT_VERSION);
    hasher.u32Value(section.count);
    for (0..section.count) |index| {
        const entry = view.sparseEntry(section, index);
        hasher.u32Value(entry.address);
        hasher.u32Value(entry.value);
    }
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
