//! Internal segment statement v2 authority shard; use segment_statement_v2.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");

pub const M31 = stwo_core.fields.m31.M31;
pub const m31 = stwo_core.fields.m31;
pub const access_clock = @import("../access_clock.zig");
pub const isa_profile = @import("../isa/profile.zig");
pub const public_data = @import("../air/public_data.zig");
pub const memory_poseidon2 = @import("../air/memory_commitment/poseidon2.zig");
pub const memory_state = @import("../runner/memory_state.zig");
pub const runner_result = @import("../runner/result.zig");
pub const Cpu = @import("../runner/cpu.zig").Cpu;
pub const channel = @import("poseidon2_channel.zig");
pub const protocol = @import("protocol.zig");
pub const span_statement = @import("span_statement.zig");

pub const Digest = channel.Digest;
pub const BaseStatementWords = span_statement.StatementWords;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const KNOWN_FLAGS: u16 = 0;

/// The native proof geometry admits at most 2^24 retired instructions and
/// 2^24 memory rows.  V2 uses the same ceiling for global ranges and each
/// sparse boundary.  A larger protocol requires a new schema, not a wider
/// attacker-controlled allocation.
pub const MAX_GLOBAL_CYCLES: u32 = 1 << 24;
pub const MAX_SPARSE_BOUNDARY_ENTRIES: u32 = 1 << 24;
pub const MAX_RW_ADDRESS_EXCLUSIVE: u32 = 1 << 30;

pub const FORMAT_ID_DOMAIN: u32 = 0x5332_464d; // "S2FM"
/// Shared with `temporal_pair_node.JOB_ID_DOMAIN`: the V2 wrapper must publish
/// the exact job identity already consumed by the temporal parent.
pub const JOB_ID_DOMAIN: u32 = 0x5450_4a42; // "TPJB"
pub const POSITION_ID_DOMAIN: u32 = 0x5332_5053; // "S2PS"
pub const MEMORY_STATE_ID_DOMAIN: u32 = 0x5332_4d53; // "S2MS"
pub const MEMORY_CLOCK_ID_DOMAIN: u32 = 0x5332_4d43; // "S2MC"
pub const BOUNDARY_LINEAGE_ID_DOMAIN: u32 = 0x5332_424c; // "S2BL"
pub const SEGMENT_LINEAGE_ID_DOMAIN: u32 = 0x5332_534c; // "S2SL"
pub const WIRE_ID_DOMAIN: u32 = 0x5332_5749; // "S2WI"
pub const ADJACENCY_ID_DOMAIN: u32 = 0x5332_4144; // "S2AD"

pub const HOT_VALIDATION_HEAP_ALLOCATIONS: usize = 0;
pub const ENCODING_FAILS_BEFORE_FIRST_WRITE = true;
pub const V1_PROJECTION_WORD_COUNT: usize =
    span_statement.SPAN_STATEMENT_CANONICAL_WORDS;

pub const Tag = enum(u32) {
    segment_statement_v2 = 70,
    entry_memory_state = 71,
    exit_memory_state = 72,
    entry_memory_clocks = 73,
    exit_memory_clocks = 74,
    completion_absent = 75,
    completion_present = 76,
};

/// Fixed header layout.  All unrestricted u32 values use two 16-bit limbs.
pub const fixed_layout = struct {
    pub const tag: usize = 0;
    pub const format_version: usize = 1;
    pub const schema_version: usize = 2;
    pub const flags: usize = 3;
    pub const session_id: usize = 4;
    pub const job_id: usize = session_id + 8;
    pub const position_id: usize = job_id + 8;
    pub const entry_lineage_id: usize = position_id + 8;
    pub const exit_lineage_id: usize = entry_lineage_id + 8;
    pub const lineage_id: usize = exit_lineage_id + 8;
    pub const base_statement_id: usize = lineage_id + 8;
    pub const base_statement: usize = base_statement_id + 8;
    pub const entry_snapshot_id: usize = base_statement + V1_PROJECTION_WORD_COUNT;
    pub const entry_snapshot_count: usize = entry_snapshot_id + 8;
    pub const entry_continuation_root: usize = entry_snapshot_count + 2;
    pub const exit_snapshot_id: usize = entry_continuation_root + 2;
    pub const exit_snapshot_count: usize = exit_snapshot_id + 8;
    pub const exit_continuation_root: usize = exit_snapshot_count + 2;
    pub const entry_memory_clock_id: usize = exit_continuation_root + 2;
    pub const entry_memory_clock_count: usize = entry_memory_clock_id + 8;
    pub const exit_memory_clock_id: usize = entry_memory_clock_count + 2;
    pub const exit_memory_clock_count: usize = exit_memory_clock_id + 8;
    pub const entry_register_clocks: usize = exit_memory_clock_count + 2;
    pub const exit_register_clocks: usize = entry_register_clocks + 64;
    pub const completion: usize = exit_register_clocks + 64;
};

pub const FIXED_CANONICAL_WORDS: usize = fixed_layout.completion + 8;
pub const SECTION_HEADER_WORDS: usize = 3;
pub const RETAINED_ENTRY_WORDS: usize = 4;
pub const MIN_CANONICAL_WORDS: usize =
    FIXED_CANONICAL_WORDS + 4 * SECTION_HEADER_WORDS;

comptime {
    if (FIXED_CANONICAL_WORDS != 652)
        @compileError("segment statement V2 fixed geometry drifted");
    if (V1_PROJECTION_WORD_COUNT != 412)
        @compileError("segment statement V2 no longer preserves V1 geometry");
    if (MAX_GLOBAL_CYCLES * access_clock.STRIDE != (1 << 26))
        @compileError("segment statement V2 clock ceiling drifted");
}

pub const Error = span_statement.Error || error{
    BaseStatementMismatch,
    BoundaryClockMismatch,
    BoundaryClockOutOfRange,
    BoundaryIdentityMismatch,
    CanonicalIntegerLimbOutOfRange,
    CanonicalLengthMismatch,
    CanonicalPaddingNonZero,
    CanonicalTagMismatch,
    CanonicalWordNonCanonical,
    ClockFrameMismatch,
    CompletionForbidden,
    CompletionMissing,
    CompletionMismatch,
    CrossSession,
    DigestMismatch,
    DuplicateBoundaryAddress,
    EmptyDigest,
    ExecutionRangeOutOfBounds,
    InputCustodyMismatch,
    InvalidCompletionAddress,
    InvalidCompletionClock,
    InvalidCompletionValue,
    InvalidMemoryAddress,
    InvalidSegmentRole,
    LineageMismatch,
    MemoryClockMissing,
    MemorySnapshotMismatch,
    NonAdjacentPosition,
    NonCanonicalDigest,
    NonCanonicalSparseZero,
    OutputCustodyMismatch,
    RetainedBoundaryMismatch,
    SegmentIndexMismatch,
    SegmentLeafRequired,
    SourceMutation,
    UnsupportedCompletion,
    UnsupportedVersion,
};

pub const CompletionKindV2 = enum(u32) {
    halt_flag = @intFromEnum(public_data.CompletionKind.halt_flag),
    unretired_self_loop = @intFromEnum(public_data.CompletionKind.unretired_self_loop),
};

pub const CompletionV2 = struct {
    kind: CompletionKindV2,
    address: u32,
    value: u32,
    clock: u32,

    pub fn validate(
        self: CompletionV2,
        exit_pc: u32,
        cycle_end: u32,
    ) Error!void {
        switch (self.kind) {
            .halt_flag => {
                if ((self.address & 3) != 0 or self.address >= 0x7fff_fffc)
                    return error.InvalidCompletionAddress;
                if (self.value == 0) return error.InvalidCompletionValue;
                if (!clockWithinBoundary(self.clock, cycle_end, false))
                    return error.InvalidCompletionClock;
            },
            .unretired_self_loop => {
                if (self.address != exit_pc or (self.address & 3) != 0)
                    return error.InvalidCompletionAddress;
                isa_profile.requireProgramWordAddress(self.address) catch
                    return error.InvalidCompletionAddress;
                if (self.value != public_data.CANONICAL_SELF_LOOP_WORD)
                    return error.InvalidCompletionValue;
                if (self.clock != 0) return error.InvalidCompletionClock;
            },
        }
    }
};

pub const StatementV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    flags: u16 = KNOWN_FLAGS,
    session_id: Digest,
    job_id: Digest,
    position_id: Digest,
    entry_lineage_id: Digest,
    exit_lineage_id: Digest,
    lineage_id: Digest,
    base_statement_id: Digest,
    base_statement_words: BaseStatementWords,
    entry_snapshot_id: Digest,
    entry_snapshot_count: u32,
    /// Pinned scalar sparse-Merkle root of every nonzero RW byte at entry.
    /// Unlike V1's role-filtered memory root, this is a continuation root.
    entry_continuation_root: u32,
    exit_snapshot_id: Digest,
    exit_snapshot_count: u32,
    /// Pinned all-RW continuation root at exit; adjacent entry must match.
    exit_continuation_root: u32,
    entry_memory_clock_id: Digest,
    entry_memory_clock_count: u32,
    exit_memory_clock_id: Digest,
    exit_memory_clock_count: u32,
    entry_register_clocks: [32]u32,
    exit_register_clocks: [32]u32,
    completion: ?CompletionV2,

    pub fn base(self: *const StatementV2) Error!span_statement.SpanStatement {
        return span_statement.SpanStatement.fromCanonicalWords(
            &self.base_statement_words,
        );
    }

    pub fn validate(self: *const StatementV2) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.flags != KNOWN_FLAGS)
        {
            return error.UnsupportedVersion;
        }
        inline for (.{
            self.session_id,
            self.job_id,
            self.position_id,
            self.entry_lineage_id,
            self.exit_lineage_id,
            self.lineage_id,
            self.base_statement_id,
            self.entry_snapshot_id,
            self.exit_snapshot_id,
            self.entry_memory_clock_id,
            self.exit_memory_clock_id,
        }) |digest| try requireDigest(digest);
        if (self.entry_snapshot_count > MAX_SPARSE_BOUNDARY_ENTRIES or
            self.exit_snapshot_count > MAX_SPARSE_BOUNDARY_ENTRIES or
            self.entry_memory_clock_count > MAX_SPARSE_BOUNDARY_ENTRIES or
            self.exit_memory_clock_count > MAX_SPARSE_BOUNDARY_ENTRIES)
        {
            return error.ExecutionRangeOutOfBounds;
        }
        if (self.entry_continuation_root >= m31.Modulus or
            self.exit_continuation_root >= m31.Modulus)
        {
            return error.NonCanonicalDigest;
        }

        const decoded_base = try self.base();
        const executed = try executedLeaf(decoded_base);
        const range = try statementRange(decoded_base, executed);
        const expected_job_id = jobIdAssumeCanonical(&self.base_statement_words);
        const expected_base_id = baseStatementIdAssumeCanonical(
            &self.base_statement_words,
        );
        if (!std.meta.eql(expected_job_id, self.job_id) or
            !std.meta.eql(expected_base_id, self.base_statement_id))
        {
            return error.DigestMismatch;
        }
        const expected_position = derivePositionId(
            self.session_id,
            self.job_id,
            executed.first_segment,
            decoded_base.job.segment_count,
            range,
            decoded_base.slots,
        );
        if (!std.meta.eql(expected_position, self.position_id))
            return error.DigestMismatch;

        try validateRegisterClocks(self.entry_register_clocks, range.start);
        try validateRegisterClocks(self.exit_register_clocks, range.end);
        for (self.entry_register_clocks, self.exit_register_clocks) |entry, exit| {
            if (exit < entry) return error.BoundaryClockMismatch;
        }

        const expected_entry_lineage = deriveBoundaryLineageId(
            self.session_id,
            self.job_id,
            executed.first_segment,
            range.start,
            self.base_statement_words[span_statement.canonical_layout.entry_state_start..][0..span_statement.MACHINE_STATE_CANONICAL_WORDS],
            .{
                .id = self.entry_snapshot_id,
                .count = self.entry_snapshot_count,
                .root = self.entry_continuation_root,
            },
            self.entry_register_clocks,
            self.entry_memory_clock_id,
            self.entry_memory_clock_count,
        );
        const expected_exit_lineage = deriveBoundaryLineageId(
            self.session_id,
            self.job_id,
            executed.first_segment + 1,
            range.end,
            self.base_statement_words[span_statement.canonical_layout.exit_state_start..][0..span_statement.MACHINE_STATE_CANONICAL_WORDS],
            .{
                .id = self.exit_snapshot_id,
                .count = self.exit_snapshot_count,
                .root = self.exit_continuation_root,
            },
            self.exit_register_clocks,
            self.exit_memory_clock_id,
            self.exit_memory_clock_count,
        );
        if (!std.meta.eql(expected_entry_lineage, self.entry_lineage_id) or
            !std.meta.eql(expected_exit_lineage, self.exit_lineage_id))
        {
            return error.LineageMismatch;
        }
        const expected_lineage = deriveSegmentLineageId(
            self.session_id,
            self.job_id,
            self.position_id,
            self.entry_lineage_id,
            self.exit_lineage_id,
            self.base_statement_id,
        );
        if (!std.meta.eql(expected_lineage, self.lineage_id))
            return error.LineageMismatch;

        const is_final = executed.endSegment() == decoded_base.job.segment_count;
        if (is_final) {
            const completion = self.completion orelse return error.CompletionMissing;
            try completion.validate(executed.exit.pc, range.end);
        } else if (self.completion != null) {
            return error.CompletionForbidden;
        }
    }

    pub fn canonicalFixedWords(self: *const StatementV2) Error![FIXED_CANONICAL_WORDS]M31 {
        try self.validate();
        var words: [FIXED_CANONICAL_WORDS]M31 = undefined;
        var writer = Writer{ .words = &words };
        self.writeFixed(&writer);
        std.debug.assert(writer.at == words.len);
        return words;
    }

    pub fn writeFixed(self: *const StatementV2, writer: *Writer) void {
        writer.tag(.segment_statement_v2);
        writer.put(self.format_version);
        writer.put(self.schema_version);
        writer.put(self.flags);
        writer.digest(self.session_id);
        writer.digest(self.job_id);
        writer.digest(self.position_id);
        writer.digest(self.entry_lineage_id);
        writer.digest(self.exit_lineage_id);
        writer.digest(self.lineage_id);
        writer.digest(self.base_statement_id);
        writer.m31s(&self.base_statement_words);
        writer.digest(self.entry_snapshot_id);
        writer.u32Value(self.entry_snapshot_count);
        writer.u32Value(self.entry_continuation_root);
        writer.digest(self.exit_snapshot_id);
        writer.u32Value(self.exit_snapshot_count);
        writer.u32Value(self.exit_continuation_root);
        writer.digest(self.entry_memory_clock_id);
        writer.u32Value(self.entry_memory_clock_count);
        writer.digest(self.exit_memory_clock_id);
        writer.u32Value(self.exit_memory_clock_count);
        for (self.entry_register_clocks) |clock| writer.u32Value(clock);
        for (self.exit_register_clocks) |clock| writer.u32Value(clock);
        writeCompletion(writer, self.completion);
    }
};

pub const RetainedSectionV2 = struct {
    payload_start: usize,
    count: u32,
};

pub const SparseEntryV2 = struct {
    address: u32,
    value: u32,
};

pub const ClockEntryV2 = struct {
    address: u32,
    clock: u32,
};

pub const RangeV2 = struct { start: u32, end: u32 };

pub fn statementRange(
    base: span_statement.SpanStatement,
    executed: span_statement.ExecutedSpan,
) Error!RangeV2 {
    _ = base;
    const end = std.math.add(u64, executed.first_cycle, executed.cycle_count) catch
        return error.ExecutionRangeOutOfBounds;
    if (executed.cycle_count == 0 or end > MAX_GLOBAL_CYCLES)
        return error.ExecutionRangeOutOfBounds;
    return .{ .start = @intCast(executed.first_cycle), .end = @intCast(end) };
}

pub fn executedLeaf(base: span_statement.SpanStatement) Error!span_statement.ExecutedSpan {
    if (base.slots.height != 0) return error.SegmentLeafRequired;
    const executed = switch (base.body) {
        .empty => return error.SegmentLeafRequired,
        .executed => |value| value,
    };
    if (executed.segment_count != 1) return error.SegmentLeafRequired;
    return executed;
}
pub const SnapshotIdentity = struct {
    id: Digest,
    count: u32,
    root: u32,
};

pub fn validateRegisterClocks(clocks: [32]u32, cycle: u32) Error!void {
    for (clocks) |clock| {
        if (!clockWithinBoundary(clock, cycle, true))
            return error.BoundaryClockOutOfRange;
    }
}

pub fn clockWithinBoundary(clock: u32, cycle: u32, allow_zero: bool) bool {
    if (cycle > MAX_GLOBAL_CYCLES) return false;
    return access_clock.isWithinExecution(clock, cycle, allow_zero);
}

pub fn jobIdAssumeCanonical(words: *const BaseStatementWords) Digest {
    return channel.hashCanonicalWords(
        words[span_statement.canonical_layout.job_start..span_statement.canonical_layout.slot_start],
        JOB_ID_DOMAIN,
    );
}

pub fn baseStatementIdAssumeCanonical(words: *const BaseStatementWords) Digest {
    var canonical: [V1_PROJECTION_WORD_COUNT]u32 = undefined;
    for (&canonical, words) |*destination, word|
        destination.* = word.toU32();
    return protocol.statementId(&canonical);
}

pub fn derivePositionId(
    session_id: Digest,
    job_id: Digest,
    segment_index: u32,
    segment_count: u32,
    range: RangeV2,
    slots: span_statement.SlotSpan,
) Digest {
    var hasher = IdentityHasher.init(POSITION_ID_DOMAIN);
    hasher.scalar(FORMAT_VERSION);
    hasher.digest(session_id);
    hasher.digest(job_id);
    hasher.u32Value(segment_index);
    hasher.u32Value(segment_count);
    hasher.u32Value(range.start);
    hasher.u32Value(range.end);
    hasher.u64Value(slots.first);
    hasher.scalar(slots.height);
    hasher.u64Value(slots.nodeIndex());
    return hasher.finalize();
}

pub fn deriveBoundaryLineageId(
    session_id: Digest,
    job_id: Digest,
    boundary_index: u32,
    cycle: u32,
    machine_words: []const M31,
    snapshot: SnapshotIdentity,
    register_clocks: [32]u32,
    memory_clock_id: Digest,
    memory_clock_count: u32,
) Digest {
    var hasher = IdentityHasher.init(BOUNDARY_LINEAGE_ID_DOMAIN);
    hasher.scalar(FORMAT_VERSION);
    hasher.digest(session_id);
    hasher.digest(job_id);
    hasher.u32Value(boundary_index);
    hasher.u32Value(cycle);
    hasher.m31s(machine_words);
    hasher.digest(snapshot.id);
    hasher.u32Value(snapshot.count);
    hasher.scalar(snapshot.root);
    for (register_clocks) |clock| hasher.u32Value(clock);
    hasher.digest(memory_clock_id);
    hasher.u32Value(memory_clock_count);
    return hasher.finalize();
}

pub fn deriveSegmentLineageId(
    session_id: Digest,
    job_id: Digest,
    position_id: Digest,
    entry_lineage_id: Digest,
    exit_lineage_id: Digest,
    base_statement_id: Digest,
) Digest {
    var hasher = IdentityHasher.init(SEGMENT_LINEAGE_ID_DOMAIN);
    hasher.scalar(FORMAT_VERSION);
    hasher.digest(session_id);
    hasher.digest(job_id);
    hasher.digest(position_id);
    hasher.digest(entry_lineage_id);
    hasher.digest(exit_lineage_id);
    hasher.digest(base_statement_id);
    return hasher.finalize();
}

pub fn writeCompletion(writer: *Writer, completion: ?CompletionV2) void {
    if (completion) |value| {
        writer.tag(.completion_present);
        writer.put(@intFromEnum(value.kind));
        writer.u32Value(value.address);
        writer.u32Value(value.value);
        writer.u32Value(value.clock);
    } else {
        writer.tag(.completion_absent);
        writer.zeroes(7);
    }
}

pub fn requireDigest(digest: Digest) Error!void {
    var aggregate: u32 = 0;
    for (digest) |word| {
        if (word >= m31.Modulus) return error.NonCanonicalDigest;
        aggregate |= word;
    }
    if (aggregate == 0) return error.EmptyDigest;
}

pub fn readEncodedU32(words: *const [2]M31) u32 {
    return words[0].toU32() | (words[1].toU32() << 16);
}

pub const Writer = struct {
    words: []M31,
    at: usize = 0,

    fn put(self: *Writer, value: anytype) void {
        const canonical: u32 = @intCast(value);
        std.debug.assert(self.at < self.words.len and canonical < m31.Modulus);
        self.words[self.at] = M31.fromCanonical(canonical);
        self.at += 1;
    }

    pub fn tag(self: *Writer, value: Tag) void {
        self.put(@intFromEnum(value));
    }

    pub fn u32Value(self: *Writer, value: u32) void {
        self.put(value & 0xffff);
        self.put(value >> 16);
    }

    fn digest(self: *Writer, value: Digest) void {
        for (value) |word| self.put(word);
    }

    fn m31s(self: *Writer, values: []const M31) void {
        for (values) |word| {
            std.debug.assert(word.toU32() < m31.Modulus);
            self.words[self.at] = word;
            self.at += 1;
        }
    }

    fn zeroes(self: *Writer, count: usize) void {
        for (0..count) |_| self.put(0);
    }
};

pub const IdentityHasher = struct {
    inner: channel.CanonicalWordHasher,

    pub fn init(domain: u32) IdentityHasher {
        return .{ .inner = channel.CanonicalWordHasher.init(domain) };
    }

    pub fn scalar(self: *IdentityHasher, value: anytype) void {
        const canonical: u32 = @intCast(value);
        std.debug.assert(canonical < m31.Modulus);
        const words = [_]M31{M31.fromCanonical(canonical)};
        self.inner.update(&words);
    }

    pub fn u32Value(self: *IdentityHasher, value: u32) void {
        const words = [_]M31{
            M31.fromCanonical(value & 0xffff),
            M31.fromCanonical(value >> 16),
        };
        self.inner.update(&words);
    }

    pub fn u64Value(self: *IdentityHasher, value: u64) void {
        inline for (0..4) |limb|
            self.scalar(@as(u32, @truncate((value >> (16 * limb)) & 0xffff)));
    }

    pub fn digest(self: *IdentityHasher, value: Digest) void {
        for (value) |word| self.scalar(word);
    }

    pub fn m31s(self: *IdentityHasher, values: []const M31) void {
        self.inner.update(values);
    }

    pub fn finalize(self: *IdentityHasher) Digest {
        return self.inner.finalize();
    }
};
