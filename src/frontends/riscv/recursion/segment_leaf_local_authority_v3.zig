//! Native authority for a globally positioned, leaf-local-clock VM segment.
//!
//! Segment statement V2 deliberately uses one global clock namespace and is
//! capped at 2^24 retirements. Large recursive executions instead prove many
//! bounded leaves: each leaf resets its AIR-visible instruction/access clocks
//! to zero while the existing 64-bit span statement owns global position.
//! This module keeps those namespaces explicit and validates their exact join.
//!
//! This is statement/custody substrate, not a proof verifier. A later V3 AIR
//! must authenticate the resulting metadata and retained sparse boundaries;
//! callers must not treat successful native validation as proof acceptance.

const std = @import("std");
const stwo_core = @import("stwo_core");

const access_clock = @import("../access_clock.zig");
const memory_state = @import("../runner/memory_state.zig");
const runner_result = @import("../runner/result.zig");
const channel = @import("poseidon2_channel.zig");
const span = @import("span_statement.zig");
const segment_v2 = @import("segment_statement_v2.zig");

const m31 = stwo_core.fields.m31;

pub const FORMAT_VERSION: u16 = 3;
pub const SCHEMA_VERSION: u16 = 1;
pub const KNOWN_FLAGS: u16 = 0;
pub const MAX_LEAF_CYCLES: u32 = segment_v2.MAX_GLOBAL_CYCLES;
pub const MAX_SPARSE_BOUNDARY_ENTRIES: u32 =
    segment_v2.MAX_SPARSE_BOUNDARY_ENTRIES;
pub const CLOCK_FRAME: runner_result.SegmentClockFrame = .leaf_local;
pub const HOT_VALIDATION_HEAP_ALLOCATIONS: usize = 0;
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const METADATA_ID_DOMAIN: u32 = 0x4c33_4d33; // "L3M3"
const BOUNDARY_IDENTITY_WORDS: usize = 8 + 2 + 1 + (32 * 2) + 8 + 2;
const POSITION_IDENTITY_WORDS: usize = 2 + 2 + 4 + 4 + 2;
const COMPLETION_IDENTITY_WORDS: usize = 8;
pub const METADATA_IDENTITY_WORDS: usize =
    4 +
    span.SPAN_STATEMENT_CANONICAL_WORDS +
    POSITION_IDENTITY_WORDS +
    (2 * BOUNDARY_IDENTITY_WORDS) +
    COMPLETION_IDENTITY_WORDS;

comptime {
    if (METADATA_IDENTITY_WORDS != 608)
        @compileError("leaf-local V3 metadata identity layout drifted");
    if (METADATA_ID_DOMAIN >= m31.Modulus)
        @compileError("leaf-local V3 metadata identity domain is not canonical");
}

pub const Error = segment_v2.Error || error{
    ClockFrameMismatch,
    ContinuationMismatch,
    CpuBoundaryMismatch,
    EntryClockNotReset,
    GlobalPositionMismatch,
    InvalidBoundaryDigest,
    LocalCycleRangeOutOfBounds,
    MemoryContinuationMismatch,
    MemorySnapshotMismatch,
    SegmentPositionMismatch,
    TraceClockMismatch,
    UnsupportedVersion,
};

/// Value-only boundary projection. The sparse tuples remain borrowed by
/// `SourceV3`; the identities here are suitable for a future canonical wire
/// only when that wire also retains and re-authenticates the tuples.
pub const BoundaryV3 = struct {
    snapshot_id: segment_v2.Digest,
    snapshot_count: u32,
    continuation_root: u32,
    register_clocks: [32]u32,
    memory_clock_id: segment_v2.Digest,
    memory_clock_count: u32,
};

/// Versioned native projection of one bounded leaf and its 64-bit position.
pub const MetadataV3 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    flags: u16 = KNOWN_FLAGS,
    clock_frame: runner_result.SegmentClockFrame = CLOCK_FRAME,
    base_statement_words: span.StatementWords,
    segment_index: u32,
    segment_count: u32,
    global_cycle_start: u64,
    global_cycle_end: u64,
    local_cycle_count: u32,
    entry: BoundaryV3,
    exit: BoundaryV3,
    completion: ?segment_v2.CompletionV2,

    pub fn validate(self: *const MetadataV3) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.flags != KNOWN_FLAGS)
        {
            return error.UnsupportedVersion;
        }
        if (self.clock_frame != CLOCK_FRAME) return error.ClockFrameMismatch;
        if (self.local_cycle_count == 0 or
            self.local_cycle_count > MAX_LEAF_CYCLES)
        {
            return error.LocalCycleRangeOutOfBounds;
        }
        const expected_end = std.math.add(
            u64,
            self.global_cycle_start,
            self.local_cycle_count,
        ) catch return error.GlobalPositionMismatch;
        if (self.global_cycle_end != expected_end)
            return error.GlobalPositionMismatch;

        const base = span.SpanStatement.fromCanonicalWords(
            &self.base_statement_words,
        ) catch return error.BaseStatementMismatch;
        const executed = try executedLeaf(base);
        if (self.segment_index != executed.first_segment or
            self.segment_index != base.slots.first or
            self.segment_count != base.job.segment_count)
        {
            return error.SegmentPositionMismatch;
        }
        if (self.global_cycle_start != executed.first_cycle or
            self.global_cycle_end != executed.endCycle() or
            executed.cycle_count != self.local_cycle_count)
        {
            return error.GlobalPositionMismatch;
        }

        try validateBoundary(&self.entry, 0);
        try validateBoundary(&self.exit, self.local_cycle_count);
        for (self.entry.register_clocks) |clock|
            if (clock != 0) return error.EntryClockNotReset;
        if (self.entry.memory_clock_count != 0 or
            !std.meta.eql(
                self.entry.memory_clock_id,
                segment_v2.memoryClockIdentity(&.{}),
            ))
        {
            return error.EntryClockNotReset;
        }

        const is_final = executed.endSegment() == base.job.segment_count;
        if (is_final) {
            const completion = self.completion orelse
                return error.CompletionMissing;
            try completion.validate(executed.exit.pc, self.local_cycle_count);
        } else if (self.completion != null) {
            return error.CompletionForbidden;
        }
    }

    /// Canonical Poseidon identity of the complete global projection,
    /// including both sparse-boundary identities and all local clock custody.
    pub fn identity(self: *const MetadataV3) Error!segment_v2.Digest {
        try self.validate();
        var words: [METADATA_IDENTITY_WORDS]stwo_core.fields.m31.M31 = undefined;
        var at: usize = 0;
        putScalar(&words, &at, self.format_version);
        putScalar(&words, &at, self.schema_version);
        putScalar(&words, &at, self.flags);
        putScalar(&words, &at, @intFromEnum(self.clock_frame));
        putM31s(&words, &at, &self.base_statement_words);
        putU32(&words, &at, self.segment_index);
        putU32(&words, &at, self.segment_count);
        putU64(&words, &at, self.global_cycle_start);
        putU64(&words, &at, self.global_cycle_end);
        putU32(&words, &at, self.local_cycle_count);
        putBoundary(&words, &at, self.entry);
        putBoundary(&words, &at, self.exit);
        if (self.completion) |completion| {
            putScalar(&words, &at, 1);
            putScalar(&words, &at, @intFromEnum(completion.kind));
            putU32(&words, &at, completion.address);
            putU32(&words, &at, completion.value);
            putU32(&words, &at, completion.clock);
        } else {
            putScalar(&words, &at, 0);
            for (0..7) |_| putScalar(&words, &at, 0);
        }
        std.debug.assert(at == words.len);
        return channel.hashCanonicalWords(&words, METADATA_ID_DOMAIN);
    }
};

/// Borrowed exact source from the resumable runner. Validation allocates
/// nothing and rechecks source bytes/state every time, so a stale metadata
/// value cannot authorize a subsequently mutated result.
pub const SourceV3 = struct {
    base_statement: span.SpanStatement,
    result: *const runner_result.SegmentResult,

    pub fn fromSegmentResult(
        base_statement: span.SpanStatement,
        result: *const runner_result.SegmentResult,
    ) Error!SourceV3 {
        const source = SourceV3{
            .base_statement = base_statement,
            .result = result,
        };
        try source.validate();
        return source;
    }

    pub fn validate(self: *const SourceV3) Error!void {
        try self.base_statement.validate();
        const executed = try executedLeaf(self.base_statement);
        const result = self.result;
        if (result.clock_frame != CLOCK_FRAME) return error.ClockFrameMismatch;
        if (!std.meta.eql(result.segment_role, result.rw_memory.segment_role))
            return error.InvalidSegmentRole;

        const local_cycles = std.math.cast(u32, result.cycle_count) orelse
            return error.LocalCycleRangeOutOfBounds;
        if (local_cycles == 0 or local_cycles > MAX_LEAF_CYCLES)
            return error.LocalCycleRangeOutOfBounds;
        if (result.global_first_cycle == 0)
            return error.GlobalPositionMismatch;
        const global_start = result.global_first_cycle - 1;
        const global_end = std.math.add(
            u64,
            global_start,
            local_cycles,
        ) catch return error.GlobalPositionMismatch;
        if (result.segment_index != executed.first_segment or
            result.segment_index != self.base_statement.slots.first)
        {
            return error.SegmentPositionMismatch;
        }
        if (global_start != executed.first_cycle or
            global_end != executed.endCycle() or
            executed.cycle_count != local_cycles)
        {
            return error.GlobalPositionMismatch;
        }

        const is_first = result.segment_index == 0;
        const is_final = executed.endSegment() ==
            self.base_statement.job.segment_count;
        if (result.segment_role.is_first != is_first or
            result.segment_role.is_last != is_final or
            (result.input != null) != is_first)
        {
            return error.InvalidSegmentRole;
        }
        try validateContinuation(result, global_end, is_final);

        if (result.entry_cpu.pc != executed.entry.pc or
            !std.mem.eql(u32, &result.entry_cpu.regs, &executed.entry.registers) or
            result.exit_cpu.pc != executed.exit.pc or
            !std.mem.eql(u32, &result.exit_cpu.regs, &executed.exit.registers))
        {
            return error.CpuBoundaryMismatch;
        }
        if (result.execution_trace.initial_pc != result.entry_cpu.pc or
            result.execution_trace.final_pc != result.exit_cpu.pc)
        {
            return error.TraceClockMismatch;
        }
        result.execution_trace.validateClockRange(
            0,
            local_cycles,
            result.execution_trace.recordedExternalSteps(),
        ) catch return error.TraceClockMismatch;
        try validateTraceRows(result, local_cycles);

        try segment_v2.validateMemoryWords(
            result.rw_memory.words,
            result.segment_role,
            local_cycles,
        );
        try segment_v2.validateClockBoundary(
            result.entry_access_clocks.register_clocks,
            result.entry_access_clocks.memory_clocks,
            0,
        );
        try segment_v2.validateClockBoundary(
            result.exit_access_clocks.register_clocks,
            result.exit_access_clocks.memory_clocks,
            local_cycles,
        );
        for (result.entry_access_clocks.register_clocks) |clock|
            if (clock != 0) return error.EntryClockNotReset;
        if (result.entry_access_clocks.memory_clocks.len != 0)
            return error.EntryClockNotReset;
        try validateTrackerBoundary(result);
        try validateSnapshotClockLink(result);
        try validateCompletionMemoryLink(result, local_cycles, is_final);

        const projection = try metadataUnchecked(self, local_cycles);
        try projection.validate();
    }

    pub fn metadata(self: *const SourceV3) Error!MetadataV3 {
        try self.validate();
        return metadataUnchecked(
            self,
            @intCast(self.result.cycle_count),
        );
    }
};

/// Metadata-only adjacency for the future recursive circuit. The global span
/// owns order and machine-state equality; the continuation root owns the
/// locally reset sparse-memory boundary. Access clocks intentionally do not
/// cross leaves—the reset is the protocol feature being authenticated.
pub fn requireAdjacentMetadata(
    left: *const MetadataV3,
    right: *const MetadataV3,
) Error!void {
    try left.validate();
    try right.validate();
    const left_base = span.SpanStatement.fromCanonicalWords(
        &left.base_statement_words,
    ) catch return error.BaseStatementMismatch;
    const right_base = span.SpanStatement.fromCanonicalWords(
        &right.base_statement_words,
    ) catch return error.BaseStatementMismatch;
    const left_span = try executedLeaf(left_base);
    const right_span = try executedLeaf(right_base);
    const next_segment = std.math.add(u32, left.segment_index, 1) catch
        return error.SegmentPositionMismatch;
    if (!std.meta.eql(left_base.job, right_base.job) or
        next_segment != right.segment_index or
        left.global_cycle_end != right.global_cycle_start or
        !std.meta.eql(left_span.exit, right_span.entry) or
        left_span.output.digest != null or
        right_span.input.digest != null)
    {
        return error.GlobalPositionMismatch;
    }
    if (!std.meta.eql(left.exit.snapshot_id, right.entry.snapshot_id) or
        left.exit.snapshot_count != right.entry.snapshot_count or
        left.exit.continuation_root != right.entry.continuation_root)
    {
        return error.MemorySnapshotMismatch;
    }
}

/// Native source adjacency additionally compares every sparse word exactly.
/// This is stronger than digest equality and catches construction bugs before
/// any data reaches the future recursive statement encoder.
pub fn requireAdjacentSources(
    left: *const SourceV3,
    right: *const SourceV3,
) Error!void {
    const left_metadata = try left.metadata();
    const right_metadata = try right.metadata();
    try requireAdjacentMetadata(&left_metadata, &right_metadata);
    left.result.rw_memory.requireContinuationTo(right.result.rw_memory) catch
        return error.MemoryContinuationMismatch;
}

fn executedLeaf(base: span.SpanStatement) Error!span.ExecutedSpan {
    if (base.slots.height != 0) return error.SegmentLeafRequired;
    const executed = switch (base.body) {
        .empty => return error.SegmentLeafRequired,
        .executed => |value| value,
    };
    if (executed.segment_count != 1) return error.SegmentLeafRequired;
    return executed;
}

fn metadataUnchecked(
    source: *const SourceV3,
    local_cycles: u32,
) Error!MetadataV3 {
    const result = source.result;
    const base_words = try source.base_statement.canonicalWords();
    const entry_snapshot = segment_v2.snapshotIdentity(
        result.rw_memory.words,
        .initial_word,
    );
    const exit_snapshot = segment_v2.snapshotIdentity(
        result.rw_memory.words,
        .final_word,
    );
    return .{
        .base_statement_words = base_words,
        .segment_index = result.segment_index,
        .segment_count = source.base_statement.job.segment_count,
        .global_cycle_start = result.global_first_cycle - 1,
        .global_cycle_end = result.global_first_cycle - 1 + local_cycles,
        .local_cycle_count = local_cycles,
        .entry = .{
            .snapshot_id = entry_snapshot.id,
            .snapshot_count = entry_snapshot.count,
            .continuation_root = entry_snapshot.root,
            .register_clocks = result.entry_access_clocks.register_clocks,
            .memory_clock_id = segment_v2.memoryClockIdentity(
                result.entry_access_clocks.memory_clocks,
            ),
            .memory_clock_count = @intCast(
                result.entry_access_clocks.memory_clocks.len,
            ),
        },
        .exit = .{
            .snapshot_id = exit_snapshot.id,
            .snapshot_count = exit_snapshot.count,
            .continuation_root = exit_snapshot.root,
            .register_clocks = result.exit_access_clocks.register_clocks,
            .memory_clock_id = segment_v2.memoryClockIdentity(
                result.exit_access_clocks.memory_clocks,
            ),
            .memory_clock_count = @intCast(
                result.exit_access_clocks.memory_clocks.len,
            ),
        },
        .completion = if (result.completion_reason) |reason|
            try segment_v2.completionFromRunner(
                reason,
                result.completion_address,
                result.completion_value,
                result.completion_clock,
            )
        else
            null,
    };
}

fn validateBoundary(boundary: *const BoundaryV3, cycle: u32) Error!void {
    try requireDigest(boundary.snapshot_id);
    try requireDigest(boundary.memory_clock_id);
    if (boundary.snapshot_count > MAX_SPARSE_BOUNDARY_ENTRIES or
        boundary.memory_clock_count > MAX_SPARSE_BOUNDARY_ENTRIES)
    {
        return error.LocalCycleRangeOutOfBounds;
    }
    if (boundary.continuation_root >= m31.Modulus)
        return error.InvalidBoundaryDigest;
    for (boundary.register_clocks) |clock| {
        if (!access_clock.isWithinExecution(clock, cycle, true))
            return error.BoundaryClockOutOfRange;
    }
}

fn requireDigest(digest: segment_v2.Digest) Error!void {
    var aggregate: u32 = 0;
    for (digest) |word| {
        if (word >= m31.Modulus) return error.InvalidBoundaryDigest;
        aggregate |= word;
    }
    if (aggregate == 0) return error.InvalidBoundaryDigest;
}

fn validateContinuation(
    result: *const runner_result.SegmentResult,
    global_end: u64,
    is_final: bool,
) Error!void {
    if (is_final) {
        if (result.continuation != null or result.completion_reason == null)
            return error.ContinuationMismatch;
        return;
    }
    if (result.completion_reason != null) return error.CompletionForbidden;
    const continuation = result.continuation orelse
        return error.ContinuationMismatch;
    const next_segment = std.math.add(u32, result.segment_index, 1) catch
        return error.ContinuationMismatch;
    const next_cycle = std.math.add(u64, global_end, 1) catch
        return error.ContinuationMismatch;
    if (continuation.schema_version != runner_result.CONTINUATION_SCHEMA_VERSION or
        continuation.clock_frame != CLOCK_FRAME or
        continuation.next_segment_index != next_segment or
        continuation.next_cycle != next_cycle or
        !std.meta.eql(continuation.cpu, result.exit_cpu) or
        !std.meta.eql(continuation.rw_memory, result.rw_memory.exitIdentity()) or
        continuation.access_clocks != result.exit_access_clocks.identity())
    {
        return error.ContinuationMismatch;
    }
}

fn validateTraceRows(
    result: *const runner_result.SegmentResult,
    local_cycles: u32,
) Error!void {
    var next_clock: u64 = 1;
    var omitted: u64 = 0;
    for (result.execution_trace.rows.items) |row| {
        if (row.clk < next_clock or row.clk > local_cycles)
            return error.TraceClockMismatch;
        omitted = std.math.add(u64, omitted, row.clk - next_clock) catch
            return error.TraceClockMismatch;
        next_clock = @as(u64, row.clk) + 1;
    }
    omitted = std.math.add(
        u64,
        omitted,
        @as(u64, local_cycles) + 1 - next_clock,
    ) catch return error.TraceClockMismatch;
    if (omitted != result.execution_trace.recordedExternalSteps())
        return error.TraceClockMismatch;
}

fn validateTrackerBoundary(result: *const runner_result.SegmentResult) Error!void {
    if (!std.meta.eql(
        result.state_chain_tracker.reg_last_clk,
        result.exit_access_clocks.register_clocks,
    ) or result.state_chain_tracker.mem_last_clk.count() !=
        result.exit_access_clocks.memory_clocks.len)
    {
        return error.BoundaryClockMismatch;
    }
    for (result.exit_access_clocks.memory_clocks) |entry| {
        if (result.state_chain_tracker.mem_last_clk.get(entry.addr) != entry.clock)
            return error.BoundaryClockMismatch;
    }
}

fn validateSnapshotClockLink(result: *const runner_result.SegmentResult) Error!void {
    var clock_at: usize = 0;
    for (result.rw_memory.words) |word| {
        while (clock_at < result.exit_access_clocks.memory_clocks.len and
            result.exit_access_clocks.memory_clocks[clock_at].addr < word.addr)
        {
            return error.MemoryClockMissing;
        }
        const expected = if (clock_at <
            result.exit_access_clocks.memory_clocks.len and
            result.exit_access_clocks.memory_clocks[clock_at].addr == word.addr)
            result.exit_access_clocks.memory_clocks[clock_at].clock
        else
            0;
        if (word.final_clock != expected) return error.MemoryClockMissing;
        if (expected != 0) clock_at += 1;
    }
    if (clock_at != result.exit_access_clocks.memory_clocks.len)
        return error.MemoryClockMissing;
}

fn validateCompletionMemoryLink(
    result: *const runner_result.SegmentResult,
    local_cycles: u32,
    is_final: bool,
) Error!void {
    if (!is_final) return;
    const reason = result.completion_reason orelse return error.CompletionMissing;
    const completion = try segment_v2.completionFromRunner(
        reason,
        result.completion_address,
        result.completion_value,
        result.completion_clock,
    );
    try completion.validate(result.exit_cpu.pc, local_cycles);
    if (completion.kind != .halt_flag) return;
    for (result.rw_memory.words) |word| {
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

fn putBoundary(
    words: []stwo_core.fields.m31.M31,
    at: *usize,
    boundary: BoundaryV3,
) void {
    putDigest(words, at, boundary.snapshot_id);
    putU32(words, at, boundary.snapshot_count);
    putScalar(words, at, boundary.continuation_root);
    for (boundary.register_clocks) |clock| putU32(words, at, clock);
    putDigest(words, at, boundary.memory_clock_id);
    putU32(words, at, boundary.memory_clock_count);
}

fn putDigest(
    words: []stwo_core.fields.m31.M31,
    at: *usize,
    digest: segment_v2.Digest,
) void {
    for (digest) |word| putScalar(words, at, word);
}

fn putM31s(
    words: []stwo_core.fields.m31.M31,
    at: *usize,
    values: []const stwo_core.fields.m31.M31,
) void {
    for (values) |value| {
        words[at.*] = value;
        at.* += 1;
    }
}

fn putScalar(
    words: []stwo_core.fields.m31.M31,
    at: *usize,
    value: u32,
) void {
    std.debug.assert(value < m31.Modulus);
    words[at.*] = stwo_core.fields.m31.M31.fromCanonical(value);
    at.* += 1;
}

fn putU32(
    words: []stwo_core.fields.m31.M31,
    at: *usize,
    value: u32,
) void {
    putScalar(words, at, value & 0xffff);
    putScalar(words, at, value >> 16);
}

fn putU64(
    words: []stwo_core.fields.m31.M31,
    at: *usize,
    value: u64,
) void {
    inline for (0..4) |limb|
        putScalar(words, at, @intCast((value >> (16 * limb)) & 0xffff));
}
