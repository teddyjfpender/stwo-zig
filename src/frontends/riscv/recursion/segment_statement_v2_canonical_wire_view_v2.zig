//! Internal segment statement v2 authority shard; use segment_statement_v2.zig publicly.

const dependency_0 = @import("segment_statement_v2_contract.zig");

const ClockEntryV2 = dependency_0.ClockEntryV2;
const CompletionV2 = dependency_0.CompletionV2;
const Digest = dependency_0.Digest;
const Error = dependency_0.Error;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const IdentityHasher = dependency_0.IdentityHasher;
const M31 = dependency_0.M31;
const MAX_RW_ADDRESS_EXCLUSIVE = dependency_0.MAX_RW_ADDRESS_EXCLUSIVE;
const MAX_SPARSE_BOUNDARY_ENTRIES = dependency_0.MAX_SPARSE_BOUNDARY_ENTRIES;
const MEMORY_CLOCK_ID_DOMAIN = dependency_0.MEMORY_CLOCK_ID_DOMAIN;
const MEMORY_STATE_ID_DOMAIN = dependency_0.MEMORY_STATE_ID_DOMAIN;
const MIN_CANONICAL_WORDS = dependency_0.MIN_CANONICAL_WORDS;
const RETAINED_ENTRY_WORDS = dependency_0.RETAINED_ENTRY_WORDS;
const RetainedSectionV2 = dependency_0.RetainedSectionV2;
const SnapshotIdentity = dependency_0.SnapshotIdentity;
const SparseEntryV2 = dependency_0.SparseEntryV2;
const StatementV2 = dependency_0.StatementV2;
const Tag = dependency_0.Tag;
const Writer = dependency_0.Writer;
const clockWithinBoundary = dependency_0.clockWithinBoundary;
const memory_poseidon2 = dependency_0.memory_poseidon2;
const memory_state = dependency_0.memory_state;
const readEncodedU32 = dependency_0.readEncodedU32;
const runner_result = dependency_0.runner_result;
const std = dependency_0.std;
const validateRegisterClocks = dependency_0.validateRegisterClocks;

/// Allocation-free authenticated view over one canonical variable-length V2
/// wire.  Offsets refer to retained four-word `(u32,u32)` entries.
pub const CanonicalWireViewV2 = struct {
    words: []const M31,
    statement: StatementV2,
    entry_snapshot: RetainedSectionV2,
    exit_snapshot: RetainedSectionV2,
    entry_memory_clocks: RetainedSectionV2,
    exit_memory_clocks: RetainedSectionV2,
    wire_id: Digest,

    pub fn sparseEntry(
        self: *const CanonicalWireViewV2,
        section: RetainedSectionV2,
        index: usize,
    ) SparseEntryV2 {
        std.debug.assert(index < section.count);
        const start = section.payload_start + index * RETAINED_ENTRY_WORDS;
        return .{
            .address = readEncodedU32(self.words[start..][0..2]),
            .value = readEncodedU32(self.words[start + 2 ..][0..2]),
        };
    }

    pub fn clockEntry(
        self: *const CanonicalWireViewV2,
        section: RetainedSectionV2,
        index: usize,
    ) ClockEntryV2 {
        std.debug.assert(index < section.count);
        const start = section.payload_start + index * RETAINED_ENTRY_WORDS;
        return .{
            .address = readEncodedU32(self.words[start..][0..2]),
            .clock = readEncodedU32(self.words[start + 2 ..][0..2]),
        };
    }

    /// One canonical transcript frame.  Callers cannot alter framing by
    /// splitting variable sections into a different sequence of mix calls.
    pub fn mixInto(self: *const CanonicalWireViewV2, transcript: anytype) void {
        transcript.mixCanonicalM31Words(self.words);
    }
};

pub fn completionFromRunner(
    reason: runner_result.CompletionReason,
    address: u32,
    value: u32,
    clock: u32,
) Error!CompletionV2 {
    return .{
        .kind = switch (reason) {
            .halt_flag => .halt_flag,
            .self_loop => .unretired_self_loop,
            else => return error.UnsupportedCompletion,
        },
        .address = address,
        .value = value,
        .clock = clock,
    };
}

pub const SnapshotSide = enum { initial_word, final_word };

/// The identity/count portion of a sparse memory snapshot.  Keeping this
/// separate from the Poseidon continuation root lets a trusted streaming
/// caller reuse the already-authenticated exit root at the next segment's
/// identical entry boundary without hashing the same sparse tree twice.
pub const SnapshotDigest = struct {
    id: Digest,
    count: u32,
};

pub fn validateMemoryWords(
    words: []const memory_state.WordState,
    role: memory_state.SegmentRole,
    cycle_end: u32,
) Error!void {
    if (words.len > MAX_SPARSE_BOUNDARY_ENTRIES)
        return error.ExecutionRangeOutOfBounds;
    var previous: ?u32 = null;
    for (words) |word| {
        if ((word.addr & 3) != 0 or word.addr > MAX_RW_ADDRESS_EXCLUSIVE - 4)
            return error.InvalidMemoryAddress;
        if (previous) |address| {
            if (word.addr == address) return error.DuplicateBoundaryAddress;
            if (word.addr < address) return error.RetainedBoundaryMismatch;
        }
        previous = word.addr;
        if (!role.is_first and word.role.is_public_input)
            return error.InvalidSegmentRole;
        if (!role.is_last and
            (word.role.is_public_output or word.role.is_public_completion))
        {
            return error.InvalidSegmentRole;
        }
        if (!clockWithinBoundary(word.final_clock, cycle_end, true))
            return error.BoundaryClockOutOfRange;
    }
}

pub fn validateClockBoundary(
    registers: [32]u32,
    memory: []const runner_result.MemoryAccessClock,
    cycle: u32,
) Error!void {
    try validateRegisterClocks(registers, cycle);
    if (memory.len > MAX_SPARSE_BOUNDARY_ENTRIES)
        return error.ExecutionRangeOutOfBounds;
    var previous: ?u32 = null;
    for (memory) |entry| {
        if ((entry.addr & 3) != 0 or entry.addr > MAX_RW_ADDRESS_EXCLUSIVE - 4)
            return error.InvalidMemoryAddress;
        if (previous) |address| {
            if (entry.addr == address) return error.DuplicateBoundaryAddress;
            if (entry.addr < address) return error.RetainedBoundaryMismatch;
        }
        previous = entry.addr;
        if (!clockWithinBoundary(entry.clock, cycle, false))
            return error.BoundaryClockOutOfRange;
    }
}

pub fn snapshotIdentity(
    words: []const memory_state.WordState,
    comptime side: SnapshotSide,
) SnapshotIdentity {
    const digest = snapshotDigest(words, side);
    var iterator = SourceByteIterator(side).init(words);
    return .{
        .id = digest.id,
        .count = digest.count,
        .root = continuationRoot(&iterator),
    };
}

pub fn snapshotDigest(
    words: []const memory_state.WordState,
    comptime side: SnapshotSide,
) SnapshotDigest {
    const count = nonZeroWordCount(words, side);
    var hasher = IdentityHasher.init(MEMORY_STATE_ID_DOMAIN);
    hasher.scalar(FORMAT_VERSION);
    hasher.u32Value(@intCast(count));
    for (words) |word| {
        const value = @field(word, @tagName(side));
        if (value == 0) continue;
        hasher.u32Value(word.addr);
        hasher.u32Value(value);
    }
    return .{
        .id = hasher.finalize(),
        .count = @intCast(count),
    };
}

/// Reuse is admitted only when the current exact sparse projection has the
/// same canonical digest and count as the previously authenticated boundary.
/// The root is never accepted as a detached caller scalar.
pub fn snapshotIdentityReusingRoot(
    previous: SnapshotIdentity,
    words: []const memory_state.WordState,
    comptime side: SnapshotSide,
) Error!SnapshotIdentity {
    const digest = snapshotDigest(words, side);
    if (!std.meta.eql(previous.id, digest.id) or
        previous.count != digest.count)
    {
        return error.MemorySnapshotMismatch;
    }
    return .{
        .id = digest.id,
        .count = digest.count,
        .root = previous.root,
    };
}

pub fn nonZeroWordCount(
    words: []const memory_state.WordState,
    comptime side: SnapshotSide,
) usize {
    var count: usize = 0;
    for (words) |word| if (@field(word, @tagName(side)) != 0) {
        count += 1;
    };
    return count;
}

pub const ByteLeaf = struct {
    index: u32,
    value: u32,
};

pub fn SourceByteIterator(comptime side: SnapshotSide) type {
    return struct {
        words: []const memory_state.WordState,
        word_index: usize = 0,
        byte_index: u3 = 0,
        current: ?ByteLeaf = null,

        const Self = @This();

        pub fn init(words: []const memory_state.WordState) Self {
            var result = Self{ .words = words };
            result.advance();
            return result;
        }

        pub fn consume(self: *Self) ByteLeaf {
            const result = self.current.?;
            self.advance();
            return result;
        }

        fn advance(self: *Self) void {
            self.current = null;
            while (self.word_index < self.words.len) {
                const word = self.words[self.word_index];
                const value = @field(word, @tagName(side));
                while (self.byte_index < 4) {
                    const byte_index = self.byte_index;
                    self.byte_index += 1;
                    const shift: u5 = @as(u5, byte_index) * 8;
                    const byte: u8 = @truncate(value >> shift);
                    if (byte == 0) continue;
                    self.current = .{
                        .index = word.addr + @as(u32, byte_index),
                        .value = byte,
                    };
                    return;
                }
                self.word_index += 1;
                self.byte_index = 0;
            }
        }
    };
}

/// Allocation-free root of the zero-normalized all-RW byte map.  Empty
/// subtrees are skipped in O(1); work is O(nonzero_bytes * tree_depth) with a
/// fixed 30-frame stack and no attacker-sized temporary storage.
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

pub fn continuationSubtreeRoot(
    iterator: anytype,
    depth: u32,
    start: u32,
    width: u32,
) u32 {
    const leaf = iterator.current orelse
        return memory_poseidon2.DEFAULT_HASHES[depth];
    std.debug.assert(leaf.index >= start);
    const end = @as(u64, start) + width;
    if (leaf.index >= end) return memory_poseidon2.DEFAULT_HASHES[depth];
    if (depth == 30) {
        std.debug.assert(width == 1 and leaf.index == start);
        return iterator.consume().value;
    }
    const half = width / 2;
    const left = continuationSubtreeRoot(iterator, depth + 1, start, half);
    const right = continuationSubtreeRoot(iterator, depth + 1, start + half, half);
    return memory_poseidon2.hashPair(left, right);
}

pub fn memoryClockIdentity(entries: []const runner_result.MemoryAccessClock) Digest {
    var hasher = IdentityHasher.init(MEMORY_CLOCK_ID_DOMAIN);
    hasher.scalar(FORMAT_VERSION);
    hasher.u32Value(@intCast(entries.len));
    for (entries) |entry| {
        hasher.u32Value(entry.addr);
        hasher.u32Value(entry.clock);
    }
    return hasher.finalize();
}

pub fn checkedWireWordCount(
    entry_snapshot: usize,
    exit_snapshot: usize,
    entry_clocks: usize,
    exit_clocks: usize,
) Error!usize {
    var entries = std.math.add(usize, entry_snapshot, exit_snapshot) catch
        return error.ExecutionRangeOutOfBounds;
    entries = std.math.add(usize, entries, entry_clocks) catch
        return error.ExecutionRangeOutOfBounds;
    entries = std.math.add(usize, entries, exit_clocks) catch
        return error.ExecutionRangeOutOfBounds;
    const payload = std.math.mul(usize, entries, RETAINED_ENTRY_WORDS) catch
        return error.ExecutionRangeOutOfBounds;
    return std.math.add(usize, MIN_CANONICAL_WORDS, payload) catch
        return error.ExecutionRangeOutOfBounds;
}

pub fn writeSnapshotSection(
    writer: *Writer,
    tag: Tag,
    words: []const memory_state.WordState,
    comptime side: SnapshotSide,
) void {
    writer.tag(tag);
    writer.u32Value(@intCast(nonZeroWordCount(words, side)));
    for (words) |word| {
        const value = @field(word, @tagName(side));
        if (value == 0) continue;
        writer.u32Value(word.addr);
        writer.u32Value(value);
    }
}

pub fn writeClockSection(
    writer: *Writer,
    tag: Tag,
    entries: []const runner_result.MemoryAccessClock,
) void {
    writer.tag(tag);
    writer.u32Value(@intCast(entries.len));
    for (entries) |entry| {
        writer.u32Value(entry.addr);
        writer.u32Value(entry.clock);
    }
}
