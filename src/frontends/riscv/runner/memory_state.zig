//! Oracle-aligned read-write memory state retained after execution.

const std = @import("std");
const Memory = @import("memory.zig").Memory;
const StateChainTracker = @import("state_chain.zig").StateChainTracker;

/// Address ranges used by pinned Stark-V to separate program and RW memory.
pub const MemoryLayout = struct {
    program_base: u32,
    program_end: u32,
    data_base: u32,
    data_end: u32,
    stack_bottom: u32,
    stack_top: u32,
    io_base: u32,
    io_end: u32,
    input_base: u32,
    input_end: u32,
    output_len_addr: u32,
    output_data_addr: u32,
    output_base: u32,
    output_end: u32,

    pub fn isInputAddr(self: MemoryLayout, addr: u32) bool {
        return addr >= self.input_base and addr < self.input_end;
    }

    pub fn isPublicOutputAddr(self: MemoryLayout, addr: u32, output_len: u32) bool {
        if (addr == (self.output_len_addr & ~@as(u32, 3))) return true;
        if (output_len == 0) return false;
        const start = self.output_data_addr & ~@as(u32, 3);
        const end = self.output_data_addr +% output_len;
        const end_aligned = (end +% 3) & ~@as(u32, 3);
        return addr >= start and addr < end_aligned;
    }

    pub fn isProgramAddr(self: MemoryLayout, addr: u32) bool {
        return addr >= self.program_base and addr < self.program_end;
    }

    pub fn isRwAddr(self: MemoryLayout, addr: u32) bool {
        return (addr >= self.data_base and addr < self.data_end) or
            (addr >= self.stack_bottom and addr < self.stack_top) or
            (addr >= self.io_base and addr < self.io_end);
    }
};

/// Position of one proof segment within an execution.
pub const SegmentRole = struct {
    is_first: bool,
    is_last: bool,

    pub fn single() SegmentRole {
        return .{ .is_first = true, .is_last = true };
    }
};

/// Compact process-local identity for one complete RW-memory boundary.
///
/// This is a misuse guard for the resumable runner, not a cryptographic
/// commitment.  Recursive public data must authenticate the sparse-Merkle
/// root derived from the full `Snapshot.words`; retaining those words here is
/// what makes that later derivation exact and avoids hashing them twice on the
/// execution path.
pub const ContinuationIdentity = struct {
    word_count: u32,
    fingerprint: u64,
};

pub const WordRole = struct {
    is_public_input: bool = false,
    is_public_output: bool = false,
    is_public_completion: bool = false,
};

/// Initial and final state of one aligned word in the RW-memory union.
pub const WordState = struct {
    addr: u32,
    initial_word: u32,
    final_word: u32,
    final_clock: u32,
    role: WordRole = .{},

    pub fn includeInitial(self: WordState) bool {
        return !self.role.is_public_input;
    }

    pub fn includeFinal(self: WordState) bool {
        if (self.role.is_public_input) return self.final_clock > 0;
        return !self.role.is_public_output and !self.role.is_public_completion;
    }
};

pub const BaselineWord = struct {
    addr: u32,
    value: u32,
};

/// Exact RW-memory contents immediately before a segment executes.
pub const SegmentBaseline = struct {
    words: []BaselineWord,

    pub fn deinit(self: *SegmentBaseline, allocator: std.mem.Allocator) void {
        allocator.free(self.words);
        self.* = undefined;
    }

    fn value(self: SegmentBaseline, addr: u32) ?u32 {
        var low: usize = 0;
        var high = self.words.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            const candidate = self.words[mid];
            if (candidate.addr < addr) {
                low = mid + 1;
            } else if (candidate.addr > addr) {
                high = mid;
            } else {
                return candidate.value;
            }
        }
        return null;
    }
};

/// Compact, deterministic commitment input retained by `RunResult`.
pub const Snapshot = struct {
    layout: MemoryLayout,
    segment_role: SegmentRole,
    words: []WordState,
    /// Aligned words of the DECLARED program region ([__text_start,
    /// __text_start + __text_len)), in address order — the pinned oracle's
    /// program-root leaf source. Empty when the region is undeclared.
    program_words: []WordState = &.{},

    pub fn deinit(self: *Snapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.words);
        allocator.free(self.program_words);
        self.* = undefined;
    }

    /// Identity of the memory state at this segment's entry boundary.
    pub fn entryIdentity(self: Snapshot) ContinuationIdentity {
        return identity(self.words, .initial_word);
    }

    /// Identity of the memory state at this segment's exit boundary.
    pub fn exitIdentity(self: Snapshot) ContinuationIdentity {
        return identity(self.words, .final_word);
    }

    /// Require exact (not hash-only) continuity between adjacent snapshots.
    /// The comparison is allocation-free because capture already canonicalizes
    /// both word sets into strictly increasing address order.  A word first
    /// touched by the next segment is absent from the previous sparse union;
    /// absence is the canonical zero leaf and therefore matches only a zero
    /// entry value.
    pub fn requireContinuationTo(
        self: Snapshot,
        next: Snapshot,
    ) error{MemoryContinuationMismatch}!void {
        if (!std.meta.eql(self.layout, next.layout)) {
            return error.MemoryContinuationMismatch;
        }
        var left_index: usize = 0;
        var right_index: usize = 0;
        while (left_index < self.words.len or right_index < next.words.len) {
            if (left_index == self.words.len) {
                if (next.words[right_index].initial_word != 0)
                    return error.MemoryContinuationMismatch;
                right_index += 1;
                continue;
            }
            if (right_index == next.words.len) {
                if (self.words[left_index].final_word != 0)
                    return error.MemoryContinuationMismatch;
                left_index += 1;
                continue;
            }
            const left = self.words[left_index];
            const right = next.words[right_index];
            if (left.addr < right.addr) {
                if (left.final_word != 0) return error.MemoryContinuationMismatch;
                left_index += 1;
            } else if (right.addr < left.addr) {
                if (right.initial_word != 0) return error.MemoryContinuationMismatch;
                right_index += 1;
            } else {
                if (left.final_word != right.initial_word)
                    return error.MemoryContinuationMismatch;
                left_index += 1;
                right_index += 1;
            }
        }
    }
};

test "memory state: continuation treats newly touched zero words as absent leaves" {
    const layout = testLayout();
    var previous_words = [_]WordState{
        .{ .addr = 0x2000, .initial_word = 3, .final_word = 5, .final_clock = 1 },
    };
    var next_words = [_]WordState{
        .{ .addr = 0x2000, .initial_word = 5, .final_word = 7, .final_clock = 2 },
        .{ .addr = 0x2004, .initial_word = 0, .final_word = 9, .final_clock = 3 },
    };
    const previous = Snapshot{
        .layout = layout,
        .segment_role = .{ .is_first = true, .is_last = false },
        .words = &previous_words,
    };
    var next = Snapshot{
        .layout = layout,
        .segment_role = .{ .is_first = false, .is_last = true },
        .words = &next_words,
    };
    try previous.requireContinuationTo(next);
    next.words[1].initial_word = 1;
    try std.testing.expectError(
        error.MemoryContinuationMismatch,
        previous.requireContinuationTo(next),
    );
}

const BoundarySide = enum { initial_word, final_word };

fn identity(words: []const WordState, comptime side: BoundarySide) ContinuationIdentity {
    // FNV-1a is intentionally used only as a cheap in-process corruption
    // detector.  Domain separation and explicit integer encoding make the
    // value deterministic across host endianness and Zig versions.
    var fingerprint: u64 = 0xcbf2_9ce4_8422_2325;
    fingerprint = identityMix(fingerprint, 0x5354_574f); // "STWO"
    fingerprint = identityMix(fingerprint, @intCast(words.len));
    for (words) |word| {
        fingerprint = identityMix(fingerprint, word.addr);
        fingerprint = identityMix(fingerprint, @field(word, @tagName(side)));
    }
    return .{ .word_count = @intCast(words.len), .fingerprint = fingerprint };
}

inline fn identityMix(current: u64, value: u64) u64 {
    var result = current;
    inline for (0..8) |byte| {
        result ^= @as(u8, @truncate(value >> @intCast(byte * 8)));
        result *%= 0x0000_0100_0000_01b3;
    }
    return result;
}

/// Capture Stark-V's sorted union of initialized and accessed RW words.
pub fn capture(
    allocator: std.mem.Allocator,
    memory: *Memory,
    tracker: *const StateChainTracker,
    layout: MemoryLayout,
    segment_role: SegmentRole,
    output_len: u32,
    completion_word_addr: ?u32,
) !Snapshot {
    return captureImpl(
        allocator,
        memory,
        tracker,
        layout,
        segment_role,
        output_len,
        completion_word_addr,
        null,
    );
}

/// Capture the canonical memory snapshot for a resumed segment.  The mutable
/// state-chain tracker intentionally retains whole-execution baselines for its
/// clock invariants; this explicit boundary supplies segment-entry values.
pub fn captureSegment(
    allocator: std.mem.Allocator,
    memory: *Memory,
    tracker: *const StateChainTracker,
    layout: MemoryLayout,
    segment_role: SegmentRole,
    output_len: u32,
    completion_word_addr: ?u32,
    baseline: SegmentBaseline,
) !Snapshot {
    return captureImpl(
        allocator,
        memory,
        tracker,
        layout,
        segment_role,
        output_len,
        completion_word_addr,
        baseline,
    );
}

fn captureImpl(
    allocator: std.mem.Allocator,
    memory: *Memory,
    tracker: *const StateChainTracker,
    layout: MemoryLayout,
    segment_role: SegmentRole,
    output_len: u32,
    completion_word_addr: ?u32,
    baseline: ?SegmentBaseline,
) !Snapshot {
    var addresses = try sortedAddressUnion(allocator, memory, tracker, layout, .proof_memory);
    defer addresses.deinit(allocator);

    var words: std.ArrayList(WordState) = .{};
    errdefer words.deinit(allocator);
    try words.ensureTotalCapacity(allocator, addresses.items.len);
    for (addresses.items) |addr| {
        if (!layout.isRwAddr(addr)) continue;
        const final_word = memory.readU32(addr);
        const final_clock = tracker.mem_last_clk.get(addr) orelse 0;
        words.appendAssumeCapacity(.{
            .addr = addr,
            .initial_word = if (baseline) |entry|
                entry.value(addr) orelse 0
            else
                tracker.mem_initial.get(addr) orelse final_word,
            .final_word = final_word,
            .final_clock = final_clock,
            .role = .{
                .is_public_input = segment_role.is_first and layout.isInputAddr(addr),
                .is_public_output = segment_role.is_last and
                    layout.isPublicOutputAddr(addr, output_len),
                .is_public_completion = segment_role.is_last and
                    completion_word_addr != null and addr == completion_word_addr.?,
            },
        });
    }

    var program_words: std.ArrayList(WordState) = .{};
    errdefer program_words.deinit(allocator);
    for (addresses.items) |addr| {
        if (!layout.isProgramAddr(addr)) continue;
        const word = memory.readU32(addr);
        try program_words.append(allocator, .{
            .addr = addr,
            .initial_word = word,
            .final_word = word,
            .final_clock = 0,
        });
    }

    return .{
        .layout = layout,
        .segment_role = segment_role,
        .words = try words.toOwnedSlice(allocator),
        .program_words = try program_words.toOwnedSlice(allocator),
    };
}

/// Snapshot all initialized or previously accessed RW words before executing
/// a segment.  This is paid once per boundary, never per instruction.
pub fn captureSegmentBaseline(
    allocator: std.mem.Allocator,
    memory: *Memory,
    tracker: *const StateChainTracker,
    layout: MemoryLayout,
) !SegmentBaseline {
    var addresses = try sortedAddressUnion(allocator, memory, tracker, layout, .rw_only);
    defer addresses.deinit(allocator);

    var words: std.ArrayList(BaselineWord) = .{};
    errdefer words.deinit(allocator);
    try words.ensureTotalCapacity(allocator, addresses.items.len);
    for (addresses.items) |addr| {
        if (!layout.isRwAddr(addr)) continue;
        words.appendAssumeCapacity(.{ .addr = addr, .value = memory.readU32(addr) });
    }
    return .{ .words = try words.toOwnedSlice(allocator) };
}

/// Materialize the initialized/accessed address union once in canonical order.
///
/// The old boundary path inserted every initialized ELF/input word into a new
/// hash table twice per segment. Large stateless-block inputs contain more
/// than a million such words, making bookkeeping dominate execution. The two
/// source maps already provide duplicate-preserving inventories; append,
/// sort, and in-place deduplication produce the identical set with one compact
/// allocation and no per-address hashing.
fn sortedAddressUnion(
    allocator: std.mem.Allocator,
    memory: *Memory,
    tracker: *const StateChainTracker,
    layout: MemoryLayout,
    scope: AddressScope,
) !std.ArrayList(u32) {
    const initialized = try memory.canonicalAlignedWordAddresses();
    var accessed_addresses: std.ArrayList(u32) = .empty;
    defer accessed_addresses.deinit(allocator);
    try accessed_addresses.ensureTotalCapacity(allocator, tracker.mem_last_clk.count());
    var accessed = tracker.mem_last_clk.keyIterator();
    while (accessed.next()) |addr| {
        const aligned = addr.* & ~@as(u32, 3);
        if (scope.includes(layout, aligned))
            accessed_addresses.appendAssumeCapacity(aligned);
    }

    std.mem.sortUnstable(u32, accessed_addresses.items, {}, std.sort.asc(u32));
    var accessed_unique_len: usize = 0;
    for (accessed_addresses.items) |addr| {
        if (accessed_unique_len != 0 and
            accessed_addresses.items[accessed_unique_len - 1] == addr) continue;
        accessed_addresses.items[accessed_unique_len] = addr;
        accessed_unique_len += 1;
    }
    accessed_addresses.items.len = accessed_unique_len;

    var addresses: std.ArrayList(u32) = .empty;
    errdefer addresses.deinit(allocator);
    try addresses.ensureTotalCapacity(
        allocator,
        initialized.len + accessed_addresses.items.len,
    );
    var initialized_index: usize = 0;
    var accessed_index: usize = 0;
    while (initialized_index < initialized.len or
        accessed_index < accessed_addresses.items.len)
    {
        const initialized_addr = if (initialized_index < initialized.len)
            initialized[initialized_index]
        else
            std.math.maxInt(u32);
        const accessed_addr = if (accessed_index < accessed_addresses.items.len)
            accessed_addresses.items[accessed_index]
        else
            std.math.maxInt(u32);
        const addr = @min(initialized_addr, accessed_addr);
        if (initialized_addr == addr) initialized_index += 1;
        if (accessed_addr == addr) accessed_index += 1;
        if (scope.includes(layout, addr)) addresses.appendAssumeCapacity(addr);
    }
    return addresses;
}

const AddressScope = enum {
    rw_only,
    proof_memory,

    fn includes(self: AddressScope, layout: MemoryLayout, addr: u32) bool {
        return layout.isRwAddr(addr) or
            (self == .proof_memory and layout.isProgramAddr(addr));
    }
};

test "memory state: address union is sorted and duplicate free" {
    var memory = Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.writeU32(0x3008, 3);
    memory.writeU32(0x1004, 1);
    memory.writeU32(0x2000, 2);

    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try tracker.mem_last_clk.put(0x2000, 5);
    try tracker.mem_last_clk.put(0x2004, 7);

    var addresses = try sortedAddressUnion(
        std.testing.allocator,
        &memory,
        &tracker,
        testLayout(),
        .proof_memory,
    );
    defer addresses.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(
        u32,
        &.{ 0x1004, 0x2000, 0x2004, 0x3008 },
        addresses.items,
    );

    var rw_addresses = try sortedAddressUnion(
        std.testing.allocator,
        &memory,
        &tracker,
        testLayout(),
        .rw_only,
    );
    defer rw_addresses.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(
        u32,
        &.{ 0x2000, 0x2004, 0x3008 },
        rw_addresses.items,
    );
}

test "memory state: leaf-local first-access values replace entry snapshot" {
    var memory = Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.writeU32(0x1000, 0x0000_0013);
    memory.writeU32(0x2000, 7);
    memory.writeU32(0x2004, 11);
    memory.writeU32(0x3000, 13);

    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    const layout = testLayout();
    var baseline = try captureSegmentBaseline(
        std.testing.allocator,
        &memory,
        &tracker,
        layout,
    );
    defer baseline.deinit(std.testing.allocator);

    try tracker.recordMemTransition(0x2000, 3, 7, 17);
    memory.writeU32(0x2000, 17);
    try tracker.recordMemTransition(0x2008, 7, 0, 19);
    memory.writeU32(0x2008, 19);
    const role = SegmentRole{ .is_first = false, .is_last = false };

    var explicit = try captureSegment(
        std.testing.allocator,
        &memory,
        &tracker,
        layout,
        role,
        0,
        null,
        baseline,
    );
    defer explicit.deinit(std.testing.allocator);
    var first_access = try capture(
        std.testing.allocator,
        &memory,
        &tracker,
        layout,
        role,
        0,
        null,
    );
    defer first_access.deinit(std.testing.allocator);

    try std.testing.expectEqualDeep(explicit.words, first_access.words);
    try std.testing.expectEqualDeep(explicit.program_words, first_access.program_words);
}

fn testLayout() MemoryLayout {
    return .{
        .program_base = 0x1000,
        .program_end = 0x1100,
        .data_base = 0x2000,
        .data_end = 0x2100,
        .stack_bottom = 0x3000,
        .stack_top = 0x3100,
        .io_base = 0x4000,
        .io_end = 0x4100,
        .input_base = 0x4010,
        .input_end = 0x4018,
        .output_len_addr = 0x4020,
        .output_data_addr = 0x4024,
        .output_base = 0x4020,
        .output_end = 0x4100,
    };
}

test "memory state: captures initialized and accessed RW words in address order" {
    var memory = Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.writeU32(0x1000, 0x0000_0013); // Program memory is excluded.
    memory.writeU32(0x2008, 0); // Initialized data, never accessed.
    memory.writeU32(0x3000, 0); // Initialized stack, never accessed.
    memory.writeU32(0x3004, 7);
    memory.writeU32(0x4010, 0x0403_0201); // Public input, never accessed.

    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try tracker.recordMemTransition(0x3004, 5, 7, 9);
    memory.writeU32(0x3004, 9);
    try tracker.recordMemTransition(0x3008, 6, 0, 0); // Accessed sparse zero.

    var snapshot = try capture(
        std.testing.allocator,
        &memory,
        &tracker,
        testLayout(),
        SegmentRole.single(),
        0,
        null,
    );
    defer snapshot.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 5), snapshot.words.len);
    try std.testing.expectEqual(@as(u32, 0x2008), snapshot.words[0].addr);
    try std.testing.expectEqual(@as(u32, 0), snapshot.words[0].initial_word);
    try std.testing.expectEqual(@as(u32, 0), snapshot.words[0].final_clock);
    try std.testing.expectEqual(@as(u32, 0x3000), snapshot.words[1].addr);
    try std.testing.expectEqual(@as(u32, 0), snapshot.words[1].final_clock);
    try std.testing.expectEqual(@as(u32, 7), snapshot.words[2].initial_word);
    try std.testing.expectEqual(@as(u32, 9), snapshot.words[2].final_word);
    try std.testing.expectEqual(@as(u32, 5), snapshot.words[2].final_clock);
    try std.testing.expectEqual(@as(u32, 0x3008), snapshot.words[3].addr);
    try std.testing.expect(snapshot.words[4].role.is_public_input);
    try std.testing.expect(!snapshot.words[4].includeInitial());
    try std.testing.expect(!snapshot.words[4].includeFinal());
}

test "memory state: first and last segment roles classify IO independently" {
    var memory = Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.writeU32(0x4010, 11);
    memory.writeU32(0x4020, 4);
    memory.writeU32(0x4024, 22);

    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    try tracker.recordMemTransition(0x4010, 2, 11, 11);
    try tracker.recordMemTransition(0x4020, 3, 0, 4);
    try tracker.recordMemTransition(0x4024, 4, 0, 22);

    var first = try capture(
        std.testing.allocator,
        &memory,
        &tracker,
        testLayout(),
        .{ .is_first = true, .is_last = false },
        4,
        null,
    );
    defer first.deinit(std.testing.allocator);
    try std.testing.expect(first.words[0].role.is_public_input);
    try std.testing.expect(!first.words[1].role.is_public_output);

    var last = try capture(
        std.testing.allocator,
        &memory,
        &tracker,
        testLayout(),
        .{ .is_first = false, .is_last = true },
        4,
        null,
    );
    defer last.deinit(std.testing.allocator);
    try std.testing.expect(!last.words[0].role.is_public_input);
    try std.testing.expect(last.words[1].role.is_public_output);
    try std.testing.expect(last.words[2].role.is_public_output);
    try std.testing.expect(!last.words[1].includeFinal());
}
