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
};

/// Capture Stark-V's sorted union of initialized and accessed RW words.
pub fn capture(
    allocator: std.mem.Allocator,
    memory: *const Memory,
    tracker: *const StateChainTracker,
    layout: MemoryLayout,
    segment_role: SegmentRole,
    output_len: u32,
    completion_word_addr: ?u32,
) !Snapshot {
    var addresses = std.AutoHashMap(u32, void).init(allocator);
    defer addresses.deinit();
    try memory.addAlignedWordAddresses(&addresses);
    var accessed = tracker.mem_last_clk.keyIterator();
    while (accessed.next()) |addr| try addresses.put(addr.* & ~@as(u32, 3), {});

    var words: std.ArrayList(WordState) = .{};
    errdefer words.deinit(allocator);
    try words.ensureTotalCapacity(allocator, addresses.count());
    var iterator = addresses.keyIterator();
    while (iterator.next()) |addr_ptr| {
        const addr = addr_ptr.*;
        if (!layout.isRwAddr(addr)) continue;
        const final_word = memory.readU32(addr);
        const final_clock = tracker.mem_last_clk.get(addr) orelse 0;
        words.appendAssumeCapacity(.{
            .addr = addr,
            .initial_word = tracker.mem_initial.get(addr) orelse final_word,
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
    std.mem.sort(WordState, words.items, {}, lessWord);

    var program_words: std.ArrayList(WordState) = .{};
    errdefer program_words.deinit(allocator);
    var program_iterator = addresses.keyIterator();
    while (program_iterator.next()) |addr_ptr| {
        const addr = addr_ptr.*;
        if (!layout.isProgramAddr(addr)) continue;
        const word = memory.readU32(addr);
        try program_words.append(allocator, .{
            .addr = addr,
            .initial_word = word,
            .final_word = word,
            .final_clock = 0,
        });
    }
    std.mem.sort(WordState, program_words.items, {}, lessWord);

    return .{
        .layout = layout,
        .segment_role = segment_role,
        .words = try words.toOwnedSlice(allocator),
        .program_words = try program_words.toOwnedSlice(allocator),
    };
}

fn lessWord(_: void, lhs: WordState, rhs: WordState) bool {
    return lhs.addr < rhs.addr;
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
