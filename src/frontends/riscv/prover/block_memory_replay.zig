//! Block-wide memory witness collection across segment-owned runner results.
//! The first runner snapshot supplies the candidate initial register, RW and
//! program-memory image;
//! later segments append only real accesses to a bounded external sorter.
//! This is an authenticated-input candidate, not proof authority: the block
//! AIR must still prove the initial image and its event permutation.
const std = @import("std");
const result = @import("../runner/result.zig");
const state_chain = @import("../runner/state_chain.zig");
const memory_state = @import("../runner/memory_state.zig");
const event = @import("../air/block/memory_event.zig");
const spool = @import("../air/block/memory_spool.zig");
const transition = @import("../air/block/memory_transition.zig");
const tree = @import("../air/memory_commitment/blake3_state_tree.zig");

/// The authentication source for a first access is part of the witness plan.
/// A later proof provider must establish the value under the corresponding
/// admitted root/public boundary before it can emit the initial-value bus.
pub const InitialSource = enum { register, rw_root, public_input, program_root };
pub const InitialWord = struct { address: u32, value: u32, source: InitialSource };

/// Host witness for the first sorted access to each word. This carries no
/// proof authority: the sorted-memory AIR and the matching initial provider
/// must prove and cancel the same (space, address, value) tuple.
pub const FirstTouch = struct {
    space: u1,
    address: u32,
    value: u32,
    source: InitialSource,
};

/// Streams the admitted sorted run without materializing all first touches.
/// The replay and its immutable initial image must outlive this reader.
pub const FirstTouchReader = struct {
    replay: *const Replay,
    sorted: transition.Reader,
    last_space: ?u1 = null,
    last_address: u32 = 0,
    count: u64 = 0,

    pub fn deinit(self: *FirstTouchReader) void {
        self.sorted.deinit();
        self.* = undefined;
    }

    pub fn next(self: *FirstTouchReader) !?FirstTouch {
        while (try self.sorted.next()) |item| {
            if (self.last_space) |space| {
                if (item.space < space or (item.space == space and item.address < self.last_address))
                    return error.UnsortedBlockMemoryFirstTouches;
                if (item.space == space and item.address == self.last_address) continue;
            }
            self.last_space = item.space;
            self.last_address = item.address;
            self.count = try std.math.add(u64, self.count, 1);
            return .{
                .space = item.space,
                .address = item.address,
                .value = item.before,
                .source = try self.replay.sourceFor(item.space, item.address),
            };
        }
        return null;
    }
};

pub const Replay = struct {
    register_custody_mode: u32 = 0,
    a: std.mem.Allocator,
    registers: [32]u32,
    words: []InitialWord,
    layout: ?memory_state.MemoryLayout = null,
    spooler: spool.Spool,
    next_segment: u32 = 0,
    next_cycle: u64 = 1,
    finished: bool = false,

    pub fn init(a: std.mem.Allocator, dir: std.fs.Dir, registers: [32]u32, snapshot: []const memory_state.WordState, chunk_events: usize) !Replay {
        return initWithProgram(a, dir, registers, snapshot, &.{}, chunk_events);
    }

    pub fn initWithProgram(a: std.mem.Allocator, dir: std.fs.Dir, registers: [32]u32, rw: []const memory_state.WordState, program: []const memory_state.WordState, chunk_events: usize) !Replay {
        const count = try std.math.add(usize, rw.len, program.len);
        const words = try a.alloc(InitialWord, count);
        errdefer a.free(words);
        var rw_index: usize = 0;
        var program_index: usize = 0;
        for (words, 0..) |*target, i| {
            const take_rw = program_index == program.len or (rw_index < rw.len and rw[rw_index].addr < program[program_index].addr);
            const word = if (take_rw) rw[rw_index] else program[program_index];
            if (word.addr & 3 != 0 or (i > 0 and words[i - 1].address >= word.addr)) return error.InvalidInitialMemoryImage;
            target.* = .{ .address = word.addr, .value = word.initial_word, .source = if (take_rw) (if (word.role.is_public_input) .public_input else .rw_root) else .program_root };
            if (take_rw) rw_index += 1 else program_index += 1;
        }
        return .{ .a = a, .registers = registers, .words = words, .spooler = try spool.Spool.init(a, dir, chunk_events) };
    }

    pub fn initFromSnapshot(a: std.mem.Allocator, dir: std.fs.Dir, registers: [32]u32, snapshot: *const memory_state.Snapshot, chunk_events: usize) !Replay {
        var replay = try initWithProgram(a, dir, registers, snapshot.words, snapshot.program_words, chunk_events);
        replay.layout = snapshot.layout;
        return replay;
    }

    pub fn sourceFor(self: *const Replay, space: u1, address: u32) !InitialSource {
        if (space == 0) {
            if (address >= self.registers.len) return error.InvalidRegisterAddress;
            return .register;
        }
        if (address & 3 != 0) return error.UnalignedMemoryAddress;
        const layout = self.layout orelse return error.MissingInitialMemoryLayout;
        if (layout.isProgramAddr(address)) return .program_root;
        if (layout.isInputAddr(address)) return .public_input;
        if (layout.isRwAddr(address)) return .rw_root;
        return error.UnclassifiedInitialMemoryAddress;
    }

    /// Reconstruct the complete initial continuation root, including public
    /// input words. This is an admission guard for the provider witness; only
    /// proved shared paths against the independently pinned root give authority.
    pub fn initialRwRoot(self: *const Replay) !tree.Digest {
        if (self.layout == null) return error.MissingInitialMemoryLayout;
        var leaves: std.ArrayList(tree.Leaf) = .empty;
        defer leaves.deinit(self.a);
        for (self.words) |word| {
            if (word.source == .program_root or word.value == 0) continue;
            try leaves.append(self.a, .{ .index = try tree.memoryIndex(word.address), .value = word.value });
        }
        const hasher = tree.TreeHasher.init(.memory);
        return hasher.root(leaves.items);
    }

    pub fn deinit(self: *Replay) void {
        self.spooler.deinit();
        self.a.free(self.words);
        self.* = undefined;
    }

    pub fn append(self: *Replay, frame: event.Frame, accesses: []const state_chain.Access) !void {
        if (self.finished or frame.global_first_cycle != self.next_cycle or frame.cycle_count == 0) return error.InvalidBlockMemoryReplayOrder;
        if (self.register_custody_mode == 0) {
            try self.spooler.appendSegment(frame, accesses);
        } else if (self.register_custody_mode == 1) {
            // Preserve the real runner event's global clock projection. The
            // excluded register accesses are proved at native/caller roots.
            errdefer self.spooler.poisoned = true;
            for (accesses) |access| if (access.addr_space == 1) try self.spooler.append(try frame.project(access));
        } else return error.InvalidV5RegisterCustodyMode;
        self.next_cycle = try std.math.add(u64, self.next_cycle, frame.cycle_count);
        self.next_segment = try std.math.add(u32, self.next_segment, 1);
    }

    /// Candidate-only immutable partition. All original accesses still require
    /// fresh native/caller classification; this sorter never grants subtraction.
    pub fn appendSelected(self: *Replay, frame: event.Frame, accesses: []const state_chain.Access, selection: *const @import("block_v5_readonly_input_selection_v1.zig").Owned) !@import("block_v5_readonly_input_proposal_v1.zig").Census {
        if (self.register_custody_mode != 1 or self.finished or frame.global_first_cycle != self.next_cycle or frame.cycle_count == 0) return error.InvalidBlockReadonlyReplayOrder;
        if (!std.meta.eql(self.layout orelse return error.MissingBlockMemoryLayout, selection.authority.layout)) return error.StaleReadonlyInputSourceAuthority;
        var census = @import("block_v5_readonly_input_proposal_v1.zig").Census{ .all_rw = 0, .mutable = 0, .readonly = 0 };
        errdefer self.spooler.poisoned = true;
        for (accesses) |access| if (access.addr_space == 1) {
            const projected = try frame.project(access);
            const interval = selection.intervals[try selection.find(projected.address)];
            census.all_rw = try std.math.add(u64, census.all_rw, 1);
            if (interval.readonly) {
                if (projected.value != interval.value) return error.ReadonlyInputWrite;
                census.readonly = try std.math.add(u64, census.readonly, 1);
            } else {
                try self.spooler.append(projected);
                census.mutable = try std.math.add(u64, census.mutable, 1);
            }
        };
        try census.require(census.all_rw);
        self.next_cycle = try std.math.add(u64, self.next_cycle, frame.cycle_count);
        self.next_segment = try std.math.add(u32, self.next_segment, 1);
        return census;
    }
    pub fn appendResultSelected(self: *Replay, segment: *const result.SegmentResult, selection: *const @import("block_v5_readonly_input_selection_v1.zig").Owned) !@import("block_v5_readonly_input_proposal_v1.zig").Census {
        if (segment.segment_index != self.next_segment) return error.InvalidBlockReadonlyReplayOrder;
        const cycles = std.math.cast(u32, segment.cycle_count) orelse return error.InvalidBlockReadonlyReplayOrder;
        return self.appendSelected(.{ .clock_frame = segment.clock_frame, .global_first_cycle = segment.global_first_cycle, .cycle_count = cycles }, segment.state_chain_tracker.accesses.items, selection);
    }

    pub fn appendResult(self: *Replay, segment: *const result.SegmentResult) !void {
        if (segment.segment_index != self.next_segment) return error.InvalidBlockMemoryReplayOrder;
        const cycles = std.math.cast(u32, segment.cycle_count) orelse return error.InvalidBlockMemoryReplayOrder;
        try self.append(.{ .clock_frame = segment.clock_frame, .global_first_cycle = segment.global_first_cycle, .cycle_count = cycles }, segment.state_chain_tracker.accesses.items);
    }

    /// The returned reader borrows the initial image in `self`. Destroy it
    /// before `Replay.deinit`; each first-address value is binary searched in
    /// the immutable first-segment image instead of copying all block states.
    pub fn finish(self: *Replay) !transition.Reader {
        if (self.finished or self.next_segment == 0) return error.InvalidBlockMemoryReplayOrder;
        const sorted = if (self.register_custody_mode == 1 and self.spooler.event_count == 0)
            try self.spooler.finishEmpty()
        else
            try self.spooler.finish();
        self.finished = true;
        return .{ .sorted = sorted, .initial = .{ .context = self, .load = initialValue } };
    }

    /// Reopen the admitted sorted events for a later proof phase. The initial
    /// image is immutable, so the same event bytes produce identical rows.
    pub fn reopenSortedTransitions(self: *Replay) !transition.Reader {
        if (!self.finished) return error.InvalidBlockMemoryReplayOrder;
        return .{ .sorted = try self.spooler.reopenSorted(), .initial = .{ .context = self, .load = initialValue } };
    }

    pub fn firstTouches(self: *Replay) !FirstTouchReader {
        return .{ .replay = self, .sorted = try self.reopenSortedTransitions() };
    }

    fn initialValue(context: *anyopaque, space: u1, address: u32) anyerror!u32 {
        const self: *const Replay = @ptrCast(@alignCast(context));
        if (space == 0) {
            if (address >= self.registers.len) return error.InvalidRegisterAddress;
            return self.registers[address];
        }
        if (address & 3 != 0) return error.UnalignedMemoryAddress;
        var low: usize = 0;
        var high: usize = self.words.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            if (self.words[mid].address < address) low = mid + 1 else high = mid;
        }
        return if (low < self.words.len and self.words[low].address == address) self.words[low].value else 0;
    }
};

test "block replay keeps one initial image and a global clock across unequal segments" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var regs: [32]u32 = @splat(0);
    regs[5] = 11;
    var replay = try Replay.initWithProgram(std.testing.allocator, tmp.dir, regs, &.{
        .{ .addr = 4096, .initial_word = 7, .final_word = 7, .final_clock = 0 },
    }, &.{
        .{ .addr = 2048, .initial_word = 19, .final_word = 19, .final_clock = 0 },
    }, 2);
    defer replay.deinit();
    const first = [_]state_chain.Access{
        .{ .addr_space = 1, .addr = 4096, .clk = 1, .clk_prev = 0, .value = 8 },
        .{ .addr_space = 0, .addr = 5, .clk = 2, .clk_prev = 0, .value = 12 },
        .{ .addr_space = 1, .addr = 2048, .clk = 3, .clk_prev = 0, .value = 20 },
    };
    const second = [_]state_chain.Access{
        .{ .addr_space = 1, .addr = 4096, .clk = 1, .clk_prev = 0, .value = 9 },
    };
    try replay.append(.{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 2 }, &first);
    try replay.append(.{ .clock_frame = .leaf_local, .global_first_cycle = 3, .cycle_count = 3 }, &second);
    var reader = try replay.finish();
    defer reader.deinit();
    const reg = (try reader.next()).?;
    try std.testing.expectEqual(@as(u32, 11), reg.before);
    try std.testing.expectEqual(@as(u32, 12), reg.after);
    const program = (try reader.next()).?;
    try std.testing.expectEqual(@as(u32, 19), program.before);
    const memory_first = (try reader.next()).?;
    const memory_second = (try reader.next()).?;
    try std.testing.expectEqual(@as(u64, 1), memory_first.clock);
    try std.testing.expectEqual(@as(u64, 9), memory_second.clock);
    try std.testing.expectEqual(@as(u32, 7), memory_first.before);
    try std.testing.expectEqual(@as(u32, 8), memory_second.before);
    try std.testing.expectEqual(@as(?transition.Transition, null), try reader.next());
    var second_pass = try replay.reopenSortedTransitions();
    defer second_pass.deinit();
    try std.testing.expectEqualDeep(reg, (try second_pass.next()).?);
    try std.testing.expectEqualDeep(program, (try second_pass.next()).?);
    try std.testing.expectEqualDeep(memory_first, (try second_pass.next()).?);
    try std.testing.expectEqualDeep(memory_second, (try second_pass.next()).?);
    try std.testing.expectEqual(@as(?transition.Transition, null), try second_pass.next());
}

test "block replay rejects gaps and malformed initial image" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try std.testing.expectError(error.InvalidInitialMemoryImage, Replay.init(std.testing.allocator, tmp.dir, @splat(0), &.{
        .{ .addr = 4096, .initial_word = 0, .final_word = 0, .final_clock = 0 },
        .{ .addr = 4096, .initial_word = 0, .final_word = 0, .final_clock = 0 },
    }, 2));
    var replay = try Replay.init(std.testing.allocator, tmp.dir, @splat(0), &.{}, 2);
    defer replay.deinit();
    try std.testing.expectError(error.InvalidBlockMemoryReplayOrder, replay.append(.{ .clock_frame = .leaf_local, .global_first_cycle = 2, .cycle_count = 1 }, &.{}));
}

test "initial witness keeps distinct register, RW, input and program authority" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const layout: memory_state.MemoryLayout = .{
        .program_base = 0x1000,
        .program_end = 0x2000,
        .data_base = 0x2000,
        .data_end = 0x4000,
        .stack_bottom = 0x4000,
        .stack_top = 0x5000,
        .io_base = 0x5000,
        .io_end = 0x6000,
        .input_base = 0x2000,
        .input_end = 0x2100,
        .output_len_addr = 0x5000,
        .output_data_addr = 0x5004,
        .output_base = 0x5000,
        .output_end = 0x6000,
    };
    var rw = [_]memory_state.WordState{
        .{ .addr = 0x2000, .initial_word = 7, .final_word = 7, .final_clock = 0, .role = .{ .is_public_input = true } },
        .{ .addr = 0x3000, .initial_word = 9, .final_word = 9, .final_clock = 0 },
    };
    var program = [_]memory_state.WordState{
        .{ .addr = 0x1000, .initial_word = 11, .final_word = 11, .final_clock = 0 },
    };
    const snapshot: memory_state.Snapshot = .{ .layout = layout, .segment_role = .{ .is_first = true, .is_last = false }, .words = &rw, .program_words = &program };
    var replay = try Replay.initFromSnapshot(std.testing.allocator, tmp.dir, @splat(0), &snapshot, 2);
    defer replay.deinit();
    try std.testing.expectEqual(InitialSource.register, try replay.sourceFor(0, 1));
    try std.testing.expectEqual(InitialSource.program_root, try replay.sourceFor(1, 0x1000));
    try std.testing.expectEqual(InitialSource.public_input, try replay.sourceFor(1, 0x2000));
    try std.testing.expectEqual(InitialSource.rw_root, try replay.sourceFor(1, 0x3000));
    try std.testing.expectEqual(InitialSource.rw_root, try replay.sourceFor(1, 0x3004));
    try std.testing.expectError(error.UnclassifiedInitialMemoryAddress, replay.sourceFor(1, 0x6000));
    const hasher = tree.TreeHasher.init(.memory);
    const expected_root = try hasher.root(&.{
        .{ .index = 0x2000 / 4, .value = 7 },
        .{ .index = 0x3000 / 4, .value = 9 },
    });
    try std.testing.expectEqualDeep(expected_root, try replay.initialRwRoot());

    const accesses = [_]state_chain.Access{
        .{ .addr_space = 1, .addr = 0x3000, .clk = 3, .clk_prev = 0, .value = 10 },
        .{ .addr_space = 1, .addr = 0x2000, .clk = 1, .clk_prev = 0, .value = 8 },
        .{ .addr_space = 1, .addr = 0x3000, .clk = 5, .clk_prev = 3, .value = 11 },
        .{ .addr_space = 1, .addr = 0x1000, .clk = 2, .clk_prev = 0, .value = 12 },
        .{ .addr_space = 0, .addr = 5, .clk = 6, .clk_prev = 0, .value = 1 },
    };
    try replay.append(.{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 2 }, &accesses);
    var sorted = try replay.finish();
    sorted.deinit();
    var touches = try replay.firstTouches();
    defer touches.deinit();
    const expected = [_]FirstTouch{
        .{ .space = 0, .address = 5, .value = 0, .source = .register },
        .{ .space = 1, .address = 0x1000, .value = 11, .source = .program_root },
        .{ .space = 1, .address = 0x2000, .value = 7, .source = .public_input },
        .{ .space = 1, .address = 0x3000, .value = 9, .source = .rw_root },
    };
    for (expected) |want| try std.testing.expectEqualDeep(want, (try touches.next()).?);
    try std.testing.expectEqual(@as(?FirstTouch, null), try touches.next());
    try std.testing.expectEqual(@as(u64, expected.len), touches.count);
}
