//! Ownership helpers for resumable execution boundaries and output capture.

const std = @import("std");
const ExecutionProfile = @import("../isa/execution_profile.zig").ExecutionProfile;
const Cpu = @import("cpu.zig").Cpu;
const Memory = @import("memory.zig").Memory;
const elf_loader = @import("elf_loader.zig");
const state_chain = @import("state_chain.zig");
const result_mod = @import("result.zig");

pub fn segmentToRunResult(segment: *result_mod.SegmentResult) result_mod.RunResult {
    std.debug.assert(segment.segment_role.is_first and segment.segment_role.is_last);
    std.debug.assert(segment.completion_reason != null);
    std.debug.assert(segment.input != null);
    const result = result_mod.RunResult{
        .initial_pc = segment.entry_cpu.pc,
        .initial_regs = snapshotRegisters(segment.entry_cpu),
        .cpu_final = segment.exit_cpu,
        .final_pc = segment.exit_cpu.pc,
        .final_regs = snapshotRegisters(segment.exit_cpu),
        .step_count = segment.cycle_count,
        .completion_reason = segment.completion_reason.?,
        .completion_address = segment.completion_address,
        .completion_value = segment.completion_value,
        .completion_clock = segment.completion_clock,
        .input = segment.input.?,
        .input_start = segment.input_start,
        .input_end = segment.input_end,
        .output = segment.output,
        .output_len = segment.output_len,
        .output_len_addr = segment.output_len_addr,
        .output_data_addr = segment.output_data_addr,
        .output_end_addr = segment.output_end_addr,
        .output_words = segment.output_words,
        .execution_trace = segment.execution_trace,
        .state_chain_tracker = segment.state_chain_tracker,
        .rw_memory = segment.rw_memory,
        .exit_code = segment.exit_code,
        .allocator = segment.allocator,
    };
    // Access-clock boundary copies belong only to the segmented API.
    segment.entry_access_clocks.deinit(segment.allocator);
    segment.exit_access_clocks.deinit(segment.allocator);
    segment.* = undefined;
    return result;
}

pub fn captureAccessClockBoundary(
    allocator: std.mem.Allocator,
    register_clocks: [32]u32,
    memory_clocks: *const std.AutoHashMap(u32, u32),
) !result_mod.AccessClockBoundary {
    const entries = try allocator.alloc(result_mod.MemoryAccessClock, memory_clocks.count());
    errdefer allocator.free(entries);
    var iterator = memory_clocks.iterator();
    var index: usize = 0;
    while (iterator.next()) |entry| : (index += 1) {
        entries[index] = .{ .addr = entry.key_ptr.*, .clock = entry.value_ptr.* };
    }
    std.mem.sort(result_mod.MemoryAccessClock, entries, {}, lessMemoryClock);
    return .{ .register_clocks = register_clocks, .memory_clocks = entries };
}

fn lessMemoryClock(_: void, lhs: result_mod.MemoryAccessClock, rhs: result_mod.MemoryAccessClock) bool {
    return lhs.addr < rhs.addr;
}

pub fn emptyAccessClockBoundary() result_mod.AccessClockBoundary {
    return .{ .register_clocks = .{0} ** 32, .memory_clocks = &.{} };
}

pub fn cloneClockMap(
    allocator: std.mem.Allocator,
    source: *const std.AutoHashMap(u32, u32),
) !std.AutoHashMap(u32, u32) {
    var result = std.AutoHashMap(u32, u32).init(allocator);
    errdefer result.deinit();
    try result.ensureTotalCapacity(@intCast(source.count()));
    var iterator = source.iterator();
    while (iterator.next()) |entry|
        result.putAssumeCapacity(entry.key_ptr.*, entry.value_ptr.*);
    return result;
}

pub const CapturedOutput = struct {
    bytes: ?[]u8,
    len: u32,
    words: []result_mod.OutputWord,

    pub fn empty() CapturedOutput {
        return .{ .bytes = null, .len = 0, .words = &.{} };
    }
};

pub fn captureOutput(
    allocator: std.mem.Allocator,
    mem: *const Memory,
    tracker: *const state_chain.StateChainTracker,
    elf_info: elf_loader.ElfInfo,
    require_access: bool,
) !CapturedOutput {
    const output_len = mem.readU32(elf_info.output_len);
    const capacity = elf_info.output_end -| elf_info.output_data;
    const valid_len = output_len != 0 and output_len <= capacity;
    var bytes: ?[]u8 = null;
    errdefer if (bytes) |output| allocator.free(output);
    if (valid_len) {
        const output = try allocator.alloc(u8, output_len);
        mem.readSlice(elf_info.output_data, output);
        bytes = output;
    }

    var words: std.ArrayList(result_mod.OutputWord) = .{};
    errdefer words.deinit(allocator);
    try appendOutputWord(
        allocator,
        &words,
        mem,
        tracker,
        elf_info.output_len & ~@as(u32, 3),
        require_access,
    );
    if (valid_len) {
        const first = elf_info.output_data & ~@as(u32, 3);
        const end = @as(u64, elf_info.output_data) + output_len;
        const end_aligned = (end + 3) & ~@as(u64, 3);
        var addr: u64 = first;
        while (addr < end_aligned) : (addr += 4) {
            try appendOutputWord(
                allocator,
                &words,
                mem,
                tracker,
                @intCast(addr),
                require_access,
            );
        }
    }
    return .{ .bytes = bytes, .len = output_len, .words = try words.toOwnedSlice(allocator) };
}

fn appendOutputWord(
    allocator: std.mem.Allocator,
    words: *std.ArrayList(result_mod.OutputWord),
    mem: *const Memory,
    tracker: *const state_chain.StateChainTracker,
    addr: u32,
    require_access: bool,
) !void {
    const clock = tracker.mem_last_clk.get(addr) orelse {
        if (require_access) return error.OutputAddressNotAccessed;
        return;
    };
    try words.append(allocator, .{ .addr = addr, .value = mem.readU32(addr), .clock = clock });
}

fn snapshotRegisters(cpu: Cpu) [32]u32 {
    var registers: [32]u32 = undefined;
    for (&registers, 0..) |*value, index|
        value.* = cpu.readReg(@intCast(index));
    return registers;
}

pub fn sessionTag(elf_bytes: []const u8, input: []const u8, profile: ExecutionProfile) u64 {
    var result: u64 = 0xcbf2_9ce4_8422_2325;
    const profile_word: u16 = @intFromEnum(profile);
    result = tagByte(result, @truncate(profile_word));
    result = tagByte(result, @truncate(profile_word >> 8));
    for (elf_bytes) |byte| result = tagByte(result, byte);
    result = tagByte(result, 0xff);
    for (input) |byte| result = tagByte(result, byte);
    return result;
}

inline fn tagByte(current: u64, byte: u8) u64 {
    return (current ^ byte) *% 0x0000_0100_0000_01b3;
}
