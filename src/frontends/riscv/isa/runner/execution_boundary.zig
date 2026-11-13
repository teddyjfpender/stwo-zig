//! Canonical execution boundary records; one nominal definition for every profile.

const std = @import("std");
const Cpu = @import("cpu.zig").Cpu;
const memory_state = @import("memory_state.zig");

pub const CompletionReason = enum {
    halt_flag,
    self_loop,
    stalled_pc,
    ecall,
    ebreak,
    host_halt,
    invalid_instruction,
    max_steps,
};

pub const CONTINUATION_SCHEMA_VERSION: u32 = 2;

pub const SegmentClockFrame = enum(u8) {
    global_continuous = 1,
    leaf_local = 2,
};

pub const MemoryAccessClock = struct {
    addr: u32,
    clock: u32,
};

pub const AccessClockBoundary = struct {
    register_clocks: [32]u32,
    memory_clocks: []MemoryAccessClock,

    pub fn deinit(self: *AccessClockBoundary, allocator: std.mem.Allocator) void {
        allocator.free(self.memory_clocks);
        self.* = undefined;
    }

    pub fn identity(self: AccessClockBoundary) u64 {
        var fingerprint: u64 = 0xcbf2_9ce4_8422_2325;
        fingerprint = mix(fingerprint, 0x434c_4f43); // "CLOC"
        for (self.register_clocks, 0..) |clock, register| {
            fingerprint = mix(fingerprint, register);
            fingerprint = mix(fingerprint, clock);
        }
        fingerprint = mix(fingerprint, self.memory_clocks.len);
        for (self.memory_clocks) |entry| {
            fingerprint = mix(fingerprint, entry.addr);
            fingerprint = mix(fingerprint, entry.clock);
        }
        return fingerprint;
    }
};

pub const ContinuationToken = struct {
    schema_version: u32 = CONTINUATION_SCHEMA_VERSION,
    clock_frame: SegmentClockFrame,
    session_tag: u64,
    next_segment_index: u32,
    next_cycle: u64,
    cpu: Cpu,
    rw_memory: memory_state.ContinuationIdentity,
    access_clocks: u64,
};

pub const OutputWord = struct {
    addr: u32,
    value: u32,
    clock: u32,
};

inline fn mix(current: u64, value: u64) u64 {
    var result = current;
    inline for (0..8) |byte| {
        result ^= @as(u8, @truncate(value >> @intCast(byte * 8)));
        result *%= 0x0000_0100_0000_01b3;
    }
    return result;
}

pub const ExternalCounts = struct {
    calls: usize,
    rows: usize,
};
