//! Concrete, resumable RV64 session. Owns its cache; borrows memory explicitly.
//! No callbacks, trace accumulation, or allocation after initialization.
const std = @import("std");
const machine = @import("machine.zig");
const memory = @import("memory.zig");
const cache = @import("decode_cache.zig");
pub const Options = struct { cache_entries: usize = 1024, max_retirements: u64 = 10000000 };
pub const Error = machine.Error || cache.Error || error{InvalidBudget};
pub const Batch = struct { written: usize, stop: ?Error = null };
pub const Session = struct {
    cpu: machine.Cpu,
    memory: *memory.Memory,
    decoder: cache.Cache,
    max_retirements: u64,

    pub fn init(allocator: std.mem.Allocator, cpu: machine.Cpu, mem: *memory.Memory, options: Options) Error!Session {
        if (options.max_retirements < cpu.retired) return error.InvalidBudget;
        return .{ .cpu = cpu, .memory = mem, .decoder = try cache.Cache.init(allocator, options.cache_entries), .max_retirements = options.max_retirements };
    }

    pub fn deinit(self: *Session) void {
        self.decoder.deinit();
        self.* = undefined;
    }

    pub fn step(self: *Session) Error!machine.Retirement {
        if (self.cpu.retired >= self.max_retirements) return error.StepLimit;
        return self.cpu.stepCached(self.memory, &self.decoder);
    }

    /// Caller owns fixed-capacity output. A trap preserves the successfully
    /// retired prefix and returns its count, rather than losing it in !void.
    /// A full buffer yields; a zero-capacity buffer leaves the session untouched.
    pub fn runInto(self: *Session, output: []machine.Retirement) Batch {
        for (output, 0..) |*row, index| {
            row.* = self.step() catch |err| return .{ .written = index, .stop = err };
        }
        return .{ .written = output.len };
    }
};
