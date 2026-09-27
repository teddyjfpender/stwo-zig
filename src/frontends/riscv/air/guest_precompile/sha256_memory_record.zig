//! General compression call with explicit little-endian state words and raw
//! message bytes. State and block spans are aligned and disjoint; only state
//! words are overwritten. The typed caller proves these same transitions.
const std = @import("std");
const sha = @import("sha256_compression.zig");
const clock = @import("../../access_clock.zig");
const contract = @import("../../isa/sha256_compression_v1.zig");
pub const word_count = 24;
pub const address_limit: u32 = 1 << 30;
pub const Record = struct {
    execution_clock: u32,
    pc: u32,
    state_register: u5,
    block_register: u5,
    state_ptr: u32,
    block_ptr: u32,
    pointer_previous_clocks: [2]u32,
    memory_previous_clocks: [word_count]u32,
    state: sha.State,
    block: [64]u8,
    output: sha.State,
    pub fn validate(self: Record) !void {
        if (self.execution_clock == 0 or clock.maximum(self.execution_clock) >= @import("stwo_core").fields.m31.Modulus or self.pc & 3 != 0 or self.pc >= address_limit - 4)
            return error.InvalidShaExecution;
        if (self.state_ptr & 3 != 0 or self.block_ptr & 3 != 0 or @as(u64, self.state_ptr) + 32 > address_limit or @as(u64, self.block_ptr) + 64 > address_limit)
            return error.InvalidShaSpan;
        if (self.state_ptr < @as(u64, self.block_ptr) + 64 and self.block_ptr < @as(u64, self.state_ptr) + 32)
            return error.OverlappingShaSpans;
        if (self.state_register == self.block_register or
            (self.state_register == 0 and self.state_ptr != 0) or
            (self.block_register == 0 and self.block_ptr != 0)) return error.InvalidShaPointerRegister;
        for (self.pointer_previous_clocks) |previous| {
            const now = clock.encode(self.execution_clock, .first);
            if (previous >= now or now - previous - 1 >= 1 << 20) return error.InvalidShaPreviousClock;
        }
        for (self.memory_previous_clocks) |previous| {
            const now = clock.encode(self.execution_clock, .second);
            if (previous >= now or now - previous - 1 >= 1 << 20) return error.InvalidShaPreviousClock;
        }
        if (!std.mem.eql(u32, &self.output, &sha.compress(self.state, self.block))) return error.InvalidShaOutput;
    }
    pub fn instruction(self: Record) u32 {
        return contract.encode(self.state_register, self.block_register);
    }
    pub fn address(self: Record, word: usize) u32 {
        std.debug.assert(word < word_count);
        return if (word < 8) self.state_ptr + 4 * @as(u32, @intCast(word)) else self.block_ptr + 4 * @as(u32, @intCast(word - 8));
    }
    pub fn before(self: Record, word: usize) u32 {
        std.debug.assert(word < word_count);
        return if (word < 8) self.state[word] else std.mem.readInt(u32, self.block[(word - 8) * 4 ..][0..4], .little);
    }
    pub fn after(self: Record, word: usize) u32 {
        return if (word < 8) self.output[word] else self.before(word);
    }
};
