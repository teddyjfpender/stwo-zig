//! Isolated fresh-execution terminal schedule. Not a proof/admission route.
//! Callers must independently select the ELF ABI, output and final guest cycle.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Word = @import("block_v5_word_memory_protocol_v1.zig");
const Transition = @import("../air/block/memory_transition.zig").Transition;
pub const VERSION: u32 = 1;
pub const OUTPUT_BYTES: usize = 43;
pub const READS: usize = 13;
pub const LOG_SIZE: u32 = 4;
pub const ROWS: usize = 1 << LOG_SIZE;
pub const MAX_FINAL_CYCLE: u64 = (@as(u64, 1) << 62) - 5;
pub const qualified = false;

pub const Policy = struct {
    final_cycle: u64,
    halt_address: u32,
    length_address: u32,
    data_address: u32,
    output_end: u32,
    output: [OUTPUT_BYTES]u8,

    pub fn validate(self: Policy) !void {
        if (self.final_cycle == 0 or self.final_cycle > MAX_FINAL_CYCLE)
            return error.InvalidTerminalClock;
        if (self.output[32] != 1) return error.UnsuccessfulTerminalOutput;
        if ((self.halt_address | self.length_address | self.data_address) & 3 != 0 or
            self.halt_address == self.length_address) return error.InvalidTerminalAddresses;
        const end = std.math.add(u32, self.data_address, 44) catch return error.InvalidTerminalAddresses;
        if (end > self.output_end or inside(self.halt_address, self.data_address, end) or
            inside(self.length_address, self.data_address, end) or
            self.halt_address > std.math.maxInt(u32) - 3 or self.length_address > std.math.maxInt(u32) - 3)
            return error.InvalidTerminalAddresses;
    }
};
fn inside(address: u32, lower: u32, upper: u32) bool {
    return address >= lower and address < upper;
}

pub const Fixed = struct {
    active: M,
    tail: M,
    address: [2]M,
    clock: [4]M,
    value: [2]M,
};

pub const Plan = struct {
    policy: Policy,
    fixed: [ROWS]Fixed,

    pub fn init(policy: Policy) !Plan {
        try policy.validate();
        var self: Plan = .{ .policy = policy, .fixed = undefined };
        for (&self.fixed, 0..) |*out, index| {
            if (index >= READS) {
                out.* = .{ .active = M.zero(), .tail = M.zero(), .address = @splat(M.zero()), .clock = @splat(M.zero()), .value = @splat(M.zero()) };
                continue;
            }
            const event = try self.transition(index, 0);
            const tuple = Word.transitionTuple(event);
            out.* = .{ .active = M.one(), .tail = M.fromCanonical(@intFromBool(index == READS - 1)), .address = tuple[1..3].*, .clock = tuple[3..7].*, .value = tuple[7..9].* };
        }
        return self;
    }

    /// Host witness generation only. Polynomial constraints must bind the
    /// resulting tuples, and their demand must close against sorted RAM.
    pub fn transition(self: Plan, index: usize, high_byte: u8) !Transition {
        try self.policy.validate();
        if (index >= READS) return error.InvalidTerminalReadIndex;
        const cycle = try std.math.add(u64, self.policy.final_cycle, index / 3);
        const clock = try std.math.add(u64, try std.math.mul(u64, cycle, 4), index % 3 + 1);
        const address = switch (index) {
            0 => self.policy.halt_address,
            1 => self.policy.length_address,
            else => try std.math.add(u32, self.policy.data_address, @as(u32, @intCast(index - 2)) * 4),
        };
        const value: u32 = switch (index) {
            0 => 1,
            1 => OUTPUT_BYTES,
            else => blk: {
                var bytes: [4]u8 = @splat(0);
                const offset = (index - 2) * 4;
                const count = @min(4, OUTPUT_BYTES - offset);
                @memcpy(bytes[0..count], self.policy.output[offset..][0..count]);
                if (index == READS - 1) bytes[3] = high_byte;
                break :blk std.mem.readInt(u32, &bytes, .little);
            },
        };
        return .{ .space = 1, .address = address, .clock = clock, .before = value, .after = value };
    }

    pub fn require(self: Plan, independently: Policy) !void {
        const expected = try init(independently);
        if (!std.meta.eql(self, expected)) return error.UntrustedTerminalPlan;
    }
};
