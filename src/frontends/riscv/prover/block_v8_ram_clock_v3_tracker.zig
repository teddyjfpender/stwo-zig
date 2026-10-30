//! Opt-in collector API for the unqualified V3 RAM-clock candidate. No live
//! session imports this module. Register collection retains canonical hops;
//! RAM collection records actual predecessor clocks and never inserts ghosts.
const std = @import("std");
const Canonical = @import("../runner/state_chain.zig");
const Kernel = @import("block_v8_ram_clock_v3_kernel.zig");
pub const production_active = false;
pub const whole_source_qualified = false;
pub const Tracker = struct {
    policy: Kernel.Policy,
    chain: Canonical.StateChainTracker,
    avoided_ram_hops: u64 = 0,
    pub fn init(a: std.mem.Allocator, cycles: u32) !Tracker {
        return .{ .policy = try Kernel.Policy.fromCycles(cycles), .chain = Canonical.StateChainTracker.init(a) };
    }
    pub fn deinit(self: *Tracker) void {
        self.chain.deinit();
        self.* = undefined;
    }
    pub fn recordRegTransition(self: *Tracker, reg: u5, clock: u32, previous: u32, next: u32) !void {
        try self.policy.requireBounded(clock, self.chain.reg_last_clk[reg]);
        if (clock <= self.chain.reg_last_clk[reg]) return error.NonIncreasingV3RamClock;
        try self.chain.recordRegTransition(reg, clock, previous, next);
    }
    /// Return the three private gap cells to the future V3 witness owner.
    /// Reservations precede every logical mutation; failed allocations leave
    /// maps, access sequence and hop accounting unchanged.
    pub fn recordMemTransition(self: *Tracker, address: u32, clock: u32, previous: u32, next: u32) ![Kernel.COLUMN_COUNT]@import("stwo_core").fields.m31.M31 {
        if (clock % 4 != 3) return error.InvalidV3RamAccessOrdinal;
        if (address >= 1 << 30) return error.InvalidV3RamAddress;
        const aligned = address & ~@as(u32, 3);
        const before_clock = self.chain.mem_last_clk.get(aligned) orelse 0;
        const gap = try Kernel.witness(self.policy, true, clock, before_clock);
        const new_hops = try std.math.add(u64, self.avoided_ram_hops, Canonical.StateChainTracker.clockGapCount(before_clock, clock));
        try self.chain.reserveTransitions(.{ .memory_address_count = @intFromBool(!self.chain.mem_last_clk.contains(aligned) or !self.chain.mem_initial.contains(aligned)), .access_count = 1, .memory_clock_update_count = 0, .register_clock_update_count = 0 });
        const initial = self.chain.mem_initial.getOrPutAssumeCapacity(aligned);
        if (!initial.found_existing) initial.value_ptr.* = previous;
        self.chain.mem_last_clk.putAssumeCapacity(aligned, clock);
        self.chain.accesses.appendAssumeCapacity(.{ .addr_space = 1, .addr = aligned, .clk = clock, .clk_prev = before_clock, .value = next });
        self.avoided_ram_hops = new_hops;
        std.debug.assert(self.chain.clock_updates_mem.items.len == 0);
        return gap;
    }
};
