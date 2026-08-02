//! Clock-ordered memory and register access chain tracking.
//!
//! For each address (memory or register), maintains the last access clock.
//! When re-accessed, records the previous clock. Generates gap-filling
//! records when the clock difference exceeds MAX_CLOCK_DIFF.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;

/// Maximum clock difference before gap-filling is required (2^20 - 1).
pub const MAX_CLOCK_DIFF: u32 = (1 << 20) - 1;
/// The shifted opcode lookup admits a positive access gap of at most 2^20.
pub const MAX_ACCESS_CLOCK_DIFF: u32 = 1 << 20;
/// Synthetic clock predecessors are decomposed as low20 + high6 * 2^20.
/// The proof geometry admits at most 2^24 opcode rows with four-wide access
/// clock buckets, so every honest predecessor is strictly below this bound.
pub const CLOCK_PREV_LOW_BITS: u5 = 20;
pub const CLOCK_PREV_HIGH_BITS: u5 = 6;
pub const CLOCK_PREV_BOUND: u32 =
    @as(u32, 1) << (CLOCK_PREV_LOW_BITS + CLOCK_PREV_HIGH_BITS);

/// A recorded access to memory or a register.
pub const Access = struct {
    /// 0 = register, 1 = memory.
    addr_space: u1,
    addr: u32,
    clk: u32,
    /// Architectural value. It is decomposed only when committed columns are
    /// materialized, keeping the execution hot log compact.
    value: u32,
    /// Clock of the previous access to the same address.
    clk_prev: u32,

    pub inline fn valueLimbs(self: Access) [4]M31 {
        return StateChainTracker.decomposeU32(self.value);
    }
};

/// A clock gap-filling record (inserted when clk - clk_prev > MAX_CLOCK_DIFF).
pub const ClockUpdate = struct {
    addr_space: u1,
    addr: u32,
    /// The synthetic clock value.
    clk: u32,
    clk_prev: u32,
    /// Value is unchanged from the previous access.
    value: u32,

    pub inline fn valueLimbs(self: ClockUpdate) [4]M31 {
        return StateChainTracker.decomposeU32(self.value);
    }
};

/// Tracks access chains for both registers and memory.
pub const StateChainTracker = struct {
    /// Last access clock per register (32 registers).
    reg_last_clk: [32]u32,
    /// Last access clock per memory address.
    mem_last_clk: std.AutoHashMap(u32, u32),
    /// Value preceding the first traced access to each aligned memory word.
    mem_initial: std.AutoHashMap(u32, u32),
    /// Recorded accesses (one per register read/write or memory access).
    accesses: std.ArrayList(Access),
    /// Clock gap-filling records for memory accesses.
    clock_updates_mem: std.ArrayList(ClockUpdate),
    /// Clock gap-filling records for register accesses.
    clock_updates_reg: std.ArrayList(ClockUpdate),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) StateChainTracker {
        return .{
            .reg_last_clk = .{0} ** 32,
            .mem_last_clk = std.AutoHashMap(u32, u32).init(allocator),
            .mem_initial = std.AutoHashMap(u32, u32).init(allocator),
            .accesses = .{},
            .clock_updates_mem = .{},
            .clock_updates_reg = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *StateChainTracker) void {
        self.mem_last_clk.deinit();
        self.mem_initial.deinit();
        self.accesses.deinit(self.allocator);
        self.clock_updates_mem.deinit(self.allocator);
        self.clock_updates_reg.deinit(self.allocator);
        self.* = undefined;
    }

    /// Release first-access baselines after the compact memory snapshot owns
    /// them. Access witnesses and final clocks remain intact.
    pub fn releaseMemoryBaselines(self: *StateChainTracker) void {
        self.mem_initial.clearAndFree();
    }

    /// Record a register access at the given clock.
    pub fn recordRegAccess(self: *StateChainTracker, reg: u5, clk: u32, value: u32) !void {
        return self.recordRegTransition(reg, clk, value, value);
    }

    /// Record an exact previous-to-next register transition.
    pub fn recordRegTransition(
        self: *StateChainTracker,
        reg: u5,
        clk: u32,
        previous: u32,
        next: u32,
    ) !void {
        const prev_clk = self.reg_last_clk[reg];
        const effective_prev_clk = try self.fillClockGap(
            0,
            @as(u32, reg),
            prev_clk,
            clk,
            previous,
        );

        try self.accesses.append(self.allocator, .{
            .addr_space = 0,
            .addr = @as(u32, reg),
            .clk = clk,
            .value = next,
            .clk_prev = effective_prev_clk,
        });
        self.reg_last_clk[reg] = clk;
    }

    /// Record a memory access at the given clock.
    pub fn recordMemAccess(self: *StateChainTracker, addr: u32, clk: u32, value: u32) !void {
        return self.recordMemTransition(addr, clk, value, value);
    }

    /// Record an exact previous-to-next transition at an aligned word.
    pub fn recordMemTransition(
        self: *StateChainTracker,
        addr: u32,
        clk: u32,
        previous: u32,
        next: u32,
    ) !void {
        const aligned_addr = addr & ~@as(u32, 3);
        const initial = try self.mem_initial.getOrPut(aligned_addr);
        if (!initial.found_existing) initial.value_ptr.* = previous;
        const prev_clk = self.mem_last_clk.get(aligned_addr) orelse 0;
        const effective_prev_clk = try self.fillClockGap(
            1,
            aligned_addr,
            prev_clk,
            clk,
            previous,
        );

        try self.accesses.append(self.allocator, .{
            .addr_space = 1,
            .addr = aligned_addr,
            .clk = clk,
            .value = next,
            .clk_prev = effective_prev_clk,
        });
        try self.mem_last_clk.put(aligned_addr, clk);
    }

    /// Fill clock gaps with intermediate records.
    fn fillClockGap(
        self: *StateChainTracker,
        addr_space: u1,
        addr: u32,
        prev_clk: u32,
        clk: u32,
        value: u32,
    ) !u32 {
        var current = prev_clk;
        while (clk -| current > MAX_CLOCK_DIFF) {
            const next = current + MAX_CLOCK_DIFF;
            const update = ClockUpdate{
                .addr_space = addr_space,
                .addr = addr,
                .clk = next,
                .clk_prev = current,
                .value = value,
            };
            if (addr_space == 0) {
                try self.clock_updates_reg.append(self.allocator, update);
            } else {
                try self.clock_updates_mem.append(self.allocator, update);
            }
            current = next;
        }
        return current;
    }

    /// Predecessor clock committed by the real access after synthetic gap rows.
    pub fn effectivePreviousClock(prev_clk: u32, clk: u32) u32 {
        var current = prev_clk;
        while (clk -| current > MAX_CLOCK_DIFF) current += MAX_CLOCK_DIFF;
        return current;
    }

    /// Decompose a u32 value into 4 byte-sized M31 limbs (little-endian).
    pub fn decomposeU32(value: u32) [4]M31 {
        return .{
            M31.fromCanonical(value & 0xFF),
            M31.fromCanonical((value >> 8) & 0xFF),
            M31.fromCanonical((value >> 16) & 0xFF),
            M31.fromCanonical((value >> 24) & 0xFF),
        };
    }

    /// Total number of memory access records.
    pub fn memAccessCount(self: *const StateChainTracker) usize {
        var count: usize = 0;
        for (self.accesses.items) |a| {
            if (a.addr_space == 1) count += 1;
        }
        return count;
    }

    /// Total number of register access records.
    pub fn regAccessCount(self: *const StateChainTracker) usize {
        var count: usize = 0;
        for (self.accesses.items) |a| {
            if (a.addr_space == 0) count += 1;
        }
        return count;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "state_chain: register access tracking" {
    const alloc = std.testing.allocator;
    var tracker = StateChainTracker.init(alloc);
    defer tracker.deinit();

    try tracker.recordRegAccess(1, 0, 42);
    try tracker.recordRegAccess(1, 2, 43);

    try std.testing.expectEqual(@as(usize, 2), tracker.regAccessCount());
    // Second access should have clk_prev = 0 (first access was at clock 0).
    try std.testing.expectEqual(@as(u32, 0), tracker.accesses.items[1].clk_prev);
}

test "state_chain: clock gap filling" {
    const alloc = std.testing.allocator;
    var tracker = StateChainTracker.init(alloc);
    defer tracker.deinit();

    // Access at clock 0, then at clock 2_000_000 (> MAX_CLOCK_DIFF).
    try tracker.recordRegAccess(1, 0, 42);
    try tracker.recordRegAccess(1, 2_000_000, 43);

    // Should have generated gap-filling records.
    try std.testing.expect(tracker.clock_updates_reg.items.len > 0);
}

test "state_chain: decomposeU32" {
    const limbs = StateChainTracker.decomposeU32(0xDEADBEEF);
    try std.testing.expectEqual(@as(u32, 0xEF), limbs[0].v);
    try std.testing.expectEqual(@as(u32, 0xBE), limbs[1].v);
    try std.testing.expectEqual(@as(u32, 0xAD), limbs[2].v);
    try std.testing.expectEqual(@as(u32, 0xDE), limbs[3].v);
}

test "state_chain: memory access tracking" {
    const alloc = std.testing.allocator;
    var tracker = StateChainTracker.init(alloc);
    defer tracker.deinit();

    try tracker.recordMemAccess(0x1000, 4, 0xFF);
    try tracker.recordMemAccess(0x1000, 8, 0xAB);

    try std.testing.expectEqual(@as(usize, 2), tracker.memAccessCount());
    // Second access should chain back to clock 4.
    try std.testing.expectEqual(@as(u32, 4), tracker.accesses.items[1].clk_prev);
}

test "state_chain: memory transition retains the first aligned baseline" {
    const alloc = std.testing.allocator;
    var tracker = StateChainTracker.init(alloc);
    defer tracker.deinit();

    try tracker.recordMemTransition(0x1001, 4, 0x0403_0201, 0x0807_0605);
    try tracker.recordMemTransition(0x1000, 8, 0x0807_0605, 0x0c0b_0a09);

    try std.testing.expectEqual(@as(u32, 0x0403_0201), tracker.mem_initial.get(0x1000).?);
    try std.testing.expectEqual(@as(u32, 8), tracker.mem_last_clk.get(0x1000).?);
    try std.testing.expectEqual(@as(u32, 0x09), tracker.accesses.items[1].valueLimbs()[0].v);
}

test "state_chain: mixed register and memory accesses" {
    const alloc = std.testing.allocator;
    var tracker = StateChainTracker.init(alloc);
    defer tracker.deinit();

    try tracker.recordRegAccess(1, 0, 10);
    try tracker.recordMemAccess(0x100, 2, 20);
    try tracker.recordRegAccess(2, 4, 30);
    try tracker.recordMemAccess(0x200, 6, 40);

    try std.testing.expectEqual(@as(usize, 2), tracker.regAccessCount());
    try std.testing.expectEqual(@as(usize, 2), tracker.memAccessCount());
    try std.testing.expectEqual(@as(usize, 4), tracker.accesses.items.len);
}

test "state_chain: no gap filling when within MAX_CLOCK_DIFF" {
    const alloc = std.testing.allocator;
    var tracker = StateChainTracker.init(alloc);
    defer tracker.deinit();

    try tracker.recordRegAccess(1, 0, 42);
    try tracker.recordRegAccess(1, MAX_CLOCK_DIFF, 43);

    // Exactly at the boundary: no gap-filling needed.
    try std.testing.expectEqual(@as(usize, 0), tracker.clock_updates_reg.items.len);
}

test "state_chain: effective predecessor matches saturating oracle distance" {
    try std.testing.expectEqual(
        @as(u32, 9),
        StateChainTracker.effectivePreviousClock(9, 3),
    );
}

test "state_chain: gap filling generates correct chain" {
    const alloc = std.testing.allocator;
    var tracker = StateChainTracker.init(alloc);
    defer tracker.deinit();

    // Access at clock 0, then at 2 * MAX_CLOCK_DIFF + 1 to force exactly 2 gap records.
    const target_clk: u32 = 2 * MAX_CLOCK_DIFF + 1;
    try tracker.recordRegAccess(5, 0, 99);
    try tracker.recordRegAccess(5, target_clk, 100);

    try std.testing.expectEqual(@as(usize, 2), tracker.clock_updates_reg.items.len);

    // First gap record: clk_prev=0, clk=MAX_CLOCK_DIFF.
    try std.testing.expectEqual(@as(u32, 0), tracker.clock_updates_reg.items[0].clk_prev);
    try std.testing.expectEqual(MAX_CLOCK_DIFF, tracker.clock_updates_reg.items[0].clk);

    // Second gap record: clk_prev=MAX_CLOCK_DIFF, clk=2*MAX_CLOCK_DIFF.
    try std.testing.expectEqual(MAX_CLOCK_DIFF, tracker.clock_updates_reg.items[1].clk_prev);
    try std.testing.expectEqual(2 * MAX_CLOCK_DIFF, tracker.clock_updates_reg.items[1].clk);
    try std.testing.expectEqual(2 * MAX_CLOCK_DIFF, tracker.accesses.items[1].clk_prev);
}

test "state_chain: long memory transition joins synthetic rows to the real access" {
    const alloc = std.testing.allocator;
    var tracker = StateChainTracker.init(alloc);
    defer tracker.deinit();

    const previous: u32 = 0x1122_3344;
    const next: u32 = 0x5566_7788;
    const target_clk: u32 = 2 * MAX_CLOCK_DIFF + 7;
    try tracker.recordMemTransition(0x1003, target_clk, previous, next);

    try std.testing.expectEqual(@as(usize, 2), tracker.clock_updates_mem.items.len);
    for (tracker.clock_updates_mem.items) |update| {
        try std.testing.expectEqual(StateChainTracker.decomposeU32(previous), update.valueLimbs());
    }
    try std.testing.expectEqual(@as(u32, 0x1000), tracker.accesses.items[0].addr);
    try std.testing.expectEqual(2 * MAX_CLOCK_DIFF, tracker.accesses.items[0].clk_prev);
    try std.testing.expectEqual(
        StateChainTracker.decomposeU32(next),
        tracker.accesses.items[0].valueLimbs(),
    );
}
