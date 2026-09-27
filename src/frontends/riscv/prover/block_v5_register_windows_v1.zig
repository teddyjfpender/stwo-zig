//! Register custody is local to each freshly verified execution window. The
//! frozen universal tuple has no execution ordinal, so claims must never be
//! pooled across windows. This policy is metadata, not a verification receipt.
const std = @import("std");
const core = @import("stwo_core");
const Public = @import("../air/public_logup_arithmetic.zig");
const AccessClock = @import("../access_clock.zig");
const Q = core.fields.qm31.QM31;
pub const MODE: u32 = 1;
pub const VERSION: u32 = 1;
pub const LOCAL_ZERO_VERSION: u32 = 2;
pub const Window = struct {
    index: u32,
    first_cycle: u64,
    cycle_count: u32,
    initial_registers: [32]u32,
    final_registers: [32]u32,
    final_clocks: [32]u32,

    pub fn fromPublic(index: u32, first_cycle: u64, data: anytype) Window {
        return .{ .index = index, .first_cycle = first_cycle, .cycle_count = data.clock, .initial_registers = data.initial_regs, .final_registers = data.final_regs, .final_clocks = data.reg_last_clock };
    }
    pub fn requirePublic(self: Window, index: u32, first_cycle: u64, data: anytype) !void {
        if (!std.meta.eql(self, fromPublic(index, first_cycle, data))) return error.UntrustedV5RegisterWindow;
    }
};
pub const Plan = struct {
    version: u32 = VERSION,
    /// Independently pinned block endpoints, not inferred from proof claims.
    initial_registers: [32]u32,
    final_registers: [32]u32,
    windows: []const Window,

    pub fn digest(self: Plan) ![32]u8 {
        try self.validate();
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(if (self.version == LOCAL_ZERO_VERSION) "stwo-zig/block-v5/native-register-windows/v2\x00" else "stwo-zig/block-v5/native-register-windows/v1\x00");
        if (self.version == LOCAL_ZERO_VERSION) h.update(&@import("../air/x0_local_custody_v1.zig").abiId());
        put(&h, u32, self.version);
        put(&h, u32, MODE);
        put(&h, u64, @intCast(self.windows.len));
        for (self.initial_registers, self.final_registers) |first, last| {
            put(&h, u32, first);
            put(&h, u32, last);
        }
        for (self.windows) |window| {
            put(&h, u32, window.index);
            put(&h, u64, window.first_cycle);
            put(&h, u32, window.cycle_count);
            for (window.initial_registers, window.final_registers, window.final_clocks) |first, last, clock| {
                put(&h, u32, first);
                put(&h, u32, last);
                put(&h, u32, clock);
            }
        }
        return h.finalResult();
    }
    pub fn validate(self: Plan) !void {
        if ((self.version != VERSION and self.version != LOCAL_ZERO_VERSION) or self.windows.len == 0 or self.windows.len > std.math.maxInt(u32) or
            self.initial_registers[0] != 0 or self.final_registers[0] != 0 or
            !std.meta.eql(self.initial_registers, self.windows[0].initial_registers) or
            !std.meta.eql(self.final_registers, self.windows[self.windows.len - 1].final_registers)) return error.InvalidV5RegisterWindowPlan;
        var next_cycle: u64 = 1;
        var previous = self.initial_registers;
        for (self.windows, 0..) |window, index| {
            if (window.index != index or window.first_cycle != next_cycle or window.cycle_count == 0 or
                window.initial_registers[0] != 0 or window.final_registers[0] != 0 or
                !std.meta.eql(window.initial_registers, previous) or
                AccessClock.maximum(window.cycle_count) >= @import("../runner/state_chain.zig").CLOCK_PREV_BOUND)
                return error.InvalidV5RegisterWindowPlan;
            if (self.version == LOCAL_ZERO_VERSION and window.final_clocks[0] != 0) return error.UntrustedX0LocalPublicBoundary;
            const last_clock = AccessClock.maximum(window.cycle_count);
            for (window.initial_registers, window.final_registers, window.final_clocks) |first, last, clock| {
                if (clock > last_clock or (clock == 0 and first != last)) return error.InvalidV5RegisterWindowClock;
            }
            next_cycle = try std.math.add(u64, next_cycle, window.cycle_count);
            previous = window.final_registers;
        }
    }
    pub fn requireNative(self: Plan, shape: *const @import("../air/statement.zig").Blake3ExecutionStatement) !void {
        if ((self.version == LOCAL_ZERO_VERSION) != shape.localZeroCustody()) return error.UntrustedV5RegisterCustodyRecipe;
    }
    pub fn requireCaller(self: Plan, statement: *const @import("blake3_ethereum_sha_statement.zig").Statement) !void {
        if ((self.version == LOCAL_ZERO_VERSION) != statement.ethereum.localZeroCustody()) return error.UntrustedV5RegisterCustodyRecipe;
    }
    /// Used only inside fresh same-root hook receivers. Public compensation
    /// alone has no proof authority and cannot attest the supplied endpoints.
    pub fn compensation(self: Plan, index: u32, relations: anytype) !Q {
        if (index >= self.windows.len) return error.InvalidV5RegisterWindowIndex;
        const window = self.windows[index];
        const data = .{ .initial_regs = window.initial_registers, .final_regs = window.final_registers, .reg_last_clock = window.final_clocks };
        if (self.version == LOCAL_ZERO_VERSION) {
            if (window.initial_registers[0] != 0 or window.final_registers[0] != 0 or window.final_clocks[0] != 0) return error.UntrustedX0LocalPublicBoundary;
            return Public.nonzeroRegisterMemoryAccessSumFor(Q, data, relations);
        }
        return Public.registerMemoryAccessSumFor(Q, data, relations);
    }
};
fn put(h: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    h.update(&bytes);
}
