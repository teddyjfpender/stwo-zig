//! Public touched set and terminal values; INIT authority remains receiver-owned.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const R = front.rv64_air.memory.closed_ram;
const Owner = @import("../expected_image.zig").Owner;
pub const Cell = R.types.Cell;
pub const Image = struct {
    context: *const anyopaque,
    initial_word: *const fn (*const anyopaque, u64) anyerror!u64,
    rights_at: *const fn (*const anyopaque, u64) anyerror!u2,
    pub fn initialWord(self: Image, address: u64) !u64 {
        return self.initial_word(self.context, address);
    }
    pub fn wordRights(self: Image, address: u64) !u2 {
        if (address & 7 != 0) return error.UnalignedMemoryWord;
        const rights = try self.rights_at(self.context, address);
        for (1..8) |i| if (try self.rights_at(self.context, address + @as(u64, @intCast(i))) != rights) return error.NonuniformMemoryWordPolicy;
        return rights;
    }
};
pub fn fromOwner(owner: *const Owner) Image {
    return .{ .context = owner, .initial_word = Callbacks.word, .rights_at = Callbacks.rights };
}
const Callbacks = struct {
    fn word(ctx: *const anyopaque, address: u64) !u64 {
        const owner: *const Owner = @ptrCast(@alignCast(ctx));
        return owner.initialWord(address);
    }
    fn rights(ctx: *const anyopaque, address: u64) !u2 {
        const owner: *const Owner = @ptrCast(@alignCast(ctx));
        for (owner.policy.regions) |region| if (region.first <= address and address <= region.last) return @intCast(region.flags & 3);
        return 0;
    }
};
pub const Statement = struct {
    initial: []const Cell,
    terminal: []const Cell,
    epoch: u16,
    ls_count: u32,
    pub fn validate(self: Statement, image: Image) !void {
        if (self.epoch != 1) return error.UnqualifiedCrossBatchMemoryScope;
        if (self.initial.len != self.terminal.len or self.initial.len > 1 << 22 or self.ls_count >= (1 << 22)) return error.InvalidMemoryStatement;
        for (self.initial, self.terminal, 0..) |before, after, i| {
            if (before.address & 7 != 0 or (i != 0 and self.initial[i - 1].address >= before.address) or after.address != before.address) return error.InvalidMemoryTouchedSet;
            if (before.state.epoch != 0 or before.state.tick != 0 or before.state.value != try image.initialWord(before.address) or before.state.rights != try image.wordRights(before.address)) return error.UntrustedMemoryInitialState;
            if (after.state.rights != before.state.rights or after.state.epoch > self.epoch) return error.InvalidMemoryTerminalState;
        }
    }
    pub fn digest(self: Statement) [32]u8 {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("RV64/full-word16/genesis-LS19-RAM14/public-boundaries/v1");
        put(&h, u16, self.epoch);
        put(&h, u32, self.ls_count);
        for ([_][]const Cell{ self.initial, self.terminal }) |cells| {
            put(&h, u32, @intCast(cells.len));
            for (cells) |cell| {
                put(&h, u64, cell.address);
                put(&h, u64, cell.state.value);
                put(&h, u16, cell.state.epoch);
                put(&h, u32, cell.state.tick);
                put(&h, u8, cell.state.rights);
            }
        }
        var digest_: [32]u8 = undefined;
        h.final(&digest_);
        return digest_;
    }
};
fn put(h: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    h.update(&bytes);
}
