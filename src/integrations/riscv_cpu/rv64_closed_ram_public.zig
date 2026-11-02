//! Independently expected finite operation/image/policy authority. No general
//! memory zero fallback or CPU execution claim is part of this closed fixture.
const std = @import("std");
const R = @import("stwo_riscv_frontend").rv64_air.memory.closed_ram;
pub const Cell = R.types.Cell;
pub const Operation = R.types.Operation;
pub const State = R.types.State;
pub const Expected = struct {
    initial: []const Cell,
    terminal: []const Cell,
    operations: []const Operation,
    split: u32,
    pub fn validate(self: @This()) !void {
        if (self.initial.len == 0 or self.initial.len > 31 or self.terminal.len != self.initial.len or self.operations.len < 2 or self.operations.len > 31 or self.split == 0 or self.split >= self.operations.len) return error.InvalidClosedRamExpected;
        for (self.initial, self.terminal, 0..) |before, after, i| {
            if (before.address & 7 != 0 or (i > 0 and self.initial[i - 1].address >= before.address) or before.address != after.address or before.state.epoch != 0 or before.state.tick != 0 or before.state.rights != after.state.rights) return error.InvalidClosedRamImage;
        }
        for (self.operations, 0..) |op, i| {
            if (op.id == 0 or op.address & 7 != 0 or op.tick == 0) return error.InvalidClosedRamOperation;
            _ = try self.cellIndex(op.address);
            for (self.operations[0..i]) |old| if (old.id == op.id or (old.address == op.address and old.epoch == op.epoch and old.tick == op.tick)) return error.DuplicateClosedRamOrigin;
        }
    }
    pub fn cellIndex(self: @This(), address: u64) !usize {
        for (self.initial, 0..) |cell, i| if (cell.address == address) return i;
        return error.ClosedRamAddressOutsideImage;
    }
    pub fn digest(self: @This()) ![32]u8 {
        try self.validate();
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(&R.types.identity());
        put(&h, u32, self.split);
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
        put(&h, u32, @intCast(self.operations.len));
        for (self.operations) |op| {
            put(&h, u16, op.id);
            put(&h, u64, op.address);
            put(&h, u16, op.epoch);
            put(&h, u32, op.tick);
            put(&h, u64, op.value);
            put(&h, u8, @intFromBool(op.write));
        }
        return h.finalResult();
    }
};
fn put(h: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    h.update(&bytes);
}
pub const A: u64 = 0x1_0000_1000;
pub const B: u64 = 0x2_0000_1000;
pub const D: u64 = 0x3_0000_1000;
pub const C: u64 = 0xffff_ffff_ffff_ff00;
pub const INITIAL = [_]Cell{
    .{ .address = A, .state = .{ .value = 5, .rights = 3 } }, .{ .address = B, .state = .{ .value = 9, .rights = 1 } },
    .{ .address = D, .state = .{ .value = 0, .rights = 2 } }, .{ .address = C, .state = .{ .value = 0, .rights = 3 } },
};
pub const TERMINAL = [_]Cell{
    .{ .address = A, .state = .{ .value = 7, .epoch = 1, .tick = 16, .rights = 3 } },  .{ .address = B, .state = .{ .value = 9, .epoch = 1, .tick = 20, .rights = 1 } },
    .{ .address = D, .state = .{ .value = 13, .epoch = 1, .tick = 24, .rights = 2 } }, .{ .address = C, .state = .{ .value = 11, .epoch = 1, .tick = 12, .rights = 3 } },
};
pub const OPERATIONS = [_]Operation{
    .{ .id = 1, .address = A, .epoch = 0, .tick = 4, .value = 5, .write = false },  .{ .id = 2, .address = A, .epoch = 0, .tick = 8, .value = 7, .write = true },
    .{ .id = 3, .address = B, .epoch = 0, .tick = 12, .value = 9, .write = false }, .{ .id = 4, .address = C, .epoch = 1, .tick = 4, .value = 11, .write = true },
    .{ .id = 5, .address = A, .epoch = 1, .tick = 8, .value = 7, .write = false },  .{ .id = 6, .address = C, .epoch = 1, .tick = 12, .value = 11, .write = false },
    .{ .id = 7, .address = A, .epoch = 1, .tick = 16, .value = 7, .write = true },  .{ .id = 8, .address = B, .epoch = 1, .tick = 20, .value = 9, .write = false },
    .{ .id = 9, .address = D, .epoch = 1, .tick = 24, .value = 13, .write = true },
};
pub fn fixture() Expected {
    return .{ .initial = &INITIAL, .terminal = &TERMINAL, .operations = &OPERATIONS, .split = 4 };
}
