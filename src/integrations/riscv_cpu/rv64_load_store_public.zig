//! Receiver-owned finite image and CPU-style LS requests. Raw instruction
//! decoding supplies the ISA opcode/width/sign/immediate authority.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const R = front.rv64_air.memory.closed_ram.types;
const Specs = front.rv64_air.memory.load_store_v1;
pub const Cell = R.Cell;
pub const Operation = struct { id: u16, instruction: u32, a: u64, b: u64 = 0, c: u64 = 0, epoch: u16, tick: u24 };
pub const Description = struct { opcode: front.rv64.decode.Opcode, immediate: u64, width: u4, signed: bool, write: bool, flag: usize };
pub fn describe(word: u32) !Description {
    const decoded = try front.rv64.decode.Instruction.decode(word);
    inline for (Specs.load_specs ++ Specs.store_specs, 0..) |spec, index| if (decoded.opcode == spec.opcode) return .{ .opcode = decoded.opcode, .immediate = @bitCast(decoded.imm), .width = @intCast(spec.width), .signed = spec.signed, .write = index >= Specs.load_specs.len, .flag = index };
    return error.NotLoadStoreInstruction;
}
pub const Expected = struct {
    initial: []const Cell,
    terminal: []const Cell,
    operations: []const Operation,
    split: u32,
    pub fn cellIndex(self: @This(), address: u64) !usize {
        for (self.initial, 0..) |cell, i| if (cell.address == address) return i;
        return error.LoadStoreAddressOutsideImage;
    }
    pub fn validate(self: @This()) !void {
        if (self.initial.len == 0 or self.initial.len > 31 or self.terminal.len != self.initial.len or self.operations.len < 2 or self.operations.len > 63 or self.split == 0 or self.split >= self.operations.len) return error.InvalidLoadStoreExpected;
        for (self.initial, self.terminal, 0..) |before, after, i| if (before.address & 7 != 0 or (i != 0 and self.initial[i - 1].address >= before.address) or after.address != before.address or before.state.epoch != 0 or before.state.tick != 0 or after.state.rights != before.state.rights) return error.InvalidLoadStoreImage;
        for (self.operations, 0..) |op, i| {
            const d = try describe(op.instruction);
            const ea = op.a +% d.immediate;
            if (op.id == 0 or op.tick == 0 or op.tick & 3 != 0 or ea & (d.width - 1) != 0 or (d.write and op.c != 0) or (!d.write and op.b != 0)) return error.InvalidLoadStoreOperation;
            _ = try self.cellIndex(ea & ~@as(u64, 7));
            for (self.operations[0..i]) |old| {
                const previous = try describe(old.instruction);
                if (op.id == old.id or ((old.a +% previous.immediate) & ~@as(u64, 7) == ea & ~@as(u64, 7) and old.epoch == op.epoch and old.tick == op.tick)) return error.DuplicateLoadStoreOrigin;
            }
        }
    }
    pub fn digest(self: @This()) ![32]u8 {
        try self.validate();
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(&front.rv64_air.memory.load_store_v1.types.identity());
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
            put(&h, u32, op.instruction);
            put(&h, u64, op.a);
            put(&h, u64, op.b);
            put(&h, u64, op.c);
            put(&h, u16, op.epoch);
            put(&h, u32, op.tick);
        }
        return h.finalResult();
    }
};
fn put(h: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    h.update(&bytes);
}
