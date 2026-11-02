//! Canonical producer diagnostic, NOT execution authority or a proof claim.
//! Hashes retained semantic values, never pointers/capacities/struct padding.
const std = @import("std");
const Capture = @import("capture.zig");
const Digest = struct {
    hash: std.crypto.hash.sha2.Sha256 = .init(.{}),
    buffer: [4096]u8 = undefined,
    used: usize = 0,
    fn write(self: *@This(), bytes: []const u8) void {
        var rest = bytes;
        while (rest.len != 0) {
            const n = @min(rest.len, self.buffer.len - self.used);
            @memcpy(self.buffer[self.used..][0..n], rest[0..n]);
            self.used += n;
            rest = rest[n..];
            if (self.used == self.buffer.len) {
                self.hash.update(&self.buffer);
                self.used = 0;
            }
        }
    }
    fn integer(self: *@This(), number: u64) void {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, number, .little);
        self.write(&bytes);
    }
    fn value(self: *@This(), item: anytype) void {
        const T = @TypeOf(item);
        switch (@typeInfo(T)) {
            .int => |info| {
                if (info.bits > 64) @compileError("diagnostic integer exceeds canonical width");
                const U = std.meta.Int(.unsigned, info.bits);
                self.integer(@as(U, @bitCast(item)));
            },
            .bool => self.integer(@intFromBool(item)),
            .@"enum" => self.value(@intFromEnum(item)),
            .array => {
                self.integer(item.len);
                for (item) |entry| self.value(entry);
            },
            .pointer => |info| {
                if (info.size != .slice) @compileError("diagnostic may not serialize pointers");
                self.integer(item.len);
                for (item) |entry| self.value(entry);
            },
            .@"struct" => |info| inline for (info.fields) |field| {
                self.integer(field.name.len);
                self.write(field.name);
                self.value(@field(item, field.name));
            },
            else => @compileError("unsupported diagnostic value " ++ @typeName(T)),
        }
    }
    fn final(self: *@This()) [32]u8 {
        self.hash.update(self.buffer[0..self.used]);
        return self.hash.finalResult();
    }
};
pub fn digest(image_identity: [32]u8, owner: *const Capture.Owner) [32]u8 {
    var h = Digest{};
    h.write("stwo/rv64/ethereum/captured-values/v1\x00");
    h.value(.{ image_identity, owner.total_steps, owner.final_pc, owner.final_registers });
    h.integer(owner.native.items.len);
    for (owner.native.items, 0..) |n, ordinal| {
        h.integer(ordinal);
        const cpu = &n.cpu.?;
        h.value(.{ n.program_identity, n.raw_counts, n.unique_memory_words });
        h.value(.{ cpu.public, cpu.epoch, cpu.log_size, cpu.metadata, cpu.rom_counts, cpu.counts16, cpu.counts8, cpu.capture_records_retired, cpu.main_projection_closed });
        h.value(.{ n.alu.facts, n.alu.weights, n.binary.facts, n.binary.weights, n.shift, n.shift_weights, n.division, n.multiplication });
        h.integer(@intFromBool(n.jalr != null));
        if (n.jalr) |j| h.value(.{ j.facts, j.fixed, j.main, j.rows, j.log_size });
    }
    h.value(.{ owner.advice.events, owner.advice.keccak, owner.advice.secp, owner.advice.initial, owner.advice.terminal });
    return h.final();
}
