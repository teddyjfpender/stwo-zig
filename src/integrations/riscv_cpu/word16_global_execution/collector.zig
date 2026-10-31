//! Narrow cross-shard predecessor hints from captured CPU effects, never VM/P2.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const X = A.memory.load_store_v2;
const R = A.memory.closed_ram;
const CPU = @import("../word16_execution/cpu_source.zig");
const Public = @import("../word16_execution/memory/statement.zig");
pub const Ledger = struct {
    allocator: std.mem.Allocator,
    image: Public.Image,
    states: std.AutoHashMapUnmanaged(u64, R.types.State) = .empty,
    initial: std.ArrayList(R.types.Cell) = .empty,
    next_epoch: u32 = 1,
    pub fn init(a: std.mem.Allocator, image: Public.Image) Ledger {
        return .{ .allocator = a, .image = image };
    }
    pub fn deinit(self: *Ledger) void {
        self.states.deinit(self.allocator);
        self.initial.deinit(self.allocator);
    }
    /// On failure discard the ledger; no partially updated cursor may be retried.
    pub fn shard(self: *Ledger, records: []const CPU.MemoryRecord, epoch: u16) ![]X.native.Event {
        if (epoch != self.next_epoch) return error.InvalidGlobalMemoryEpoch;
        const out = try self.allocator.alloc(X.native.Event, records.len);
        errdefer self.allocator.free(out);
        var previous: u24 = 0;
        for (records, out) |record, *event| {
            if (record.epoch != epoch or record.tick <= previous or record.tick & 3 != 0) return error.InvalidMemoryRecordTime;
            previous = record.tick;
            const d = try X.native.describe(record.opcode);
            const ea = record.a +% record.immediate;
            const address = ea & ~@as(u64, 7);
            if (record.effect.address.toInt() != ea or record.effect.width != d.width or record.effect.write != d.write) return error.InvalidMemoryRecordEffect;
            const slot = try self.states.getOrPut(self.allocator, address);
            if (!slot.found_existing) {
                slot.value_ptr.* = .{ .value = try self.image.initialWord(address), .rights = try self.image.wordRights(address) };
                try self.initial.append(self.allocator, .{ .address = address, .state = slot.value_ptr.* });
            }
            const before = slot.value_ptr.*;
            if (record.effect.before_word.toInt() != before.value) return error.InconsistentCapturedMemoryBefore;
            const after = R.types.State{ .value = record.effect.after_word.toInt(), .epoch = epoch, .tick = record.tick, .rights = before.rights };
            event.* = .{ .opcode = record.opcode, .immediate = record.immediate, .a = record.a, .b = record.b, .c = record.c, .epoch = epoch, .tick = record.tick, .before = before, .after = after };
            try X.native.validate(event.*);
            slot.value_ptr.* = after;
        }
        self.next_epoch += 1;
        return out;
    }
    pub fn boundaries(self: *const Ledger) !struct { initial: []R.types.Cell, terminal: []R.types.Cell } {
        const initial = try self.allocator.dupe(R.types.Cell, self.initial.items);
        errdefer self.allocator.free(initial);
        std.mem.sort(R.types.Cell, initial, {}, less);
        const terminal = try self.allocator.alloc(R.types.Cell, initial.len);
        errdefer self.allocator.free(terminal);
        for (initial, terminal) |cell, *out| out.* = .{ .address = cell.address, .state = self.states.get(cell.address).? };
        return .{ .initial = initial, .terminal = terminal };
    }
};
fn less(_: void, a: R.types.Cell, b: R.types.Cell) bool {
    return a.address < b.address;
}
