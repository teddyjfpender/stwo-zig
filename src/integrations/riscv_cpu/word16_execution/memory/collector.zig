//! Clock predecessor hints from captured effects; no VM or instruction replay.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const X = front.rv64_air.memory.load_store_v2;
const R = front.rv64_air.memory.closed_ram;
const CPU = @import("../cpu_source.zig");
const Public = @import("statement.zig");
pub const Collected = struct {
    allocator: std.mem.Allocator,
    events: []X.native.Event,
    initial: []R.types.Cell,
    terminal: []R.types.Cell,
    pub fn deinit(self: *Collected) void {
        self.allocator.free(self.events);
        self.allocator.free(self.initial);
        self.allocator.free(self.terminal);
        self.* = undefined;
    }
};
fn less(_: void, a: R.types.Cell, b: R.types.Cell) bool {
    return a.address < b.address;
}
pub fn collect(a: std.mem.Allocator, image: Public.Image, records: []const CPU.MemoryRecord, epoch: u16) !Collected {
    if (records.len >= (1 << 22)) return error.MemoryEventLimit;
    var states: std.AutoHashMapUnmanaged(u64, R.types.State) = .empty;
    defer states.deinit(a);
    var initial: std.ArrayList(R.types.Cell) = .empty;
    defer initial.deinit(a);
    const events = try a.alloc(X.native.Event, records.len);
    errdefer a.free(events);
    var previous: u24 = 0;
    for (records, events) |record, *event| {
        if (record.epoch != epoch or record.tick <= previous or record.tick & 3 != 0) return error.InvalidMemoryRecordTime;
        previous = record.tick;
        const d = try X.native.describe(record.opcode);
        const ea = record.a +% record.immediate;
        const address = ea & ~@as(u64, 7);
        if (record.effect.address.toInt() != ea or record.effect.width != d.width or record.effect.write != d.write) return error.InvalidMemoryRecordEffect;
        const entry = try states.getOrPut(a, address);
        if (!entry.found_existing) {
            entry.value_ptr.* = .{ .value = try image.initialWord(address), .rights = try image.wordRights(address) };
            try initial.append(a, .{ .address = address, .state = entry.value_ptr.* });
        }
        const before = entry.value_ptr.*;
        if (record.effect.before_word.toInt() != before.value) return error.InconsistentCapturedMemoryBefore;
        const after = R.types.State{ .value = record.effect.after_word.toInt(), .epoch = epoch, .tick = record.tick, .rights = before.rights };
        event.* = .{ .opcode = record.opcode, .immediate = record.immediate, .a = record.a, .b = record.b, .c = record.c, .epoch = epoch, .tick = record.tick, .before = before, .after = after };
        try X.native.validate(event.*);
        entry.value_ptr.* = after;
    }
    const input = try initial.toOwnedSlice(a);
    errdefer a.free(input);
    std.mem.sort(R.types.Cell, input, {}, less);
    const terminal = try a.alloc(R.types.Cell, input.len);
    errdefer a.free(terminal);
    for (input, terminal) |cell, *out| out.* = .{ .address = cell.address, .state = states.get(cell.address).? };
    return .{ .allocator = a, .events = events, .initial = input, .terminal = terminal };
}
