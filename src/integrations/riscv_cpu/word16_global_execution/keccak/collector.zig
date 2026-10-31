//! Captured effects interleaved in instruction order. This ledger supplies
//! hints only: RAM14 and CPU OWNER19 physical proofs establish acceptance.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const LS = A.memory.load_store_v2;
const B = A.crypto.keccak.word16_bridge;
const Cell = A.memory.closed_ram.types.Cell;
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Old = @import("../collector.zig");
pub const Advice = struct {
    allocator: std.mem.Allocator,
    events: [][]LS.native.Event,
    calls: [][]B.types.Call,
    initial: []Cell,
    terminal: []Cell,
    pub fn deinit(self: *Advice) void {
        for (self.events) |e| self.allocator.free(e);
        for (self.calls) |c| self.allocator.free(c);
        self.allocator.free(self.events);
        self.allocator.free(self.calls);
        self.allocator.free(self.initial);
        self.allocator.free(self.terminal);
    }
};
pub fn collect(a: std.mem.Allocator, prepared: []const *Native, tapes: []const *const front.rv64.compact_tape.Tape, image: @import("../../word16_execution/memory/statement.zig").Image) !Advice {
    if (prepared.len == 0 or prepared.len != tapes.len or prepared.len > 65535) return error.InvalidServiceExecutionRoster;
    var ledger = Old.Ledger.init(a, image);
    defer ledger.deinit();
    const events = try a.alloc([]LS.native.Event, prepared.len);
    errdefer a.free(events);
    const calls = try a.alloc([]B.types.Call, prepared.len);
    errdefer a.free(calls);
    var done: usize = 0;
    errdefer for (0..done) |i| {
        a.free(events[i]);
        a.free(calls[i]);
    };
    for (prepared, tapes, 0..) |native, tape, index| {
        const cpu = native.cpu orelse return error.PreparedExecutionConsumed;
        if (cpu.epoch != index + 1 or tape.secp_calls.items.len != 0 or cpu.services.items.len != tape.service_calls.items.len) return error.InvalidServiceExecutionRoster;
        const ee = try a.alloc(LS.native.Event, cpu.memory.items.len);
        errdefer a.free(ee);
        const cc = try a.alloc(B.types.Call, cpu.services.items.len);
        errdefer a.free(cc);
        var mi: usize = 0;
        var ci: usize = 0;
        var previous: u24 = 0;
        while (mi < ee.len or ci < cc.len) {
            const mt = if (mi < ee.len) cpu.memory.items[mi].tick else std.math.maxInt(u24);
            const ct = if (ci < cc.len) cpu.services.items[ci].tick else std.math.maxInt(u24);
            if (mt == ct or @min(mt, ct) <= previous) return error.InvalidServiceChronology;
            previous = @min(mt, ct);
            if (mt < ct) {
                const record = cpu.memory.items[mi];
                const d = try LS.native.describe(record.opcode);
                const ea = record.a +% record.immediate;
                const address = ea & ~@as(u64, 7);
                if (record.epoch != cpu.epoch or record.tick & 3 != 0 or record.effect.address.toInt() != ea or record.effect.width != d.width or record.effect.write != d.write) return error.InvalidMemoryRecordEffect;
                const before = try get(&ledger, address);
                if (before.value != record.effect.before_word.toInt()) return error.InconsistentCapturedMemoryBefore;
                const after = A.memory.closed_ram.types.State{ .value = record.effect.after_word.toInt(), .epoch = cpu.epoch, .tick = record.tick, .rights = before.rights };
                ee[mi] = .{ .opcode = record.opcode, .a = record.a, .b = record.b, .c = record.c, .immediate = record.immediate, .epoch = cpu.epoch, .tick = record.tick, .before = before, .after = after };
                try LS.native.validate(ee[mi]);
                ledger.states.getPtr(address).?.* = after;
                mi += 1;
            } else {
                const record = cpu.services.items[ci];
                const captured = tape.service_calls.items[ci];
                if (record.tag != 0x10001 or captured.pointer != record.pointer or captured.clock <= tape.initial_clock or captured.clock - tape.initial_clock > tape.len or 4 * (captured.clock - tape.initial_clock) != record.tick or record.epoch != cpu.epoch) return error.InvalidCapturedKeccakOwner;
                if (captured.pointer & 7 != 0 or captured.pointer > std.math.maxInt(u64) - 199) return error.InvalidCapturedKeccakOwner;
                var call: B.types.Call = .{ .pointer = captured.pointer, .epoch = cpu.epoch, .tick = record.tick, .before = captured.before, .after = captured.after, .predecessors = undefined };
                for (0..25) |lane| {
                    const address = captured.pointer + 8 * lane;
                    call.predecessors[lane] = try get(&ledger, address);
                }
                try B.source.validate(call);
                for (0..25) |lane| ledger.states.getPtr(captured.pointer + 8 * lane).?.* = .{ .value = call.after[lane], .epoch = call.epoch, .tick = call.tick, .rights = call.predecessors[lane].rights };
                cc[ci] = call;
                ci += 1;
            }
        }
        events[index] = ee;
        calls[index] = cc;
        done += 1;
    }
    const b = try ledger.boundaries();
    return .{ .allocator = a, .events = events, .calls = calls, .initial = b.initial, .terminal = b.terminal };
}
fn get(ledger: *Old.Ledger, address: u64) !A.memory.closed_ram.types.State {
    const entry = try ledger.states.getOrPut(ledger.allocator, address);
    if (!entry.found_existing) {
        entry.value_ptr.* = .{ .value = try ledger.image.initialWord(address), .rights = try ledger.image.wordRights(address) };
        try ledger.initial.append(ledger.allocator, .{ .address = address, .state = entry.value_ptr.* });
    }
    return entry.value_ptr.*;
}
