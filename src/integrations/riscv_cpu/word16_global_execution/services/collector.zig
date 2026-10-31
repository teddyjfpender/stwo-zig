//! One chronological hint ledger for ordinary LS and all three service kinds.
//! Neither captured sidecar values nor this ledger grant acceptance authority.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const LS = A.memory.load_store_v2;
const K = A.crypto.keccak.word16_bridge;
const S = A.crypto.secp256k1.word16_bridge;
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Old = @import("../collector.zig");
const Cell = A.memory.closed_ram.types.Cell;
pub const Advice = struct {
    allocator: std.mem.Allocator,
    events: [][]LS.native.Event,
    keccak: [][]K.types.Call,
    secp: [][2][]S.types.Call,
    initial: []Cell,
    terminal: []Cell,
    pub fn deinit(self: *Advice) void {
        const a = self.allocator;
        for (self.events) |e| a.free(e);
        for (self.keccak) |c| a.free(c);
        for (self.secp) |cc| for (cc) |c| a.free(c);
        a.free(self.events);
        a.free(self.keccak);
        a.free(self.secp);
        a.free(self.initial);
        a.free(self.terminal);
    }
};
pub fn collect(a: std.mem.Allocator, prepared: []const *Native, tapes: []const *const front.rv64.compact_tape.Tape, image: @import("../../word16_execution/memory/statement.zig").Image) !Advice {
    if (prepared.len == 0 or prepared.len != tapes.len or prepared.len > 65535) return error.InvalidCombinedServiceRoster;
    var ledger = Old.Ledger.init(a, image);
    defer ledger.deinit();
    const events = try a.alloc([]LS.native.Event, prepared.len);
    errdefer a.free(events);
    const keccak = try a.alloc([]K.types.Call, prepared.len);
    errdefer a.free(keccak);
    const secp = try a.alloc([2][]S.types.Call, prepared.len);
    errdefer a.free(secp);
    var done: usize = 0;
    errdefer for (0..done) |i| {
        a.free(events[i]);
        a.free(keccak[i]);
        for (secp[i]) |cc| a.free(cc);
    };
    for (prepared, tapes, 0..) |native, tape, index| {
        const cpu = native.cpu orelse return error.PreparedExecutionConsumed;
        if (tape.execution_profile != .ethereum_services_v2 or cpu.epoch != index + 1 or cpu.services.items.len != tape.service_calls.items.len + tape.secp_calls.items.len) return error.InvalidCombinedServiceRoster;
        var sizes: [2]usize = @splat(0);
        for (tape.secp_calls.items) |call| sizes[@intFromEnum(call.kind) - 1] += 1;
        const ee = try a.alloc(LS.native.Event, cpu.memory.items.len);
        errdefer a.free(ee);
        const kk = try a.alloc(K.types.Call, tape.service_calls.items.len);
        errdefer a.free(kk);
        const aa = try a.alloc(S.types.Call, sizes[0]);
        errdefer a.free(aa);
        const dd = try a.alloc(S.types.Call, sizes[1]);
        errdefer a.free(dd);
        const ss = [2][]S.types.Call{ aa, dd };
        var next: [2]usize = @splat(0);
        var mi: usize = 0;
        var ci: usize = 0;
        var ki: usize = 0;
        var si: usize = 0;
        var previous: u24 = 0;
        while (mi < ee.len or ci < cpu.services.items.len) {
            const mt = if (mi < ee.len) cpu.memory.items[mi].tick else std.math.maxInt(u24);
            const ct = if (ci < cpu.services.items.len) cpu.services.items[ci].tick else std.math.maxInt(u24);
            if (mt == ct or @min(mt, ct) <= previous) return error.InvalidCombinedServiceChronology;
            previous = @min(mt, ct);
            if (mt < ct) {
                const rec = cpu.memory.items[mi];
                const desc = try LS.native.describe(rec.opcode);
                const ea = rec.a +% rec.immediate;
                const address = ea & ~@as(u64, 7);
                if (rec.epoch != cpu.epoch or rec.tick & 3 != 0 or rec.effect.address.toInt() != ea or rec.effect.width != desc.width or rec.effect.write != desc.write) return error.InvalidMemoryRecordEffect;
                const before = try get(&ledger, address);
                if (before.value != rec.effect.before_word.toInt()) return error.InconsistentCapturedMemoryBefore;
                const after = A.memory.closed_ram.types.State{ .value = rec.effect.after_word.toInt(), .epoch = cpu.epoch, .tick = rec.tick, .rights = before.rights };
                ee[mi] = .{ .opcode = rec.opcode, .a = rec.a, .b = rec.b, .c = rec.c, .immediate = rec.immediate, .epoch = cpu.epoch, .tick = rec.tick, .before = before, .after = after };
                try LS.native.validate(ee[mi]);
                ledger.states.getPtr(address).?.* = after;
                mi += 1;
            } else {
                const rec = cpu.services.items[ci];
                if (rec.epoch != cpu.epoch or rec.tick & 3 != 0) return error.InvalidCombinedServiceOwner;
                if (rec.tag == 0x10001) {
                    if (ki >= kk.len) return error.InvalidCombinedServiceOwner;
                    const captured = tape.service_calls.items[ki];
                    if (rec.pointer & 7 != 0 or rec.pointer > std.math.maxInt(u64) - 199) return error.InvalidCombinedServiceOwner;
                    try owner(rec.pointer, rec.tick, tape, captured.pointer, captured.clock);
                    var call: K.types.Call = .{ .pointer = rec.pointer, .epoch = cpu.epoch, .tick = rec.tick, .before = captured.before, .after = captured.after, .predecessors = undefined };
                    for (0..25) |lane| call.predecessors[lane] = try get(&ledger, rec.pointer + 8 * lane);
                    try K.source.validate(call);
                    for (0..25) |lane| ledger.states.getPtr(rec.pointer + 8 * lane).?.* = .{ .value = call.after[lane], .epoch = call.epoch, .tick = call.tick, .rights = call.predecessors[lane].rights };
                    kk[ki] = call;
                    ki += 1;
                } else if (rec.tag == 0x20011 or rec.tag == 0x20012) {
                    if (si >= tape.secp_calls.items.len) return error.InvalidCombinedServiceOwner;
                    const captured = tape.secp_calls.items[si];
                    if (rec.pointer & 31 != 0 or rec.pointer > std.math.maxInt(u64) - (8 * captured.wordCount() - 1)) return error.InvalidCombinedServiceOwner;
                    if (captured.packet_format != .little_endian_words_v2 or captured.tag() != rec.tag) return error.InvalidCombinedServiceOwner;
                    try owner(rec.pointer, rec.tick, tape, captured.pointer, captured.clock);
                    var call: S.types.Call = .{ .pointer = rec.pointer, .epoch = cpu.epoch, .tick = rec.tick, .before = captured.before, .after = captured.after, .predecessors = @splat(.{ .value = 0, .rights = 0 }) };
                    for (0..captured.wordCount()) |lane| call.predecessors[lane] = try get(&ledger, rec.pointer + 8 * lane);
                    try S.source.validate(captured.kind, call);
                    for (0..captured.wordCount()) |lane| ledger.states.getPtr(rec.pointer + 8 * lane).?.* = .{ .value = call.after[lane], .epoch = call.epoch, .tick = call.tick, .rights = call.predecessors[lane].rights };
                    const family = @intFromEnum(captured.kind) - 1;
                    ss[family][next[family]] = call;
                    next[family] += 1;
                    si += 1;
                } else return error.UnqualifiedCombinedServiceTag;
                ci += 1;
            }
        }
        if (ki != kk.len or si != tape.secp_calls.items.len) return error.InvalidCombinedServiceRoster;
        events[index] = ee;
        keccak[index] = kk;
        secp[index] = ss;
        done += 1;
    }
    const boundary = try ledger.boundaries();
    return .{ .allocator = a, .events = events, .keccak = keccak, .secp = secp, .initial = boundary.initial, .terminal = boundary.terminal };
}
fn owner(pointer: u64, tick: u24, tape: *const front.rv64.compact_tape.Tape, captured_pointer: u64, clock: u64) !void {
    if (pointer != captured_pointer or clock <= tape.initial_clock or clock - tape.initial_clock > tape.len or 4 * (clock - tape.initial_clock) != tick) return error.InvalidCombinedServiceOwner;
}
fn get(ledger: *Old.Ledger, address: u64) !A.memory.closed_ram.types.State {
    const entry = try ledger.states.getOrPut(ledger.allocator, address);
    if (!entry.found_existing) {
        entry.value_ptr.* = .{ .value = try ledger.image.initialWord(address), .rights = try ledger.image.wordRights(address) };
        try ledger.initial.append(ledger.allocator, .{ .address = address, .state = entry.value_ptr.* });
    }
    return entry.value_ptr.*;
}
