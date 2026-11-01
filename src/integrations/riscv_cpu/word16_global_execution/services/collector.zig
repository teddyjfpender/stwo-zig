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
    /// Admitted v3 SHA-256 packets per shard (empty for v2 tapes).
    sha256: [][]S.types.Call,
    initial: []Cell,
    terminal: []Cell,
    pub fn deinit(self: *Advice) void {
        const a = self.allocator;
        for (self.events) |e| a.free(e);
        for (self.keccak) |c| a.free(c);
        for (self.secp) |cc| for (cc) |c| a.free(c);
        for (self.sha256) |c| a.free(c);
        a.free(self.events);
        a.free(self.keccak);
        a.free(self.secp);
        a.free(self.sha256);
        a.free(self.initial);
        a.free(self.terminal);
    }
};
/// Append one packet, then release its tape. A failed append poisons this
/// builder: discard it rather than retrying a partially updated RAM ledger.
pub const Builder = struct {
    allocator: std.mem.Allocator,
    ledger: Old.Ledger,
    shards: std.ArrayList(Shard) = .{},
    failed: bool = false,
    finished: bool = false,
    pub fn init(a: std.mem.Allocator, image: @import("../../word16_execution/memory/statement.zig").Image) Builder {
        return .{ .allocator = a, .ledger = Old.Ledger.init(a, image) };
    }
    pub fn deinit(self: *Builder) void {
        if (!self.finished) for (self.shards.items) |shard| shard.deinit(self.allocator);
        self.shards.deinit(self.allocator);
        self.ledger.deinit();
    }
    pub fn append(self: *Builder, native: *Native, tape: *const front.rv64.compact_tape.Tape) !void {
        if (self.failed or self.finished) return error.InvalidServiceCollectorPhase;
        errdefer self.failed = true;
        if (self.shards.items.len >= 65535) return error.InvalidCombinedServiceRoster;
        try self.shards.ensureUnusedCapacity(self.allocator, 1);
        const shard = try one(self.allocator, &self.ledger, native, tape, self.shards.items.len);
        self.shards.appendAssumeCapacity(shard);
    }
    pub fn finish(self: *Builder) !Advice {
        if (self.failed or self.finished or self.shards.items.len == 0) return error.InvalidServiceCollectorPhase;
        const a = self.allocator;
        // Allocate every output header and both boundaries before transferring
        // any shard arrays. A finish failure remains safely retryable.
        const events = try a.alloc([]LS.native.Event, self.shards.items.len);
        errdefer a.free(events);
        const keccak = try a.alloc([]K.types.Call, self.shards.items.len);
        errdefer a.free(keccak);
        const secp = try a.alloc([2][]S.types.Call, self.shards.items.len);
        errdefer a.free(secp);
        const sha256 = try a.alloc([]S.types.Call, self.shards.items.len);
        errdefer a.free(sha256);
        const boundaries = try self.ledger.boundaries();
        for (self.shards.items, events, keccak, secp, sha256) |shard, *e, *k, *s, *h| {
            e.* = shard.events;
            k.* = shard.keccak;
            s.* = shard.secp;
            h.* = shard.sha256;
        }
        self.finished = true;
        return .{ .allocator = a, .events = events, .keccak = keccak, .secp = secp, .sha256 = sha256, .initial = boundaries.initial, .terminal = boundaries.terminal };
    }
};
pub fn collect(a: std.mem.Allocator, prepared: []const *Native, tapes: []const *const front.rv64.compact_tape.Tape, image: @import("../../word16_execution/memory/statement.zig").Image) !Advice {
    if (prepared.len == 0 or prepared.len != tapes.len or prepared.len > 65535) return error.InvalidCombinedServiceRoster;
    var builder = Builder.init(a, image);
    defer builder.deinit();
    for (prepared, tapes) |native, tape| try builder.append(native, tape);
    return builder.finish();
}
const Shard = struct {
    events: []LS.native.Event,
    keccak: []K.types.Call,
    secp: [2][]S.types.Call,
    sha256: []S.types.Call,
    fn deinit(self: Shard, a: std.mem.Allocator) void {
        a.free(self.events);
        a.free(self.keccak);
        for (self.secp) |calls| a.free(calls);
        a.free(self.sha256);
    }
};
fn one(a: std.mem.Allocator, ledger: *Old.Ledger, native: *Native, tape: *const front.rv64.compact_tape.Tape, index: usize) !Shard {
    const cpu = native.cpu orelse return error.PreparedExecutionConsumed;
    if (cpu.capture_records_retired) return error.MissingPreparedMemoryRecords;
    // v3 is v2 plus SHA-256; a v2 tape can never carry a v3 record.
    const v3 = tape.execution_profile == .ethereum_services_v3;
    if ((tape.execution_profile != .ethereum_services_v2 and !v3) or cpu.epoch != index + 1 or cpu.services.items.len != tape.serviceCount()) return error.InvalidCombinedServiceRoster;
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
    const hh = try a.alloc(S.types.Call, tape.sha256_calls.items.len);
    errdefer a.free(hh);
    var hi: usize = 0;
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
            const before = try get(ledger, address);
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
                for (0..25) |lane| call.predecessors[lane] = try get(ledger, rec.pointer + 8 * lane);
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
                for (0..captured.wordCount()) |lane| call.predecessors[lane] = try get(ledger, rec.pointer + 8 * lane);
                try S.source.validate(S.types.kindOf(captured.kind), call);
                for (0..captured.wordCount()) |lane| ledger.states.getPtr(rec.pointer + 8 * lane).?.* = .{ .value = call.after[lane], .epoch = call.epoch, .tick = call.tick, .rights = call.predecessors[lane].rights };
                const family = @intFromEnum(captured.kind) - 1;
                ss[family][next[family]] = call;
                next[family] += 1;
                si += 1;
            } else if (v3 and rec.tag == 0x30010) {
                if (hi >= hh.len) return error.InvalidCombinedServiceOwner;
                const captured = tape.sha256_calls.items[hi];
                const words = @TypeOf(captured).WORDS;
                if (rec.pointer & 31 != 0 or rec.pointer > std.math.maxInt(u64) - (8 * words - 1)) return error.InvalidCombinedServiceOwner;
                try owner(rec.pointer, rec.tick, tape, captured.pointer, captured.clock);
                var call: S.types.Call = .{ .pointer = rec.pointer, .epoch = cpu.epoch, .tick = rec.tick, .before = @splat(0), .after = @splat(0), .predecessors = @splat(.{ .value = 0, .rights = 0 }) };
                call.before[0..words].* = captured.before;
                call.after[0..words].* = captured.after;
                for (0..words) |lane| call.predecessors[lane] = try get(ledger, rec.pointer + 8 * lane);
                try S.source.validate(.sha256, call);
                for (0..words) |lane| ledger.states.getPtr(rec.pointer + 8 * lane).?.* = .{ .value = call.after[lane], .epoch = call.epoch, .tick = call.tick, .rights = call.predecessors[lane].rights };
                hh[hi] = call;
                hi += 1;
            } else return error.UnqualifiedCombinedServiceTag;
            ci += 1;
        }
    }
    if (ki != kk.len or si != tape.secp_calls.items.len or hi != hh.len) return error.InvalidCombinedServiceRoster;
    return .{ .events = ee, .keccak = kk, .secp = ss, .sha256 = hh };
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
