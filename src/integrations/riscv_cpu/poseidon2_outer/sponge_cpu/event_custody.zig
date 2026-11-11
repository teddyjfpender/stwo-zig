//! Producer-only LS advice custody; not proof/source authority. Callers own
//! the event slice and must pass its original allocator. No ledger is replayed.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const LS = A.memory.load_store_v2.native;
const Opcode = @import("stwo_riscv_frontend").rv64.decode.Opcode;
const Store = @import("../pure_p2_retained_main.zig").Store;
const Reserved = @import("stwo_prover_engine").file_backed_allocator.ReservedFile;
const Hash = std.crypto.hash.sha2.Sha256;
pub const Event = LS.Event;
pub const record_bytes = 66;
const chunk_events = 64;
pub const Descriptor = struct {
    program: [32]u8,
    boundary: A.word16_execution.types.Boundary,
    epoch: u16,
    ordinal: u32,
    count: usize,
};
/// Every field is encoded explicitly, including both complete RAM states.
/// Opcode enum value is the source decoder's stable tag, never a struct byte.
pub fn encode(event: Event) ![record_bytes]u8 {
    _ = try LS.describe(event.opcode);
    var out: [record_bytes]u8 = undefined;
    var at: usize = 0;
    put(u8, &out, &at, @intFromEnum(event.opcode));
    inline for (.{ "immediate", "a", "b", "c" }) |name| put(u64, &out, &at, @field(event, name));
    put(u16, &out, &at, event.epoch);
    put(u24, &out, &at, event.tick);
    inline for (.{ "before", "after" }) |name| {
        const state = @field(event, name);
        put(u64, &out, &at, state.value);
        put(u16, &out, &at, state.epoch);
        put(u24, &out, &at, state.tick);
        put(u8, &out, &at, state.rights);
    }
    std.debug.assert(at == out.len);
    return out;
}
pub fn decode(bytes: *const [record_bytes]u8) !Event {
    var at: usize = 0;
    const op = try std.meta.intToEnum(Opcode, get(u8, bytes, &at));
    _ = try LS.describe(op);
    var event: Event = undefined;
    event.opcode = op;
    inline for (.{ "immediate", "a", "b", "c" }) |name| @field(event, name) = get(u64, bytes, &at);
    event.epoch = get(u16, bytes, &at);
    event.tick = get(u24, bytes, &at);
    inline for (.{ "before", "after" }) |name| {
        const value = get(u64, bytes, &at);
        const epoch = get(u16, bytes, &at);
        const tick = get(u24, bytes, &at);
        const rights = get(u8, bytes, &at);
        if (rights > 3) return error.OpEventRightsEncoding;
        @field(event, name) = .{ .value = value, .epoch = epoch, .tick = tick, .rights = @intCast(rights) };
    }
    return event;
}
fn put(comptime T: type, bytes: []u8, at: *usize, value: T) void {
    const n = @bitSizeOf(T) / 8;
    std.mem.writeInt(T, bytes[at.*..][0..n], value, .little);
    at.* += n;
}
fn get(comptime T: type, bytes: []const u8, at: *usize) T {
    const n = @bitSizeOf(T) / 8;
    const result = std.mem.readInt(T, bytes[at.*..][0..n], .little);
    at.* += n;
    return result;
}
pub const Token = struct {
    store: *Store,
    file: ?Reserved,
    descriptor: Descriptor,
    digest: [32]u8,
    rounded: usize,
    restored: ?[]Event = null,
    /// Closes only the file/quota; a restored slice always belongs to caller.
    pub fn deinit(self: *Token) void {
        if (self.file) |*file| {
            file.deinit();
            self.store.releaseAdvice(self.rounded);
        }
        self.file = null;
    }
    pub fn restore(self: *Token, a: std.mem.Allocator, descriptor: Descriptor, target: *[]Event) !void {
        const file = self.file orelse return error.OpEventCustodyConsumed;
        if (!std.meta.eql(descriptor, self.descriptor) or target.len != 0 or self.restored != null) return error.OpEventCustodySource;
        if (try file.file.getEndPos() != self.rounded) return error.OpEventCustodyLength;
        const events = try a.alloc(Event, descriptor.count);
        errdefer a.free(events);
        var hash = Hash.init(.{});
        var buffer: [chunk_events * record_bytes]u8 = undefined;
        var pos: usize = 0;
        while (pos < events.len) {
            const count: usize = @min(chunk_events, events.len - pos);
            const bytes = buffer[0 .. count * record_bytes];
            if (try file.file.preadAll(bytes, pos * record_bytes) != bytes.len) return error.OpEventCustodyLength;
            hash.update(bytes);
            for (events[pos..][0..count], 0..) |*event, i| event.* = try decode(bytes[i * record_bytes ..][0..record_bytes]);
            pos += count;
        }
        var digest: [32]u8 = undefined;
        hash.final(&digest);
        if (!std.mem.eql(u8, &digest, &self.digest)) return error.OpEventCustodyIntegrity;
        target.* = events;
        self.restored = events;
    }
    /// After planning, retire the borrowed immutable view and restore later.
    /// After source construction consumes the events, use consumed() instead.
    pub fn retire(self: *Token, a: std.mem.Allocator, target: *[]Event) !void {
        const restored = self.restored orelse return error.OpEventCustodyNotRestored;
        if (self.file == null or target.ptr != restored.ptr or target.len != restored.len) return error.OpEventCustodySource;
        var hash = Hash.init(.{});
        for (target.*) |event| hash.update(&(try encode(event)));
        var digest: [32]u8 = undefined;
        hash.final(&digest);
        if (!std.mem.eql(u8, &digest, &self.digest)) return error.OpEventCustodyMutation;
        a.free(target.*);
        target.* = &.{};
        self.restored = null;
    }
    /// The consumer must have freed/moved the restored allocation and cleared
    /// its owning slice. This only clears our non-owning pointer, never frees.
    pub fn consumed(self: *Token, target: []const Event) !void {
        if (self.restored == null or target.len != 0) return error.OpEventCustodySource;
        self.restored = null;
    }
};
pub fn park(store: *Store, a: std.mem.Allocator, descriptor: Descriptor, events: *[]Event) !Token {
    if (events.len == 0 or events.len != descriptor.count) return error.OpEventCustodyCount;
    const bytes = try std.math.mul(usize, events.len, record_bytes);
    const rounded = try store.reserveAdvice(bytes);
    errdefer store.releaseAdvice(rounded);
    var file = try Reserved.init(store.backing.dir, bytes);
    errdefer file.deinit();
    var hash = Hash.init(.{});
    var buffer: [chunk_events * record_bytes]u8 = undefined;
    var pos: usize = 0;
    while (pos < events.len) {
        const count: usize = @min(chunk_events, events.len - pos);
        for (events.*[pos..][0..count], 0..) |event, i| buffer[i * record_bytes ..][0..record_bytes].* = try encode(event);
        const chunk = buffer[0 .. count * record_bytes];
        hash.update(chunk);
        try file.file.pwriteAll(chunk, pos * record_bytes);
        pos += count;
    }
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    const result = Token{ .store = store, .file = file, .descriptor = descriptor, .digest = digest, .rounded = rounded };
    a.free(events.*);
    events.* = &.{};
    return result;
}

fn sample() Event {
    return .{ .opcode = .SD, .immediate = 0xfffffffffffffff8, .a = 16, .b = 0xfedcba9876543210, .epoch = 65535, .tick = 0xffffff, .before = .{ .value = 0x0123456789abcdef, .epoch = 65534, .tick = 0xfffffe, .rights = 3 }, .after = .{ .value = 0xfedcba9876543210, .epoch = 65535, .tick = 0xffffff, .rights = 3 } };
}
test "OP event custody canonical codec preserves complete values clocks and rejects aliases" {
    const event = sample();
    var bytes = try encode(event);
    try std.testing.expectEqualDeep(event, try decode(&bytes));
    try std.testing.expectEqual(@as(u8, 0xf8), bytes[1]);
    bytes[51] = 4;
    try std.testing.expectError(error.OpEventRightsEncoding, decode(&bytes));
    bytes = try encode(event);
    bytes[0] = 255;
    try std.testing.expectError(error.InvalidEnumTag, decode(&bytes));
    var invalid = event;
    invalid.opcode = .ADD;
    try std.testing.expectError(error.NotLoadStoreOpcode, encode(invalid));
}
fn allocationProbe(a: std.mem.Allocator) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var store = try Store.init(a, path, 1 << 20, 1 << 20);
    defer store.deinit();
    var events = try a.alloc(Event, 65);
    defer a.free(events);
    @memset(events, sample());
    const saved = events[0];
    const descriptor = Descriptor{ .program = @splat(7), .boundary = std.mem.zeroes(A.word16_execution.types.Boundary), .epoch = 65535, .ordinal = 2, .count = events.len };
    var token = try park(&store, a, descriptor, &events);
    defer token.deinit();
    try token.restore(a, descriptor, &events);
    try std.testing.expectEqualDeep(saved, events[64]);
    try token.retire(a, &events);
    try token.restore(a, descriptor, &events);
    a.free(events);
    events = &.{};
    try token.consumed(events);
    token.deinit();
    token.deinit();
    try std.testing.expectEqual(@as(usize, 0), store.reserved);
}
test "OP event custody chunked roundtrip allocation failure atomic" {
    try allocationProbe(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationProbe, .{});
}
test "OP event custody rejects source quota corruption and mutation without losing owner" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var store = try Store.init(a, path, 1 << 20, 1 << 20);
    defer store.deinit();
    var events = try a.alloc(Event, 1);
    defer a.free(events);
    events[0] = sample();
    const descriptor = Descriptor{ .program = @splat(7), .boundary = std.mem.zeroes(A.word16_execution.types.Boundary), .epoch = 65535, .ordinal = 2, .count = 1 };
    store.disk_limit = 1;
    try std.testing.expectError(error.OpParkingDiskLimit, park(&store, a, descriptor, &events));
    try std.testing.expectEqual(@as(usize, 1), events.len);
    store.disk_limit = 1 << 20;
    var token = try park(&store, a, descriptor, &events);
    defer token.deinit();
    var changed = descriptor;
    changed.ordinal += 1;
    try std.testing.expectError(error.OpEventCustodySource, token.restore(a, changed, &events));
    changed = descriptor;
    changed.boundary.final_pc += 4;
    try std.testing.expectError(error.OpEventCustodySource, token.restore(a, changed, &events));
    try std.testing.expectError(error.OutOfMemory, token.restore(std.testing.failing_allocator, descriptor, &events));
    try token.file.?.file.pwriteAll(&.{0}, 1);
    try std.testing.expectError(error.OpEventCustodyIntegrity, token.restore(a, descriptor, &events));
    const original = try encode(sample());
    try token.file.?.file.pwriteAll(&original, 0);
    try token.file.?.file.setEndPos(1);
    try std.testing.expectError(error.OpEventCustodyLength, token.restore(a, descriptor, &events));
    try token.file.?.file.setEndPos(token.rounded);
    try token.file.?.file.pwriteAll(&original, 0);
    try token.restore(a, descriptor, &events);
    events[0].after.value ^= 1;
    try std.testing.expectError(error.OpEventCustodyMutation, token.retire(a, &events));
    events[0].after.value ^= 1;
    try token.retire(a, &events);
    token.deinit();
    try std.testing.expectError(error.OpEventCustodyConsumed, token.restore(a, descriptor, &events));
    try std.testing.expectEqual(@as(usize, 0), store.reserved);
}
