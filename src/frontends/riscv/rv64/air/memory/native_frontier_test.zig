const std = @import("std");
const core = @import("stwo_core");
const Native = @import("native_frontier.zig");
const values = @import("values.zig");
const batch = @import("batch.zig");
const openings = @import("openings.zig");
const Policy = @import("policy.zig").Policy;
const Memory = @import("../../memory.zig").Memory;
const Trace = @import("private_trace.zig").Trace;
const a = std.testing.allocator;
pub const Fixture = struct {
    memory: Memory,
    mappings: Policy,
    owned: openings.Owned,
    cache: values.Cache,
    memory_alive: bool = true,
    cache_alive: bool = true,
    pub fn init(g: values.Geometry) !Fixture {
        var memory = Memory.init(a, .{});
        errdefer memory.deinit();
        var initial = Memory.init(a, .{});
        defer initial.deinit();
        const base = 0x100001000;
        const high = std.math.maxInt(u64) - g.bytes() + 1;
        for ([_]*Memory{ &memory, &initial }) |m| {
            try m.map(.{ .start = base, .size = 2 * g.bytes(), .permissions = .{ .read = true, .write = true } });
            try m.map(.{ .start = high, .size = g.bytes(), .permissions = .{ .read = true, .write = true } });
        }
        const cells = [_]openings.Cell{
            .{ .address = base, .initial = 0, .final = 9, .terminal_clock = 4, .rights = 3 },
            .{ .address = base + 8, .initial = 7, .final = 7, .terminal_clock = 8, .rights = 3 },
            .{ .address = base + g.bytes() + 16, .initial = 13, .final = 0, .terminal_clock = 12, .rights = 3 },
            .{ .address = high + 24, .initial = std.math.maxInt(u64), .final = 31, .terminal_clock = (1 << 24) - 4, .rights = 3 },
        };
        for (cells) |cell| {
            try word(&initial, cell.address, cell.initial);
            try word(&memory, cell.address, cell.final);
        }
        var mappings = try Policy.fromMemory(a, &memory);
        errdefer mappings.deinit();
        var cache = try values.Cache.fromMemory(a, g, &initial);
        errdefer cache.deinit();
        const owned = try openings.Owned.init(a, g, &mappings, &memory, &cells);
        return .{ .memory = memory, .mappings = mappings, .owned = owned, .cache = cache };
    }
    pub fn deinit(self: *Fixture) void {
        if (self.memory_alive) self.memory.deinit();
        self.mappings.deinit();
        self.owned.deinit();
        if (self.cache_alive) self.cache.deinit();
    }
};
fn word(memory: *Memory, address: u64, value: u64) !void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .little);
    try memory.initialize(address, &bytes);
}
const Receipt = struct {
    cache: *const values.Cache,
    calls: usize = 0,
    fail: bool = false,
    fn persist(context: ?*anyopaque, prepared: *const Native.Prepared) !void {
        const self: *Receipt = @ptrCast(@alignCast(context.?));
        self.calls += 1;
        try std.testing.expectEqual(Native.Phase.prepared, prepared.phase);
        try std.testing.expect(values.equal(self.cache.root(), prepared.view().before));
        try std.testing.expectEqual(try prepared.counts.permutations(prepared.witness.geometry), prepared.view().io.len);
        if (self.fail) return error.InjectedDurableHandoffFailure;
    }
    fn value(self: *Receipt) Native.Handoff {
        return .{ .context = self, .persist = persist };
    }
};
test "native RAM frontier equals qualified wide witness for both geometries and full address range" {
    for ([_]values.Geometry{ .chunk512, .page4096 }) |g| {
        var f = try Fixture.init(g);
        defer f.deinit();
        var accounting = std.testing.FailingAllocator.init(a, .{});
        var native = try Native.Prepared.init(accounting.allocator(), &f.cache, &f.owned);
        defer native.deinit();
        const before = f.cache.root();
        const owned_bytes = native.io.len * @sizeOf(values.PermutationIO) + native.witness.leaves.len * @sizeOf(batch.Leaf) + (native.witness.before_nodes.len + native.witness.after_nodes.len) * @sizeOf(batch.Node) + native.witness.sides.len * @sizeOf(@import("graph_model.zig").Side) + native.witness.patches.len * @sizeOf(values.Patch);
        try std.testing.expectEqual(owned_bytes, native.ownedBytes());
        try std.testing.expectEqual(owned_bytes, accounting.allocated_bytes - accounting.freed_bytes);
        var reference = try Trace.initOwned(a, &f.cache, &f.mappings, &f.owned);
        defer reference.deinit();
        try std.testing.expectEqualDeep(reference.witness.before, native.witness.before);
        try std.testing.expectEqualDeep(reference.witness.after, native.witness.after);
        try std.testing.expectEqualDeep(reference.witness.leaves, native.witness.leaves);
        try std.testing.expectEqualDeep(reference.witness.before_nodes, native.witness.before_nodes);
        try std.testing.expectEqualDeep(reference.witness.after_nodes, native.witness.after_nodes);
        try std.testing.expectEqualDeep(reference.witness.sides, native.witness.sides);
        try std.testing.expectEqualDeep(reference.witness.patches, native.witness.patches);
        try std.testing.expectEqualDeep(reference.recorder.calls.items, native.io);
        try std.testing.expect(owned_bytes < reference.provider.len * @sizeOf(core.fields.m31.M31));
        try std.testing.expect(values.equal(before, f.cache.root()));
        var receipt = Receipt{ .cache = &f.cache, .fail = true };
        try std.testing.expectError(error.InvalidNativeFrontierPhase, native.finishPublish(&f.cache));
        try std.testing.expectError(error.InjectedDurableHandoffFailure, native.handoffAndPublish(&f.cache, receipt.value()));
        try std.testing.expectEqual(Native.Phase.prepared, native.phase);
        try std.testing.expect(values.equal(before, f.cache.root()));
        receipt.fail = false;
        try native.handoffAndPublish(&f.cache, receipt.value());
        try std.testing.expectEqual(Native.Phase.published, native.phase);
        var expected = try values.Cache.fromMemory(a, g, &f.memory);
        defer expected.deinit();
        try std.testing.expect(values.equal(expected.root(), f.cache.root()));
        try std.testing.expectEqual(@as(usize, 2), receipt.calls);
        try std.testing.expectError(error.InvalidNativeFrontierPhase, native.handoffAndPublish(&f.cache, receipt.value()));
    }
}

test "native RAM frontier rejects orphan coverage IO aliases patches and stale cache before handoff" {
    var f = try Fixture.init(.chunk512);
    defer f.deinit();
    var native = try Native.Prepared.init(a, &f.cache, &f.owned);
    defer native.deinit();
    const first = native.witness.leaves[0].before_io;
    native.witness.leaves[0].before_io = std.math.maxInt(u32);
    try std.testing.expectError(error.InvalidNativeFrontier, native.validate());
    native.witness.leaves[0].before_io = first;
    native.witness.patches[0].after[0] ^= 1;
    try std.testing.expectError(error.InvalidNativeFrontierPatch, native.validate());
    native.witness.patches[0].after[0] ^= 1;
    const io = native.witness.before_nodes[0].io;
    native.io[io].input[15] = native.io[io].input[15].add(core.fields.m31.M31.one());
    try std.testing.expectError(error.InvalidNativeFrontierIO, native.validate());
    native.io[io].input[15] = native.io[io].input[15].sub(core.fields.m31.M31.one());
    const old = native.witness.sides;
    const extra = try a.alloc(@import("graph_model.zig").Side, old.len + 1);
    defer a.free(extra);
    @memcpy(extra[0..old.len], old);
    extra[old.len] = old[0];
    native.witness.sides = extra;
    native.counts.sides += 1;
    try std.testing.expectError(error.UnbalancedRamGraph, native.validate());
    native.witness.sides = old;
    native.counts.sides -= 1;
    try native.validate();
    var stale = try values.Cache.empty(a, .chunk512);
    defer stale.deinit();
    var receipt = Receipt{ .cache = &stale };
    try std.testing.expectError(error.PrivateRamBeforeRootMismatch, native.handoffAndPublish(&stale, receipt.value()));
    try std.testing.expectEqual(@as(usize, 0), receipt.calls);
}

fn constructionFailure(allocator: std.mem.Allocator, cache: *const values.Cache, owned: *const openings.Owned) !void {
    var native = try Native.Prepared.init(allocator, cache, owned);
    defer native.deinit();
}
test "native RAM frontier construction allocation failures preserve cache and opening ownership" {
    var f = try Fixture.init(.chunk512);
    defer f.deinit();
    const root = f.cache.root();
    const pointer = f.owned.words.ptr;
    try std.testing.checkAllAllocationFailures(a, constructionFailure, .{ &f.cache, &f.owned });
    try std.testing.expect(values.equal(root, f.cache.root()));
    try std.testing.expect(pointer == f.owned.words.ptr);
}
fn publicationFailure(allocator: std.mem.Allocator, owned: *const openings.Owned) !void {
    var cache = try values.Cache.empty(allocator, .chunk512);
    defer cache.deinit();
    var native = try Native.Prepared.init(a, &cache, owned);
    defer native.deinit();
    const root = cache.root();
    var receipt = Receipt{ .cache = &cache };
    native.handoffAndPublish(&cache, receipt.value()) catch |err| {
        try std.testing.expectEqual(@as(usize, 1), receipt.calls);
        try std.testing.expectEqual(Native.Phase.durable, native.phase);
        try std.testing.expect(values.equal(root, cache.root()));
        try std.testing.expectEqual(@as(usize, 0), cache.count());
        return err;
    };
}
test "native RAM frontier durable handoff survives publication OOM without repeat or partial patch" {
    const before: [64]u64 = @splat(0);
    var after = before;
    after[0] = 9;
    var clocks: [64]u32 = @splat(0);
    clocks[0] = 4;
    const rights: [64]u2 = @splat(3);
    var owned = try openings.Owned.copy(a, .chunk512, &.{.{ .index = 1, .before = &before, .after = &after, .terminal_clocks = &clocks, .rights = &rights }});
    defer owned.deinit();
    try std.testing.checkAllAllocationFailures(a, publicationFailure, .{&owned});
    var fail = std.testing.FailingAllocator.init(a, .{});
    var cache = try values.Cache.empty(fail.allocator(), .chunk512);
    defer cache.deinit();
    var native = try Native.Prepared.init(a, &cache, &owned);
    defer native.deinit();
    var receipt = Receipt{ .cache = &cache };
    fail.fail_index = fail.alloc_index;
    try std.testing.expectError(error.OutOfMemory, native.handoffAndPublish(&cache, receipt.value()));
    fail.fail_index = std.math.maxInt(usize);
    try native.handoffAndPublish(&cache, receipt.value());
    try std.testing.expectEqual(@as(usize, 1), receipt.calls);
    try std.testing.expectEqual(Native.Phase.published, native.phase);
    try std.testing.expect(values.equal(native.witness.after, cache.root()));
}

test "native RAM read-only frontier reuses the before root and cannot publish an empty capture" {
    var f = try Fixture.init(.chunk512);
    defer f.deinit();
    for (f.owned.chunks) |chunk| @memcpy(@constCast(chunk.after), chunk.before);
    var native = try Native.Prepared.init(a, &f.cache, &f.owned);
    defer native.deinit();
    try std.testing.expectEqual(@as(usize, 0), native.counts.changed_leaves);
    try std.testing.expectEqual(@as(usize, 0), native.witness.after_nodes.len);
    try std.testing.expectEqual(@as(usize, 0), native.witness.patches.len);
    try std.testing.expect(values.equal(native.witness.before, native.witness.after));
    var receipt = Receipt{ .cache = &f.cache };
    try native.handoffAndPublish(&f.cache, receipt.value());
    try std.testing.expect(values.equal(native.witness.before, f.cache.root()));
    var empty = try openings.Owned.copy(a, .chunk512, &.{});
    defer empty.deinit();
    try std.testing.expectError(error.InvalidPrivateRamBatch, Native.Prepared.init(a, &f.cache, &empty));
}
