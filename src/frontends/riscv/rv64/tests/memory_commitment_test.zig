const std = @import("std");
const ram = @import("../air/memory/commitment.zig");
const image = @import("../air/memory/image.zig");
const transition = @import("../air/memory/transition.zig");
const Memory = @import("../memory.zig").Memory;
const a = std.testing.allocator;

fn mapped() !Memory {
    var memory = Memory.init(a, .{});
    errdefer memory.deinit();
    try memory.map(.{ .start = 0x1000, .size = 8192, .permissions = .{ .read = true, .write = true } });
    try memory.store(0x1000, 8, 0x1122334455667788);
    return memory;
}

test "RV64 RAM: page encoding preserves high bytes and mapping permissions" {
    var page: ram.Page = @splat(.{});
    page[0] = .{ .value = 0xffff_ffff_ffff_ffff, .permissions = 0x6db6db };
    const words = try ram.pageWords(&page);
    try std.testing.expectEqual(@as(u32, 65535), words[3].toU32());
    const root = try ram.hashPage(&page, null);
    page[0].value -= 0x7fff_ffff;
    const changed_value = try ram.hashPage(&page, null);
    try std.testing.expect(!ram.equal(root, changed_value));
    page[0].permissions ^= 1;
    try std.testing.expect(!ram.equal(changed_value, try ram.hashPage(&page, null)));
    page[1].value = 1;
    try std.testing.expectError(error.NonzeroUnmappedByte, ram.hashPage(&page, null));
}

test "RV64 RAM: batched pages close against independent final image and reject malicious openings" {
    var memory = try mapped();
    defer memory.deinit();
    const touched = [_]u64{ 1, 2 };
    const updates = [_]transition.NetUpdate{
        .{ .address = 0x1000, .value = 0x11223344556677ff, .byte_mask = 1 },
        .{ .address = 0x2008, .value = 7, .byte_mask = 1 },
    };
    var witness = try transition.Witness.build(a, &memory, &touched, &updates);
    defer witness.deinit();
    var cached = try image.snapshot(a, &memory);
    defer cached.deinit();
    try memory.store(0x1000, 8, updates[0].value);
    try memory.store(0x2008, 8, updates[1].value);
    var final = try image.snapshot(a, &memory);
    defer final.deinit();
    try witness.verifyUpdates(a, witness.before, final.root(), &touched, &updates);
    try std.testing.expectError(error.UnexpectedRamNetUpdate, witness.validateNetUpdates(&.{}));
    try witness.advance(a, &cached, &touched);
    try std.testing.expect(ram.equal(cached.root(), final.root()));
    var next = try transition.Witness.buildFromSnapshot(a, &memory, &cached, &.{1}, &.{});
    defer next.deinit();
    try std.testing.expect(ram.equal(next.before, next.after));
    // Two pages share their ancestor path, rather than opening two full paths.
    try std.testing.expect(witness.sides.len < 2 * ram.PAGE_DEPTH);
    witness.pages[0].before[0].value ^= 1;
    try std.testing.expectError(error.RamBeforeRootMismatch, witness.verify(a, witness.before, final.root(), &touched));
    witness.pages[0].before[0].value ^= 1;
    witness.pages[0].after[0].permissions ^= 1;
    try std.testing.expectError(error.RamPermissionMutation, witness.verify(a, witness.before, final.root(), &touched));
    witness.pages[0].after[0].permissions ^= 1;
    const side = witness.sides[0];
    witness.sides[0].index ^= 1;
    try std.testing.expectError(error.NoncanonicalRamMultiproof, witness.verify(a, witness.before, final.root(), &touched));
    witness.sides[0] = side;
    witness.sides[0].digest[0] ^= 1;
    try std.testing.expectError(error.RamBeforeRootMismatch, witness.verify(a, witness.before, final.root(), &touched));
}

test "RV64 RAM: bad cached patches publish no partial mutations" {
    var memory = try mapped();
    defer memory.deinit();
    var cached = try image.snapshot(a, &memory);
    defer cached.deinit();
    const before = cached.root();
    const page = cached.layers[0].storage[0].digest;
    var changed = page;
    changed[0] ^= 1;
    var wrong = before;
    wrong[0] ^= 1;
    const patches = [_]ram.Patch{
        .{ .height = 0, .index = 1, .before = page, .after = changed },
        .{ .height = ram.PAGE_DEPTH, .index = 0, .before = wrong, .after = wrong },
    };
    try std.testing.expectError(error.RamPatchBeforeMismatch, cached.applyPatch(&patches));
    try std.testing.expect(ram.equal(cached.layers[0].storage[0].digest, page));
    try std.testing.expect(ram.equal(cached.root(), before));
}

test "RV64 RAM: partial mappings, high addresses and native-clock independence" {
    var memory = Memory.init(a, .{});
    defer memory.deinit();
    const high = std.math.maxInt(u64) - 4095;
    try memory.map(.{ .start = high + 3, .size = 4093, .permissions = .{ .read = true, .write = true } });
    try memory.store(high + 4095, 1, 9);
    const page = try image.readPage(&memory, high >> 12);
    try std.testing.expectEqual(@as(u24, 0), page[0].permissions & 0x1ff);
    try std.testing.expectEqual(@as(u64, 9) << 56, page[511].value);
    var witness = try transition.Witness.build(a, &memory, &.{high >> 12}, &.{});
    defer witness.deinit();
    try std.testing.expect(ram.equal(witness.before, witness.after));
    try witness.verify(a, witness.before, witness.after, &.{high >> 12});
    try std.testing.expectError(error.InvalidRamOpeningCoverage, witness.verify(a, witness.before, witness.after, &.{0}));
    try std.testing.expectError(error.RamWriteDenied, transition.Witness.build(a, &memory, &.{high >> 12}, &.{.{ .address = high, .value = 1, .byte_mask = 1 }}));
}

test "RV64 RAM: malformed net updates and explicit defaults fail closed" {
    var memory = try mapped();
    defer memory.deinit();
    try std.testing.expectError(error.NoncanonicalTouchedPages, transition.Witness.build(a, &memory, &.{ 1, 1 }, &.{}));
    try std.testing.expectError(error.UntouchedUpdatePage, transition.Witness.build(a, &memory, &.{1}, &.{.{ .address = 0x2000, .value = 1, .byte_mask = 1 }}));
    try std.testing.expectError(error.NoncanonicalMaskedUpdate, transition.Witness.build(a, &memory, &.{1}, &.{.{ .address = 0x1000, .value = 0, .byte_mask = 1 }}));
    try std.testing.expectError(error.ExplicitDefaultRamCell, ram.Snapshot.init(a, &.{.{ .address = 0, .cell = .{} }}));
}

fn allocationFixture(allocator: std.mem.Allocator, memory: *const Memory, snapshot: *const ram.Snapshot) !void {
    var witness = try transition.Witness.buildFromSnapshot(allocator, memory, snapshot, &.{1}, &.{.{ .address = 0x1000, .value = 0x1122334455667799, .byte_mask = 1 }});
    defer witness.deinit();
    var calls = try witness.recordHashCalls(allocator);
    defer calls.deinit();
}

test "RV64 RAM: batched witness and hash ledger clean every allocation failure" {
    var memory = try mapped();
    defer memory.deinit();
    var snapshot = try image.snapshot(a, &memory);
    defer snapshot.deinit();
    const before = snapshot.root();
    try std.testing.checkAllAllocationFailures(a, allocationFixture, .{ &memory, &snapshot });
    try std.testing.expect(ram.equal(before, snapshot.root()));
}
