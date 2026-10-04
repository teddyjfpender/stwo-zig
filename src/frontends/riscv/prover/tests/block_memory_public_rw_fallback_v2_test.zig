const std = @import("std");
const core = @import("stwo_core");
const fallback = @import("../block_memory_public_rw_fallback_v2.zig");
const tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
const replay = @import("../block_memory_replay.zig");
const bus = @import("../block_memory_relation_v2.zig");
const seal_mod = @import("../block_memory_source_seal_v2.zig");
const scoped = @import("../block_memory_initial_range_receiver_v2.zig");
const source_roster = @import("../block_memory_source_roster_v2.zig");

const layout = @import("../../runner/memory_state.zig").MemoryLayout{
    .program_base = 0x1000,
    .program_end = 0x2000,
    .data_base = 0x2000,
    .data_end = 0x4000,
    .stack_bottom = 0x8000,
    .stack_top = 0x9000,
    .io_base = 0xa000,
    .io_end = 0xb000,
    .input_base = 0x3000,
    .input_end = 0x3100,
    .output_len_addr = 0xa000,
    .output_data_addr = 0xa004,
    .output_base = 0xa000,
    .output_end = 0xb000,
};
const Image = struct { address: u32, value: u32 };
const Touch = struct { space: u1, address: u32, value: u32, source: replay.InitialSource };
const image = [_]Image{ .{ .address = 0x2000, .value = 7 }, .{ .address = 0x3000, .value = 9 } };
const touches = [_]Touch{
    .{ .space = 0, .address = 1, .value = 123, .source = .register },
    .{ .space = 1, .address = 0x1000, .value = 55, .source = .program_root },
    .{ .space = 1, .address = 0x2000, .value = 7, .source = .rw_root },
    .{ .space = 1, .address = 0x2004, .value = 0, .source = .rw_root },
    .{ .space = 1, .address = 0x3000, .value = 9, .source = .public_input },
};

fn writeImage(dir: std.fs.Dir, values: []const Image) !void {
    var file = try dir.createFile("image.bin", .{ .truncate = true });
    defer file.close();
    for (values) |item| {
        var record: [8]u8 = undefined;
        std.mem.writeInt(u32, record[0..4], item.address, .little);
        std.mem.writeInt(u32, record[4..8], item.value, .little);
        try file.writeAll(&record);
    }
}
fn writeTouches(dir: std.fs.Dir, values: []const Touch) !void {
    var file = try dir.createFile("touches.bin", .{ .truncate = true });
    defer file.close();
    for (values) |item| {
        var record: [10]u8 = undefined;
        record[0] = item.space;
        std.mem.writeInt(u32, record[1..5], item.address, .little);
        std.mem.writeInt(u32, record[5..9], item.value, .little);
        record[9] = @intFromEnum(item.source);
        try file.writeAll(&record);
    }
}
fn rootFor(values: []const Image) !tree.Digest {
    const leaves = try std.testing.allocator.alloc(tree.Leaf, values.len);
    defer std.testing.allocator.free(leaves);
    for (values, leaves) |item, *leaf| leaf.* = .{ .index = try tree.memoryIndex(item.address), .value = item.value };
    const hasher = tree.TreeHasher.init(.memory);
    return hasher.root(leaves);
}
fn run(dir: std.fs.Dir, expected_root: tree.Digest, image_count: u64, touch_count: u64) !fallback.Result {
    var image_file = try dir.openFile("image.bin", .{});
    defer image_file.close();
    var touch_file = try dir.openFile("touches.bin", .{});
    defer touch_file.close();
    const files = fallback.Files{ .nonzero_image = image_file, .first_touches = touch_file };
    const pin = fallback.Pin{ .initial_rw_root = expected_root, .layout = layout, .image_count = image_count, .first_touch_count = touch_count };
    const roster_digest = try fallback.digestRoster(pin, files);
    const base = @import("../block_commitment_manifest.zig").Sealed{ .digest = @splat(21), .instance_count = 1 };
    const seal = try seal_mod.SourceSeal.initBound(base, 0, roster_digest, 1, 1, @splat(22), @splat(23));
    return fallback.verifyDirectBound(std.testing.allocator, pin, files, seal);
}
fn runMainnet(dir: std.fs.Dir, expected_root: tree.Digest, first_touch_count: u64, registers: [32]u32) !fallback.Result {
    var image_file = try dir.openFile("image.bin", .{});
    defer image_file.close();
    var touch_file = try dir.openFile("touches.bin", .{});
    defer touch_file.close();
    const files = fallback.Files{ .nonzero_image = image_file, .first_touches = touch_file };
    const pin = fallback.Pin{ .initial_rw_root = expected_root, .layout = layout, .image_count = image.len, .first_touch_count = first_touch_count };
    const roster_digest = try fallback.digestRoster(pin, files);
    const base = @import("../block_commitment_manifest.zig").Sealed{ .digest = @splat(21), .instance_count = 1 };
    const seal = try seal_mod.SourceSeal.initBound(base, 0, roster_digest, 1, 1, @splat(22), @splat(23));
    return fallback.verifyMainnetDirectBound(std.testing.allocator, pin, files, seal, registers);
}

fn initialTupleFor(touch: Touch) bus.InitialTuple {
    const t = @import("../../air/block/memory_transition.zig").Transition{ .space = touch.space, .address = touch.address, .clock = 0, .before = touch.value, .after = 0 };
    return bus.initialTuple(t);
}

test "public complete nonzero image authenticates zero and nonzero first touches" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeImage(tmp.dir, &image);
    try writeTouches(tmp.dir, &touches);
    const root = try rootFor(&image);
    const result = try run(tmp.dir, root, image.len, touches.len);
    try std.testing.expectEqual(@as(u64, 5), result.total_first_touches);
    try std.testing.expectEqual(@as(u64, 3), result.rw_first_touches);
    try std.testing.expectEqual(@as(u64, 1), result.rw_zero_first_touches);
    const base = @import("../block_commitment_manifest.zig").Sealed{ .digest = @splat(21), .instance_count = 1 };
    const seal = try seal_mod.SourceSeal.initBound(base, 0, result.roster_digest, 1, 1, @splat(22), @splat(23));
    const challenges = try bus.Challenges.draw(std.testing.allocator, seal);
    var expected = core.fields.qm31.QM31.zero();
    for (touches[2..]) |touch| {
        const t = @import("../../air/block/memory_transition.zig").Transition{ .space = 1, .address = touch.address, .clock = 0, .before = touch.value, .after = 0 };
        expected = expected.add(try challenges.initial.combineBase(bus.initialTuple(t)).inv());
    }
    try std.testing.expect(result.initial_sum.eql(expected));
}

test "public fallback rejects changed roots, values, ordering, source and lengths" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeImage(tmp.dir, &image);
    try writeTouches(tmp.dir, &touches);
    const root = try rootFor(&image);
    var changed_image = image;
    changed_image[0].value = 8;
    try writeImage(tmp.dir, &changed_image);
    try std.testing.expectError(error.PublicInitialRwRootMismatch, run(tmp.dir, root, image.len, touches.len));
    try writeImage(tmp.dir, &image);
    var changed_touches = touches;
    changed_touches[3].value = 7;
    try writeTouches(tmp.dir, &changed_touches);
    try std.testing.expectError(error.PublicFirstTouchValueMismatch, run(tmp.dir, root, image.len, touches.len));
    changed_touches = touches;
    changed_touches[3].address = 0x2000;
    try writeTouches(tmp.dir, &changed_touches);
    try std.testing.expectError(error.DuplicateOrUnsortedPublicFirstTouch, run(tmp.dir, root, image.len, touches.len));
    changed_touches = touches;
    changed_touches[3].source = .program_root;
    try writeTouches(tmp.dir, &changed_touches);
    try std.testing.expectError(error.PublicFirstTouchSourceMismatch, run(tmp.dir, root, image.len, touches.len));
    try writeTouches(tmp.dir, &touches);
    const image_with_hidden_word = [_]Image{
        .{ .address = 0x2000, .value = 7 },
        .{ .address = 0x2004, .value = 11 },
        .{ .address = 0x3000, .value = 9 },
    };
    try writeImage(tmp.dir, &image_with_hidden_word);
    const changed_root = try rootFor(&image_with_hidden_word);
    try std.testing.expectError(error.PublicFirstTouchValueMismatch, run(tmp.dir, changed_root, image_with_hidden_word.len, touches.len));
    try writeImage(tmp.dir, &image);
    try std.testing.expectError(error.InvalidPublicInitialRosterLength, run(tmp.dir, root, image.len, touches.len + 1));
}

test "public fallback rejects a roster changed after source seal" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeImage(tmp.dir, &image);
    try writeTouches(tmp.dir, &touches);
    const root = try rootFor(&image);
    var image_file = try tmp.dir.openFile("image.bin", .{});
    defer image_file.close();
    var touch_file = try tmp.dir.openFile("touches.bin", .{});
    defer touch_file.close();
    const files = fallback.Files{ .nonzero_image = image_file, .first_touches = touch_file };
    const pin = fallback.Pin{ .initial_rw_root = root, .layout = layout, .image_count = image.len, .first_touch_count = touches.len };
    const digest = try fallback.digestRoster(pin, files);
    const base = @import("../block_commitment_manifest.zig").Sealed{ .digest = @splat(21), .instance_count = 1 };
    const seal = try seal_mod.SourceSeal.initBound(base, 0, digest, 1, 1, @splat(22), @splat(23));
    var changed_touches = touches;
    changed_touches[0].value = 124;
    try writeTouches(tmp.dir, &changed_touches);
    try std.testing.expectError(error.UnboundPublicInitialRoster, fallback.verifyDirectBound(std.testing.allocator, pin, files, seal));
}

test "mainnet scoped fallback checks registers and rejects program first touches" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeImage(tmp.dir, &image);
    const mainnet_touches = [_]Touch{ touches[0], touches[2], touches[3], touches[4] };
    try writeTouches(tmp.dir, &mainnet_touches);
    const root = try rootFor(&image);
    var registers: [32]u32 = @splat(0);
    registers[1] = 123;
    const result = try runMainnet(tmp.dir, root, mainnet_touches.len, registers);
    try std.testing.expectEqual(@as(u64, 1), result.register_first_touches);
    try std.testing.expectEqual(@as(u64, 3), result.rw_first_touches);
    const base = @import("../block_commitment_manifest.zig").Sealed{ .digest = @splat(21), .instance_count = 1 };
    const seal = try seal_mod.SourceSeal.initBound(base, 0, result.roster_digest, 1, 1, @splat(22), @splat(23));
    const challenges = try bus.Challenges.draw(std.testing.allocator, seal);
    const register_expected = try challenges.initial.combineBase(initialTupleFor(mainnet_touches[0])).inv();
    try std.testing.expect(result.register_sum.eql(register_expected));
    var changed = mainnet_touches;
    changed[0].value = 124;
    try writeTouches(tmp.dir, &changed);
    try std.testing.expectError(error.PublicInitialRegisterValueMismatch, runMainnet(tmp.dir, root, changed.len, registers));
    changed = mainnet_touches;
    changed[0].address = 32;
    try writeTouches(tmp.dir, &changed);
    try std.testing.expectError(error.InvalidPublicFirstTouchAddress, runMainnet(tmp.dir, root, changed.len, registers));
    try writeTouches(tmp.dir, &touches);
    try std.testing.expectError(error.ProgramFirstTouchNeedsAuthenticatedProvider, runMainnet(tmp.dir, root, touches.len, registers));
}

test "scoped initial closure rejects omitted and extra first touches" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeImage(tmp.dir, &image);
    const actual = [_]Touch{ touches[0], touches[2], touches[3], touches[4] };
    const root = try rootFor(&image);
    var registers: [32]u32 = @splat(0);
    registers[1] = 123;
    try writeTouches(tmp.dir, &actual);
    const honest = try runMainnet(tmp.dir, root, actual.len, registers);
    const base = @import("../block_commitment_manifest.zig").Sealed{ .digest = @splat(21), .instance_count = 1 };
    const honest_seal = try seal_mod.SourceSeal.initBound(base, 0, honest.roster_digest, 1, 1, @splat(22), @splat(23));
    const honest_challenges = try bus.Challenges.draw(std.testing.allocator, honest_seal);
    var honest_sorted_sum = core.fields.qm31.QM31.zero();
    for (actual) |touch| honest_sorted_sum = honest_sorted_sum.sub(try honest_challenges.initial.combineBase(initialTupleFor(touch)).inv());
    try scoped.checkInitialClosure(honest_sorted_sum, honest.initial_sum, honest.register_sum);

    const omitted = actual[1..];
    try writeTouches(tmp.dir, omitted);
    const omitted_result = try runMainnet(tmp.dir, root, omitted.len, registers);
    const omitted_seal = try seal_mod.SourceSeal.initBound(base, 0, omitted_result.roster_digest, 1, 1, @splat(22), @splat(23));
    const omitted_challenges = try bus.Challenges.draw(std.testing.allocator, omitted_seal);
    var sorted_sum = core.fields.qm31.QM31.zero();
    for (actual) |touch| sorted_sum = sorted_sum.sub(try omitted_challenges.initial.combineBase(initialTupleFor(touch)).inv());
    try std.testing.expectError(error.UnclosedInitialMemoryRelation, scoped.checkInitialClosure(sorted_sum, omitted_result.initial_sum, omitted_result.register_sum));

    const extra = [_]Touch{ actual[0], .{ .space = 0, .address = 2, .value = 0, .source = .register }, actual[1], actual[2], actual[3] };
    try writeTouches(tmp.dir, &extra);
    const extra_result = try runMainnet(tmp.dir, root, extra.len, registers);
    const extra_seal = try seal_mod.SourceSeal.initBound(base, 0, extra_result.roster_digest, 1, 1, @splat(22), @splat(23));
    const extra_challenges = try bus.Challenges.draw(std.testing.allocator, extra_seal);
    sorted_sum = core.fields.qm31.QM31.zero();
    for (actual) |touch| sorted_sum = sorted_sum.sub(try extra_challenges.initial.combineBase(initialTupleFor(touch)).inv());
    try std.testing.expectError(error.UnclosedInitialMemoryRelation, scoped.checkInitialClosure(sorted_sum, extra_result.initial_sum, extra_result.register_sum));
    try std.testing.expectError(error.UnclosedInitialMemoryRelation, scoped.checkInitialClosure(honest_sorted_sum.add(core.fields.qm31.QM31.one()), honest.initial_sum, honest.register_sum));
}

test "mainnet fallback is included in an exact sealed source aggregate" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeImage(tmp.dir, &image);
    const mainnet_touches = [_]Touch{ touches[0], touches[2], touches[3], touches[4] };
    try writeTouches(tmp.dir, &mainnet_touches);
    var image_file = try tmp.dir.openFile("image.bin", .{});
    defer image_file.close();
    var touch_file = try tmp.dir.openFile("touches.bin", .{});
    defer touch_file.close();
    const files = fallback.Files{ .nonzero_image = image_file, .first_touches = touch_file };
    const pin = fallback.Pin{ .initial_rw_root = try rootFor(&image), .layout = layout, .image_count = image.len, .first_touch_count = mainnet_touches.len };
    const rw_digest = try fallback.digestRoster(pin, files);
    var entries = [_]source_roster.Entry{
        .{ .family = .public_rw_fallback, .index = 0, .digest = rw_digest },
        .{ .family = .program, .index = 0, .digest = @splat(70) },
        .{ .family = .hash, .index = 0, .digest = @splat(71) },
    };
    const aggregate = try source_roster.digest(&entries);
    const base = @import("../block_commitment_manifest.zig").Sealed{ .digest = @splat(21), .instance_count = 1 };
    const seal = try seal_mod.SourceSeal.initBound(base, 0, aggregate, 1, 1, @splat(22), @splat(23));
    var registers: [32]u32 = @splat(0);
    registers[1] = 123;
    try source_roster.admitExpected(&entries, &.{@splat(70)}, &.{@splat(71)});
    const result = try fallback.verifyMainnetAggregated(std.testing.allocator, pin, files, seal, registers, &entries);
    try std.testing.expectEqual(@as(u64, 4), result.total_first_touches);
    entries[1].digest[0] ^= 1;
    try std.testing.expectError(error.UnboundBlockSourceRoster, fallback.verifyMainnetAggregated(std.testing.allocator, pin, files, seal, registers, &entries));
    entries[1].digest[0] ^= 1;
    entries[0].digest[0] ^= 1;
    try std.testing.expectError(error.UnboundPublicInitialRoster, fallback.verifyMainnetAggregated(std.testing.allocator, pin, files, seal, registers, &entries));
}
