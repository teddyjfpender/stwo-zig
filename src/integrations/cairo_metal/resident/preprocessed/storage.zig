//! Versioned preprocessed-evaluation artifact storage over resident bindings.

const std = @import("std");
const arena_plan = @import("../../../../backends/metal/arena_plan.zig");
const fixed_table_bundle_mod = @import("stwo_cairo_frontend").witness.fixed_table_bundle;
const schedule_bindings = @import("../../schedule_bindings.zig");
const commitment_ordering = @import("../commitment/ordering.zig");
const Error = @import("../errors.zig").Error;

pub fn spillPreprocessedEvaluations(
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    path: []const u8,
) !void {
    const evaluations = try schedule_bindings.collectScheduleOrder(
        allocator,
        schedule,
        plan,
        "PreprocessedEvaluations",
    );
    defer allocator.free(evaluations);
    const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    var buffer: [1 << 20]u8 = undefined;
    var file_writer = file.writer(&buffer);
    const writer = &file_writer.interface;
    try writer.writeAll("STWZPEV\x00");
    try writer.writeInt(u32, 1, .little);
    try writer.writeInt(u32, @intCast(evaluations.len), .little);
    for (evaluations) |binding| {
        try writer.writeInt(u64, binding.size_bytes, .little);
        try writer.writeAll(try resident_arena.bytes(binding));
    }
    try writer.flush();
}

pub fn spillRetainedMerkleLayers(
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    tree_index: u32,
    path: []const u8,
) !void {
    const layers = try commitment_ordering.collectTreePurpose(
        allocator,
        schedule,
        plan,
        "RetainedMerkleLayers",
        tree_index,
    );
    defer allocator.free(layers);
    const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    var buffer: [1 << 20]u8 = undefined;
    var file_writer = file.writer(&buffer);
    const writer = &file_writer.interface;
    try writer.writeAll("STWZMRK\x00");
    try writer.writeInt(u32, 1, .little);
    try writer.writeInt(u32, tree_index, .little);
    try writer.writeInt(u32, @intCast(layers.len), .little);
    for (layers) |binding| {
        try writer.writeInt(u64, binding.size_bytes, .little);
        try writer.writeAll(try resident_arena.bytes(binding));
    }
    try writer.flush();
}

pub fn restoreRetainedMerkleLayers(
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    tree_index: u32,
    path: []const u8,
) !void {
    const layers = try commitment_ordering.collectTreePurpose(
        allocator,
        schedule,
        plan,
        "RetainedMerkleLayers",
        tree_index,
    );
    defer allocator.free(layers);
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    var buffer: [1 << 20]u8 = undefined;
    var file_reader = file.reader(&buffer);
    const reader = &file_reader.interface;
    if (!std.mem.eql(u8, try reader.takeArray(8), "STWZMRK\x00") or
        try reader.takeInt(u32, .little) != 1 or
        try reader.takeInt(u32, .little) != tree_index or
        try reader.takeInt(u32, .little) != layers.len)
        return Error.InvalidSchedule;
    for (layers) |binding| {
        if (try reader.takeInt(u64, .little) != binding.size_bytes) return Error.InvalidBindingSize;
        try reader.readSliceAll(try resident_arena.bytes(binding));
    }
    var trailing: [1]u8 = undefined;
    if (try reader.readSliceShort(&trailing) != 0) return Error.InvalidSchedule;
}

pub fn restorePreprocessedEvaluations(
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    path: []const u8,
) !void {
    const evaluations = try schedule_bindings.collectScheduleOrder(
        allocator,
        schedule,
        plan,
        "PreprocessedEvaluations",
    );
    defer allocator.free(evaluations);
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    var buffer: [1 << 20]u8 = undefined;
    var file_reader = file.reader(&buffer);
    const reader = &file_reader.interface;
    if (!std.mem.eql(u8, try reader.takeArray(8), "STWZPEV\x00") or
        try reader.takeInt(u32, .little) != 1 or
        try reader.takeInt(u32, .little) != evaluations.len)
        return Error.InvalidSchedule;
    for (evaluations) |binding| {
        if (try reader.takeInt(u64, .little) != binding.size_bytes) return Error.InvalidBindingSize;
        try reader.readSliceAll(try resident_arena.bytes(binding));
    }
    var trailing: [1]u8 = undefined;
    if (try reader.readSliceShort(&trailing) != 0) return Error.InvalidSchedule;
}

pub fn restoreFixedTablePreprocessedEvaluations(
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    fixed_bundle: fixed_table_bundle_mod.Bundle,
    path: []const u8,
) !void {
    var wanted = [_]bool{false} ** 161;
    for (fixed_bundle.entries) |entry| {
        const lookups = schedule_bindings.collectComponent(
            allocator,
            schedule,
            plan,
            "LookupInputs",
            entry.component,
        ) catch |err| switch (err) {
            schedule_bindings.Error.MissingBinding => continue,
            else => return err,
        };
        allocator.free(lookups);
        for (entry.preprocessed_sources) |identity| {
            const source_ordinal = fixed_bundle.identityOrdinal(identity) orelse return Error.MissingBinding;
            if (source_ordinal >= wanted.len) return Error.InvalidCardinality;
            wanted[source_ordinal] = true;
        }
    }
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    var buffer: [1 << 20]u8 = undefined;
    var file_reader = file.reader(&buffer);
    const reader = &file_reader.interface;
    var evaluation_count: usize = 0;
    for (schedule) |entry| if (std.mem.eql(u8, try schedule_bindings.purpose(entry), "PreprocessedEvaluations")) {
        evaluation_count += 1;
    };
    if (!std.mem.eql(u8, try reader.takeArray(8), "STWZPEV\x00") or
        try reader.takeInt(u32, .little) != 1 or
        try reader.takeInt(u32, .little) != evaluation_count)
        return Error.InvalidSchedule;
    var seen: usize = 0;
    for (schedule) |entry| {
        if (!std.mem.eql(u8, try schedule_bindings.purpose(entry), "PreprocessedEvaluations")) continue;
        const binding = plan.binding(try schedule_bindings.logicalId(entry)) catch return Error.MissingBinding;
        const size_bytes = try reader.takeInt(u64, .little);
        if (size_bytes != binding.size_bytes) return Error.InvalidBindingSize;
        const source_ordinal = try schedule_bindings.ordinal(entry);
        if (source_ordinal >= wanted.len) return Error.InvalidCardinality;
        if (wanted[source_ordinal])
            try reader.readSliceAll(try resident_arena.bytes(binding))
        else
            try reader.discardAll64(size_bytes);
        seen += 1;
    }
    if (seen != evaluation_count) return Error.InvalidPreprocessedCount;
    var trailing: [1]u8 = undefined;
    if (try reader.readSliceShort(&trailing) != 0) return Error.InvalidSchedule;
}

test "retained Merkle layer storage round trips and rejects trailing data" {
    const schedule_json =
        \\[
        \\ {"purpose":"RetainedMerkleLayers","ordinal":1048576,"id":1},
        \\ {"purpose":"RetainedMerkleLayers","ordinal":1048577,"id":2}
        \\]
    ;
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        schedule_json,
        .{},
    );
    defer parsed.deinit();

    const occupied = [_]u64{0} ** (arena_plan.max_ticks / 64);
    const bindings = [_]arena_plan.Binding{
        .{
            .logical_id = 1,
            .slot = 0,
            .offset_bytes = 0,
            .size_bytes = 4,
            .materialization = .resident,
            .occupied = occupied,
        },
        .{
            .logical_id = 2,
            .slot = 1,
            .offset_bytes = 4,
            .size_bytes = 4,
            .materialization = .resident,
            .occupied = occupied,
        },
    };
    const plan = arena_plan.Plan{
        .allocator = std.testing.allocator,
        .bindings = @constCast(&bindings),
        .slots = &.{},
        .actions = &.{},
        .action_offsets = &.{},
        .total_bytes = 8,
        .peak_live_bytes = 8,
        .plan_hash = 0,
    };
    var words = [_]u32{ 0x10203040, 0xa0b0c0d0 };
    var resident_arena = arena_plan.ResidentArena{ .buffer = .{
        .handle = @ptrCast(&words),
        .contents = @ptrCast(&words),
        .byte_length = @sizeOf(@TypeOf(words)),
    } };
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const directory = try temporary.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(directory);
    const path = try std.fs.path.join(std.testing.allocator, &.{ directory, "layers.bin" });
    defer std.testing.allocator.free(path);

    try spillRetainedMerkleLayers(
        std.testing.allocator,
        &resident_arena,
        parsed.value.array.items,
        plan,
        1,
        path,
    );
    @memset(&words, 0);
    try restoreRetainedMerkleLayers(
        std.testing.allocator,
        &resident_arena,
        parsed.value.array.items,
        plan,
        1,
        path,
    );
    try std.testing.expectEqualSlices(u32, &.{ 0x10203040, 0xa0b0c0d0 }, &words);

    const artifact = try temporary.dir.openFile("layers.bin", .{ .mode = .write_only });
    defer artifact.close();
    try artifact.seekFromEnd(0);
    try artifact.writeAll(&.{0xff});
    try std.testing.expectError(
        Error.InvalidSchedule,
        restoreRetainedMerkleLayers(
            std.testing.allocator,
            &resident_arena,
            parsed.value.array.items,
            plan,
            1,
            path,
        ),
    );
}
