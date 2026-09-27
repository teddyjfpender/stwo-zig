//! Persist only transport metadata from a closed staged block-v4 producer.
//! The resulting bundle has no proof authority without independent final
//! policy pins and fresh file-backed verification.
const std = @import("std");
const transport = @import("block_v4_cpu_bundle_manifest_v1.zig");
const product_mod = @import("block_v4_cpu_streaming_produce.zig");
const leaf_stage = @import("block_v4_cpu_incremental_leaf_stage.zig");
const forest_stage = @import("block_v4_cpu_incremental_forest_stage.zig");
const outer_stage = @import("block_v4_cpu_incremental_outer_stage.zig");

/// `product` must be `rebind.Provisional.product` after
/// `finalizeCompletePins`; the candidate producer Product still carries
/// provisional outer/forest pins and is deliberately rejected here.
pub fn write(
    a: std.mem.Allocator,
    dir: std.fs.Dir,
    product: product_mod.Product,
    leaves: *const leaf_stage.Capture,
    forest: *const forest_stage.Stage,
    outer: *const outer_stage.Stage,
    candidate_manifest_sha256: transport.Digest,
    final_manifest_sha256: transport.Digest,
) !transport.Digest {
    if (leaves.next != product.first.entries.len or
        product.executions.next != product.first.entries.len or
        product.memories.next_memory != product.memories.memory.len or
        product.memories.next_table != product.memories.tables.len or
        !std.meta.eql(forest.digest, outer.forest_digest))
        return error.IncompleteBlockV4BundleSnapshot;
    try requireFinalPins(product.statement.complete_pins, forest.digest, outer.admission.expected_id);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const scratch = arena.allocator();
    const opcode_tables = try snapshotTables(scratch, dir, product.opcode_tables.wires, .opcode_table);
    const external_tables = if (product.external_tables) |tables|
        try snapshotTables(scratch, dir, tables.wires, .external_table)
    else
        &.{};
    const leaf_pins = try scratch.alloc(transport.LeafPin, leaves.entries.len);
    for (leaves.entries, leaf_pins) |entry, *pin| pin.* = .{
        .file = .{ .len = entry.byte_len, .sha256 = entry.sha256 },
        .admission = entry.admission,
        .descriptor = entry.descriptor,
    };
    const parent_pins = try scratch.alloc(transport.ParentPin, forest.parents.len);
    for (forest.parents, parent_pins) |entry, *pin| pin.* = .{
        .file = .{ .len = entry.byte_len, .sha256 = entry.sha256 },
        .statement = entry.statement,
        .admission = entry.admission,
        .left = entry.left,
        .right = entry.right,
    };
    const roots = try scratch.alloc(transport.RootPin, forest.roots.len);
    for (forest.roots, roots) |root, *pin| pin.* = .{
        .statement = root.statement,
        .admission = root.admission,
        .parent_file = switch (root.file) { .parent => true, .leaf => false },
        .file_index = switch (root.file) { .parent => |index| @intCast(index), .leaf => |index| index },
    };
    return transport.write(scratch, dir, .{
        .version = transport.VERSION,
        .candidate_manifest_sha256 = candidate_manifest_sha256,
        .final_manifest_sha256 = final_manifest_sha256,
        .statement = product.statement,
        .first_entries = product.first.entries,
        .event_count = product.first.event_count,
        .opcode_events = product.first.opcode_events,
        .external_events = product.first.external_events,
        .public_pin = product.public.pin,
        .public_registers = product.public.registers,
        .public_entries = product.public.entries,
        .public_image = try pinOpenFile(&product.public.image),
        .public_touches = try pinOpenFile(&product.public.touches),
        .memories = product.memories.memory,
        .memory_tables = product.memories.tables,
        .executions = product.executions.entries,
        .opcode_tables = opcode_tables,
        .external_tables = external_tables,
        .leaves = leaf_pins,
        .parents = parent_pins,
        .roots = roots,
        .outer = .{
            .file = .{ .len = outer.byte_len, .sha256 = outer.sha256 },
            .statement = outer.statement,
            .admission = outer.admission,
            .forest_digest = outer.forest_digest,
        },
    });
}

fn requireFinalPins(pins: ?@import("block_memory_batch_statement_v2.zig").CompletePins, forest_digest: transport.Digest, outer_key_id: transport.Digest) !void {
    const value = pins orelse return error.UnfinalizedBlockV4BundlePins;
    if (!std.meta.eql(value.forest_roster_digest, forest_digest) or
        !std.meta.eql(value.outer_recursive_key_id, outer_key_id))
        return error.UnfinalizedBlockV4BundlePins;
}

fn snapshotTables(a: std.mem.Allocator, dir: std.fs.Dir, wires: []const @import("block_memory_batch_verify_v2.zig").SerializedTableProof, kind: std.meta.Tag(transport.Locator)) ![]transport.TablePin {
    const pins = try a.alloc(transport.TablePin, wires.len);
    for (wires, pins, 0..) |wire, *pin, index| {
        const locator: transport.Locator = switch (kind) {
            .opcode_table => .{ .opcode_table = @intCast(index) },
            .external_table => .{ .external_table = @intCast(index) },
            else => unreachable,
        };
        const file_pin = try writePinnedBytes(dir, locator, wire.stark_bytes);
        pin.* = .{ .file = file_pin, .claim = wire.claim };
    }
    return pins;
}

fn writePinnedBytes(dir: std.fs.Dir, locator: transport.Locator, bytes: []const u8) !transport.FilePin {
    if (bytes.len == 0 or bytes.len > transport.MAX_FILE_BYTES)
        return error.InvalidBlockV4BundleFilePin;
    var buffer: [96]u8 = undefined;
    const name = try transport.fileName(locator, &buffer);
    var file = try dir.createFile(name, .{ .exclusive = true });
    defer file.close();
    errdefer dir.deleteFile(name) catch {};
    try file.writeAll(bytes);
    try file.sync();
    return .{ .len = bytes.len, .sha256 = transport.sha(bytes) };
}

fn pinOpenFile(file: *const std.fs.File) !transport.FilePin {
    const len = try file.getEndPos();
    if (len > transport.MAX_FILE_BYTES) return error.InvalidBlockV4BundleFilePin;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var chunk: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < len) {
        const take: usize = @intCast(@min(chunk.len, len - offset));
        if (try file.preadAll(chunk[0..take], offset) != take)
            return error.TruncatedBlockV4BundlePublicFile;
        hasher.update(chunk[0..take]);
        offset += take;
    }
    return .{ .len = len, .sha256 = hasher.finalResult() };
}

test "bundle snapshot rejects an incomplete staged leaf roster" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var first: @import("block_v4_cpu_streaming_first_round.zig").FirstRound = undefined;
    first.entries = &.{};
    var leaves: leaf_stage.Capture = undefined;
    leaves.next = 1;
    const product = product_mod.Product{
        .statement = undefined,
        .source = undefined,
        .first = &first,
        .public = undefined,
        .memories = undefined,
        .opcode_tables = undefined,
        .external_tables = null,
        .executions = undefined,
        .elapsed_ns = 0,
    };
    try std.testing.expectError(error.IncompleteBlockV4BundleSnapshot,
        write(a, tmp.dir, product, &leaves, undefined, undefined, @splat(1), @splat(2)));
}

test "bundle snapshot requires rebound final forest and outer pins" {
    try std.testing.expectError(error.UnfinalizedBlockV4BundlePins, requireFinalPins(null, @splat(1), @splat(2)));
    const pins = @import("block_memory_batch_statement_v2.zig").CompletePins{
        .expected_job = undefined,
        .initial_rw_anchor = @splat(0),
        .program_root = @splat(0),
        .outer_recursive_key_id = @splat(2),
        .forest_roster_digest = @splat(1),
    };
    try requireFinalPins(pins, @splat(1), @splat(2));
    try std.testing.expectError(error.UnfinalizedBlockV4BundlePins, requireFinalPins(pins, @splat(3), @splat(2)));
}
