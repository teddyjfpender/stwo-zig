//! Independent native RAM-root authority from the admitted ELF/input loader.
//! This is initialization evidence, not a STARK or a continuation receipt.
const std = @import("std");
const ram = @import("commitment.zig");
const Memory = @import("../../memory.zig").Memory;
const contract = @import("../../ethereum_contract.zig");

pub fn readPage(memory: *const Memory, index: u64) !ram.Page {
    if (index >= @as(u64, 1) << ram.PAGE_DEPTH) return error.InvalidRamPage;
    const start = index << ram.PAGE_BITS;
    const last = start | 4095;
    var page: ram.Page = @splat(.{});
    const backing = memory.backing.table.get(index);
    for (memory.mappings.entries.items) |region| {
        if (region.last < start or region.first > last) continue;
        const permission: u24 = @as(u24, @intFromBool(region.permissions.read)) |
            (@as(u24, @intFromBool(region.permissions.write)) << 1) |
            (@as(u24, @intFromBool(region.permissions.execute)) << 2);
        // A mapping with no accessible rights is outside this explicit policy.
        if (permission == 0) return error.UnsupportedInaccessibleMapping;
        const begin: usize = @intCast(@max(start, region.first) - start);
        const end: usize = @intCast(@min(last, region.last) - start);
        for (begin..end + 1) |offset| {
            const cell = &page[offset / 8];
            cell.permissions |= permission << @intCast(3 * (offset % 8));
            if (backing) |bytes| cell.value |= @as(u64, bytes[offset]) << @intCast(8 * (offset % 8));
        }
    }
    return page;
}

pub fn snapshot(a: std.mem.Allocator, memory: *const Memory) !ram.Snapshot {
    var entries: std.ArrayList(ram.Entry) = .empty;
    defer entries.deinit(a);
    var last_index: ?u64 = null;
    var zeros: [8]?ram.Digest = @splat(null);
    for (memory.mappings.entries.items) |region| {
        var index = region.first >> ram.PAGE_BITS;
        const end = region.last >> ram.PAGE_BITS;
        while (true) {
            if (last_index == null or index != last_index.?) {
                const page = try readPage(memory, index);
                var uniform_zero = true;
                for (page) |cell| if (cell.value != 0 or cell.permissions != page[0].permissions) {
                    uniform_zero = false;
                    break;
                };
                const permission: usize = page[0].permissions & 7;
                uniform_zero = uniform_zero and page[0].permissions == @as(u24, @intCast(permission)) * 0x249249;
                const digest = if (uniform_zero and zeros[permission] != null) zeros[permission].? else blk: {
                    const digest = try ram.hashPage(&page, null);
                    if (uniform_zero) zeros[permission] = digest;
                    break :blk digest;
                };
                try entries.append(a, .{ .index = index, .digest = digest });
                last_index = index;
            }
            if (index == end) break;
            index += 1;
        }
    }
    return ram.Snapshot.fromPages(a, entries.items);
}

pub const Initial = struct {
    root: ram.Digest,
    elf_sha256: [32]u8,
    input_sha256: [32]u8,
    schema_version: u32 = ram.SCHEMA_VERSION,
};

pub fn fromEthereumElf(a: std.mem.Allocator, symbols: contract.Symbols, elf: []const u8, input: []const u8) !Initial {
    var loaded = try contract.load(a, symbols, elf, input);
    defer loaded.deinit();
    var tree = try snapshot(a, &loaded.memory);
    defer tree.deinit();
    var initial = Initial{ .root = tree.root(), .elf_sha256 = undefined, .input_sha256 = undefined };
    std.crypto.hash.sha2.Sha256.hash(elf, &initial.elf_sha256, .{});
    std.crypto.hash.sha2.Sha256.hash(input, &initial.input_sha256, .{});
    return initial;
}
