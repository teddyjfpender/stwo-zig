//! Private native boundary/opening records. Each touched word is32 wire bytes;
//! opening descriptors are reconstructed as views into one owned flat payload.
const std = @import("std");
const F = @import("rv64_ethereum_batch.zig");
const CPU = @import("rv64_keccak_cpu.zig");
const rv = @import("stwo_riscv_frontend").rv64;
const R = @import("stwo_riscv_frontend").rv64_air.memory;
const IO = @import("rv64_work_packet_io.zig");
const Public = @import("rv64_work_packet_public.zig");
pub fn write(writer: *IO.Writer, finished: *const F.Finished) !void {
    try writer.bytes(&(try Public.encode(finished.public)));
    for (finished.cells, finished.memory_clocks) |cell, clock| {
        try writer.int(u64, cell.address);
        try writer.int(u64, cell.initial);
        try writer.int(u64, cell.final);
        try writer.int(u32, clock);
        try writer.int(u8, @as(u8, @intFromBool(cell.readable)) | (@as(u8, @intFromBool(cell.writable)) << 1));
        try writer.bytes(&.{ 0, 0, 0 });
    }
    if (finished.openings) |*owned| {
        for (owned.chunks) |chunk| try writer.int(u64, chunk.index);
        for (owned.words) |word| try writer.int(u64, word);
        for (owned.clocks) |clock| try writer.int(u32, clock);
        for (owned.rights) |rights| try writer.int(u8, rights);
    }
}
pub fn read(a: std.mem.Allocator, reader: *IO.Reader, public: CPU.Public, cell_count: u32, chunk_count: u32) !F.Finished {
    const captured = try a.alloc(rv.boundary_capture.Cell, cell_count);
    errdefer a.free(captured);
    const cells = try a.alloc(@import("rv64_full_statement.zig").Cell, cell_count);
    errdefer a.free(cells);
    const clocks = try a.alloc(u32, cell_count);
    errdefer a.free(clocks);
    for (captured, cells, clocks) |*native, *cell, *clock| {
        const address = try reader.int(u64);
        const initial = try reader.int(u64);
        const final = try reader.int(u64);
        clock.* = try reader.int(u32);
        const rights = try reader.int(u8);
        var reserved: [3]u8 = undefined;
        try reader.bytes(&reserved);
        if (rights == 0 or rights > 3 or !std.mem.allEqual(u8, &reserved, 0)) return error.InvalidWorkPacketCell;
        native.* = .{ .address = address, .initial = initial, .final = final, .terminal_clock = clock.*, .rights = @intCast(rights) };
        cell.* = .{ .address = address, .initial = initial, .final = final, .readable = rights & 1 != 0, .writable = rights & 2 != 0 };
    }
    const openings = if (chunk_count == 0) null else try readOpenings(a, reader, chunk_count);
    return .{ .allocator = a, .public = public, .captured = captured, .cells = cells, .memory_clocks = clocks, .openings = openings };
}
fn readOpenings(a: std.mem.Allocator, reader: *IO.Reader, count: u32) !R.openings.Owned {
    const chunks = try a.alloc(R.batch.Opening, count);
    errdefer a.free(chunks);
    const n = try std.math.mul(usize, count, 64);
    const words = try a.alloc(u64, try std.math.mul(usize, n, 2));
    errdefer a.free(words);
    const clocks = try a.alloc(u32, n);
    errdefer a.free(clocks);
    const rights = try a.alloc(u2, n);
    errdefer a.free(rights);
    for (chunks, 0..) |*chunk, i| chunk.* = .{ .index = try reader.int(u64), .before = words[64 * i ..][0..64], .after = words[n + 64 * i ..][0..64], .terminal_clocks = clocks[64 * i ..][0..64], .rights = rights[64 * i ..][0..64] };
    for (words) |*word| word.* = try reader.int(u64);
    for (clocks) |*clock| clock.* = try reader.int(u32);
    for (rights) |*right| {
        const value = try reader.int(u8);
        if (value > 3) return error.InvalidWorkPacketRights;
        right.* = @intCast(value);
    }
    return .{ .allocator = a, .chunks = chunks, .words = words, .clocks = clocks, .rights = rights };
}
pub fn validate(finished: *const F.Finished) !void {
    const cells = finished.cells;
    if (cells.len != finished.captured.len or cells.len != finished.memory_clocks.len or (cells.len == 0) != (finished.openings == null)) return error.InvalidWorkPacketCell;
    const limit = @as(u64, finished.public.statement.steps) * 4;
    for (cells, finished.captured, finished.memory_clocks, 0..) |cell, native, clock, i| {
        const rights: u2 = @as(u2, @intFromBool(cell.readable)) | (@as(u2, @intFromBool(cell.writable)) << 1);
        if (cell.address & 7 != 0 or rights == 0 or clock == 0 or clock & 3 != 0 or clock > limit or (i != 0 and cells[i - 1].address >= cell.address) or native.address != cell.address or native.initial != cell.initial or native.final != cell.final or native.terminal_clock != clock or native.rights != rights) return error.InvalidWorkPacketCell;
    }
    const owned = if (finished.openings) |*value| value else return;
    const n = try std.math.mul(usize, owned.chunks.len, 64);
    if (owned.words.len != try std.math.mul(usize, n, 2) or owned.clocks.len != n or owned.rights.len != n) return error.InvalidWorkPacketOpening;
    var cursor: usize = 0;
    for (owned.chunks, 0..) |chunk, i| {
        if (chunk.index >= @as(u64, 1) << 55 or (i != 0 and owned.chunks[i - 1].index >= chunk.index) or chunk.before.len != 64 or chunk.after.len != 64 or chunk.terminal_clocks.len != 64 or chunk.rights.len != 64 or chunk.before.ptr != owned.words[64 * i ..].ptr or chunk.after.ptr != owned.words[n + 64 * i ..].ptr or chunk.terminal_clocks.ptr != owned.clocks[64 * i ..].ptr or chunk.rights.ptr != owned.rights[64 * i ..].ptr) return error.InvalidWorkPacketOpening;
        const first = cursor;
        for (0..64) |slot| {
            const address = (chunk.index << 9) + 8 * slot;
            if (cursor < cells.len and cells[cursor].address == address) {
                const cell = cells[cursor];
                const rights: u2 = @as(u2, @intFromBool(cell.readable)) | (@as(u2, @intFromBool(cell.writable)) << 1);
                if (chunk.before[slot] != cell.initial or chunk.after[slot] != cell.final or chunk.terminal_clocks[slot] != finished.memory_clocks[cursor] or chunk.rights[slot] != rights) return error.InvalidWorkPacketOpening;
                cursor += 1;
            } else if (chunk.terminal_clocks[slot] != 0 or chunk.before[slot] != chunk.after[slot]) return error.InvalidWorkPacketOpening;
        }
        if (first == cursor) return error.InvalidWorkPacketOpening;
    }
    if (cursor != cells.len) return error.InvalidWorkPacketOpening;
}
