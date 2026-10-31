//! One bounded native capture adapter. Read each distinct touched chunk from
//! the CURRENT final image once, then reverse only first-before words. This is
//! not an all-RAM snapshot or execution replay. Sparse-root AIR authenticates
//! the reconstructed before values; native inputs are not receiver authority.
const std = @import("std");
const values = @import("values.zig");
const batch = @import("batch.zig");
const policy = @import("policy.zig");
const Memory = @import("../../memory.zig").Memory;
pub const Cell = @import("../../boundary_capture.zig").Cell;
pub const Owned = struct {
    allocator: std.mem.Allocator,
    chunks: []batch.Opening,
    words: []u64,
    clocks: []u32,
    rights: []u2,
    pub fn init(a: std.mem.Allocator, geometry: values.Geometry, mappings: *const policy.Policy, final_memory: *const Memory, cells: []const Cell) !Owned {
        try mappings.validateImmutableExecution();
        if (cells.len == 0 or cells.len > 65536 * 512) return error.InvalidPrivateRamCapture;
        var count: usize = 0;
        for (cells, 0..) |cell, i| {
            if (cell.address & 7 != 0 or cell.terminal_clock == 0 or cell.terminal_clock >= 1 << 24 or cell.rights == 0 or (i > 0 and cells[i - 1].address >= cell.address)) return error.InvalidPrivateRamCapture;
            if (i == 0 or cells[i - 1].address >> geometry.logBytes() != cell.address >> geometry.logBytes()) count += 1;
        }
        if (count > batch.MAX_OPENINGS) return error.PrivateRamBatchResourceLimit;
        const chunks = try a.alloc(batch.Opening, count);
        errdefer a.free(chunks);
        const word_count = try std.math.mul(usize, count, geometry.cells());
        const words = try a.alloc(u64, try std.math.mul(usize, 2, word_count));
        errdefer a.free(words);
        const clocks = try a.alloc(u32, word_count);
        errdefer a.free(clocks);
        @memset(clocks, 0);
        const rights = try a.alloc(u2, word_count);
        errdefer a.free(rights);
        var read: usize = 0;
        for (chunks, 0..) |*chunk, i| {
            const index = cells[read].address >> geometry.logBytes();
            const base = index << geometry.logBytes();
            const before = words[i * geometry.cells() ..][0..geometry.cells()];
            const after = words[word_count + i * geometry.cells() ..][0..geometry.cells()];
            const chunk_clocks = clocks[i * geometry.cells() ..][0..geometry.cells()];
            const chunk_rights = rights[i * geometry.cells() ..][0..geometry.cells()];
            const backing = final_memory.backing.table.get(base >> 12);
            for (after, chunk_rights, 0..) |*word, *mask, cell| {
                const offset = @as(usize, @intCast(base & 4095)) + 8 * cell;
                word.* = if (backing) |page| std.mem.readInt(u64, page[offset..][0..8], .little) else 0;
                const address = base + 8 * cell;
                const r = hasRight(mappings, address, 1);
                const w = hasRight(mappings, address, 2);
                mask.* = @as(u2, @intFromBool(r)) | (@as(u2, @intFromBool(w)) << 1);
            }
            @memcpy(before, after);
            while (read < cells.len and cells[read].address >> geometry.logBytes() == index) : (read += 1) {
                const cell = cells[read];
                const slot: usize = @intCast((cell.address - base) >> 3);
                if (after[slot] != cell.final) return error.PrivateRamFinalImageMismatch;
                if (chunk_rights[slot] != cell.rights) return error.PrivateRamPermissionMismatch;
                before[slot] = cell.initial;
                chunk_clocks[slot] = cell.terminal_clock;
            }
            chunk.* = .{ .index = index, .before = before, .after = after, .terminal_clocks = chunk_clocks, .rights = chunk_rights };
        }
        std.debug.assert(read == cells.len);
        return .{ .allocator = a, .chunks = chunks, .words = words, .clocks = clocks, .rights = rights };
    }
    /// Compatibility constructor for direct native openings. Production capture
    /// transfers Owned itself into Trace.initOwned, avoiding this narrow copy.
    pub fn copy(a: std.mem.Allocator, geometry: values.Geometry, source: []const batch.Opening) !Owned {
        const chunks = try a.alloc(batch.Opening, source.len);
        errdefer a.free(chunks);
        const count = try std.math.mul(usize, source.len, geometry.cells());
        const words = try a.alloc(u64, try std.math.mul(usize, 2, count));
        errdefer a.free(words);
        const clocks = try a.alloc(u32, count);
        errdefer a.free(clocks);
        const rights = try a.alloc(u2, count);
        errdefer a.free(rights);
        for (chunks, source, 0..) |*out, input, i| {
            if (input.before.len != geometry.cells() or input.after.len != geometry.cells() or input.terminal_clocks.len != geometry.cells() or input.rights.len != geometry.cells()) return error.InvalidPrivateRamCapture;
            const before = words[i * geometry.cells() ..][0..geometry.cells()];
            const after = words[count + i * geometry.cells() ..][0..geometry.cells()];
            const clock = clocks[i * geometry.cells() ..][0..geometry.cells()];
            const mask = rights[i * geometry.cells() ..][0..geometry.cells()];
            @memcpy(before, input.before);
            @memcpy(after, input.after);
            @memcpy(clock, input.terminal_clocks);
            @memcpy(mask, input.rights);
            out.* = .{ .index = input.index, .before = before, .after = after, .terminal_clocks = clock, .rights = mask };
        }
        return .{ .allocator = a, .chunks = chunks, .words = words, .clocks = clocks, .rights = rights };
    }
    /// Explicit move; original allocator survives so ordinary deinit is safe.
    pub fn take(self: *Owned) Owned {
        const result = self.*;
        self.* = .{ .allocator = self.allocator, .chunks = &.{}, .words = &.{}, .clocks = &.{}, .rights = &.{} };
        return result;
    }
    pub fn deinit(self: *Owned) void {
        self.allocator.free(self.chunks);
        self.allocator.free(self.words);
        self.allocator.free(self.clocks);
        self.allocator.free(self.rights);
        self.* = undefined;
    }
};
fn hasRight(mappings: *const policy.Policy, address: u64, mask: u2) bool {
    _ = mappings.find(.word8, address, mask) catch return false;
    return true;
}
