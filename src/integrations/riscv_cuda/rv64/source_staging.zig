//! Bounded zero-copy custody of compact uploads until their GPU stream joins.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const Inputs = CPU.rv64_family_input;
const Memory = CPU.rv64_memory_input;
pub const Owner = struct {
    allocator: std.mem.Allocator,
    byte_cap: usize,
    retained_bytes: usize = 0,
    peak_bytes: usize = 0,
    batches: std.ArrayList(Inputs.Batch) = .empty,
    cells: std.ArrayList([]Memory.Cell) = .empty,
    fn fits(self: *const Owner, bytes: usize) bool {
        return bytes <= self.byte_cap - @min(self.byte_cap, self.retained_bytes);
    }
    /// False/error leaves ownership unchanged; success moves the original data.
    pub fn adoptBatch(self: *Owner, value: *Inputs.Batch) !bool {
        const bytes = try std.math.mul(usize, value.facts.len, @sizeOf(Inputs.Fact));
        if (!self.fits(bytes)) return false;
        try self.batches.append(self.allocator, value.*);
        value.facts = &.{};
        self.retained_bytes += bytes;
        self.peak_bytes = @max(self.peak_bytes, self.retained_bytes);
        return true;
    }
    pub fn adoptCells(self: *Owner, value: *[]Memory.Cell) !bool {
        const bytes = try std.math.mul(usize, value.len, @sizeOf(Memory.Cell));
        if (!self.fits(bytes)) return false;
        try self.cells.append(self.allocator, value.*);
        value.* = &.{};
        self.retained_bytes += bytes;
        self.peak_bytes = @max(self.peak_bytes, self.retained_bytes);
        return true;
    }
    /// Caller must join submitted reads before releasing this custody.
    pub fn clearAfterJoin(self: *Owner) void {
        for (self.batches.items) |*batch| batch.deinit();
        for (self.cells.items) |cells| self.allocator.free(cells);
        self.batches.clearRetainingCapacity();
        self.cells.clearRetainingCapacity();
        self.retained_bytes = 0;
    }
    pub fn deinitAfterJoin(self: *Owner) void {
        self.clearAfterJoin();
        self.batches.deinit(self.allocator);
        self.cells.deinit(self.allocator);
    }
};
test "source staging adopts payload without a second copy" {
    const a = std.testing.allocator;
    const Fact = @import("stwo_riscv_frontend").rv64_air.word16_v1.alu_experiment.source.Fact;
    var batch = try Inputs.Batch.alu(a, &.{Fact{ .op = .add, .a = 7, .b = 11, .c = 18 }}, &.{3}, 5);
    defer batch.deinit();
    const pointer = batch.facts.ptr;
    var owner = Owner{ .allocator = a, .byte_cap = 32 };
    defer owner.deinitAfterJoin();
    try std.testing.expect(try owner.adoptBatch(&batch));
    try std.testing.expectEqual(@as(usize, 0), batch.facts.len);
    try std.testing.expectEqual(pointer, owner.batches.items[0].facts.ptr);
    try std.testing.expectEqual(@as(u64, 18), owner.batches.items[0].facts[0].c);
    try std.testing.expectEqual(@as(usize, 32), owner.peak_bytes);
}
test "source staging cap and OOM preserve caller ownership" {
    const a = std.testing.allocator;
    var cells = try a.alloc(Memory.Cell, 2);
    defer a.free(cells);
    const pointer = cells.ptr;
    var owner = Owner{ .allocator = a, .byte_cap = 32 };
    defer owner.deinitAfterJoin();
    try std.testing.expect(!try owner.adoptCells(&cells));
    try std.testing.expectEqual(pointer, cells.ptr);
    try std.testing.expectEqual(@as(usize, 0), owner.retained_bytes);
    var failing = std.testing.FailingAllocator.init(a, .{});
    var bounded = Owner{ .allocator = failing.allocator(), .byte_cap = 64 };
    defer bounded.deinitAfterJoin();
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, bounded.adoptCells(&cells));
    try std.testing.expectEqual(pointer, cells.ptr);
    try std.testing.expectEqual(@as(usize, 0), bounded.retained_bytes);
}
