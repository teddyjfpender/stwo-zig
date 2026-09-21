//! Ethereum diagnostic ledger capacity without touching unused pages.
//! Zig0.15's Allocator.alloc/free poison the entire allocation in safe modes;
//! this owner uses the same allocator's tracked raw allocation API instead.
//! Only TupleLedger.append initializes records, and only items[0..len] is read.
const std = @import("std");
const relation = @import("stwo_riscv_frontend").recursion.air.relation_interaction;
const Record = relation.TupleContribution;
const alignment = std.mem.Alignment.of(Record);

pub const Reservation = struct {
    ledger: *relation.TupleLedger,

    /// Attach an uninitialized capacity buffer to an empty diagnostic ledger.
    /// The ledger must outlive this owner. Deinit this owner before the ledger;
    /// it releases capacity and leaves the ordinary ledger deinit harmless.
    pub fn init(ledger: *relation.TupleLedger, capacity: usize) !Reservation {
        if (ledger.contributions.items.len != 0 or ledger.contributions.capacity != 0)
            return error.EthereumTupleLedgerAlreadyReserved;
        const bytes = std.math.mul(usize, capacity, @sizeOf(Record)) catch return error.OutOfMemory;
        if (bytes != 0) {
            const raw = ledger.allocator.rawAlloc(bytes, alignment, @returnAddress()) orelse return error.OutOfMemory;
            const records: [*]Record = @ptrCast(@alignCast(raw));
            ledger.contributions = .{ .items = records[0..0], .capacity = capacity };
        }
        return .{ .ledger = ledger };
    }

    pub fn deinit(self: *Reservation) void {
        // Use current storage, so normal ArrayList growth remains correct even
        // if the diagnostic estimate is exceeded. Never poison unused capacity.
        const ledger = self.ledger;
        if (ledger.contributions.capacity != 0) {
            const capacity = ledger.contributions.allocatedSlice();
            ledger.allocator.rawFree(std.mem.sliceAsBytes(capacity), alignment, @returnAddress());
        }
        ledger.contributions = .empty;
        self.* = undefined;
    }
};

test "Ethereum tuple reservation preserves untouched capacity and exact initialized records" {
    const core = @import("stwo_core");
    var buffer: [4 * @sizeOf(Record)]u8 align(@alignOf(Record)) = undefined;
    @memset(&buffer, 0xa5);
    var fixed = std.heap.FixedBufferAllocator.init(&buffer);
    var ledger = relation.TupleLedger.init(fixed.allocator());
    defer ledger.deinit();
    var reservation = try Reservation.init(&ledger, 4);
    try std.testing.expectEqual(@as(usize, 4), ledger.contributions.capacity);
    try std.testing.expectEqual(@as(usize, 0), ledger.contributions.items.len);
    try std.testing.expect(std.mem.allEqual(u8, &buffer, 0xa5));
    try std.testing.expect(@intFromPtr(ledger.contributions.items.ptr) % @alignOf(Record) == 0);
    try std.testing.expectError(error.EthereumTupleLedgerAlreadyReserved, Reservation.init(&ledger, 1));
    try ledger.append(.recursion_wire, 0, 0, .emit, core.fields.qm31.QM31.one(), &.{});
    try std.testing.expectEqual(@as(usize, 1), ledger.contributions.items.len);
    try std.testing.expect(std.mem.allEqual(u8, buffer[@sizeOf(Record)..], 0xa5));
    try std.testing.expectEqual(@as(usize, 1), ledger.classify().unmatched_tuple_count);
    reservation.deinit();
    try std.testing.expectEqual(@as(usize, 0), ledger.contributions.capacity);
    try std.testing.expectEqual(@as(usize, 0), ledger.contributions.items.len);
    try std.testing.expect(std.mem.allEqual(u8, buffer[@sizeOf(Record)..], 0xa5));
    try std.testing.expectEqual(@as(usize, 0), fixed.end_index);
}

test "Ethereum tuple reservation retains allocator ownership through growth and failure" {
    const core = @import("stwo_core");
    var ledger = relation.TupleLedger.init(std.testing.allocator);
    defer ledger.deinit();
    try std.testing.expectError(error.OutOfMemory, Reservation.init(&ledger, std.math.maxInt(usize)));
    var reservation = try Reservation.init(&ledger, 1);
    defer reservation.deinit();
    for (0..4) |_| try ledger.append(.recursion_wire, 0, 0, .emit, core.fields.qm31.QM31.one(), &.{});
    try std.testing.expect(ledger.contributions.capacity >= 4);
    try std.testing.expectEqual(@as(usize, 4), ledger.contributions.items.len);
    try std.testing.expectEqual(@as(usize, 1), ledger.classify().unmatched_tuple_count);
}
