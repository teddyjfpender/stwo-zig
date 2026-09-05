//! Cross-segment snapshot-authority scheduling for block materialization.
//!
//! The execution thread projects only the canonical nonzero `(address,value)`
//! pairs for the first entry and every segment exit. Independent workers then
//! expand those compact projections and invoke the existing one-lane
//! `ParallelSnapshotHasher`, preserving the exact V2 digest/root formulas
//! while allowing multiple Poseidon sponge chains to overlap execution.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const memory_state = frontend.runner.memory_state;
const segment_v2 = frontend.recursion.segment_statement_v2;

pub const MAX_WORKERS: usize = 32;

const State = enum { empty, queued, complete, failed };

const Slot = struct {
    allocator: std.mem.Allocator = undefined,
    projection: std.ArrayList(segment_v2.SparseEntryV2) = .empty,
    identity: segment_v2.SnapshotIdentity = undefined,
    state: State = .empty,

    fn run(self: *Slot) void {
        self.compute() catch {
            self.state = .failed;
            return;
        };
        self.state = .complete;
    }

    fn compute(self: *Slot) !void {
        defer {
            self.projection.deinit(self.allocator);
            self.projection = .empty;
        }
        const words = try self.allocator.alloc(
            memory_state.WordState,
            self.projection.items.len,
        );
        defer self.allocator.free(words);
        for (words, self.projection.items) |*destination, source| {
            destination.* = .{
                .addr = source.address,
                .initial_word = source.value,
                .final_word = source.value,
                .final_clock = 0,
            };
        }
        var hasher: segment_v2.ParallelSnapshotHasher = .{};
        try hasher.initInPlace(1);
        defer hasher.deinit();
        self.identity = try hasher.snapshotIdentity(words, .initial_word);
        if (self.identity.count !=
            @as(u32, @intCast(self.projection.items.len)))
        {
            return error.SnapshotProjectionCountMismatch;
        }
    }
};

/// Stable owner for one fixed, ordered batch. Initialize it only after its
/// containing object has reached its final address: the thread pool and jobs
/// retain pointers into this value until `finish`/`deinit`.
pub const Batch = struct {
    allocator: std.mem.Allocator = undefined,
    pool: std.Thread.Pool = undefined,
    wait_group: std.Thread.WaitGroup = .{},
    slots: []Slot = &.{},
    worker_count: usize = 0,
    enqueued: usize = 0,
    pool_initialized: bool = false,
    joined: bool = false,

    pub fn initInPlace(
        self: *Batch,
        allocator: std.mem.Allocator,
        snapshot_count: usize,
        worker_count: usize,
    ) !void {
        if (snapshot_count == 0 or
            worker_count == 0 or worker_count > MAX_WORKERS)
        {
            return error.InvalidSnapshotBatchGeometry;
        }
        self.* = .{
            .allocator = allocator,
            .worker_count = worker_count,
        };
        errdefer self.* = .{};
        self.slots = try allocator.alloc(Slot, snapshot_count);
        errdefer allocator.free(self.slots);
        for (self.slots) |*slot| slot.* = .{
            // Projection jobs overlap one another and the execution thread;
            // never impose thread-safety requirements on the caller's owner
            // allocator.
            .allocator = std.heap.smp_allocator,
        };
        if (worker_count > 1) {
            try self.pool.init(.{
                .allocator = std.heap.smp_allocator,
                // All requested lanes remain available while the execution
                // thread advances subsequent segments. `waitAndWork` may let
                // that thread help only after terminal execution.
                .n_jobs = worker_count,
            });
            self.pool_initialized = true;
        }
    }

    pub fn deinit(self: *Batch) void {
        self.join();
        if (self.pool_initialized) self.pool.deinit();
        for (self.slots) |*slot| {
            if (slot.state == .empty or slot.state == .queued)
                slot.projection.deinit(slot.allocator);
        }
        if (self.slots.len != 0) self.allocator.free(self.slots);
        self.* = .{};
    }

    /// Project one canonical snapshot in one pass. Slots are append-only and
    /// must be submitted in order, preventing an async result from being
    /// rebound to another segment boundary.
    pub fn enqueue(
        self: *Batch,
        slot_index: usize,
        words: []const memory_state.WordState,
        side: segment_v2.SnapshotSide,
    ) !void {
        if (self.joined or slot_index != self.enqueued or
            slot_index >= self.slots.len)
        {
            return error.InvalidSnapshotBatchOrder;
        }
        const slot = &self.slots[slot_index];
        if (slot.state != .empty) return error.SnapshotSlotAlreadyQueued;
        var projection: std.ArrayList(segment_v2.SparseEntryV2) = .empty;
        errdefer projection.deinit(slot.allocator);
        try projection.ensureTotalCapacity(
            slot.allocator,
            @min(words.len, @as(usize, 64 * 1024)),
        );
        var previous: ?u32 = null;
        for (words) |word| {
            if ((word.addr & 3) != 0 or
                word.addr > segment_v2.MAX_RW_ADDRESS_EXCLUSIVE - 4)
            {
                return error.InvalidSnapshotProjectionAddress;
            }
            if (previous) |address| {
                if (word.addr <= address)
                    return error.InvalidSnapshotProjectionOrder;
            }
            previous = word.addr;
            const value = switch (side) {
                .initial_word => word.initial_word,
                .final_word => word.final_word,
            };
            if (value == 0) continue;
            if (projection.items.len ==
                @as(usize, segment_v2.MAX_SPARSE_BOUNDARY_ENTRIES))
            {
                return error.SnapshotProjectionResourceLimitExceeded;
            }
            try projection.append(slot.allocator, .{
                .address = word.addr,
                .value = value,
            });
        }
        slot.projection = projection;
        slot.state = .queued;
        self.enqueued += 1;
        if (self.pool_initialized) {
            self.pool.spawnWg(&self.wait_group, Slot.run, .{slot});
        } else {
            slot.run();
        }
    }

    pub fn finish(self: *Batch) !void {
        if (self.enqueued != self.slots.len)
            return error.IncompleteSnapshotBatch;
        self.join();
        for (self.slots) |slot| if (slot.state != .complete)
            return error.SnapshotAuthorityDerivationFailed;
    }

    pub fn identityAt(
        self: *const Batch,
        slot_index: usize,
    ) !segment_v2.SnapshotIdentity {
        if (!self.joined or slot_index >= self.slots.len or
            self.slots[slot_index].state != .complete)
        {
            return error.SnapshotAuthorityUnavailable;
        }
        return self.slots[slot_index].identity;
    }

    fn join(self: *Batch) void {
        if (self.joined) return;
        if (self.pool_initialized)
            self.pool.waitAndWork(&self.wait_group);
        self.joined = true;
    }
};

test "snapshot batch preserves canonical identity and ordered slots" {
    const allocator = std.testing.allocator;
    const words = [_]memory_state.WordState{
        .{
            .addr = 0x1000,
            .initial_word = 0,
            .final_word = 0x0102_0304,
            .final_clock = 0,
        },
        .{
            .addr = 0x1004,
            .initial_word = 0xa5a5_5a5a,
            .final_word = 0,
            .final_clock = 0,
        },
        .{
            .addr = 0x2000,
            .initial_word = 0x1122_3344,
            .final_word = 0x5566_7788,
            .final_clock = 0,
        },
    };
    var batch: Batch = .{};
    try batch.initInPlace(allocator, 3, 2);
    defer batch.deinit();
    try batch.enqueue(0, &words, .initial_word);
    try batch.enqueue(1, &words, .final_word);
    try batch.enqueue(2, &.{}, .final_word);
    try batch.finish();
    try std.testing.expectEqual(
        segment_v2.snapshotIdentity(&words, .initial_word),
        try batch.identityAt(0),
    );
    try std.testing.expectEqual(
        segment_v2.snapshotIdentity(&words, .final_word),
        try batch.identityAt(1),
    );
    try std.testing.expectEqual(
        segment_v2.snapshotIdentity(&.{}, .final_word),
        try batch.identityAt(2),
    );
}

test "snapshot batch rejects reordered and mutated projections" {
    const allocator = std.testing.allocator;
    var ordered = [_]memory_state.WordState{
        .{ .addr = 0x1000, .initial_word = 1, .final_word = 2, .final_clock = 0 },
        .{ .addr = 0x1004, .initial_word = 3, .final_word = 4, .final_clock = 0 },
    };
    var batch: Batch = .{};
    try batch.initInPlace(allocator, 1, 1);
    defer batch.deinit();
    try std.testing.expectError(
        error.InvalidSnapshotBatchOrder,
        batch.enqueue(1, &ordered, .initial_word),
    );
    std.mem.swap(memory_state.WordState, &ordered[0], &ordered[1]);
    try std.testing.expectError(
        error.InvalidSnapshotProjectionOrder,
        batch.enqueue(0, &ordered, .initial_word),
    );

    std.mem.swap(memory_state.WordState, &ordered[0], &ordered[1]);
    var mutation_batch: Batch = .{};
    try mutation_batch.initInPlace(allocator, 2, 2);
    defer mutation_batch.deinit();
    try mutation_batch.enqueue(0, &ordered, .initial_word);
    ordered[1].initial_word ^= 1;
    try mutation_batch.enqueue(1, &ordered, .initial_word);
    try mutation_batch.finish();
    try std.testing.expect(!std.meta.eql(
        try mutation_batch.identityAt(0),
        try mutation_batch.identityAt(1),
    ));
}
