//! Exact parallel continuation-root derivation for segment statement V2.
//!
//! The canonical scalar implementation remains the protocol definition. This
//! module partitions the fixed 30-bit byte address space at a fixed tree depth,
//! computes independent canonical subtrees on a persistent thread pool, and
//! combines them in the same left-to-right Poseidon2 order. No proof or wire
//! field depends on the worker count.

const std = @import("std");
const contract = @import("segment_statement_v2_contract.zig");
const canonical = @import("segment_statement_v2_canonical_wire_view_v2.zig");

const memory_poseidon2 = contract.memory_poseidon2;
const memory_state = contract.memory_state;

pub const SnapshotIdentity = contract.SnapshotIdentity;
pub const SnapshotSide = canonical.SnapshotSide;

pub const MAX_WORKERS: usize = 32;
pub const SHARD_DEPTH: u32 = 12;
pub const SHARD_COUNT: usize = 1 << SHARD_DEPTH;
pub const SHARD_WIDTH: u32 = contract.MAX_RW_ADDRESS_EXCLUSIVE >> SHARD_DEPTH;

comptime {
    if (SHARD_COUNT * SHARD_WIDTH != contract.MAX_RW_ADDRESS_EXCLUSIVE)
        @compileError("parallel continuation-root shards do not cover RW space");
}

/// Persistent pool owner. It must be initialized in place and must not move
/// until `deinit`, because `std.Thread.Pool` workers retain the pool address.
pub const ParallelSnapshotHasher = struct {
    pool: std.Thread.Pool = undefined,
    worker_count: usize = 0,
    pool_initialized: bool = false,

    pub fn initInPlace(self: *ParallelSnapshotHasher, worker_count: usize) !void {
        if (worker_count == 0 or worker_count > MAX_WORKERS)
            return error.InvalidParallelSnapshotWorkerCount;
        self.* = .{ .worker_count = worker_count };
        errdefer self.* = .{};
        if (worker_count > 1) {
            try self.pool.init(.{
                .allocator = std.heap.smp_allocator,
                .n_jobs = worker_count - 1,
            });
            self.pool_initialized = true;
        }
    }

    pub fn deinit(self: *ParallelSnapshotHasher) void {
        if (self.pool_initialized) self.pool.deinit();
        self.* = .{};
    }

    pub fn snapshotIdentity(
        self: *ParallelSnapshotHasher,
        words: []const memory_state.WordState,
        comptime side: SnapshotSide,
    ) !SnapshotIdentity {
        if (self.worker_count == 0)
            return error.ParallelSnapshotHasherNotInitialized;

        const digest = canonical.snapshotDigest(words, side);
        var roots: [SHARD_COUNT]u32 = undefined;
        var offsets: [SHARD_COUNT + 1]usize = undefined;
        partitionWords(words, &offsets);

        var work = Work(side){
            .words = words,
            .offsets = &offsets,
            .roots = &roots,
        };
        if (self.pool_initialized) {
            var wait_group: std.Thread.WaitGroup = .{};
            for (1..self.worker_count) |_|
                self.pool.spawnWg(&wait_group, Work(side).run, .{&work});
            work.run();
            self.pool.waitAndWork(&wait_group);
        } else {
            work.run();
        }
        if (work.failed.load(.acquire))
            return error.ParallelSnapshotAllocationFailed;

        var active = SHARD_COUNT;
        while (active > 1) : (active /= 2) {
            for (0..active / 2) |index|
                roots[index] = memory_poseidon2.hashPair(
                    roots[index * 2],
                    roots[index * 2 + 1],
                );
        }
        return .{
            .id = digest.id,
            .count = digest.count,
            .root = roots[0],
        };
    }
};

fn Work(comptime side: SnapshotSide) type {
    return struct {
        words: []const memory_state.WordState,
        offsets: *const [SHARD_COUNT + 1]usize,
        roots: *[SHARD_COUNT]u32,
        next: std.atomic.Value(usize) = .init(0),
        failed: std.atomic.Value(bool) = .init(false),

        const Self = @This();

        fn run(self: *Self) void {
            const allocator = std.heap.smp_allocator;
            var current: std.ArrayList(Node) = .empty;
            defer current.deinit(allocator);
            var next_layer: std.ArrayList(Node) = .empty;
            defer next_layer.deinit(allocator);
            while (true) {
                if (self.failed.load(.acquire)) return;
                const shard = self.next.fetchAdd(1, .monotonic);
                if (shard >= SHARD_COUNT) return;
                self.roots[shard] = reduceShard(
                    side,
                    self.words[self.offsets[shard]..self.offsets[shard + 1]],
                    shard,
                    &current,
                    &next_layer,
                ) catch {
                    self.failed.store(true, .release);
                    return;
                };
            }
        }
    };
}

const Node = struct {
    index: u32,
    value: u32,
};

fn reduceShard(
    comptime side: SnapshotSide,
    words: []const memory_state.WordState,
    shard: usize,
    current: *std.ArrayList(Node),
    next_layer: *std.ArrayList(Node),
) !u32 {
    const allocator = std.heap.smp_allocator;
    current.clearRetainingCapacity();
    next_layer.clearRetainingCapacity();
    const maximum_leaves = std.math.mul(usize, words.len, 4) catch
        return error.OutOfMemory;
    try current.ensureTotalCapacity(allocator, maximum_leaves);
    for (words) |word| {
        const value = @field(word, @tagName(side));
        inline for (0..4) |byte_index| {
            const shift: u5 = byte_index * 8;
            const byte: u8 = @truncate(value >> shift);
            if (byte != 0) current.appendAssumeCapacity(.{
                .index = word.addr + @as(u32, byte_index),
                .value = byte,
            });
        }
    }
    if (current.items.len == 0)
        return memory_poseidon2.DEFAULT_HASHES[SHARD_DEPTH];
    try next_layer.ensureTotalCapacity(allocator, current.items.len);

    var depth: u32 = 30;
    while (depth > SHARD_DEPTH) : (depth -= 1) {
        next_layer.clearRetainingCapacity();
        const child_default = memory_poseidon2.DEFAULT_HASHES[depth];
        var parent_indices: [4]u32 = undefined;
        var left: [4]u32 = .{child_default} ** 4;
        var right: [4]u32 = .{child_default} ** 4;
        var batch_count: usize = 0;
        var cursor: usize = 0;
        while (cursor < current.items.len) {
            const first = current.items[cursor];
            const parent_index = first.index >> 1;
            parent_indices[batch_count] = parent_index;
            left[batch_count] = child_default;
            right[batch_count] = child_default;
            if ((first.index & 1) == 0) {
                left[batch_count] = first.value;
            } else {
                right[batch_count] = first.value;
            }
            cursor += 1;
            if (cursor < current.items.len and
                (current.items[cursor].index >> 1) == parent_index)
            {
                const second = current.items[cursor];
                std.debug.assert((first.index & 1) == 0);
                std.debug.assert((second.index & 1) == 1);
                right[batch_count] = second.value;
                cursor += 1;
            }
            batch_count += 1;
            if (batch_count == 4) {
                appendHashedBatch(
                    next_layer,
                    parent_indices,
                    left,
                    right,
                    batch_count,
                );
                batch_count = 0;
            }
        }
        if (batch_count != 0) appendHashedBatch(
            next_layer,
            parent_indices,
            left,
            right,
            batch_count,
        );
        std.mem.swap(std.ArrayList(Node), current, next_layer);
    }
    std.debug.assert(current.items.len == 1);
    std.debug.assert(current.items[0].index == shard);
    return current.items[0].value;
}

fn appendHashedBatch(
    output: *std.ArrayList(Node),
    parent_indices: [4]u32,
    left: [4]u32,
    right: [4]u32,
    count: usize,
) void {
    const hashes = memory_poseidon2.hashPairs4(left, right);
    for (0..count) |index| output.appendAssumeCapacity(.{
        .index = parent_indices[index],
        .value = hashes[index],
    });
}

fn partitionWords(
    words: []const memory_state.WordState,
    offsets: *[SHARD_COUNT + 1]usize,
) void {
    var word_index: usize = 0;
    for (0..SHARD_COUNT) |shard| {
        const start: u32 = @intCast(shard * SHARD_WIDTH);
        while (word_index < words.len and words[word_index].addr < start)
            word_index += 1;
        offsets[shard] = word_index;
    }
    offsets[SHARD_COUNT] = words.len;
}
