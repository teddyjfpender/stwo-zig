//! Resource thresholds and process-level tuning for lifted Merkle commitments.

const std = @import("std");
const builtin = @import("builtin");
const mmap_alloc = @import("../mmap_alloc.zig");

pub const parallel_min_nodes: usize = 1 << 11;
pub const parallel_min_nodes_per_worker: usize = 1 << 10;
pub const max_parallel_workers: usize = 32;
pub const merkle_worker_stack_size: usize = 1 << 20;
pub const leaf_tile_len: usize = 256;
pub const max_leaf_scratch_bytes: usize = 256 * 1024;
pub const default_leaf_batch_size: usize = 1 << 12;
pub const batched_leaf_threshold: usize = 1 << 8;

/// Layer buffers at or above this many bytes come from mmap (sequential-read
/// hint, pages returned to the OS on free). Smaller buffers go through the
/// general-purpose heap: an mmap/madvise/munmap round-trip plus first-touch
/// page faults costs far more than the buffer's entire hash pass for the
/// small upper layers and the FRI inner-layer tail.
pub const mmap_layer_threshold_bytes: usize = 1 << 20;

const SizeRoutedLayerAllocator = struct {
    fn allocator() std.mem.Allocator {
        return .{
            .ptr = undefined,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free_fn,
            },
        };
    }

    fn heap() std.mem.Allocator {
        return std.heap.smp_allocator;
    }

    fn alloc(_: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        if (len >= mmap_layer_threshold_bytes) {
            const mmap_vtable = mmap_alloc.MmapAllocator.allocator().vtable;
            return mmap_vtable.alloc(undefined, len, alignment, ret_addr);
        }
        const h = heap();
        return h.vtable.alloc(h.ptr, len, alignment, ret_addr);
    }

    fn resize(_: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        if (buf.len >= mmap_layer_threshold_bytes) return false;
        if (new_len >= mmap_layer_threshold_bytes) return false;
        const h = heap();
        return h.vtable.resize(h.ptr, buf, alignment, new_len, ret_addr);
    }

    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }

    fn free_fn(_: *anyopaque, buf: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        if (buf.len >= mmap_layer_threshold_bytes) {
            const mmap_vtable = mmap_alloc.MmapAllocator.allocator().vtable;
            mmap_vtable.free(undefined, buf, alignment, ret_addr);
            return;
        }
        const h = heap();
        h.vtable.free(h.ptr, buf, alignment, ret_addr);
    }
};

pub fn layerAllocator(fallback: std.mem.Allocator) std.mem.Allocator {
    if (comptime builtin.os.tag == .macos or builtin.os.tag == .linux) {
        return SizeRoutedLayerAllocator.allocator();
    }
    return fallback;
}

pub fn merkleWorkerOverride(allocator: std.mem.Allocator) ?usize {
    return positiveIntegerEnv(allocator, "STWO_ZIG_MERKLE_WORKERS", false);
}

pub fn leafBatchSizeOverride(allocator: std.mem.Allocator) ?usize {
    return positiveIntegerEnv(allocator, "STWO_ZIG_LEAF_BATCH_SIZE", true);
}

pub fn merklePoolReuseEnabled(allocator: std.mem.Allocator) bool {
    const raw = std.process.getEnvVarOwned(allocator, "STWO_ZIG_MERKLE_POOL_REUSE") catch return false;
    defer allocator.free(raw);
    return parseBoolean(raw) orelse false;
}

pub fn parallelWorkersForLayer(out_len: usize, worker_override: ?usize) usize {
    if (builtin.single_threaded or out_len < parallel_min_nodes) return 1;
    const capacity = out_len / parallel_min_nodes_per_worker;
    if (capacity < 2) return 1;
    if (worker_override) |requested| {
        if (requested <= 1) return 1;
        return @min(@min(requested, max_parallel_workers), capacity);
    }
    const cpu_count: usize = @intCast(std.Thread.getCpuCount() catch return 1);
    if (cpu_count <= 1) return 1;
    return @min(@min(cpu_count, capacity), max_parallel_workers);
}

fn positiveIntegerEnv(
    allocator: std.mem.Allocator,
    name: []const u8,
    require_power_of_two: bool,
) ?usize {
    const raw = std.process.getEnvVarOwned(allocator, name) catch return null;
    defer allocator.free(raw);
    const parsed = std.fmt.parseInt(usize, raw, 10) catch return null;
    if (parsed == 0 or (require_power_of_two and !std.math.isPowerOfTwo(parsed))) return null;
    return parsed;
}

fn parseBoolean(raw: []const u8) ?bool {
    if (std.mem.eql(u8, raw, "1") or std.ascii.eqlIgnoreCase(raw, "true") or
        std.ascii.eqlIgnoreCase(raw, "yes") or std.ascii.eqlIgnoreCase(raw, "on")) return true;
    if (std.mem.eql(u8, raw, "0") or std.ascii.eqlIgnoreCase(raw, "false") or
        std.ascii.eqlIgnoreCase(raw, "no") or std.ascii.eqlIgnoreCase(raw, "off")) return false;
    return null;
}

test "lifted VCS boolean tuning values are explicit" {
    for ([_][]const u8{ "1", "TRUE", "yes", "On" }) |value| {
        try std.testing.expectEqual(true, parseBoolean(value));
    }
    for ([_][]const u8{ "0", "FALSE", "no", "Off" }) |value| {
        try std.testing.expectEqual(false, parseBoolean(value));
    }
    try std.testing.expectEqual(@as(?bool, null), parseBoolean("enabled"));
}

test "lifted VCS worker count respects thresholds and overrides" {
    try std.testing.expectEqual(@as(usize, 1), parallelWorkersForLayer(parallel_min_nodes - 1, 8));
    try std.testing.expectEqual(@as(usize, 1), parallelWorkersForLayer(parallel_min_nodes, 1));
    try std.testing.expectEqual(
        @as(usize, if (builtin.single_threaded) 1 else 2),
        parallelWorkersForLayer(parallel_min_nodes, 8),
    );
}
