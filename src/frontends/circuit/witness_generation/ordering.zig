//! Stable witness-task ordering only; dependency/producer discovery is unchanged.
//! Histograms belong to fixed logical source chunks, never physical workers.
const std = @import("std");
const Pools = @import("stwo_prover_engine").work_pool;
const Rows = @import("stwo_prover_engine").lookups.row_work;
pub const MAX_CHUNKS = 8;
pub const SCRATCH_CAP_BYTES: usize = 16 << 20;
pub const MIN_TASKS: usize = 1 << 16;
pub const Options = struct {
    // Separate wave caps also exercise changing physical worker availability.
    count_shards: usize = MAX_CHUNKS,
    scatter_shards: usize = MAX_CHUNKS,
};
pub const Error = error{ InvalidWitnessLevel, InvalidOrderingGeometry };

/// Original count/prefix/reverse-stable-scatter control, with borrowed storage.
pub fn serial(comptime Task: type, source: []const Task, levels: []const u32, ends: []usize, cursors: []usize, ordered: []Task) Error!void {
    if (ends.len == 0 or source.len != levels.len or ordered.len != source.len or cursors.len != ends.len) return error.InvalidOrderingGeometry;
    @memset(ends, 0);
    for (levels) |level| {
        if (level >= ends.len) return error.InvalidWitnessLevel;
        ends[level] += 1;
    }
    for (1..ends.len) |i| ends[i] += ends[i - 1];
    @memcpy(cursors, ends);
    var i = source.len;
    while (i > 0) {
        i -= 1;
        const level = levels[i];
        cursors[level] -= 1;
        ordered[cursors[level]] = source[i];
        ordered[cursors[level]].level = level;
    }
}
fn boundary(count: usize, chunk: usize) usize {
    return count / MAX_CHUNKS * chunk + @min(chunk, count % MAX_CHUNKS);
}

/// Allocations happen on the caller, with one optional bounded histogram. An
/// OOM for this acceleration scratch preserves the serial path. Both waves
/// complete before freeing scratch or reporting malformed level input.
pub fn fill(comptime Task: type, a: std.mem.Allocator, source: []const Task, levels: []const u32, ends: []usize, cursors: []usize, ordered: []Task, options: Options) Error!bool {
    if (ends.len == 0 or source.len != levels.len or ordered.len != source.len or cursors.len != ends.len) return error.InvalidOrderingGeometry;
    if (try parallel(Task, a, source, levels, ends, ordered, options)) return true;
    try serial(Task, source, levels, ends, cursors, ordered);
    return false;
}
fn parallel(comptime Task: type, a: std.mem.Allocator, source: []const Task, levels: []const u32, ends: []usize, ordered: []Task, options: Options) Error!bool {
    const pool = Pools.currentScopedPool() orelse return false;
    if (source.len < MIN_TASKS or pool.availableWorkers() < 2 or Pools.cooperative.current() != null) return false;
    const cells = std.math.mul(usize, MAX_CHUNKS, ends.len) catch return false;
    const bytes = std.math.mul(usize, cells, @sizeOf(usize)) catch return false;
    // Count conversion should be smaller than the record pass; a deep narrow
    // schedule can otherwise cost more histogram work than the serial route.
    const total_scratch = std.math.add(usize, bytes, bytes / MAX_CHUNKS) catch return false;
    if (total_scratch > SCRATCH_CAP_BYTES or cells > source.len) return false;
    const histogram = a.alloc(usize, cells) catch return false;
    defer a.free(histogram);
    const Count = struct {
        levels: []const u32,
        width: usize,
        histogram: []usize,
        invalid: [MAX_CHUNKS]bool = @splat(false),
        pub fn runRange(self: *@This(), _: usize, begin: usize, end: usize) void {
            for (begin..end) |chunk| {
                const counts = self.histogram[chunk * self.width ..][0..self.width];
                @memset(counts, 0);
                for (self.levels[boundary(self.levels.len, chunk)..boundary(self.levels.len, chunk + 1)]) |level| {
                    if (level >= self.width) {
                        self.invalid[chunk] = true;
                        break;
                    }
                    counts[level] += 1;
                }
            }
        }
    };
    var count = Count{ .levels = levels, .width = ends.len, .histogram = histogram };
    _ = Rows.forEachRange(MAX_CHUNKS, &count, .{ .min_rows_per_shard = 1, .max_shards = options.count_shards });
    for (count.invalid) |invalid| if (invalid) return error.InvalidWitnessLevel;
    // Prefix by level, then original contiguous chunk order. Counts become
    // disjoint global output cursors; no second histogram/cursor plane exists.
    var next: usize = 0;
    for (0..ends.len) |level| {
        for (0..MAX_CHUNKS) |chunk| {
            const index = chunk * ends.len + level;
            const n = histogram[index];
            histogram[index] = next;
            next += n;
        }
        ends[level] = next;
    }
    std.debug.assert(next == source.len);
    const Scatter = struct {
        source: []const Task,
        levels: []const u32,
        width: usize,
        histogram: []usize,
        ordered: []Task,
        pub fn runRange(self: *@This(), _: usize, begin: usize, end: usize) void {
            for (begin..end) |chunk| {
                const positions = self.histogram[chunk * self.width ..][0..self.width];
                const first = boundary(self.source.len, chunk);
                const last = boundary(self.source.len, chunk + 1);
                for (first..last) |i| {
                    const level = self.levels[i];
                    const out = positions[level];
                    self.ordered[out] = self.source[i];
                    self.ordered[out].level = level;
                    positions[level] += 1;
                }
            }
        }
    };
    var scatter = Scatter{ .source = source, .levels = levels, .width = ends.len, .histogram = histogram, .ordered = ordered };
    _ = Rows.forEachRange(MAX_CHUNKS, &scatter, .{ .min_rows_per_shard = 1, .max_shards = options.scatter_shards });
    return true;
}

test {
    _ = @import("ordering_test.zig");
}
