//! Gather directly into final column slabs without a row-sized location map.
const std = @import("std");
const inputs = @import("gathered_inputs.zig");
const plans = @import("../proof_plan.zig");
const split = @import("pool_split.zig");

const Source = struct {
    edge: plans.ProducerEdge,
    producer: inputs.Producer,
};

pub fn materialize(allocator: std.mem.Allocator, edges: []const plans.ProducerEdge, producers: []const inputs.Producer, geometry: inputs.Geometry) !inputs.GatheredInput {
    if (!std.meta.eql(try inputs.deriveGeometry(edges, producers), geometry)) return error.InvalidRowCount;
    const columns = std.math.add(usize, geometry.input_width, 1) catch return error.AllocationSizeOverflow;
    const rows: usize = geometry.padded_rows;
    const words = std.math.mul(usize, columns, rows) catch return error.AllocationSizeOverflow;
    const storage = try allocator.alloc(u32, words);
    errdefer allocator.free(storage);
    const sources = try allocator.alloc(Source, edges.len);
    defer allocator.free(sources);
    var full_rows: usize = 0;
    for (edges, sources) |edge, *source| {
        const producer = for (producers) |producer| {
            if (std.mem.eql(u8, edge.producer, producer.label)) break producer;
        } else return error.MissingProducer;
        source.* = .{ .edge = edge, .producer = producer };
        full_rows += @as(usize, producer.active_rows & ~@as(u32, 15)) * edge.instances;
    }
    const remainder_rows = geometry.active_rows - full_rows;
    const initialized_rows = full_rows + std.mem.alignForward(usize, remainder_rows, 16);
    if (initialized_rows == 0 or initialized_rows > rows) return error.InvalidRowCount;

    // Each worker owns complete output columns. Producer feeds are immutable
    // until all workers join; padding reads only the worker's own written data.
    const worker_count = @min(@as(usize, geometry.input_width), split.workerCount(.{
        .rows = words,
        .min_rows_per_worker = 65536,
    }));
    var workers: [split.work_pool.MAX_WORKERS]Work = undefined;
    for (workers[0..worker_count], 0..) |*worker, index| worker.* = .{
        .storage = storage,
        .sources = sources,
        .rows = rows,
        .full_rows = full_rows,
        .initialized_rows = initialized_rows,
        .columns = split.span(geometry.input_width, index, worker_count),
    };
    try split.dispatch(Work, workers[0..worker_count]);
    const selector = storage[@as(usize, geometry.input_width) * rows ..][0..rows];
    @memset(selector[0..geometry.active_rows], 1);
    @memset(selector[geometry.active_rows..], 0);
    return .{
        .allocator = allocator,
        .storage = storage,
        .columns = columns,
        .rows = rows,
        .active_rows = geometry.active_rows,
    };
}

const Work = struct {
    storage: []u32,
    sources: []const Source,
    rows: usize,
    full_rows: usize,
    initialized_rows: usize,
    columns: split.Span,
    failure: ?anyerror = null,

    pub fn run(self: *Work) void {
        for (self.columns.start..self.columns.end) |word| {
            const column = self.storage[word * self.rows ..][0..self.rows];
            var full_cursor: usize = 0;
            var remainder_cursor = self.full_rows;
            for (self.sources) |source| {
                const producer = source.producer;
                const complete = producer.active_rows & ~@as(u32, 15);
                for (0..source.edge.instances) |instance| {
                    const source_word = source.edge.word_base + instance * source.edge.words_per_instance + word;
                    for (0..complete) |row| {
                        column[full_cursor] = producer.words[row * producer.words_per_row + source_word];
                        full_cursor += 1;
                    }
                    for (complete..producer.active_rows) |row| {
                        column[remainder_cursor] = producer.words[row * producer.words_per_row + source_word];
                        remainder_cursor += 1;
                    }
                }
            }
            // Remainder-pack fill repeats its first real entry. Domain padding
            // then repeats the first complete SIMD pack, exactly as the oracle.
            if (remainder_cursor < self.initialized_rows)
                @memset(column[remainder_cursor..self.initialized_rows], column[self.full_rows]);
            for (self.initialized_rows..self.rows) |row| column[row] = column[row & 15];
        }
    }
};
