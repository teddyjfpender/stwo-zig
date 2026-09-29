//! Copy admitted witness words into their final, disjoint base-field columns.
const std = @import("std");
const prover = @import("stwo_prover_engine");
const M31 = @import("stwo_core").fields.m31.M31;
const split = @import("pool_split.zig");

pub fn lower(sources: []const []const u32, outputs: []const []M31, parallel: bool) !void {
    if (sources.len != outputs.len) return error.InvalidBaseTraceGeometry;
    var total: usize = 0;
    for (sources, outputs) |source, output| {
        if (source.len != output.len) return error.InvalidBaseTraceGeometry;
        total = std.math.add(usize, total, source.len) catch return error.AllocationSizeOverflow;
    }
    const workers = if (parallel)
        @min(@as(usize, 8), split.workerCount(.{ .rows = total, .min_rows_per_worker = 1 << 17 }))
    else
        1;
    const Work = struct {
        sources: []const []const u32,
        outputs: []const []M31,
        range: split.Span,
        failure: ?anyerror = null,

        pub fn run(self: *@This()) void {
            var column_start: usize = 0;
            for (self.sources, self.outputs) |source, output| {
                const column_end = column_start + source.len;
                const start = @max(column_start, self.range.start);
                const end = @min(column_end, self.range.end);
                if (start < end) {
                    const first = start - column_start;
                    const last = end - column_start;
                    for (source[first..last], output[first..last]) |raw, *value|
                        value.* = M31.fromCanonical(raw);
                }
                column_start = column_end;
                if (column_start >= self.range.end) break;
            }
        }
    };
    var work: [8]Work = undefined;
    for (work[0..workers], 0..) |*slot, index| slot.* = .{
        .sources = sources,
        .outputs = outputs,
        .range = split.span(total, index, workers),
    };
    try split.dispatch(Work, work[0..workers]);
}

test "Cairo column lowering preserves mixed column lengths across worker boundaries" {
    var pool: prover.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4 });
    defer pool.deinit();
    var binding = try prover.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const words = try std.testing.allocator.alloc(u32, (1 << 20) + 17);
    defer std.testing.allocator.free(words);
    const values = try std.testing.allocator.alloc(M31, words.len);
    defer std.testing.allocator.free(values);
    for (words, 0..) |*word, index| word.* = @intCast(index * 101 % 0x7fffffff);
    @memset(values, M31.zero());
    const sources = [_][]const u32{ words[0..17], words[17..65553], words[65553..] };
    const outputs = [_][]M31{ values[0..17], values[17..65553], values[65553..] };
    try lower(&sources, &outputs, true);
    for (words, values) |word, value| try std.testing.expectEqual(word, value.v);
    try std.testing.expectError(error.InvalidBaseTraceGeometry, lower(sources[0..2], &outputs, true));
    var malformed = outputs;
    malformed[2] = values[65553 .. values.len - 1];
    try std.testing.expectError(error.InvalidBaseTraceGeometry, lower(&sources, &malformed, true));
}
