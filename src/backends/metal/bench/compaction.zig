const std = @import("std");
const stwo = @import("stwo");
const metal = stwo.backends.metal.runtime;

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const log_rows: u5 = if (args.len == 1) 24 else if (args.len == 2)
        try std.fmt.parseInt(u5, args[1], 10)
    else
        return error.InvalidArguments;
    if (log_rows < 8 or log_rows > 24) return error.InvalidArguments;
    const sort_rows: u32 = @as(u32, 1) << log_rows;
    const consumer_rows: u32 = @min(sort_rows, 1 << 16);
    const tuple_words: u32 = 7;
    const block_count = sort_rows / 256;
    const source_words = sort_rows * tuple_words;
    const tuple_scratch_words = source_words;
    const radix_words = block_count * 16;
    const output_words = consumer_rows * 10;
    const total_words: u64 = @as(u64, source_words) + tuple_scratch_words + @as(u64, sort_rows) * 2 +
        @as(u64, radix_words) * 2 + 16 + @as(u64, sort_rows) * 2 + block_count + 2 + output_words;
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(@intCast(total_words * 4));
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    var next: u32 = 0;
    const source_offset = next;
    next += source_words;
    for (0..tuple_words) |word| for (0..sort_rows) |row| {
        const key: u32 = @intCast(row & (consumer_rows - 1));
        words[source_offset + word * sort_rows + row] = if (word == 0) key else key *% @as(u32, @intCast(0x9e37 + word * 0x101)) +% @as(u32, @intCast(word));
    };
    const tuples_offset = next;
    next += tuple_scratch_words;
    const indices_a_offset = next;
    next += sort_rows;
    const indices_b_offset = next;
    next += sort_rows;
    const counts_offset = next;
    next += radix_words;
    const radix_offsets_offset = next;
    next += radix_words;
    const bases_offset = next;
    next += 16;
    const heads_offset = next;
    next += sort_rows;
    const positions_offset = next;
    next += sort_rows;
    const block_sums_offset = next;
    next += block_count;
    const error_offset = next;
    next += 1;
    const unique_offset = next;
    next += 1;
    var output_offsets: [10]u32 = undefined;
    for (&output_offsets) |*offset| {
        offset.* = next;
        next += consumer_rows;
    }
    if (next != total_words) return error.SizeMismatch;
    const source_offsets = [_]u32{source_offset};
    const descriptors = [_]u32{ sort_rows, 0, tuple_words, 1, 0 };
    var plan = try runtime.prepareCompact(&source_offsets, &descriptors, &output_offsets, .{
        .tuple_words = tuple_words,
        .key_words = 1,
        .total_rows = sort_rows,
        .sort_rows = sort_rows,
        .consumer_rows = consumer_rows,
        .tuples_offset = tuples_offset,
        .indices_a_offset = indices_a_offset,
        .indices_b_offset = indices_b_offset,
        .counts_offset = counts_offset,
        .radix_offsets_offset = radix_offsets_offset,
        .bases_offset = bases_offset,
        .heads_offset = heads_offset,
        .positions_offset = positions_offset,
        .block_sums_offset = block_sums_offset,
        .error_offset = error_offset,
        .unique_offset = unique_offset,
        .enabler_slot = 7,
        .iota_slot = 8,
        .multiplicity_slot = 9,
    });
    defer plan.deinit();
    _ = try runtime.compactPrepared(arena, plan);
    var samples: [3]f64 = undefined;
    for (&samples) |*sample| sample.* = try runtime.compactPrepared(arena, plan);
    std.mem.sort(f64, &samples, {}, std.sort.asc(f64));
    if (words[unique_offset] != consumer_rows) return error.InvalidCompaction;
    for (0..consumer_rows) |row| {
        if (words[output_offsets[0] + row] != row or words[output_offsets[9] + row] != sort_rows / consumer_rows)
            return error.InvalidCompaction;
    }
    const result = .{
        .sort_rows = sort_rows,
        .tuple_words = tuple_words,
        .key_words = 1,
        .consumer_rows = consumer_rows,
        .gpu_ms_median = samples[1],
        .input_rows_per_second = @as(f64, @floatFromInt(sort_rows)) * 1000.0 / samples[1],
        .arena_bytes = arena.byte_length,
        .hot_path_allocations = 0,
        .compatibility_readback_bytes = 0,
    };
    var output: [2048]u8 = undefined;
    var writer = std.fs.File.stdout().writer(&output);
    try std.json.Stringify.value(result, .{ .whitespace = .indent_2 }, &writer.interface);
    try writer.interface.writeByte('\n');
    try writer.interface.flush();
}
