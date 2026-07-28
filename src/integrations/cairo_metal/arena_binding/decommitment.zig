const std = @import("std");
const arena_plan = @import("stwo_metal_backend").arena_plan;
const metal_runtime = @import("stwo_metal_backend").runtime;
const schedule_bindings = @import("../schedule_bindings.zig");
const resident_twiddles = @import("../resident/twiddles.zig");
const Error = @import("../resident/errors.zig").Error;

const DecommitTraceGroupBindings = schedule_bindings.DecommitTraceGroupBindings;
const DecommitTraceTreeBindings = schedule_bindings.DecommitTraceTreeBindings;
const DecommitFriTreeBindings = schedule_bindings.DecommitFriTreeBindings;
const twiddleBankBinding = resident_twiddles.twiddleBankBinding;
const twiddleOffsetForLog = resident_twiddles.twiddleOffsetForLog;

fn writeWideWordOffset(words: []u32, index: usize, offset_words: u64) !void {
    const base = std.math.mul(usize, index, 2) catch return Error.InvalidBindingSize;
    if (base + 2 > words.len) return Error.InvalidBindingSize;
    words[base] = @truncate(offset_words);
    words[base + 1] = @truncate(offset_words >> 32);
}

fn writeWideBindingOffsets(
    resident_arena: *arena_plan.ResidentArena,
    destination: arena_plan.Binding,
    sources: []const arena_plan.Binding,
) !void {
    const bytes = try resident_arena.bytes(destination);
    if (bytes.len % 4 != 0 or bytes.len < sources.len * 2 * @sizeOf(u32))
        return Error.InvalidBindingSize;
    const aligned: []align(4) u8 = @alignCast(bytes);
    const words = std.mem.bytesAsSlice(u32, aligned);
    @memset(words, 0);
    for (sources, 0..) |source, index| {
        if (source.offset_bytes % 4 != 0) return Error.InvalidBindingSize;
        try writeWideWordOffset(words, index, source.offset_bytes / 4);
    }
}

test "Cairo decommit pointer entries preserve word offsets above 16 GiB" {
    var words = [_]u32{0} ** 4;
    const high_offset = (@as(u64, 1) << 32) + 0x12345678;
    try writeWideWordOffset(&words, 1, high_offset);
    try std.testing.expectEqual(@as(u32, 0x12345678), words[2]);
    try std.testing.expectEqual(@as(u32, 1), words[3]);
}

fn bindingWords(
    resident_arena: *arena_plan.ResidentArena,
    binding: arena_plan.Binding,
) ![]u32 {
    const bytes = try resident_arena.bytes(binding);
    if (bytes.len % 4 != 0) return Error.InvalidBindingSize;
    const aligned: []align(4) u8 = @alignCast(bytes);
    return std.mem.bytesAsSlice(u32, aligned);
}

pub fn populateTraceRetainedPointers(
    resident_arena: *arena_plan.ResidentArena,
    tree: DecommitTraceTreeBindings,
    retained_bottom_first: []const arena_plan.Binding,
) !void {
    const first_retained_log = tree.leaf_log - tree.unretained;
    if (retained_bottom_first.len != first_retained_log + 1) return Error.InvalidCardinality;
    const words = try bindingWords(resident_arena, tree.retained_pointers);
    if (words.len < (tree.leaf_log + 1) * 2) return Error.InvalidBindingSize;
    @memset(words, 0);
    for (0..first_retained_log + 1) |level| {
        const retained_index = first_retained_log - level;
        const retained = retained_bottom_first[retained_index];
        if (retained.offset_bytes % 4 != 0) return Error.InvalidBindingSize;
        try writeWideWordOffset(words, level, retained.offset_bytes / 4);
    }
}

pub fn populateFriRetainedPointers(
    resident_arena: *arena_plan.ResidentArena,
    tree: DecommitFriTreeBindings,
    retained_root_first: []const arena_plan.Binding,
) !void {
    if (retained_root_first.len != tree.leaf_log + 1) return Error.InvalidCardinality;
    try writeWideBindingOffsets(resident_arena, tree.retained_pointers, retained_root_first);
}

pub fn populateFriCoordinatePointers(
    resident_arena: *arena_plan.ResidentArena,
    tree: DecommitFriTreeBindings,
    evaluation: arena_plan.Binding,
) !void {
    const rows = @as(u64, 1) << @intCast(tree.leaf_log + 2);
    if (evaluation.size_bytes != rows * 16) return Error.InvalidBindingSize;
    const words = try bindingWords(resident_arena, tree.coordinate_pointers);
    if (words.len < 8) return Error.InvalidBindingSize;
    @memset(words, 0);
    if (evaluation.offset_bytes % 4 != 0) return Error.InvalidBindingSize;
    const base = evaluation.offset_bytes / 4;
    for (0..4) |coordinate| {
        const offset = std.math.add(u64, base, @as(u64, coordinate) * rows) catch
            return Error.InvalidBindingSize;
        try writeWideWordOffset(words, coordinate, offset);
    }
}

pub fn populateSparseOffsets(
    resident_arena: *arena_plan.ResidentArena,
    sparse_indices: arena_plan.Binding,
    sparse_offsets: arena_plan.Binding,
    unretained: u32,
) !void {
    if (unretained == 0 or unretained > 4) return Error.InvalidBindingSize;
    const words = try bindingWords(resident_arena, sparse_offsets);
    if (words.len < unretained) return Error.InvalidBindingSize;
    @memset(words, 0);
    var offset: u64 = 0;
    var capacity: u64 = 70 * (@as(u64, 1) << @intCast(unretained));
    for (0..unretained) |distance| {
        words[distance] = std.math.cast(u32, offset) orelse return Error.InvalidBindingSize;
        offset += capacity;
        capacity >>= 1;
    }
    if (offset * 4 > sparse_indices.size_bytes) return Error.InvalidBindingSize;
}

pub fn executeTraceLdeGroup(
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    twiddles: arena_plan.Binding,
    tile: arena_plan.Binding,
    group: DecommitTraceGroupBindings,
    coefficients: []const arena_plan.Binding,
) !f64 {
    if (coefficients.len != group.column_count or coefficients.len == 0 or coefficients.len > 16)
        return Error.InvalidCardinality;
    var source_offsets: [16]u64 = undefined;
    var source_logs: [16]u32 = undefined;
    var output_offsets: [16]u32 = undefined;
    var output_logs: [16]u32 = undefined;
    var tile_cursor: u64 = 0;
    var max_evaluation_log: u32 = 0;
    for (coefficients, 0..) |source, index| {
        if (source.size_bytes < 32 or source.size_bytes % 4 != 0 or
            !std.math.isPowerOfTwo(source.size_bytes / 4))
            return Error.InvalidBindingSize;
        const source_log: u32 = std.math.log2_int(u64, source.size_bytes / 4);
        const evaluation_log = source_log + 1;
        const evaluation_words = @as(u64, 1) << @intCast(evaluation_log);
        if (tile_cursor + evaluation_words > tile.size_bytes / 4) return Error.InvalidBindingSize;
        source_offsets[index] = source.offset_bytes / 4;
        source_logs[index] = source_log;
        output_offsets[index] = std.math.cast(u32, tile.offset_bytes / 4 + tile_cursor) orelse
            return Error.InvalidBindingSize;
        output_logs[index] = evaluation_log;
        max_evaluation_log = @max(max_evaluation_log, evaluation_log);
        tile_cursor += evaluation_words;
    }

    const evaluation_pointer_words = try bindingWords(resident_arena, group.evaluation_pointers);
    const evaluation_log_words = try bindingWords(resident_arena, group.evaluation_logs);
    if (evaluation_pointer_words.len < coefficients.len * 2 or evaluation_log_words.len < coefficients.len)
        return Error.InvalidBindingSize;
    @memset(evaluation_pointer_words, 0);
    @memset(evaluation_log_words, 0);
    for (output_offsets[0..coefficients.len], 0..) |offset, index|
        try writeWideWordOffset(evaluation_pointer_words, index, offset);
    @memcpy(evaluation_log_words[0..coefficients.len], output_logs[0..coefficients.len]);
    if (group.coefficients) |coefficient_bindings| {
        try writeWideBindingOffsets(resident_arena, coefficient_bindings.pointers, coefficients);
        const size_words = try bindingWords(resident_arena, coefficient_bindings.sizes);
        const output_pointer_words = try bindingWords(resident_arena, coefficient_bindings.lde_output_pointers);
        if (size_words.len < coefficients.len or output_pointer_words.len < coefficients.len * 2)
            return Error.InvalidBindingSize;
        @memset(size_words, 0);
        @memset(output_pointer_words, 0);
        for (coefficients, size_words[0..coefficients.len]) |source, *size|
            size.* = std.math.cast(u32, source.size_bytes / 4) orelse return Error.InvalidBindingSize;
        for (output_offsets[0..coefficients.len], 0..) |offset, index|
            try writeWideWordOffset(output_pointer_words, index, offset);
    }

    var gpu_ms: f64 = 0;
    for (4..max_evaluation_log + 1) |evaluation_log_usize| {
        const evaluation_log: u32 = @intCast(evaluation_log_usize);
        var filtered_sources: [16]u64 = undefined;
        var filtered_logs: [16]u32 = undefined;
        var filtered_outputs: [16]u32 = undefined;
        var filtered_count: usize = 0;
        for (output_logs[0..coefficients.len], 0..) |candidate_log, index| {
            if (candidate_log != evaluation_log) continue;
            filtered_sources[filtered_count] = source_offsets[index];
            filtered_logs[filtered_count] = source_logs[index];
            filtered_outputs[filtered_count] = output_offsets[index];
            filtered_count += 1;
        }
        if (filtered_count == 0) continue;
        const evaluation_twiddles = twiddleBankBinding(twiddles, evaluation_log);
        var lde = try metal.prepareCompositionLde(
            filtered_sources[0..filtered_count],
            filtered_logs[0..filtered_count],
            filtered_outputs[0..filtered_count],
            evaluation_log,
            try twiddleOffsetForLog(evaluation_twiddles, evaluation_log),
        );
        defer lde.deinit();
        gpu_ms += try metal.compositionLdePrepared(resident_arena.buffer, lde);
    }
    return gpu_ms;
}
