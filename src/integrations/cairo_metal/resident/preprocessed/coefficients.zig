//! Preprocessed coefficient loading, canonicalization, and Metal evaluation.

const std = @import("std");
const arena_plan = @import("../../../../backends/metal/arena_plan.zig");
const metal_runtime = @import("../../../../backends/metal/runtime.zig");
const cairo_adapter = @import("stwo_cairo_frontend").adapter;
const fixed_table_bundle_mod = @import("stwo_cairo_frontend").witness.fixed_table_bundle;
const schedule_bindings = @import("../../schedule_bindings.zig");
const resident_binding = @import("../binding.zig");
const resident_twiddles = @import("../twiddles.zig");
const Error = @import("../errors.zig").Error;

const collect = schedule_bindings.collect;
const collectScheduleOrder = schedule_bindings.collectScheduleOrder;
const logicalId = schedule_bindings.logicalId;
const one = schedule_bindings.one;
const oneOrdinal = schedule_bindings.oneOrdinal;
const ordinal = schedule_bindings.ordinal;
const purpose = schedule_bindings.purpose;
const twiddleBankBinding = resident_twiddles.twiddleBankBinding;
const twiddleOffsetForLog = resident_twiddles.twiddleOffsetForLog;
const wordOffset = resident_binding.wordOffset;

/// Binds all 33 canonical witness programs to the captured SN2 arena. The
/// pointer workspaces retain their CUDA-sized allocation but contain native
/// u32 Metal word offsets in the leading half.
pub fn populateExecutionTables(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    input: *const cairo_adapter.ProverInput,
) !f64 {
    const raw_address = try one(schedule, plan, "ExecutionTableRawAddressToId");
    const raw_big = try one(schedule, plan, "ExecutionTableRawF252Words");
    const raw_small = try one(schedule, plan, "ExecutionTableRawSmallWords");
    if (raw_address.size_bytes != @as(u64, input.memory.address_to_id.len) * 4 or
        raw_big.size_bytes != @as(u64, input.memory.f252_values.len) * 8 * 4 or
        raw_small.size_bytes != @as(u64, input.memory.small_values.len) * 4 * 4)
        return Error.InvalidBindingSize;

    @memcpy(try resident_arena.bytes(raw_address), std.mem.sliceAsBytes(input.memory.address_to_id));
    @memcpy(try resident_arena.bytes(raw_big), std.mem.sliceAsBytes(input.memory.f252_values));
    const small_bytes = try resident_arena.bytes(raw_small);
    const small_aligned: []align(4) u8 = @alignCast(small_bytes);
    const small_words = std.mem.bytesAsSlice(u32, small_aligned);
    for (input.memory.small_values, 0..) |value, row| {
        inline for (0..4) |word| small_words[row * 4 + word] = @truncate(value >> (word * 32));
    }

    const big = try collect(allocator, schedule, plan, "ExecutionTableBigLimb");
    defer allocator.free(big);
    const small = try collect(allocator, schedule, plan, "ExecutionTableSmallLimb");
    defer allocator.free(small);
    if (big.len != 28 or small.len != 8) return Error.InvalidCardinality;
    const big_rows = std.math.cast(u32, big[0].size_bytes / 4) orelse return Error.InvalidBindingSize;
    const small_rows = std.math.cast(u32, small[0].size_bytes / 4) orelse return Error.InvalidBindingSize;
    var big_offsets: [28]u32 = undefined;
    var small_offsets: [8]u32 = undefined;
    for (big, &big_offsets) |binding, *offset| {
        if (binding.size_bytes != @as(u64, big_rows) * 4) return Error.InvalidBindingSize;
        offset.* = try wordOffset(binding);
    }
    for (small, &small_offsets) |binding, *offset| {
        if (binding.size_bytes != @as(u64, small_rows) * 4) return Error.InvalidBindingSize;
        offset.* = try wordOffset(binding);
    }
    var gpu_ms = try metal.executionTableSplit(
        resident_arena.buffer,
        try wordOffset(raw_big),
        @intCast(input.memory.f252_values.len),
        big_rows,
        8,
        &big_offsets,
    );
    gpu_ms += try metal.executionTableSplit(
        resident_arena.buffer,
        try wordOffset(raw_small),
        @intCast(input.memory.small_values.len),
        small_rows,
        4,
        &small_offsets,
    );
    return gpu_ms;
}

pub fn populatePreprocessedCoefficients(
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    fixed_bundle: fixed_table_bundle_mod.Bundle,
    path: []const u8,
) !void {
    _ = try populatePreprocessedCoefficientsMode(
        allocator,
        resident_arena,
        schedule,
        plan,
        fixed_bundle,
        path,
        .all,
    );
}

pub const PreprocessedCoefficientLoad = struct {
    loaded_columns: usize,
    loaded_bytes: u64,
    reconstructed_columns: usize,
    reconstructed_bytes: u64,
};

/// Validates the complete coefficient artifact while avoiding host copies for
/// columns that the authenticated evaluation artifact will immediately IFFT
/// into the same ordinal and byte shape.
pub fn populateUnreconstructedPreprocessedCoefficients(
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    fixed_bundle: fixed_table_bundle_mod.Bundle,
    path: []const u8,
) !PreprocessedCoefficientLoad {
    return populatePreprocessedCoefficientsMode(
        allocator,
        resident_arena,
        schedule,
        plan,
        fixed_bundle,
        path,
        .unreconstructed_only,
    );
}

const PreprocessedCoefficientLoadMode = enum { all, unreconstructed_only };

fn populatePreprocessedCoefficientsMode(
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    fixed_bundle: fixed_table_bundle_mod.Bundle,
    path: []const u8,
    mode: PreprocessedCoefficientLoadMode,
) !PreprocessedCoefficientLoad {
    const coefficients = try collectScheduleOrder(allocator, schedule, plan, "PreprocessedCoefficients");
    defer allocator.free(coefficients);
    if (coefficients.len != fixed_bundle.preprocessed_identities.len) return Error.InvalidPreprocessedCount;
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    var buffer: [1 << 20]u8 = undefined;
    var reader = file.readerStreaming(&buffer);
    const stream = &reader.interface;
    if (!std.mem.eql(u8, try stream.takeArray(8), "STWZPPC\x00")) return Error.InvalidSchedule;
    if (try stream.takeInt(u32, .little) != 1 or try stream.takeInt(u32, .little) != coefficients.len)
        return Error.InvalidPreprocessedCount;
    var result: PreprocessedCoefficientLoad = .{
        .loaded_columns = 0,
        .loaded_bytes = 0,
        .reconstructed_columns = 0,
        .reconstructed_bytes = 0,
    };
    for (coefficients, fixed_bundle.preprocessed_identities, 0..) |binding, expected_identity, index| {
        const identity_len = try stream.takeInt(u16, .little);
        if (try stream.takeInt(u16, .little) != 0 or identity_len != expected_identity.len)
            return Error.InvalidSchedule;
        const log_size = try stream.takeInt(u32, .little);
        const value_count = try stream.takeInt(u64, .little);
        if (log_size >= 31 or value_count != @as(u64, 1) << @intCast(log_size) or binding.size_bytes != value_count * 4)
            return Error.InvalidBindingSize;
        const identity = try allocator.alloc(u8, identity_len);
        defer allocator.free(identity);
        try stream.readSliceAll(identity);
        if (!std.mem.eql(u8, identity, expected_identity)) return Error.InvalidSchedule;
        const evaluation = oneOrdinal(
            schedule,
            plan,
            "PreprocessedEvaluations",
            std.math.cast(u32, index) orelse return Error.InvalidCardinality,
        ) catch null;
        const reconstructed = mode == .unreconstructed_only and log_size >= 4 and log_size < 25 and
            evaluation != null and evaluation.?.size_bytes == binding.size_bytes;
        if (reconstructed) {
            try stream.discardAll64(binding.size_bytes);
            result.reconstructed_columns += 1;
            result.reconstructed_bytes += binding.size_bytes;
        } else {
            const destination = try resident_arena.bytes(binding);
            try stream.readSliceAll(destination);
            const aligned: []align(4) u8 = @alignCast(destination);
            const words = std.mem.bytesAsSlice(u32, aligned);
            for (words) |value| if (value >= 0x7fffffff) return Error.InvalidSchedule;
            if (log_size > 16) canonicalizeSimdCoefficientBlocks(words, log_size);
            result.loaded_columns += 1;
            result.loaded_bytes += binding.size_bytes;
        }
    }
    var trailing: [1]u8 = undefined;
    if (try stream.readSliceShort(&trailing) != 0) return Error.InvalidSchedule;
    return result;
}

fn canonicalizeSimdCoefficientBlocks(words: []u32, log_size: u32) void {
    const log_lanes: u32 = 4;
    std.debug.assert(log_size > 16 and words.len == @as(usize, 1) << @intCast(log_size));
    const log_vectors = log_size - log_lanes;
    const half = log_vectors / 2;
    const outer = @as(usize, 1) << @intCast(half);
    const middle = @as(usize, 1) << @intCast(log_vectors & 1);
    for (0..outer) |a| {
        for (0..middle) |b| {
            for (0..outer) |c| {
                const i = (a << @intCast(log_vectors - half)) | (b << @intCast(half)) | c;
                const j = (c << @intCast(log_vectors - half)) | (b << @intCast(half)) | a;
                if (i >= j) continue;
                const lhs = words[i * 16 ..][0..16];
                const rhs = words[j * 16 ..][0..16];
                for (lhs, rhs) |*left, *right| std.mem.swap(u32, left, right);
            }
        }
    }
}

pub fn evaluatePreprocessedCoefficients(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    twiddle_storage: ?arena_plan.Binding,
) !f64 {
    const twiddles = try one(schedule, plan, "ForwardTwiddles");
    var gpu_ms: f64 = 0;
    for (4..26) |log_size_usize| {
        const log_size: u32 = @intCast(log_size_usize);
        var source_offsets = std.ArrayList(u64).empty;
        defer source_offsets.deinit(allocator);
        var source_logs = std.ArrayList(u32).empty;
        defer source_logs.deinit(allocator);
        var destination_offsets = std.ArrayList(u32).empty;
        defer destination_offsets.deinit(allocator);
        const expected_bytes = (@as(u64, 1) << @intCast(log_size)) * 4;
        for (schedule) |entry| {
            if (!std.mem.eql(u8, try purpose(entry), "PreprocessedEvaluations")) continue;
            const destination = plan.binding(try logicalId(entry)) catch return Error.MissingBinding;
            if (destination.size_bytes != expected_bytes) continue;
            const source = try oneOrdinal(schedule, plan, "PreprocessedCoefficients", try ordinal(entry));
            if (destination.size_bytes != expected_bytes) return Error.InvalidBindingSize;
            try source_offsets.append(allocator, source.offset_bytes / 4);
            try source_logs.append(allocator, log_size);
            try destination_offsets.append(allocator, try wordOffset(destination));
        }
        if (source_offsets.items.len == 0) continue;
        var prepared = try metal.prepareCompositionLde(
            source_offsets.items,
            source_logs.items,
            destination_offsets.items,
            log_size,
            try twiddleOffsetForLog(if (twiddle_storage) |storage| twiddleBankBinding(storage, log_size) else twiddles, log_size),
        );
        defer prepared.deinit();
        gpu_ms += try metal.compositionLdePrepared(resident_arena.buffer, prepared);
    }
    const seq4 = try oneOrdinal(schedule, plan, "PreprocessedEvaluations", 0);
    const seq4_bytes = try resident_arena.bytes(seq4);
    if (seq4_bytes.len != 16 * 4) return Error.InvalidBindingSize;
    const seq4_aligned: []align(4) u8 = @alignCast(seq4_bytes);
    for (std.mem.bytesAsSlice(u32, seq4_aligned), 0..) |value, expected| {
        if (value != expected) {
            std.log.err("preprocessed seq_4 parity mismatch at row {d}: expected {d}, got {d}", .{ expected, expected, value });
            return Error.InvalidSchedule;
        }
    }
    return gpu_ms;
}

test "Cairo preprocessed SIMD coefficient blocks are canonicalized" {
    const allocator = std.testing.allocator;
    const log_size: u32 = 17;
    const words = try allocator.alloc(u32, @as(usize, 1) << log_size);
    defer allocator.free(words);
    for (words, 0..) |*word, index| word.* = @intCast(index);
    canonicalizeSimdCoefficientBlocks(words, log_size);
    try std.testing.expectEqual(@as(u32, 128 * 16), words[16]);
    try std.testing.expectEqual(@as(u32, 16), words[128 * 16]);
    canonicalizeSimdCoefficientBlocks(words, log_size);
    for (words, 0..) |word, index| try std.testing.expectEqual(@as(u32, @intCast(index)), word);
}
