const std = @import("std");
const metal = @import("stwo_metal_backend").runtime;
const m31 = @import("stwo_core").fields.m31;
const blake2_merkle = @import("stwo_core").vcs_lifted.blake2_merkle;
const blake2_hash = @import("stwo_core").vcs.blake2_hash;
const merkle_prover = @import("stwo_prover_engine").vcs_lifted.prover;
const pcs_core = @import("stwo_core").pcs;
const MetalProverEngine = @import("stwo_metal_backend").prover_engine.MetalProverEngine;
const canonic = @import("stwo_core").poly.circle.canonic;
const circle_poly = @import("stwo_prover_engine").poly.circle.poly;
const twiddles = @import("stwo_prover_engine").poly.twiddles;
const core_fri = @import("stwo_core").fri;
const qm31 = @import("stwo_core").fields.qm31;
const line = @import("stwo_core").poly.line;
const prover_line = @import("stwo_prover_engine").line;
const MetalBackend = @import("stwo_metal_backend").commit_backend.MetalCommitBackend;
const metal_commit_policy = @import("stwo_metal_backend").commit_policy;
const eval_program = @import("stwo_cairo_frontend").witness.eval_program;
const cairo_metal = @import("stwo_cairo_metal_integration");
const eval_codegen = cairo_metal.eval_codegen;
const circle_core = @import("stwo_core").circle;
const core_utils = @import("stwo_core").utils;
const blake2s_channel = @import("stwo_core").channel.blake2s;
const protocol_recipes = @import("stwo_metal_backend").protocol_recipes;
const arena_plan = @import("stwo_metal_backend").arena_plan;
const secure_column = @import("stwo_prover_engine").secure_column;
const secure_circle_poly = @import("stwo_prover_engine").poly.circle.secure_poly;
const cairo_arena_binding = cairo_metal.arena_binding;
const cairo_oods = cairo_metal.oods;
const cairo_quotient_inputs = cairo_metal.quotient_inputs;
const cairo_quotient_reference = cairo_metal.quotient_reference;

const M31 = m31.M31;
const Hasher = blake2_merkle.Blake2sMerkleHasher;
const PlainHasher = blake2_merkle.Blake2sPlainMerkleHasher;
const QM31 = qm31.QM31;

fn testResidentBinding(logical_id: u32, offset_words: u32, word_count: u32) arena_plan.Binding {
    return .{
        .logical_id = logical_id,
        .slot = logical_id,
        .offset_bytes = @as(u64, offset_words) * @sizeOf(u32),
        .size_bytes = @as(u64, word_count) * @sizeOf(u32),
        .materialization = .resident,
        .occupied = [_]u64{0} ** (arena_plan.max_ticks / 64),
    };
}

test "metal: Felt252 Montgomery multiplication and inversion match scalar vectors" {
    var runtime = try metal.Runtime.initFull();
    defer runtime.deinit();
    const inputs = [_]u32{
        3,          0,          0,          0,          0,          0,          0,  0,          5,          0,          0,          0,          0,          0,          0,  0,
        123456789,  0,          0,          0,          0,          0,          0,  0,          987654321,  0,          0,          0,          0,          0,          0,  0,
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 16, 0x08000000, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 16, 0x08000000,
    };
    const expected = [_]u32{
        15,         0,          0,          0,          0,          0,          0,          0,
        1431655766, 1431655765, 1431655765, 1431655765, 1431655765, 1431655765, 2863311536, 44739242,
        4227814277, 28389652,   0,          0,          0,          0,          0,          0,
        4182502465, 3289839419, 2437154633, 1097617667, 246538787,  226687632,  2597573368, 27746315,
        6,          0,          0,          0,          0,          0,          0,          0,
        0,          0,          0,          0,          0,          2147483648, 8,          67108864,
    };
    var outputs: [expected.len]u32 = undefined;
    _ = try runtime.felt252Oracle(&inputs, &outputs);
    try std.testing.expectEqualSlices(u32, &expected, &outputs);
}

test "metal: resident EC-op matches canonical Rust witness ABI" {
    const allocator = std.testing.allocator;
    const bytes = try std.fs.cwd().readFileAlloc(allocator, "vectors/cairo/ec_op_parity.bin", 16 * 1024 * 1024);
    defer allocator.free(bytes);
    var cursor: usize = 0;
    const Read = struct {
        fn word(data: []const u8, at: *usize) u32 {
            const value = std.mem.readInt(u32, data[at.*..][0..4], .little);
            at.* += 4;
            return value;
        }
    };
    try std.testing.expectEqualSlices(u8, "STWZECO\x00", bytes[0..8]);
    cursor = 8;
    try std.testing.expectEqual(@as(u32, 1), Read.word(bytes, &cursor));
    const rows = Read.word(bytes, &cursor);
    const segment = Read.word(bytes, &cursor);
    const n_addresses = Read.word(bytes, &cursor);
    const n_big = Read.word(bytes, &cursor);
    const n_small = Read.word(bytes, &cursor);
    try std.testing.expectEqual(@as(u32, 64), rows);
    const address_bytes: []align(4) const u8 = @alignCast(bytes[cursor .. cursor + @as(usize, n_addresses) * 4]);
    const addresses = std.mem.bytesAsSlice(u32, address_bytes);
    cursor += @as(usize, n_addresses) * 4;
    const big_bytes: []align(4) const u8 = @alignCast(bytes[cursor .. cursor + @as(usize, n_big) * 8 * 4]);
    const big_words = std.mem.bytesAsSlice(u32, big_bytes);
    cursor += @as(usize, n_big) * 8 * 4;
    const small_bytes: []align(4) const u8 = @alignCast(bytes[cursor .. cursor + @as(usize, n_small) * 4 * 4]);
    const small_words = std.mem.bytesAsSlice(u32, small_bytes);
    cursor += @as(usize, n_small) * 4 * 4;
    const trace_bytes: []align(4) const u8 = @alignCast(bytes[cursor .. cursor + @as(usize, rows) * 273 * 4]);
    const expected_trace = std.mem.bytesAsSlice(u32, trace_bytes);
    cursor += @as(usize, rows) * 273 * 4;
    const lookup_bytes: []align(4) const u8 = @alignCast(bytes[cursor .. cursor + @as(usize, rows) * 488 * 4]);
    const expected_lookup = std.mem.bytesAsSlice(u32, lookup_bytes);
    cursor += @as(usize, rows) * 488 * 4;
    const partial_rows = @as(usize, rows) * 256;
    const partial_bytes: []align(4) const u8 = @alignCast(bytes[cursor .. cursor + partial_rows * 127 * 4]);
    const expected_partial = std.mem.bytesAsSlice(u32, partial_bytes);
    cursor += partial_rows * 127 * 4;
    try std.testing.expectEqual(bytes.len, cursor);

    var runtime = try metal.Runtime.initFull();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(12 * 1024 * 1024);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    var next: u32 = 0;
    const address_offset = next;
    @memcpy(words[next .. next + addresses.len], addresses);
    next += @intCast(addresses.len);
    var execution_offsets: [37]u32 = undefined;
    execution_offsets[0] = address_offset;
    for (0..28) |limb| {
        execution_offsets[1 + limb] = next;
        for (0..n_big) |index| {
            const source = big_words[index * 8 ..][0..8];
            const bit = limb * 9;
            const source_limb = bit / 32;
            const shift: u5 = @intCast(bit % 32);
            var value = source[source_limb] >> shift;
            if (shift > 23 and source_limb + 1 < 8) value |= source[source_limb + 1] << @intCast(@as(u6, 32) - shift);
            words[next + index] = value & 0x1ff;
        }
        next += n_big;
    }
    for (0..8) |limb| {
        execution_offsets[29 + limb] = next;
        const bit = limb * 9;
        const source_limb = bit / 32;
        const shift: u5 = @intCast(bit % 32);
        for (0..n_small) |index| {
            const source = small_words[index * 4 ..][0..4];
            var value = source[source_limb] >> shift;
            if (shift > 23 and source_limb + 1 < 4) value |= source[source_limb + 1] << @intCast(@as(u6, 32) - shift);
            words[next + index] = value & 0x1ff;
        }
        next += n_small;
    }
    var trace_offsets: [273]u32 = undefined;
    for (&trace_offsets) |*offset| {
        offset.* = next;
        @memset(words[next .. next + rows], 0);
        next += rows;
    }
    const lookup_offset = next;
    @memset(words[next .. next + rows * 488], 0);
    next += rows * 488;
    var partial_offsets: [127]u32 = undefined;
    for (&partial_offsets) |*offset| {
        offset.* = next;
        @memset(words[next .. next + partial_rows], 0);
        next += @intCast(partial_rows);
    }
    var multiplicity_offsets: [4]u32 = undefined;
    const multiplicity_lengths = [_]u32{ n_addresses, n_big, n_small, 256 };
    for (&multiplicity_offsets, multiplicity_lengths) |*offset, length| {
        offset.* = next;
        @memset(words[next .. next + length], 0);
        next += length;
    }
    const segment_offset = next;
    words[next] = segment;
    next += 1;
    const scratch_offset = partial_offsets[126];
    try std.testing.expect(@as(usize, next) * 4 <= arena.byte_length);

    var plan = try runtime.prepareEcOp(
        execution_offsets,
        trace_offsets,
        partial_offsets,
        multiplicity_offsets,
        lookup_offset,
        segment_offset,
        scratch_offset,
        rows,
        true,
        true,
    );
    defer plan.deinit();
    const gpu_ms = try runtime.ecOpPrepared(arena, plan);
    try std.testing.expect(gpu_ms > 0);
    for (0..rows) |row| for (trace_offsets, 0..) |offset, column| {
        const expected = expected_trace[row * 273 + column];
        const actual = words[offset + row];
        if (expected != actual) {
            std.debug.print("EC-op trace mismatch at row {}, column {}: expected {}, found {}\n", .{ row, column, expected, actual });
            return error.TestExpectedEqual;
        }
    };
    try std.testing.expectEqualSlices(u32, expected_lookup, words[lookup_offset .. lookup_offset + expected_lookup.len]);
    for (partial_offsets, 0..) |offset, column| {
        try std.testing.expectEqualSlices(u32, expected_partial[column * partial_rows ..][0..partial_rows], words[offset .. offset + partial_rows]);
    }

    const untouched: u32 = 0x5a5a5a5a;
    for (trace_offsets) |offset| @memset(words[offset .. offset + rows], untouched);
    for (partial_offsets) |offset| @memset(words[offset .. offset + partial_rows], untouched);
    for (multiplicity_offsets, multiplicity_lengths) |offset, length| @memset(words[offset .. offset + length], untouched);
    @memset(words[lookup_offset .. lookup_offset + expected_lookup.len], 0);
    var lookup_plan = try runtime.prepareEcOp(
        execution_offsets,
        trace_offsets,
        partial_offsets,
        multiplicity_offsets,
        lookup_offset,
        segment_offset,
        scratch_offset,
        rows,
        false,
        true,
    );
    defer lookup_plan.deinit();
    _ = try runtime.ecOpPrepared(arena, lookup_plan);
    try std.testing.expectEqualSlices(u32, expected_lookup, words[lookup_offset .. lookup_offset + expected_lookup.len]);
    for (trace_offsets) |offset| for (words[offset .. offset + rows]) |value| try std.testing.expectEqual(untouched, value);
    for (partial_offsets) |offset| for (words[offset .. offset + partial_rows]) |value| try std.testing.expectEqual(untouched, value);
    for (multiplicity_offsets, multiplicity_lengths) |offset, length| for (words[offset .. offset + length]) |value| try std.testing.expectEqual(untouched, value);
}

test "metal: resident EC-op finalizes canonical padding across threadgroups" {
    const allocator = std.testing.allocator;
    const bytes = try std.fs.cwd().readFileAlloc(allocator, "vectors/cairo/ec_op_parity.bin", 16 * 1024 * 1024);
    defer allocator.free(bytes);
    var cursor: usize = 8;
    const Read = struct {
        fn word(data: []const u8, at: *usize) u32 {
            const value = std.mem.readInt(u32, data[at.*..][0..4], .little);
            at.* += 4;
            return value;
        }
    };
    try std.testing.expectEqualSlices(u8, "STWZECO\x00", bytes[0..8]);
    try std.testing.expectEqual(@as(u32, 1), Read.word(bytes, &cursor));
    const fixture_rows = Read.word(bytes, &cursor);
    const segment = Read.word(bytes, &cursor);
    const n_addresses = Read.word(bytes, &cursor);
    const n_big = Read.word(bytes, &cursor);
    const n_small = Read.word(bytes, &cursor);
    try std.testing.expectEqual(@as(u32, 64), fixture_rows);
    const address_bytes: []align(4) const u8 = @alignCast(bytes[cursor .. cursor + @as(usize, n_addresses) * 4]);
    const addresses = std.mem.bytesAsSlice(u32, address_bytes);
    cursor += @as(usize, n_addresses) * 4;
    const big_bytes: []align(4) const u8 = @alignCast(bytes[cursor .. cursor + @as(usize, n_big) * 8 * 4]);
    const big_words = std.mem.bytesAsSlice(u32, big_bytes);
    cursor += @as(usize, n_big) * 8 * 4;
    const small_bytes: []align(4) const u8 = @alignCast(bytes[cursor .. cursor + @as(usize, n_small) * 4 * 4]);
    const small_words = std.mem.bytesAsSlice(u32, small_bytes);
    cursor += @as(usize, n_small) * 4 * 4;
    const trace_bytes: []align(4) const u8 = @alignCast(bytes[cursor .. cursor + @as(usize, fixture_rows) * 273 * 4]);
    const expected_trace = std.mem.bytesAsSlice(u32, trace_bytes);
    cursor += @as(usize, fixture_rows) * 273 * 4;
    cursor += @as(usize, fixture_rows) * 488 * 4;
    const fixture_partial_rows = @as(usize, fixture_rows) * 256;
    const partial_bytes: []align(4) const u8 = @alignCast(bytes[cursor .. cursor + fixture_partial_rows * 127 * 4]);
    const expected_partial = std.mem.bytesAsSlice(u32, partial_bytes);

    const rows: u32 = 512;
    const address_count = @max(addresses.len, @as(usize, segment) + @as(usize, rows) * 7);
    const expanded_addresses = try allocator.alloc(u32, address_count);
    defer allocator.free(expanded_addresses);
    @memset(expanded_addresses, 0);
    @memcpy(expanded_addresses[0..addresses.len], addresses);
    for (0..rows) |row| {
        const source = @as(usize, segment) + (row % fixture_rows) * 7;
        const destination = @as(usize, segment) + row * 7;
        @memcpy(expanded_addresses[destination..][0..7], addresses[source..][0..7]);
    }

    const partial_rows = @as(usize, rows) * 256;
    const total_words = address_count + @as(usize, n_big) * 28 + @as(usize, n_small) * 8 +
        @as(usize, rows) * (273 + 488) + partial_rows * 127 +
        address_count + @as(usize, n_big) + @as(usize, n_small) + 256 + 1;
    var runtime = try metal.Runtime.initFull();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(total_words * 4);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    var next: u32 = 0;
    var execution_offsets: [37]u32 = undefined;
    execution_offsets[0] = next;
    @memcpy(words[next .. next + address_count], expanded_addresses);
    next += @intCast(address_count);
    for (0..28) |limb| {
        execution_offsets[1 + limb] = next;
        const bit = limb * 9;
        const source_limb = bit / 32;
        const shift: u5 = @intCast(bit % 32);
        for (0..n_big) |index| {
            const source = big_words[index * 8 ..][0..8];
            var value = source[source_limb] >> shift;
            if (shift > 23 and source_limb + 1 < 8) value |= source[source_limb + 1] << @intCast(@as(u6, 32) - shift);
            words[next + index] = value & 0x1ff;
        }
        next += n_big;
    }
    for (0..8) |limb| {
        execution_offsets[29 + limb] = next;
        const bit = limb * 9;
        const source_limb = bit / 32;
        const shift: u5 = @intCast(bit % 32);
        for (0..n_small) |index| {
            const source = small_words[index * 4 ..][0..4];
            var value = source[source_limb] >> shift;
            if (shift > 23 and source_limb + 1 < 4) value |= source[source_limb + 1] << @intCast(@as(u6, 32) - shift);
            words[next + index] = value & 0x1ff;
        }
        next += n_small;
    }
    var trace_offsets: [273]u32 = undefined;
    for (&trace_offsets) |*offset| {
        offset.* = next;
        next += rows;
    }
    const lookup_offset = next;
    next += rows * 488;
    var partial_offsets: [127]u32 = undefined;
    for (&partial_offsets) |*offset| {
        offset.* = next;
        next += @intCast(partial_rows);
    }
    var multiplicity_offsets: [4]u32 = undefined;
    const multiplicity_lengths = [_]u32{ @intCast(address_count), n_big, n_small, 256 };
    for (&multiplicity_offsets, multiplicity_lengths) |*offset, length| {
        offset.* = next;
        next += length;
    }
    const segment_offset = next;
    words[next] = segment;
    next += 1;
    try std.testing.expect(@as(usize, next) <= total_words);

    var plan = try runtime.prepareEcOp(
        execution_offsets,
        trace_offsets,
        partial_offsets,
        multiplicity_offsets,
        lookup_offset,
        segment_offset,
        partial_offsets[126],
        rows,
        true,
        false,
    );
    defer plan.deinit();
    const poison: u32 = 0xa5a5a5a5;
    for (0..2) |_| {
        for (trace_offsets) |offset| @memset(words[offset .. offset + rows], poison);
        for (partial_offsets) |offset| @memset(words[offset .. offset + partial_rows], poison);
        for (multiplicity_offsets, multiplicity_lengths) |offset, length| @memset(words[offset .. offset + length], 0);
        _ = try runtime.ecOpPrepared(arena, plan);

        for (0..rows) |row| for (trace_offsets, 0..) |offset, column| {
            const source_row = row % fixture_rows;
            try std.testing.expectEqual(expected_trace[source_row * 273 + column], words[offset + row]);
        };
        for ([_]u32{ 0, 1, 251 }) |round| for (partial_offsets[0..126], 0..) |offset, column| for (0..rows) |row| {
            const expected = if (column == 0)
                @as(u32, @intCast(row))
            else
                expected_partial[column * fixture_partial_rows + @as(usize, round) * fixture_rows + row % fixture_rows];
            try std.testing.expectEqual(expected, words[offset + @as(usize, round) * rows + row]);
        };
        for (252..256) |round| for (partial_offsets[0..126], 0..) |offset, column| for (0..rows) |row| {
            const pad = (round - 252) * rows + row;
            const expected = if (column == 125) @as(u32, 0) else expected_partial[column * fixture_partial_rows + (pad & 15)];
            try std.testing.expectEqual(expected, words[offset + round * rows + row]);
        };
        for (words[partial_offsets[126] .. partial_offsets[126] + partial_rows], 0..) |value, index|
            try std.testing.expectEqual(@as(u32, @intCast(index)), value);
    }
}

test "metal: resident compact writer matches canonical multiset ordering" {
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(16 * 1024);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    const tuples = [_][3]u32{
        .{ 3, 2, 30 }, .{ 0, 5, 5 },  .{ 2, 2, 22 }, .{ 1, 9, 19 },
        .{ 2, 2, 22 }, .{ 3, 2, 30 }, .{ 0, 5, 5 },  .{ 2, 2, 22 },
        .{ 7, 1, 71 }, .{ 1, 9, 19 }, .{ 2, 2, 22 }, .{ 0, 5, 5 },
        .{ 3, 2, 30 }, .{ 2, 2, 22 }, .{ 0, 5, 5 },  .{ 2, 2, 22 },
    };
    var next: u32 = 0;
    var source_offsets: [2]u32 = undefined;
    for (&source_offsets, 0..) |*offset, source_index| {
        offset.* = next;
        for (0..3) |tuple_word| for (0..8) |row| {
            words[next + tuple_word * 8 + row] = tuples[source_index * 8 + row][tuple_word];
        };
        next += 24;
    }
    const descriptors = [_]u32{
        8, 0, 3, 1, 0,
        8, 0, 3, 1, 8,
    };
    const tuples_offset = next;
    next += 16 * 3;
    const indices_a_offset = next;
    next += 16;
    const indices_b_offset = next;
    next += 16;
    const counts_offset = next;
    next += 16;
    const radix_offsets_offset = next;
    next += 16;
    const bases_offset = next;
    next += 16;
    const heads_offset = next;
    next += 16;
    const positions_offset = next;
    next += 16;
    const block_sums_offset = next;
    next += 1;
    const error_offset = next;
    next += 1;
    const unique_offset = next;
    next += 1;
    var output_offsets: [6]u32 = undefined;
    for (&output_offsets) |*offset| {
        offset.* = next;
        next += 16;
    }
    try std.testing.expect(@as(usize, next) * 4 <= arena.byte_length);
    var plan = try runtime.prepareCompact(&source_offsets, &descriptors, &output_offsets, .{
        .tuple_words = 3,
        .key_words = 2,
        .total_rows = 16,
        .sort_rows = 16,
        .consumer_rows = 16,
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
        .enabler_slot = 3,
        .iota_slot = 4,
        .multiplicity_slot = 5,
    });
    defer plan.deinit();
    const gpu_ms = try runtime.compactPrepared(arena, plan);
    try std.testing.expect(gpu_ms > 0);
    try std.testing.expectEqual(@as(u32, 5), words[unique_offset]);
    const expected = [_][3]u32{ .{ 0, 5, 5 }, .{ 1, 9, 19 }, .{ 2, 2, 22 }, .{ 3, 2, 30 }, .{ 7, 1, 71 } };
    for (0..3) |tuple_word| {
        for (expected, 0..) |tuple, row| try std.testing.expectEqual(tuple[tuple_word], words[output_offsets[tuple_word] + row]);
        for (expected.len..16) |row| try std.testing.expectEqual(expected[0][tuple_word], words[output_offsets[tuple_word] + row]);
    }
    try std.testing.expectEqualSlices(u32, &.{ 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, words[output_offsets[3] .. output_offsets[3] + 16]);
    for (0..16) |row| try std.testing.expectEqual(@as(u32, @intCast(row)), words[output_offsets[4] + row]);
    try std.testing.expectEqualSlices(u32, &.{ 4, 2, 6, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, words[output_offsets[5] .. output_offsets[5] + 16]);

    words[source_offsets[1] + 2 * 8 + 5] = 23;
    _ = try runtime.compactPrepared(arena, plan);
    try std.testing.expectEqual(std.math.maxInt(u32), words[unique_offset]);
}

test "metal: resident witness feed matches scalar histogram" {
    var runtime = try metal.Runtime.initFull();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(16 * 1024);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    const inputs = [_]u32{ 0, 1, 1, 2, 2, 2, 3, 3 };
    @memcpy(words[0..inputs.len], &inputs);
    const count_offset: u32 = 64;
    try runtime.clearArenaRanges(arena, &.{.{ count_offset, 4 }});
    const none = std.math.maxInt(u32);
    const descriptor = [_]u32{
        0, 1, 2, 0, 0, 0, 0, // source word and tuple geometry
        0, 4, none, 0, 0, 0, 0, // relation/table/destination-table index/kind
    };
    var plan = try runtime.prepareWitnessFeed(&descriptor, &.{}, &.{count_offset}, &.{0}, &.{.{ count_offset, 4 }});
    defer plan.deinit();
    const gpu_ms = try runtime.witnessFeedCountsPrepared(arena, inputs.len, plan);
    try std.testing.expect(gpu_ms > 0);
    try std.testing.expectEqualSlices(u32, &.{ 1, 2, 3, 2 }, words[count_offset .. count_offset + 4]);
    _ = try runtime.witnessFeedCountsPrepared(arena, inputs.len, plan);
    try std.testing.expectEqualSlices(u32, &.{ 1, 2, 3, 2 }, words[count_offset .. count_offset + 4]);
}

test "metal: witness feed batch clears shared consumers once" {
    var runtime = try metal.Runtime.initFull();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(16 * 1024);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    @memcpy(words[0..4], &[_]u32{ 0, 1, 1, 2 });
    @memcpy(words[16..20], &[_]u32{ 1, 2, 3, 3 });
    const count_offset: u32 = 64;
    const none = std.math.maxInt(u32);
    const descriptor = [_]u32{
        0, 1, 2,    0, 0, 0, 0,
        0, 4, none, 0, 0, 0, 0,
    };
    const ranges = [_][2]u32{.{ count_offset, 4 }};
    var first = try runtime.prepareWitnessFeed(&descriptor, &.{}, &.{count_offset}, &.{0}, &ranges);
    var second = try runtime.prepareWitnessFeed(&descriptor, &.{}, &.{count_offset}, &.{16}, &ranges);
    const plans = [_]metal.WitnessFeedPlan{ first, second };
    var batch = try runtime.prepareWitnessFeedBatch(&plans, &.{ 4, 4 }, &ranges);
    defer batch.deinit();
    first.deinit();
    second.deinit();

    _ = try runtime.witnessFeedBatchCountsPrepared(arena, batch);
    try std.testing.expectEqualSlices(u32, &.{ 1, 3, 2, 2 }, words[count_offset .. count_offset + 4]);
    _ = try runtime.witnessFeedBatchCountsPrepared(arena, batch);
    try std.testing.expectEqualSlices(u32, &.{ 1, 3, 2, 2 }, words[count_offset .. count_offset + 4]);
}

test "metal: resident FRI folds and coordinate conversion match CPU" {
    const allocator = std.testing.allocator;
    const log_size: u32 = 10;
    const domain = canonic.CanonicCoset.new(log_size).circleDomain();
    var source = try MetalBackend.allocateSecureColumn(domain.size());
    defer source.deinit(allocator);
    for (source.columns, 0..) |column, coordinate| {
        for (column, 0..) |*value, index| {
            value.* = M31.fromCanonical(@intCast((coordinate * 65537 + index * 8191 + 19) % m31.Modulus));
        }
    }
    const alpha = QM31.fromU32Unchecked(7, 11, 13, 17);
    const line_domain = try line.LineDomain.init(@import("stwo_core").circle.Coset.halfOdds(log_size - 1));

    const expected = try allocator.alloc(QM31, line_domain.size());
    defer allocator.free(expected);
    @memset(expected, QM31.zero());
    var cpu_circle_workspace = try core_fri.FoldCircleWorkspace.init(allocator, expected.len);
    defer cpu_circle_workspace.deinit(allocator);
    try core_fri.foldCircleColumnsIntoLineWithWorkspace(
        allocator,
        expected,
        source.columns,
        domain,
        alpha,
        &cpu_circle_workspace,
    );

    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(64 * 1024);
    defer arena.deinit();
    const arena_words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    const source_offset: u32 = 0;
    const inverse_offset: u32 = @intCast(domain.size() * 4);
    const alpha_offset: u32 = inverse_offset + @as(u32, @intCast(line_domain.size()));
    const destination_offset: u32 = alpha_offset + 4;
    const source_words = std.mem.bytesAsSlice(
        u32,
        std.mem.sliceAsBytes(source.columns[0].ptr[0 .. domain.size() * 4]),
    );
    @memcpy(arena_words[source_offset .. source_offset + source_words.len], source_words);
    for (cpu_circle_workspace.inv_py_values[0..line_domain.size()], 0..) |value, row| {
        arena_words[inverse_offset + row] = value.v;
    }
    for (alpha.toM31Array(), 0..) |value, coordinate| arena_words[alpha_offset + coordinate] = value.v;
    var prepared = try runtime.prepareFriFold(
        source_offset,
        inverse_offset,
        alpha_offset,
        destination_offset,
        @intCast(domain.size()),
        true,
    );
    defer prepared.deinit();
    try std.testing.expect(try runtime.friFoldPrepared(arena, prepared) > 0);
    const prepared_values: [*]const QM31 = @ptrCast(@alignCast(arena_words + destination_offset));
    try std.testing.expectEqualSlices(QM31, expected, prepared_values[0..line_domain.size()]);

    var resident_line = try MetalBackend.allocateLineEvaluation(line_domain);
    defer resident_line.deinit(allocator);
    var gpu_circle_workspace = try core_fri.FoldCircleWorkspace.init(allocator, expected.len);
    defer gpu_circle_workspace.deinit(allocator);
    try MetalBackend.foldCircleIntoLine(
        allocator,
        @constCast(resident_line.values),
        source.columns,
        domain,
        alpha,
        &gpu_circle_workspace,
    );
    try std.testing.expectEqualSlices(QM31, expected, resident_line.values);

    const resident_telemetry_before = try MetalBackend.telemetrySnapshot();
    var coordinates = try MetalBackend.secureColumnFromLine(resident_line);
    defer coordinates.deinit(allocator);
    const resident_telemetry_after = try MetalBackend.telemetrySnapshot();
    const resident_telemetry_delta = resident_telemetry_after.delta(resident_telemetry_before);
    try std.testing.expectEqual(
        @as(u64, 1),
        resident_telemetry_delta.counters.metal_qm31_coordinate_dispatches,
    );
    for (expected, 0..) |value, index| try std.testing.expect(value.eql(coordinates.at(index)));

    const telemetry_before = resident_telemetry_after;
    var host_coordinates = try MetalBackend.secureColumnForMerkle(allocator, resident_line);
    defer host_coordinates.deinit(allocator);
    const telemetry_after = try MetalBackend.telemetrySnapshot();
    const telemetry_delta = telemetry_after.delta(telemetry_before);
    try std.testing.expect(!metal_commit_policy.secureColumnUsesResidentMerkle(resident_line.len()));
    try std.testing.expect(host_coordinates.resident_storage == null);
    try std.testing.expect(host_coordinates.contiguous);
    try std.testing.expectEqual(@as(u64, 0), telemetry_delta.counters.metal_qm31_coordinate_dispatches);
    for (expected, 0..) |value, index| try std.testing.expect(value.eql(host_coordinates.at(index)));

    var cpu_line_workspace = try core_fri.FoldLineWorkspace.init(allocator, expected.len / 2);
    defer cpu_line_workspace.deinit(allocator);
    const expected_fold = try core_fri.foldLineNWithWorkspace(
        allocator,
        expected,
        line_domain,
        alpha,
        &cpu_line_workspace,
        2,
    );
    defer allocator.free(expected_fold.values);

    var gpu_line_workspace = try core_fri.FoldLineWorkspace.init(allocator, expected.len / 2);
    defer gpu_line_workspace.deinit(allocator);
    var resident_fold = try MetalBackend.foldLineEvaluationN(
        allocator,
        resident_line,
        alpha,
        &gpu_line_workspace,
        2,
    );
    defer resident_fold.deinit(allocator);
    try std.testing.expectEqualSlices(QM31, expected_fold.values, resident_fold.values);
}
