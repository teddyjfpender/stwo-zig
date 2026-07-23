const std = @import("std");
const m31 = @import("stwo_core").fields.m31;

const M31 = m31.M31;

/// Whether three adjacent stages can be fused while retaining packed,
/// contiguous lanes.
pub fn canFuseThreeLayersPacked(lowest_stage: u32) bool {
    if (lowest_stage >= @bitSizeOf(usize)) return false;
    const distance = @as(usize, 1) << @intCast(lowest_stage);
    return distance >= m31.PACK_WIDTH and distance % m31.PACK_WIDTH == 0;
}

fn run(
    values: []M31,
    log_size: u32,
    stage: u32,
    twiddles: []const M31,
    comptime inverse_transform: bool,
    comptime normalize: bool,
    normalization: M31,
    comptime duplicate_upper_from_lower: bool,
) void {
    std.debug.assert(log_size < @bitSizeOf(usize));
    std.debug.assert(values.len == @as(usize, 1) << @intCast(log_size));
    const pair_count = values.len / 2;
    std.debug.assert(twiddles.len >= pair_count);
    std.debug.assert(!normalize or inverse_transform);
    std.debug.assert(!duplicate_upper_from_lower or (!inverse_transform and !normalize));

    const lowest_stage = if (inverse_transform) stage else stage - 2;
    std.debug.assert(canFuseThreeLayersPacked(lowest_stage));
    std.debug.assert(if (inverse_transform) stage + 2 < log_size else stage >= 2 and stage < log_size);

    const distance = @as(usize, 1) << @intCast(lowest_stage);
    const group_count = values.len >> @intCast(lowest_stage + 3);
    std.debug.assert(!duplicate_upper_from_lower or group_count == 2);
    const PW = m31.PACK_WIDTH;
    const normalization_packed: m31.PackedM31 = @splat(normalization.v);

    // Expansion starts with the upper group while its lower-half source is
    // intact. Normal transforms retain ascending traversal.
    var group_cursor: usize = if (duplicate_upper_from_lower) group_count else 0;
    while (if (duplicate_upper_from_lower) group_cursor > 0 else group_cursor < group_count) {
        if (duplicate_upper_from_lower) group_cursor -= 1;
        const group = group_cursor;
        const base = group << @intCast(lowest_stage + 3);
        const load_base = if (duplicate_upper_from_lower and group == 1) 0 else base;
        var lane: usize = 0;
        while (lane < distance) : (lane += PW) {
            var tuple: [8]m31.PackedM31 = undefined;
            inline for (0..8) |item| {
                tuple[item] = m31.loadPacked(values.ptr + load_base + lane + item * distance);
            }

            inline for (0..3) |step| {
                const substage = if (inverse_transform)
                    stage + @as(u32, @intCast(step))
                else
                    stage - @as(u32, @intCast(step));
                const half_span: usize = if (inverse_transform)
                    @as(usize, 1) << @intCast(step)
                else
                    @as(usize, 4) >> @intCast(step);
                const block_count = 4 / half_span;
                const twiddle_offset = pair_count -
                    (@as(usize, 1) << @intCast(log_size - substage));

                inline for (0..block_count) |block| {
                    const raw_twiddle = twiddles[twiddle_offset + group * block_count + block];
                    const twiddle: m31.PackedM31 = @splat(
                        if (inverse_transform and normalize and step == 2)
                            raw_twiddle.mul(normalization).v
                        else
                            raw_twiddle.v,
                    );
                    const block_start = block * (half_span * 2);
                    inline for (0..half_span) |item| {
                        const lo = block_start + item;
                        const hi = lo + half_span;
                        const lhs = tuple[lo];
                        const rhs = tuple[hi];
                        if (inverse_transform) {
                            tuple[lo] = if (normalize and step == 2)
                                m31.mulPacked(m31.addPacked(lhs, rhs), normalization_packed)
                            else
                                m31.addPacked(lhs, rhs);
                            tuple[hi] = m31.mulPacked(m31.subPacked(lhs, rhs), twiddle);
                        } else {
                            const product = m31.mulPacked(rhs, twiddle);
                            tuple[lo] = m31.addPacked(lhs, product);
                            tuple[hi] = m31.subPacked(lhs, product);
                        }
                    }
                }
            }

            inline for (0..8) |item| {
                m31.storePacked(values.ptr + base + lane + item * distance, tuple[item]);
            }
        }
        if (!duplicate_upper_from_lower) group_cursor += 1;
    }
}

fn runForwardBatch(
    values_batch: []const []M31,
    log_size: u32,
    highest_stage: u32,
    twiddles: []const M31,
    comptime duplicate_upper_from_lower: bool,
) void {
    std.debug.assert(values_batch.len != 0);
    std.debug.assert(log_size < @bitSizeOf(usize));
    const values_len = @as(usize, 1) << @intCast(log_size);
    for (values_batch) |values| std.debug.assert(values.len == values_len);
    const pair_count = values_len / 2;
    std.debug.assert(twiddles.len >= pair_count);

    const lowest_stage = highest_stage - 2;
    std.debug.assert(canFuseThreeLayersPacked(lowest_stage));
    std.debug.assert(highest_stage >= 2 and highest_stage < log_size);

    const distance = @as(usize, 1) << @intCast(lowest_stage);
    const group_count = values_len >> @intCast(lowest_stage + 3);
    std.debug.assert(!duplicate_upper_from_lower or group_count == 2);
    const PW = m31.PACK_WIDTH;

    var group_cursor: usize = if (duplicate_upper_from_lower) group_count else 0;
    while (if (duplicate_upper_from_lower) group_cursor > 0 else group_cursor < group_count) {
        if (duplicate_upper_from_lower) group_cursor -= 1;
        const group = group_cursor;
        const base = group << @intCast(lowest_stage + 3);
        const load_base = if (duplicate_upper_from_lower and group == 1) 0 else base;

        // Every buffer uses the same transform geometry and twiddle tree.
        // Load each stage's 1+2+4 packed twiddles once for the whole group.
        var group_twiddles: [7]m31.PackedM31 = undefined;
        inline for (0..3) |step| {
            const substage = highest_stage - @as(u32, @intCast(step));
            const half_span: usize = @as(usize, 4) >> @intCast(step);
            const block_count = 4 / half_span;
            const packed_offset = (@as(usize, 1) << @intCast(step)) - 1;
            const twiddle_offset = pair_count -
                (@as(usize, 1) << @intCast(log_size - substage));
            inline for (0..block_count) |block| {
                group_twiddles[packed_offset + block] = @splat(
                    twiddles[twiddle_offset + group * block_count + block].v,
                );
            }
        }

        for (values_batch) |values| {
            var lane: usize = 0;
            while (lane < distance) : (lane += PW) {
                var tuple: [8]m31.PackedM31 = undefined;
                inline for (0..8) |item| {
                    tuple[item] = m31.loadPacked(values.ptr + load_base + lane + item * distance);
                }

                inline for (0..3) |step| {
                    const half_span: usize = @as(usize, 4) >> @intCast(step);
                    const block_count = 4 / half_span;
                    const packed_offset = (@as(usize, 1) << @intCast(step)) - 1;
                    inline for (0..block_count) |block| {
                        const twiddle = group_twiddles[packed_offset + block];
                        const block_start = block * (half_span * 2);
                        inline for (0..half_span) |item| {
                            const lo = block_start + item;
                            const hi = lo + half_span;
                            const lhs = tuple[lo];
                            const product = m31.mulPacked(tuple[hi], twiddle);
                            tuple[lo] = m31.addPacked(lhs, product);
                            tuple[hi] = m31.subPacked(lhs, product);
                        }
                    }
                }

                inline for (0..8) |item| {
                    m31.storePacked(values.ptr + base + lane + item * distance, tuple[item]);
                }
            }
        }
        if (!duplicate_upper_from_lower) group_cursor += 1;
    }
}

pub fn forward(
    values: []M31,
    log_size: u32,
    highest_stage: u32,
    twiddles: []const M31,
) void {
    run(values, log_size, highest_stage, twiddles, false, false, M31.one(), false);
}

pub fn forwardBatch(
    values_batch: []const []M31,
    log_size: u32,
    highest_stage: u32,
    twiddles: []const M31,
) void {
    runForwardBatch(values_batch, log_size, highest_stage, twiddles, false);
}

pub fn forwardFromDuplicatedHalf(
    values: []M31,
    log_size: u32,
    highest_stage: u32,
    twiddles: []const M31,
) void {
    run(values, log_size, highest_stage, twiddles, false, false, M31.one(), true);
}

pub fn forwardBatchFromDuplicatedHalf(
    values_batch: []const []M31,
    log_size: u32,
    highest_stage: u32,
    twiddles: []const M31,
) void {
    runForwardBatch(values_batch, log_size, highest_stage, twiddles, true);
}

pub fn inverse(
    values: []M31,
    log_size: u32,
    lowest_stage: u32,
    itwiddles: []const M31,
) void {
    run(values, log_size, lowest_stage, itwiddles, true, false, M31.one(), false);
}

pub fn inverseNormalized(
    values: []M31,
    log_size: u32,
    lowest_stage: u32,
    itwiddles: []const M31,
    normalization: M31,
) void {
    run(values, log_size, lowest_stage, itwiddles, true, true, normalization, false);
}

test "batched forward matches independent packed radix-8 transforms" {
    const log_size: u32 = 10;
    const value_count = @as(usize, 1) << @intCast(log_size);
    const pair_count = value_count / 2;
    var prng = std.Random.DefaultPrng.init(0xb7e1_5162_8aed_2a6b);
    const random = prng.random();

    const input = try std.testing.allocator.alloc(M31, value_count);
    defer std.testing.allocator.free(input);
    const input_b = try std.testing.allocator.alloc(M31, value_count);
    defer std.testing.allocator.free(input_b);
    const expected = try std.testing.allocator.alloc(M31, value_count);
    defer std.testing.allocator.free(expected);
    const expected_b = try std.testing.allocator.alloc(M31, value_count);
    defer std.testing.allocator.free(expected_b);
    const batch_a = try std.testing.allocator.alloc(M31, value_count);
    defer std.testing.allocator.free(batch_a);
    const batch_b = try std.testing.allocator.alloc(M31, value_count);
    defer std.testing.allocator.free(batch_b);
    const twiddles = try std.testing.allocator.alloc(M31, pair_count);
    defer std.testing.allocator.free(twiddles);

    for (input) |*value| value.* = M31.fromCanonical(
        random.intRangeLessThan(u32, 0, m31.Modulus),
    );
    for (input_b) |*value| value.* = M31.fromCanonical(
        random.intRangeLessThan(u32, 0, m31.Modulus),
    );
    for (twiddles) |*value| value.* = M31.fromCanonical(
        random.intRangeLessThan(u32, 1, m31.Modulus),
    );

    for ([_]u32{ 9, 5 }) |highest_stage| {
        @memcpy(expected, input);
        @memcpy(expected_b, input_b);
        forward(expected, log_size, highest_stage, twiddles);
        forward(expected_b, log_size, highest_stage, twiddles);
        @memcpy(batch_a, input);
        @memcpy(batch_b, input_b);
        const batch = [_][]M31{ batch_a, batch_b };
        forwardBatch(&batch, log_size, highest_stage, twiddles);
        try std.testing.expectEqualSlices(M31, expected, batch_a);
        try std.testing.expectEqualSlices(M31, expected_b, batch_b);
    }

    @memcpy(expected, input);
    @memcpy(expected_b, input_b);
    @memcpy(expected[value_count / 2 ..], expected[0 .. value_count / 2]);
    @memcpy(expected_b[value_count / 2 ..], expected_b[0 .. value_count / 2]);
    forward(expected, log_size, 8, twiddles);
    forward(expected_b, log_size, 8, twiddles);
    @memcpy(batch_a, input);
    @memcpy(batch_b, input_b);
    const expansion_batch = [_][]M31{ batch_a, batch_b };
    forwardBatchFromDuplicatedHalf(&expansion_batch, log_size, 8, twiddles);
    try std.testing.expectEqualSlices(M31, expected, batch_a);
    try std.testing.expectEqualSlices(M31, expected_b, batch_b);
}
