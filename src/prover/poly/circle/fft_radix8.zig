const std = @import("std");
const m31 = @import("stwo_core").fields.m31;

const M31 = m31.M31;

/// Whether three adjacent stages can be fused while retaining packed,
/// contiguous lanes.
pub fn canFuseThreeLayersPacked(lowest_stage: u32) bool {
    if (lowest_stage >= @bitSizeOf(usize)) return false;
    const distance = @as(usize, 1) << @intCast(lowest_stage);
    return distance >= m31.VEC_WIDTH and distance % m31.VEC_WIDTH == 0;
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
    // Keep the radix tuple on the portable four-lane primitives. Native x86
    // u32 widths widen the u64 products beyond the target's vector width and
    // Zig 0.15.2 miscompiles later radix groups.
    const PW = m31.VEC_WIDTH;
    const normalization_packed: m31.Vec4u32 = @splat(normalization.v);

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
            var tuple: [8]m31.Vec4u32 = undefined;
            inline for (0..8) |item| {
                tuple[item] = m31.loadVec4(values.ptr + load_base + lane + item * distance);
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
                    const twiddle: m31.Vec4u32 = @splat(
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
                                m31.mulVec4(m31.addVec4(lhs, rhs), normalization_packed)
                            else
                                m31.addVec4(lhs, rhs);
                            tuple[hi] = m31.mulVec4(m31.subVec4(lhs, rhs), twiddle);
                        } else {
                            const product = m31.mulVec4(rhs, twiddle);
                            tuple[lo] = m31.addVec4(lhs, product);
                            tuple[hi] = m31.subVec4(lhs, product);
                        }
                    }
                }
            }

            inline for (0..8) |item| {
                m31.storeVec4(values.ptr + base + lane + item * distance, tuple[item]);
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

pub fn forwardFromDuplicatedHalf(
    values: []M31,
    log_size: u32,
    highest_stage: u32,
    twiddles: []const M31,
) void {
    run(values, log_size, highest_stage, twiddles, false, false, M31.one(), true);
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
