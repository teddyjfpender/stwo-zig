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
    first_unit: usize,
    end_unit: usize,
    comptime ranged: bool,
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
    const units_per_group = distance / PW;
    std.debug.assert(first_unit <= end_unit and end_unit <= values.len / (8 * PW));
    if (first_unit == end_unit) return;
    const first_group = if (ranged) first_unit / units_per_group else 0;
    const end_group = if (ranged) (end_unit + units_per_group - 1) / units_per_group else group_count;
    var group_cursor: usize = if (duplicate_upper_from_lower) end_group else first_group;
    while (if (duplicate_upper_from_lower) group_cursor > first_group else group_cursor < end_group) {
        if (duplicate_upper_from_lower) group_cursor -= 1;
        const group = group_cursor;
        const base = group << @intCast(lowest_stage + 3);
        const load_base = if (duplicate_upper_from_lower and group == 1) 0 else base;
        const group_unit = group * units_per_group;
        var lane: usize = if (ranged) (if (first_unit > group_unit) first_unit - group_unit else 0) * PW else 0;
        const end_lane = if (ranged) @min(units_per_group, end_unit - group_unit) * PW else distance;
        while (lane < end_lane) : (lane += PW) {
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
                // A larger canonical tower stores this transform's twiddles
                // in its suffix, just as the scalar layer kernels expect.
                const twiddle_offset = twiddles.len -
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
    run(values, log_size, highest_stage, twiddles, false, false, M31.one(), false, 0, values.len / (8 * m31.VEC_WIDTH), false);
}

pub fn forwardFromDuplicatedHalf(
    values: []M31,
    log_size: u32,
    highest_stage: u32,
    twiddles: []const M31,
) void {
    run(values, log_size, highest_stage, twiddles, false, false, M31.one(), true, 0, values.len / (8 * m31.VEC_WIDTH), false);
}

pub fn inverse(
    values: []M31,
    log_size: u32,
    lowest_stage: u32,
    itwiddles: []const M31,
) void {
    run(values, log_size, lowest_stage, itwiddles, true, false, M31.one(), false, 0, values.len / (8 * m31.VEC_WIDTH), false);
}

pub fn inverseNormalized(
    values: []M31,
    log_size: u32,
    lowest_stage: u32,
    itwiddles: []const M31,
    normalization: M31,
) void {
    run(values, log_size, lowest_stage, itwiddles, true, true, normalization, false, 0, values.len / (8 * m31.VEC_WIDTH), false);
}

/// Splits independent radix tuples, including lanes within one giant group.
/// Duplicated-half expansion joins the upper group before overwriting its source.
pub fn withPool(
    values: []M31,
    log_size: u32,
    stage: u32,
    twiddles: []const M31,
    comptime inverse_transform: bool,
    comptime normalize: bool,
    normalization: M31,
    comptime duplicate_upper_from_lower: bool,
    pool: *@import("../../work_pool.zig").WorkPool,
) void {
    const Pool = @import("../../work_pool.zig");
    const Work = struct {
        values: []M31,
        log_size: u32,
        stage: u32,
        twiddles: []const M31,
        normalization: M31,
        cursor: *std.atomic.Value(usize),
        end: usize,
        fn execute(work: *const @This()) void {
            while (true) {
                const first = work.cursor.fetchAdd(1024, .monotonic);
                if (first >= work.end) return;
                run(work.values, work.log_size, work.stage, work.twiddles, inverse_transform, normalize, work.normalization, duplicate_upper_from_lower, first, @min(first + 1024, work.end), true);
            }
        }
    };
    const units = values.len / (8 * m31.VEC_WIDTH);
    const phases: usize = if (duplicate_upper_from_lower) 2 else 1;
    for (0..phases) |phase| {
        const first = if (duplicate_upper_from_lower and phase == 0) units / 2 else 0;
        const end = if (duplicate_upper_from_lower and phase == 1) units / 2 else units;
        var cursor = std.atomic.Value(usize).init(first);
        const workers = @max(@as(usize, 1), @min(pool.workerCount(), (end - first + 1023) / 1024));
        var work: [Pool.MAX_WORKERS]Work = undefined;
        for (work[0..workers]) |*item| item.* = .{ .values = values, .log_size = log_size, .stage = stage, .twiddles = twiddles, .normalization = normalization, .cursor = &cursor, .end = end };
        var group: std.Thread.WaitGroup = .{};
        for (work[1..workers]) |*item| pool.spawnWg(&group, Work.execute, .{@as(*const Work, item)});
        Work.execute(&work[0]);
        group.wait();
    }
}
