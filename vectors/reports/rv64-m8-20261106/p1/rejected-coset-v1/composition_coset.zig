//! Compact inputs and half-domain twiddles for an unchanged rl+2 AIR role.
//! A trace-row mask preserves each half of the bit-reversed rl+2 domain.
//! Each half is evaluated at rl+1, using its original denominator slice.
const std = @import("std");

pub fn supportsGeometry(trace_log: u32, eval_log: u32) bool {
    return eval_log >= 20 and eval_log <= 28 and trace_log == eval_log - 2;
}

pub const Selection = struct {
    /// Flattened indices in the original FIXED, MAIN, INTER source roster.
    source_indices: []usize,
    /// One packed column slot per authenticated input mask, including aliases.
    mask_slots: []u32,

    pub fn init(a: std.mem.Allocator, widths: [3]usize, inputs: anytype) !Selection {
        const second = try std.math.add(usize, widths[0], widths[1]);
        const total = try std.math.add(usize, second, widths[2]);
        if (inputs.len == 0 or total > std.math.maxInt(u32)) return error.InvalidCosetInputs;
        const bases = [_]usize{ 0, widths[0], second };
        const slots = try a.alloc(u32, total);
        defer a.free(slots);
        const missing = std.math.maxInt(u32);
        @memset(slots, missing);
        for (inputs) |input| {
            if (input.tree >= 3 or input.column >= widths[input.tree]) return error.InvalidCosetInputs;
            slots[bases[input.tree] + input.column] = 0;
        }
        var count: usize = 0;
        for (slots) |slot| if (slot != missing) {
            count += 1;
        };
        const sources = try a.alloc(usize, count);
        errdefer a.free(sources);
        var at: usize = 0;
        for (slots, 0..) |*slot, i| if (slot.* != missing) {
            slot.* = @intCast(at);
            sources[at] = i;
            at += 1;
        };
        const masks = try a.alloc(u32, inputs.len);
        errdefer a.free(masks);
        for (inputs, masks) |input, *mask| mask.* = slots[bases[input.tree] + input.column];
        return .{ .source_indices = sources, .mask_slots = masks };
    }

    pub fn deinit(self: *Selection, a: std.mem.Allocator) void {
        a.free(self.source_indices);
        a.free(self.mask_slots);
        self.* = undefined;
    }
};

/// Select one subtree from every layer of the original forward twiddle tower.
/// This is NOT the canonical smaller-domain tower (nor its contiguous suffix).
/// The first global FFT stage only copies coefficients: its high half is zero.
pub fn packTwiddles(a: std.mem.Allocator, full: []const u32, half: u1) ![]u32 {
    if (full.len < 8 or !std.math.isPowerOfTwo(full.len)) return error.InvalidCosetTwiddles;
    const out = try a.alloc(u32, full.len / 2);
    errdefer a.free(out);
    var count: usize = 1;
    while (count < out.len) : (count *= 2) {
        const target = out.len - 2 * count;
        const source = full.len - 4 * count + @as(usize, half) * count;
        @memcpy(out[target..][0..count], full[source..][0..count]);
    }
    // The tower's unit entry is not read by the transform, but retain its law.
    out[out.len - 1] = 1;
    return out;
}

pub fn arenaWords(active_columns: usize, eval_log: u32) !u64 {
    if (active_columns == 0 or eval_log < 6 or eval_log > 28) return error.InvalidCosetGeometry;
    const tile_rows = @as(u64, 1) << @intCast(eval_log - 1);
    // Selected LDE columns, eight-coordinate output tile, packed twiddles.
    return std.math.add(u64, try std.math.mul(u64, try std.math.add(u64, active_columns, 8), tile_rows), tile_rows / 2);
}

test "coset selection preserves trees, aliases and original source indices" {
    const Input = struct { tree: u8, column: u32, offset: i8 = 0 };
    var selected = try Selection.init(std.testing.allocator, .{ 3, 4, 2 }, &[_]Input{
        .{ .tree = 1, .column = 2 },               .{ .tree = 0, .column = 2 },
        .{ .tree = 1, .column = 2, .offset = -1 }, .{ .tree = 2, .column = 1 },
    });
    defer selected.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(usize, &.{ 2, 5, 8 }, selected.source_indices);
    try std.testing.expectEqualSlices(u32, &.{ 1, 0, 1, 2 }, selected.mask_slots);
    try std.testing.expectError(error.InvalidCosetInputs, Selection.init(std.testing.allocator, .{ 3, 4, 2 }, &[_]Input{.{ .tree = 2, .column = 2 }}));
}

// Independent stagewise reference for the production CUDA circle N2B. Tests
// compare full-domain results with packed halves, including nontrivial words.
fn referenceFft(values: []u32, twiddles: []const u32) void {
    const prime: u64 = 2147483647;
    const log = std.math.log2_int(usize, values.len);
    var stage: usize = 1;
    while (stage <= log) : (stage += 1) {
        const stride = @as(usize, 1) << @intCast(log - stage);
        for (0..values.len / 2) |pair| {
            const butterfly = pair / stride;
            const left = pair % stride + butterfly * 2 * stride;
            const right = left + stride;
            const tw: u64 = if (stage == log) blk: {
                const v = twiddles[2 * (butterfly / 4) + @intFromBool(butterfly % 4 < 2)];
                break :blk if (butterfly % 4 == 1 or butterfly % 4 == 2) (prime - v) % prime else v;
            } else twiddles[values.len / 2 - (@as(usize, 1) << @intCast(stage)) + butterfly];
            const product = @as(u64, values[right]) * tw % prime;
            const first: u64 = values[left];
            values[left] = @intCast((first + product) % prime);
            values[right] = @intCast((first + prime - product) % prime);
        }
    }
}

test "packed cosets match the full circle FFT and trace-row masks" {
    const a = std.testing.allocator;
    const offsetRow = @import("stwo_core").utils.offsetBitReversedCircleDomainIndex;
    var prng = std.Random.DefaultPrng.init(17);
    const random = prng.random();
    for (5..11) |log| {
        const n = @as(usize, 1) << @intCast(log);
        const tw = try a.alloc(u32, n / 2);
        defer a.free(tw);
        for (tw) |*v| v.* = random.uintLessThan(u32, 2147483647);
        const coefficients = try a.alloc(u32, n / 4);
        defer a.free(coefficients);
        for (coefficients) |*v| v.* = random.uintLessThan(u32, 2147483647);
        const expected = try a.alloc(u32, n);
        defer a.free(expected);
        @memset(expected, 0);
        @memcpy(expected[0..coefficients.len], coefficients);
        referenceFft(expected, tw);
        for (0..2) |half| {
            const tile_twiddles = try packTwiddles(a, tw, @intCast(half));
            defer a.free(tile_twiddles);
            const actual = try a.alloc(u32, n / 2);
            defer a.free(actual);
            @memset(actual, 0);
            @memcpy(actual[0..coefficients.len], coefficients);
            referenceFft(actual, tile_twiddles);
            try std.testing.expectEqualSlices(u32, expected[half * (n / 2) ..][0 .. n / 2], actual);
            for (0..n / 2) |row| for ([_]isize{ -7, -2, -1, 0, 1, 2, 7 }) |offset| {
                const global = offsetRow(half * (n / 2) + row, @intCast(log - 2), @intCast(log), offset);
                const local = offsetRow(row, @intCast(log - 2), @intCast(log - 1), offset);
                try std.testing.expectEqual(half * (n / 2) + local, global);
            };
        }
    }
}
