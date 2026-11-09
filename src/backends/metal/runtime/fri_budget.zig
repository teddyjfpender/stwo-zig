//! Checked logical extents for the existing FRI buffer/framing ABI.
//! Caller-owned coordinates, source and terminal evaluations are excluded.
const std = @import("std");
pub const Extent = struct { peak_bytes: usize, retained_bytes: usize };

pub fn secureValues(count: usize) !usize {
    if (count == 0 or !std.math.isPowerOfTwo(count) or count > 1 << 30) return error.InvalidFriBudgetGeometry;
    return std.math.mul(usize, count, 16);
}

pub fn inverseCount(source_count: usize, layers: usize) !usize {
    if (source_count < 2 or !std.math.isPowerOfTwo(source_count) or source_count > 1 << 30 or layers == 0 or layers > std.math.log2_int(usize, source_count)) return error.InvalidFriBudgetGeometry;
    return source_count - (source_count >> @intCast(layers));
}

pub fn cascade(source_count: usize, layers: usize) !Extent {
    _ = try inverseCount(source_count, layers);
    // Exactly transcript root/alpha slots and 64-word alignment in the C ABI.
    var words = try alignWords(try std.math.add(usize, 16, try std.math.mul(usize, layers, 12)));
    var count = source_count;
    for (0..layers) |_| {
        var nodes = count;
        while (nodes > 1) : (nodes >>= 1) {
            words = try alignWords(words);
            words = try std.math.add(usize, words, try std.math.mul(usize, nodes, 8));
        }
        count >>= 1;
    }
    if (words > std.math.maxInt(u32)) return error.InvalidFriBudgetGeometry;
    const retained = try std.math.mul(usize, words, 4);
    // Only nonterminal folded destinations are private temporaries.
    const intermediate_values = (try inverseCount(source_count, layers)) - count;
    const temporary = try std.math.add(usize, 64, try std.math.mul(usize, intermediate_values, 16));
    return .{ .retained_bytes = retained, .peak_bytes = try std.math.add(usize, retained, temporary) };
}

pub fn foldedCommit(source_count: usize, layers: usize) !Extent {
    const inverses = try inverseCount(source_count, layers);
    const final_count = source_count >> @intCast(layers);
    // This ABI uses individual unpadded hash layers, unlike the cascade.
    const retained = try std.math.mul(usize, try std.math.sub(usize, try std.math.mul(usize, final_count, 2), 1), 32);
    var scratch = try std.math.add(usize, 64, try std.math.mul(usize, layers, 16));
    scratch = try std.math.add(usize, scratch, try std.math.mul(usize, inverses, 4));
    scratch = try std.math.add(usize, scratch, try std.math.mul(usize, inverses - final_count, 16));
    return .{ .retained_bytes = retained, .peak_bytes = try std.math.add(usize, retained, scratch) };
}

fn alignWords(words: usize) !usize {
    return (try std.math.add(usize, words, 63)) & ~@as(usize, 63);
}
