//! Logical MTLBuffer extents for the existing uniform commitment ABI.
//! Host no-copy arenas/aliases are already heap charged; only private copies,
//! hash storage and device descriptor buffers enter these external extents.
//! NSObject/NSData/command/framework overhead is outside this accounting.
const std = @import("std");
pub const Extent = struct { peak_bytes: usize, retained_bytes: usize };

pub fn merkleBytes(log: u32) !usize {
    if (log == 0 or log >= 31) return error.InvalidResidentBudgetGeometry;
    var count: usize = @as(usize, 1) << @intCast(log);
    var words: usize = 0;
    for (0..log + 1) |_| {
        // Exactly the 64-word layer alignment in circle_commit_epoch.m.
        words = (try std.math.add(usize, words, 63)) & ~@as(usize, 63);
        words = try std.math.add(usize, words, try std.math.mul(usize, count, 8));
        count >>= 1;
    }
    return std.math.mul(usize, words, 4);
}

pub fn commitment(log: u32, columns: usize, inverse_copy_bytes: usize, forward_copy_bytes: usize, source_copy_bytes: usize) !Extent {
    if (columns == 0 or columns > 256) return error.InvalidResidentBudgetGeometry;
    const retained = try merkleBytes(log);
    // Three column routing buffers, leaf seed and parent-chain seed. Twiddle
    // and source copies are passed only for actual non-alias upload branches.
    var peak = try std.math.add(usize, retained, try std.math.add(usize, try std.math.mul(usize, columns, 12), 64));
    peak = try std.math.add(usize, peak, inverse_copy_bytes);
    peak = try std.math.add(usize, peak, forward_copy_bytes);
    peak = try std.math.add(usize, peak, source_copy_bytes);
    return .{ .peak_bytes = peak, .retained_bytes = retained };
}

pub fn copiedBytes(pointer: usize, bytes: usize, page_size: usize) !usize {
    if (page_size == 0 or !std.math.isPowerOfTwo(page_size)) return error.InvalidResidentBudgetAlignment;
    return if (pointer % page_size == 0 and bytes % page_size == 0) 0 else bytes;
}

pub fn interaction(rows: usize, planes: usize, inputs: usize, parameters: usize) !Extent {
    if (rows < 2 or rows > 1 << 24 or !std.math.isPowerOfTwo(rows) or (planes != 2 and planes != 17 and planes != 23) or inputs == 0 or inputs > 512) return error.InvalidResidentBudgetGeometry;
    const retained = try std.math.mul(usize, try std.math.mul(usize, planes, 16), rows + 1);
    const scratch = try std.math.mul(usize, try std.math.mul(usize, planes, 16), (rows + 255) / 256);
    const offsets = try std.math.mul(usize, inputs, 8);
    const profiles = @max(@as(usize, 4), try std.math.mul(usize, parameters, 16));
    // Four reserved relation words plus the checked status word.
    const descriptors = try std.math.add(usize, try std.math.add(usize, offsets, profiles), 20);
    return .{ .retained_bytes = retained, .peak_bytes = try std.math.add(usize, try std.math.add(usize, retained, scratch), descriptors) };
}
