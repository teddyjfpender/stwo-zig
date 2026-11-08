//! Deterministic, reusable C-013 Poseidon2 input corpus.

const std = @import("std");

pub const modulus: u32 = 0x7fff_ffff;
pub const lanes: usize = 16;
pub const maximum_calls: usize = 4096;

pub fn makeInput(allocator: std.mem.Allocator, call_count: usize) ![]u8 {
    if (call_count > maximum_calls) return error.CallCountOutOfRange;
    const word_count = try std.math.add(
        usize,
        1,
        try std.math.mul(usize, call_count, lanes),
    );
    const bytes = try allocator.alloc(u8, try std.math.mul(
        usize,
        word_count,
        @sizeOf(u32),
    ));
    std.mem.writeInt(u32, bytes[0..4], @intCast(call_count), .little);
    var random_state: u64 = 0x6a09_e667_f3bc_c909;
    for (0..call_count) |call| {
        for (0..lanes) |lane| {
            const value: u32 = if (call == 0)
                @intCast(lane)
            else value: {
                random_state +%= 0x9e37_79b9_7f4a_7c15;
                var mixed = random_state;
                mixed = (mixed ^ (mixed >> 30)) *% 0xbf58_476d_1ce4_e5b9;
                mixed = (mixed ^ (mixed >> 27)) *% 0x94d0_49bb_1331_11eb;
                mixed ^= mixed >> 31;
                break :value @intCast(mixed % modulus);
            };
            const word_index = 1 + call * lanes + lane;
            std.mem.writeInt(
                u32,
                bytes[4 * word_index ..][0..4],
                value,
                .little,
            );
        }
    }
    return bytes;
}

pub fn defaultMaxSteps(call_count: usize) !usize {
    return defaultMaxStepsForBackground(call_count, 0);
}

/// Conservative execution guard for one measured permutation plus an exact
/// number of portable background permutations per call. This changes only the
/// hang bound; proofs retain the actual executed row count.
pub fn defaultMaxStepsForBackground(
    call_count: usize,
    background_permutations_per_call: usize,
) !usize {
    if (call_count > maximum_calls) return error.CallCountOutOfRange;
    const permutations_per_call = try std.math.add(
        usize,
        background_permutations_per_call,
        1,
    );
    return std.math.add(
        usize,
        100_000,
        try std.math.mul(
            usize,
            call_count,
            try std.math.mul(usize, permutations_per_call, 100_000),
        ),
    );
}

test "C-013 pair input is deterministic canonical and boundary sized" {
    const first = try makeInput(std.testing.allocator, 8);
    defer std.testing.allocator.free(first);
    const second = try makeInput(std.testing.allocator, 8);
    defer std.testing.allocator.free(second);
    try std.testing.expectEqualSlices(u8, first, second);
    try std.testing.expectEqual(@as(usize, 4 + 8 * lanes * 4), first.len);
    for (1..1 + 8 * lanes) |word| {
        try std.testing.expect(
            std.mem.readInt(u32, first[4 * word ..][0..4], .little) < modulus,
        );
    }
}
