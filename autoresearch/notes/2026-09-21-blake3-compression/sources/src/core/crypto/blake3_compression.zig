//! Canonical BLAKE3 compression schedule, shared with typed arithmetic authorship.
//! The production streaming hash still uses the independently implemented std hash.
const std = @import("std");
pub const IV = [8]u32{ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
pub const PERMUTATION = [16]usize{ 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 };
pub const G_INDICES = [8][4]usize{
    .{ 0, 4, 8, 12 },  .{ 1, 5, 9, 13 },  .{ 2, 6, 10, 14 }, .{ 3, 7, 11, 15 },
    .{ 0, 5, 10, 15 }, .{ 1, 6, 11, 12 }, .{ 2, 7, 8, 13 },  .{ 3, 4, 9, 14 },
};
pub fn g(comptime Ops: type, ops: *Ops, input: [6]Ops.Word) ![4]Ops.Word {
    var a = input[0];
    var b = input[1];
    var c = input[2];
    var d = input[3];
    a = try ops.add(try ops.add(a, b), input[4]);
    d = try ops.xorRotate(d, a, 16);
    c = try ops.add(c, d);
    b = try ops.xorRotate(b, c, 12);
    a = try ops.add(try ops.add(a, b), input[5]);
    d = try ops.xorRotate(d, a, 8);
    c = try ops.add(c, d);
    b = try ops.xorRotate(b, c, 7);
    return .{ a, b, c, d };
}
pub const Native = struct {
    pub const Word = u32;
    pub fn add(_: *Native, a: u32, b: u32) !u32 {
        return a +% b;
    }
    pub fn xorRotate(_: *Native, a: u32, b: u32, comptime rotation: u5) !u32 {
        return std.math.rotr(u32, a ^ b, rotation);
    }
};
pub const Call = struct { round: u8, slot: u8, input: [6]u32, output: [4]u32 };
pub const Trace = struct {
    calls: [56]Call = undefined,
    output: [16]u32 = undefined,
    count: usize = 0,
    fn record(self: *Trace, call: Call) void {
        self.calls[self.count] = call;
        self.count += 1;
    }
};
const Ignore = struct {
    fn record(_: *Ignore, _: Call) void {}
};
pub fn trace(cv: [8]u32, block: [16]u32, counter: u64, block_len: u32, flags: u32) !Trace {
    var result = Trace{};
    result.output = try compressObserved(cv, block, counter, block_len, flags, &result);
    std.debug.assert(result.count == result.calls.len);
    return result;
}
pub fn compress(cv: [8]u32, block: [16]u32, counter: u64, block_len: u32, flags: u32) ![16]u32 {
    var ignore = Ignore{};
    return compressObserved(cv, block, counter, block_len, flags, &ignore);
}
fn compressObserved(cv: [8]u32, block: [16]u32, counter: u64, block_len: u32, flags: u32, observer: anytype) ![16]u32 {
    if (block_len > 64) return error.InvalidBlake3BlockLength;
    var state: [16]u32 = cv ++ IV[0..4].* ++ [4]u32{ @truncate(counter), @truncate(counter >> 32), block_len, flags };
    var message = block;
    var ops = Native{};
    for (0..7) |round| {
        for (G_INDICES, 0..) |indices, i| {
            const input = [6]u32{ state[indices[0]], state[indices[1]], state[indices[2]], state[indices[3]], message[2 * i], message[2 * i + 1] };
            const result = try g(Native, &ops, input);
            observer.record(.{ .round = @intCast(round), .slot = @intCast(i), .input = input, .output = result });
            for (indices, result) |index, value| state[index] = value;
        }
        const old = message;
        for (&message, PERMUTATION) |*word, index| word.* = old[index];
    }
    for (0..8) |i| {
        state[i] ^= state[i + 8];
        state[i + 8] ^= cv[i];
    }
    return state;
}
