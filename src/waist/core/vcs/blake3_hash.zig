const std = @import("std");

pub const Blake3Hash = [32]u8;

const Blake3 = blk: {
    if (@hasDecl(std.crypto, "hash") and @hasDecl(std.crypto.hash, "Blake3")) {
        break :blk std.crypto.hash.Blake3;
    }
    if (@hasDecl(std.crypto, "blake3") and @hasDecl(std.crypto.blake3, "Blake3")) {
        break :blk std.crypto.blake3.Blake3;
    }
    @compileError("Blake3 not found in std.crypto");
};

pub const Blake3Hasher = struct {
    state: Blake3,

    pub fn init() Blake3Hasher {
        return .{ .state = Blake3.init(.{}) };
    }

    pub fn update(self: *Blake3Hasher, data: []const u8) void {
        self.state.update(data);
    }

    pub fn finalize(self: *const Blake3Hasher) Blake3Hash {
        var out: Blake3Hash = undefined;
        self.state.final(out[0..]);
        return out;
    }

    pub fn hash(data: []const u8) Blake3Hash {
        if (data.len <= 1024) return hashChunk(data);
        var out: Blake3Hash = undefined;
        Blake3.hash(data, out[0..], .{});
        return out;
    }

    pub fn concatAndHash(left: Blake3Hash, right: Blake3Hash) Blake3Hash {
        var hasher = Blake3Hasher.init();
        hasher.update(left[0..]);
        hasher.update(right[0..]);
        return hasher.finalize();
    }
};

// A single BLAKE3 chunk needs no streaming state or CV stack. The last
// compression carries ROOT, including the empty message and full final block.
fn hashChunk(data: []const u8) Blake3Hash {
    const compression = @import("../crypto/blake3_compression.zig");
    var cv = compression.IV;
    var at: usize = 0;
    while (true) {
        const len = @min(64, data.len - at);
        const last = at + len == data.len;
        var bytes: [64]u8 = @splat(0);
        @memcpy(bytes[0..len], data[at..][0..len]);
        var block: [16]u32 = undefined;
        inline for (0..16) |i| block[i] = std.mem.readInt(u32, bytes[i * 4 ..][0..4], .little);
        const flags: u32 = (if (at == 0) @as(u32, 1) else 0) | (if (last) @as(u32, 2 | 8) else 0);
        const output = compression.compress(cv, block, 0, @intCast(len), flags) catch unreachable;
        if (last) {
            var digest: Blake3Hash = undefined;
            inline for (0..8) |i| std.mem.writeInt(u32, digest[i * 4 ..][0..4], output[i], .little);
            return digest;
        }
        cv = output[0..8].*;
        at += len;
    }
}

test "blake3 hash: short chunk and streaming boundary differential" {
    var input: [4097]u8 = undefined;
    var rng = std.Random.DefaultPrng.init(0x20260924);
    rng.random().bytes(&input);
    for (0..input.len + 1) |len| {
        var expected: Blake3Hash = undefined;
        Blake3.hash(input[0..len], &expected, .{});
        try std.testing.expectEqualSlices(u8, &expected, &Blake3Hasher.hash(input[0..len]));
    }
}

fn digestToHex(digest: Blake3Hash) [64]u8 {
    return std.fmt.bytesToHex(digest, .lower);
}

test "blake3 hash: single hash test" {
    const hash_a = Blake3Hasher.hash("a");
    const hex = digestToHex(hash_a);
    try std.testing.expectEqualStrings(
        "17762fddd969a453925d65717ac3eea21320b66b54342fde15128d6caf21215f",
        &hex,
    );
}

test "blake3 hash: incremental equals one-shot" {
    var hasher = Blake3Hasher.init();
    hasher.update("a");
    hasher.update("b");
    const inc = hasher.finalize();
    const one_shot = Blake3Hasher.hash("ab");
    try std.testing.expect(std.mem.eql(u8, inc[0..], one_shot[0..]));
}

test "blake3 hash: concat and hash matches manual update" {
    const left = Blake3Hasher.hash("left");
    const right = Blake3Hasher.hash("right");

    var hasher = Blake3Hasher.init();
    hasher.update(left[0..]);
    hasher.update(right[0..]);
    const manual = hasher.finalize();

    const combined = Blake3Hasher.concatAndHash(left, right);
    try std.testing.expect(std.mem.eql(u8, manual[0..], combined[0..]));
}
