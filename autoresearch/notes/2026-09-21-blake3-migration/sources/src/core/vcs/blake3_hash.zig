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
