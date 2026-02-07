const std = @import("std");

/// 32-byte digest.
pub const Digest32 = [32]u8;

/// Select a 256-bit hash implementation.
///
/// Preference order:
/// 1) Blake2s256 (if available in std)
/// 2) Sha256 (fallback)
const Sha256 = blk: {
    if (@hasDecl(std.crypto.hash, "sha2") and @hasDecl(std.crypto.hash.sha2, "Sha256")) {
        break :blk std.crypto.hash.sha2.Sha256;
    }
    if (@hasDecl(std.crypto.hash, "Sha256")) {
        break :blk std.crypto.hash.Sha256;
    }
    @compileError("No Sha256 implementation found in std.crypto.hash");
};

const HashImpl = blk: {
    if (@hasDecl(std.crypto.hash, "Blake2s256")) {
        break :blk std.crypto.hash.Blake2s256;
    }
    if (@hasDecl(std.crypto.hash, "blake2") and @hasDecl(std.crypto.hash.blake2, "Blake2s256")) {
        break :blk std.crypto.hash.blake2.Blake2s256;
    }
    break :blk Sha256;
};

pub const Hasher256 = struct {
    ctx: HashImpl,

    pub fn init() Hasher256 {
        return .{ .ctx = HashImpl.init(.{}) };
    }

    pub fn update(self: *Hasher256, data: []const u8) void {
        self.ctx.update(data);
    }

    pub fn final(self: *Hasher256, out: *Digest32) void {
        self.ctx.final(out);
    }
};

/// One-shot hash of `data`.
pub fn hash(data: []const u8) Digest32 {
    var h = Hasher256.init();
    h.update(data);
    var out: Digest32 = undefined;
    h.final(&out);
    return out;
}

/// Hash domain-separated by a single-byte prefix.
pub fn hashPrefix1(prefix: u8, data: []const u8) Digest32 {
    var h = Hasher256.init();
    h.update(&[_]u8{prefix});
    h.update(data);
    var out: Digest32 = undefined;
    h.final(&out);
    return out;
}

/// Hash domain-separated by a single-byte prefix over two 32-byte digests.
pub fn hashPrefix2(prefix: u8, left: *const Digest32, right: *const Digest32) Digest32 {
    var h = Hasher256.init();
    h.update(&[_]u8{prefix});
    h.update(left.*[0..]);
    h.update(right.*[0..]);
    var out: Digest32 = undefined;
    h.final(&out);
    return out;
}

/// Hex encoding helper (for debugging / test output).
pub fn toHexLower(out: []u8, digest: *const Digest32) void {
    const lut = "0123456789abcdef";
    std.debug.assert(out.len == 64);
    for (digest.*, 0..) |b, i| {
        out[i * 2 + 0] = lut[(b >> 4) & 0x0f];
        out[i * 2 + 1] = lut[b & 0x0f];
    }
}
