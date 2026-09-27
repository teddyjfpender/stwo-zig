//! Bounded split transport: read header/metadata/proof directly into separate
//! owners, hashing each span once. These bytes remain proposals until the
//! original typed recursive verifier succeeds. No full-envelope proof copy.
const std = @import("std");
pub const HEADER_BYTES: usize = 32;
pub const Extent = struct { metadata: usize, proof: usize, total: usize };
pub fn extent(header: []const u8, magic: []const u8, family: u32, version: u32, index: u32, limits: anytype, comptime invalid: anyerror) !Extent {
    if (header.len != HEADER_BYTES or !std.mem.eql(u8, header[0..8], magic) or
        std.mem.readInt(u32, header[8..12], .little) != family or
        std.mem.readInt(u32, header[12..16], .little) != version or
        std.mem.readInt(u32, header[16..20], .little) != index) return invalid;
    const metadata = std.mem.readInt(u32, header[20..24], .little);
    const proof = std.math.cast(usize, std.mem.readInt(u64, header[24..32], .little)) orelse return error.Overflow;
    return .{ .metadata = metadata, .proof = proof, .total = try limits.requireBytes(metadata, proof) };
}
pub fn parts(raw: []const u8, admitted: Extent, comptime invalid: anyerror) !struct { metadata: []const u8, proof: []const u8 } {
    const payload = std.math.add(usize, admitted.metadata, admitted.proof) catch return invalid;
    const total = std.math.add(usize, HEADER_BYTES, payload) catch return invalid;
    if (admitted.total != total or raw.len != total) return invalid;
    return .{ .metadata = raw[HEADER_BYTES..][0..admitted.metadata], .proof = raw[HEADER_BYTES + admitted.metadata ..] };
}
pub const Owned = struct {
    a: std.mem.Allocator,
    header: [HEADER_BYTES]u8,
    metadata: []u8,
    proof: []u8,
    pub fn deinit(self: *Owned) void {
        self.a.free(self.metadata);
        self.a.free(self.proof);
        self.* = undefined;
    }
    pub fn detachProof(self: *Owned) []u8 {
        const bytes = self.proof;
        self.proof = &.{};
        return bytes;
    }
};
/// C.admitHeader validates typed family/index/security and resource limits
/// BEFORE metadata/proof allocation. SHA/length are immutable transport pins.
/// The returned split owner grants no equation or verified file state.
pub fn readPinned(comptime C: type, a: std.mem.Allocator, dir: std.fs.Dir, path: []const u8, byte_len: u64, digest: [32]u8, policy: C.Policy, limits: anytype) !Owned {
    if (byte_len == 0 or byte_len > C.maxFileBytes(limits)) return error.V5BundleFileResourceLimit;
    var file = try dir.openFile(path, .{});
    defer file.close();
    if (byte_len <= HEADER_BYTES or (try file.stat()).size != byte_len) return error.TamperedV5BundleFileLength;
    var header: [HEADER_BYTES]u8 = undefined;
    if (try file.readAll(&header) != HEADER_BYTES) return error.TamperedV5BundleFileLength;
    const admitted = C.admitHeader(&header, policy, limits) catch |err| {
        if (err == error.OutOfMemory) return err;
        // Keep transport hash/length rejection ahead of file-carried grammar
        // errors, without allocating from an untrusted header. The rare error
        // path hashes the bounded remaining bytes through fixed stack scratch.
        try requireRemainingHash(&file, &header, byte_len, digest);
        return err;
    };
    if (admitted.total != byte_len) return error.TamperedV5BundleFileLength;
    const metadata = try a.alloc(u8, admitted.metadata);
    errdefer a.free(metadata);
    const proof = try a.alloc(u8, admitted.proof);
    errdefer a.free(proof);
    if (try file.readAll(metadata) != metadata.len or try file.readAll(proof) != proof.len) return error.TamperedV5BundleFileLength;
    var trailing: [1]u8 = undefined;
    if (try file.read(&trailing) != 0) return error.TamperedV5BundleFileLength;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(&header);
    hash.update(metadata);
    hash.update(proof);
    if (!std.meta.eql(hash.finalResult(), digest)) return error.TamperedV5BundleFileHash;
    return .{ .a = a, .header = header, .metadata = metadata, .proof = proof };
}
fn requireRemainingHash(file: *std.fs.File, header: *const [HEADER_BYTES]u8, byte_len: u64, digest: [32]u8) !void {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(header);
    var remaining = byte_len - HEADER_BYTES;
    var scratch: [4096]u8 = undefined;
    while (remaining != 0) {
        const count: usize = @intCast(@min(remaining, scratch.len));
        if (try file.readAll(scratch[0..count]) != count) return error.TamperedV5BundleFileLength;
        hash.update(scratch[0..count]);
        remaining -= count;
    }
    var trailing: [1]u8 = undefined;
    if (try file.read(&trailing) != 0) return error.TamperedV5BundleFileLength;
    if (!std.meta.eql(hash.finalResult(), digest)) return error.TamperedV5BundleFileHash;
}
