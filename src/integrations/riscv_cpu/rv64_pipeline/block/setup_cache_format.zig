//! Authenticated setup-cache wire format and bounded allocation parsing.
//! Cache ownership, source identity and file I/O stay with setup_cache.zig.
const std = @import("std");
const engine = @import("stwo_prover_engine");

pub const MAGIC = "RV64SUC1";
pub const FORMAT_VERSION: u32 = 1;
pub const HEADER_BYTES: usize = 256;
pub const FLAG_BULK: u32 = 1;
pub const CHUNK_BYTES: usize = engine.chunked_sha256.default_chunk_bytes;
pub const MAX_VK_BYTES: u64 = 1 << 20;
pub const MAX_STRUCTURE_BYTES: u64 = 64 << 20;
pub const MAX_PAYLOAD_BYTES: u64 = 8 << 30;

pub const Vk = struct {
    suite_identity: [32]u8,
    source_root: [32]u8,
    source_logs: []u32,
    log_blowup: u32,
    identity: [32]u8,
    root: [32]u8,
    cells: u64,
    candidate_logs: []u32,
    pub fn deinit(self: *Vk, a: std.mem.Allocator) void {
        a.free(self.source_logs);
        a.free(self.candidate_logs);
    }
    pub fn encode(self: Vk, a: std.mem.Allocator) ![]u8 {
        var out = std.ArrayList(u8).empty;
        errdefer out.deinit(a);
        try out.appendSlice(a, &self.suite_identity);
        try out.appendSlice(a, &self.source_root);
        try appendU32(&out, a, @intCast(self.source_logs.len));
        for (self.source_logs) |l| try appendU32(&out, a, l);
        try appendU32(&out, a, self.log_blowup);
        try out.appendSlice(a, &self.identity);
        try out.appendSlice(a, &self.root);
        try appendU64(&out, a, self.cells);
        try appendU32(&out, a, @intCast(self.candidate_logs.len));
        for (self.candidate_logs) |l| try appendU32(&out, a, l);
        return out.toOwnedSlice(a);
    }
    pub fn decode(a: std.mem.Allocator, bytes: []const u8) !Vk {
        var r = Reader{ .bytes = bytes };
        var vk: Vk = undefined;
        vk.suite_identity = (try r.take(32))[0..32].*;
        vk.source_root = (try r.take(32))[0..32].*;
        vk.source_logs = try r.u32s(a);
        errdefer a.free(vk.source_logs);
        vk.log_blowup = try r.u32v();
        vk.identity = (try r.take(32))[0..32].*;
        vk.root = (try r.take(32))[0..32].*;
        vk.cells = try r.u64v();
        vk.candidate_logs = try r.u32s(a);
        errdefer a.free(vk.candidate_logs);
        if (r.at != bytes.len) return error.SetupCacheArtifactRejected;
        return vk;
    }
};

pub const ColumnRecord = struct { height: u32, coefficient_log: u32, values_len: u64, view: bool, digest: [32]u8 };

pub fn appendU32(out: *std.ArrayList(u8), a: std.mem.Allocator, v: u32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    try out.appendSlice(a, &b);
}
pub fn appendU64(out: *std.ArrayList(u8), a: std.mem.Allocator, v: u64) !void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, v, .little);
    try out.appendSlice(a, &b);
}

pub const Reader = struct {
    bytes: []const u8,
    at: usize = 0,
    pub fn take(self: *Reader, n: usize) ![]const u8 {
        if (n > self.bytes.len - self.at) return error.SetupCacheArtifactRejected;
        defer self.at += n;
        return self.bytes[self.at..][0..n];
    }
    pub fn u32v(self: *Reader) !u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .little);
    }
    pub fn u64v(self: *Reader) !u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .little);
    }
    pub fn u32s(self: *Reader, a: std.mem.Allocator) ![]u32 {
        const n = try self.u32v();
        if (n == 0 or n > 1 << 16) return error.SetupCacheArtifactRejected;
        const out = try a.alloc(u32, n);
        errdefer a.free(out);
        for (out) |*v| {
            v.* = try self.u32v();
            if (v.* > 30) return error.SetupCacheArtifactRejected;
        }
        return out;
    }
};

pub const Header = struct {
    flags: u32,
    key: [32]u8,
    code: [32]u8,
    vk_len: u64,
    structure_len: u64,
    payload_len: u64,
    vk_digest: [32]u8,
    bulk_digest: [32]u8,
    pub fn encode(self: Header) [HEADER_BYTES]u8 {
        var b: [HEADER_BYTES]u8 = @splat(0);
        @memcpy(b[0..8], MAGIC);
        std.mem.writeInt(u32, b[8..12], FORMAT_VERSION, .little);
        std.mem.writeInt(u32, b[12..16], self.flags, .little);
        @memcpy(b[16..48], &self.key);
        @memcpy(b[48..80], &self.code);
        std.mem.writeInt(u64, b[80..88], self.vk_len, .little);
        std.mem.writeInt(u64, b[88..96], self.structure_len, .little);
        std.mem.writeInt(u64, b[96..104], self.payload_len, .little);
        @memcpy(b[104..136], &self.vk_digest);
        @memcpy(b[136..168], &self.bulk_digest);
        std.mem.writeInt(u32, b[168..172], @intCast(CHUNK_BYTES), .little);
        var d: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(b[0..224], &d, .{});
        @memcpy(b[224..256], &d);
        return b;
    }
    pub fn decode(b: *const [HEADER_BYTES]u8) !Header {
        var d: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(b[0..224], &d, .{});
        if (!std.crypto.timing_safe.eql([32]u8, d, b[224..256].*)) return error.SetupCacheArtifactRejected;
        if (!std.mem.eql(u8, b[0..8], MAGIC) or std.mem.readInt(u32, b[8..12], .little) != FORMAT_VERSION or std.mem.readInt(u32, b[168..172], .little) != CHUNK_BYTES) return error.SetupCacheArtifactRejected;
        for (b[172..224]) |byte| if (byte != 0) return error.SetupCacheArtifactRejected;
        const h = Header{ .flags = std.mem.readInt(u32, b[12..16], .little), .key = b[16..48].*, .code = b[48..80].*, .vk_len = std.mem.readInt(u64, b[80..88], .little), .structure_len = std.mem.readInt(u64, b[88..96], .little), .payload_len = std.mem.readInt(u64, b[96..104], .little), .vk_digest = b[104..136].*, .bulk_digest = b[136..168].* };
        if (h.flags & ~FLAG_BULK != 0 or h.vk_len == 0 or h.vk_len > MAX_VK_BYTES or h.structure_len > MAX_STRUCTURE_BYTES or h.payload_len > MAX_PAYLOAD_BYTES) return error.SetupCacheArtifactRejected;
        return h;
    }
};
