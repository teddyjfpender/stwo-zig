//! B5RMOWN1 proposals only: independently derived keys are compared after
//! fresh original verification. No received catalogue selects a verifier key.
const std = @import("std");
const Files = @import("block_v5_artifact_files_v1.zig");
pub const NAME = "source-memory-recursive.b5rmo";
pub const MAGIC = "B5RMOWN1";
pub const FilePin = struct { byte_len: u64, sha256: [32]u8 };
pub const Record = struct { file: FilePin, expected_id: [32]u8 };
pub const Header = struct { ram: u32, range: u32, nodes: u32, seal: [32]u8, memory_plan: [32]u8, page_owner: [32]u8 };
pub const Limits = struct { max_bytes: usize = 1 << 20, max_records: usize = 8193, max_proof_bytes: usize = 512 << 20, max_total_proof_bytes: u64 = 512 << 30 };
pub const Owned = struct {
    a: std.mem.Allocator,
    header: Header,
    records: []Record,
    pub fn deinit(self: *Owned) void {
        self.a.free(self.records);
        self.* = undefined;
    }
};
const HEADER_BYTES: usize = 120;
const RECORD_BYTES: usize = 72;
pub fn count(header: Header) !usize {
    return std.math.add(usize, try std.math.add(usize, try std.math.add(usize, header.ram, header.range), header.nodes), 1);
}
pub fn requiredBytes(header: Header) !usize {
    return std.math.add(usize, HEADER_BYTES, try std.math.mul(usize, try count(header), RECORD_BYTES));
}
pub fn require(header: Header, records: []const Record, limits: Limits) !void {
    const n = try count(header);
    if (limits.max_bytes == 0 or n > limits.max_records or records.len != n or try std.math.add(usize, HEADER_BYTES, try std.math.mul(usize, n, RECORD_BYTES)) > limits.max_bytes) return error.RamForestManifestLimit;
    for ([_][32]u8{ header.seal, header.memory_plan, header.page_owner }) |root| if (std.mem.allEqual(u8, &root, 0)) return error.UntrustedRamForestManifest;
    var total: u64 = 0;
    for (records) |record| {
        if (record.file.byte_len == 0 or record.file.byte_len > limits.max_proof_bytes or std.mem.allEqual(u8, &record.file.sha256, 0) or std.mem.allEqual(u8, &record.expected_id, 0)) return error.UntrustedRamForestManifest;
        total = try std.math.add(u64, total, record.file.byte_len);
        if (total > limits.max_total_proof_bytes) return error.RamForestManifestLimit;
    }
}
pub fn encode(a: std.mem.Allocator, header: Header, records: []const Record, limits: Limits) ![]u8 {
    try require(header, records, limits);
    const bytes = try a.alloc(u8, HEADER_BYTES + records.len * RECORD_BYTES);
    @memcpy(bytes[0..8], MAGIC);
    for ([_]u32{ 1, header.ram, header.range, header.nodes }, 0..) |word, i| std.mem.writeInt(u32, bytes[8 + 4 * i ..][0..4], word, .little);
    for ([_][32]u8{ header.seal, header.memory_plan, header.page_owner }, 0..) |root, i| @memcpy(bytes[24 + 32 * i ..][0..32], &root);
    for (records, 0..) |record, i| {
        const offset = HEADER_BYTES + i * RECORD_BYTES;
        std.mem.writeInt(u64, bytes[offset..][0..8], record.file.byte_len, .little);
        @memcpy(bytes[offset + 8 ..][0..32], &record.file.sha256);
        @memcpy(bytes[offset + 40 ..][0..32], &record.expected_id);
    }
    return bytes;
}
pub fn decode(a: std.mem.Allocator, bytes: []const u8, limits: Limits) !Owned {
    if (bytes.len < HEADER_BYTES or bytes.len > limits.max_bytes or !std.mem.eql(u8, bytes[0..8], MAGIC) or std.mem.readInt(u32, bytes[8..12], .little) != 1) return error.UntrustedRamForestManifest;
    const header = Header{ .ram = std.mem.readInt(u32, bytes[12..16], .little), .range = std.mem.readInt(u32, bytes[16..20], .little), .nodes = std.mem.readInt(u32, bytes[20..24], .little), .seal = bytes[24..56].*, .memory_plan = bytes[56..88].*, .page_owner = bytes[88..120].* };
    const n = try count(header);
    if (n > limits.max_records or bytes.len != try std.math.add(usize, HEADER_BYTES, try std.math.mul(usize, n, RECORD_BYTES))) return error.RamForestManifestLimit;
    const records = try a.alloc(Record, n);
    errdefer a.free(records);
    for (records, 0..) |*record, i| {
        const offset = HEADER_BYTES + i * RECORD_BYTES;
        record.* = .{ .file = .{ .byte_len = std.mem.readInt(u64, bytes[offset..][0..8], .little), .sha256 = bytes[offset + 8 ..][0..32].* }, .expected_id = bytes[offset + 40 ..][0..32].* };
    }
    try require(header, records, limits);
    return .{ .a = a, .header = header, .records = records };
}
pub fn read(a: std.mem.Allocator, dir: std.fs.Dir, pin: FilePin, limits: Limits) !Owned {
    const bytes = try Files.readPinned(a, dir, NAME, pin.byte_len, pin.sha256, limits.max_bytes);
    defer a.free(bytes);
    return decode(a, bytes, limits);
}
pub fn requireDerived(record: Record, derived: [32]u8) !void {
    if (!std.meta.eql(record.expected_id, derived)) return error.UntrustedRamForestExpectedKey;
}
