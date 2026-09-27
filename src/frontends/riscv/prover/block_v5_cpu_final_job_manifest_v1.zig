//! Fixed bounded proposal catalogue for genuine PUBLIC21 and FINAL22 bytes.
//! Independent original row/key reconstruction always precedes key comparison.
const std = @import("std");
const Files = @import("block_v5_artifact_files_v1.zig");
pub const NAME = "block-v5-final-job.b5j2";
pub const PUBLIC_PROOF = "block-v5-requester-public.b5rq21";
pub const FINAL_PROOF = "block-v5-requester-memory.b5rm22";
pub const MAGIC = "B5JOB221";
pub const BYTE_LEN: usize = 320;
pub const FilePin = struct { byte_len: u64, sha256: [32]u8 };
pub const Record = struct { file: FilePin, expected_id: [32]u8 };
pub const Bindings = struct { requester_context: [32]u8, source_seal: [32]u8, memory_plan: [32]u8, memory_public: [32]u8, register_windows: [32]u8 };
pub const Proposal = struct { bindings: Bindings, records: [2]Record };
pub const Limits = struct { max_manifest_bytes: usize = BYTE_LEN, max_proof_bytes: usize = 512 << 20, max_total_proof_bytes: u64 = 1 << 30 };
pub fn validate(proposal: Proposal, limits: Limits) !void {
    if (limits.max_manifest_bytes < BYTE_LEN or limits.max_proof_bytes == 0 or limits.max_total_proof_bytes == 0) return error.FinalJobManifestLimit;
    inline for (std.meta.fields(Bindings)) |field| if (std.mem.allEqual(u8, &@field(proposal.bindings, field.name), 0)) return error.UntrustedFinalJobManifest;
    var total: u64 = 0;
    for (proposal.records) |record| {
        if (record.file.byte_len == 0 or record.file.byte_len > limits.max_proof_bytes or std.mem.allEqual(u8, &record.file.sha256, 0) or std.mem.allEqual(u8, &record.expected_id, 0)) return error.UntrustedFinalJobManifest;
        total = try std.math.add(u64, total, record.file.byte_len);
        if (total > limits.max_total_proof_bytes) return error.FinalJobManifestLimit;
    }
}
pub fn encode(proposal: Proposal, limits: Limits) ![BYTE_LEN]u8 {
    try validate(proposal, limits);
    var bytes: [BYTE_LEN]u8 = undefined;
    @memcpy(bytes[0..8], MAGIC);
    std.mem.writeInt(u32, bytes[8..12], 1, .little);
    std.mem.writeInt(u32, bytes[12..16], 2, .little);
    inline for (std.meta.fields(Bindings), 0..) |field, i| @memcpy(bytes[16 + 32 * i ..][0..32], &@field(proposal.bindings, field.name));
    for (proposal.records, 0..) |record, i| {
        const first = 176 + i * 72;
        std.mem.writeInt(u64, bytes[first..][0..8], record.file.byte_len, .little);
        @memcpy(bytes[first + 8 ..][0..32], &record.file.sha256);
        @memcpy(bytes[first + 40 ..][0..32], &record.expected_id);
    }
    return bytes;
}
pub fn decode(bytes: []const u8, limits: Limits) !Proposal {
    if (limits.max_manifest_bytes < BYTE_LEN or bytes.len > limits.max_manifest_bytes) return error.FinalJobManifestLimit;
    if (bytes.len != BYTE_LEN or !std.mem.eql(u8, bytes[0..8], MAGIC) or std.mem.readInt(u32, bytes[8..12], .little) != 1 or std.mem.readInt(u32, bytes[12..16], .little) != 2) return error.UntrustedFinalJobManifest;
    var proposal: Proposal = undefined;
    inline for (std.meta.fields(Bindings), 0..) |field, i| @field(proposal.bindings, field.name) = bytes[16 + 32 * i ..][0..32].*;
    for (&proposal.records, 0..) |*record, i| {
        const first = 176 + i * 72;
        record.* = .{ .file = .{ .byte_len = std.mem.readInt(u64, bytes[first..][0..8], .little), .sha256 = bytes[first + 8 ..][0..32].* }, .expected_id = bytes[first + 40 ..][0..32].* };
    }
    try validate(proposal, limits);
    return proposal;
}
pub fn read(a: std.mem.Allocator, dir: std.fs.Dir, pin: FilePin, limits: Limits) !Proposal {
    const bytes = try Files.readPinned(a, dir, NAME, pin.byte_len, pin.sha256, limits.max_manifest_bytes);
    defer a.free(bytes);
    return decode(bytes, limits);
}
pub fn requireBindings(proposal: Proposal, independent: Bindings) !void {
    if (!std.meta.eql(proposal.bindings, independent)) return error.UnpairedFinalJobManifest;
}
pub fn requireKey(record: Record, derived: [32]u8) !void {
    if (!std.meta.eql(record.expected_id, derived)) return error.UntrustedFinalJobExpectedKey;
}
pub fn removePublished(dir: std.fs.Dir, published_public: bool, published_final: bool) void {
    if (published_final) dir.deleteFile(FINAL_PROOF) catch {};
    if (published_public) dir.deleteFile(PUBLIC_PROOF) catch {};
}
