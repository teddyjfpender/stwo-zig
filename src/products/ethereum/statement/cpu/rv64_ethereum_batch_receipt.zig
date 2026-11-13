//! Per-batch durable physical proof and narrow public statement. Immutable ROM
//! is supplied independently by the receiver; it is never repeated in receipts.
const std = @import("std");
const A = @import("stwo_riscv_cpu_integration").rv64_execution.legacy.authenticated;
const artifact_support = @import("stwo_riscv_cpu_integration").rv64_proof_artifact_support;
const request = @import("rv64_ethereum_request.zig");
pub const Receipt = struct {
    schema: []const u8 = "rv64-authenticated-ethereum-batch-v1",
    index: u32,
    first_step: u64,
    public: A.Public,
    claims: A.Claims,
    proof_sha256: [64]u8,
    pub fn create(index: u32, first: u64, public: A.Public, claims: A.Claims, bytes: []const u8) Receipt {
        var narrow = public;
        narrow.cpu.statement.program = .{ .base = 0, .words = &.{}, .addresses = &.{} };
        return .{ .index = index, .first_step = first, .public = narrow, .claims = claims, .proof_sha256 = std.fmt.bytesToHex(request.sha(bytes), .lower) };
    }
    pub fn bound(self: Receipt, authority: *const A.Full.ProgramAuthority) !A.Public {
        if (!std.mem.eql(u8, self.schema, "rv64-authenticated-ethereum-batch-v1") or self.public.cpu.execution_profile != authority.profile or self.public.cpu.control_policy != authority.control_policy or self.public.cpu.statement.program.base != 0 or self.public.cpu.statement.program.words.len != 0 or self.public.cpu.statement.program.addresses.len != 0) return error.InvalidEthereumBatchReceipt;
        var result = self.public;
        result.cpu.statement.program = authority.expectedProgram();
        return result;
    }
};
pub const SourceCells = artifact_support.SourceCells;
pub const sourceCells = artifact_support.sourceCells;
pub fn write(a: std.mem.Allocator, directory: std.fs.Dir, index: u32, first: u64, public: A.Public, bundle: *const A.Bundle) !usize {
    const wire = @import("stwo_proof_wire");
    const bytes = try wire.encodeProofBytesBinary(a, bundle.proof);
    defer a.free(bytes);
    return writeEncoded(a, directory, index, first, public, bundle.claims, bytes);
}
pub fn writeEncoded(a: std.mem.Allocator, directory: std.fs.Dir, index: u32, first: u64, public: A.Public, claims: A.Claims, bytes: []const u8) !usize {
    const receipt = Receipt.create(index, first, public, claims, bytes);
    const json = try std.json.Stringify.valueAlloc(a, receipt, .{ .whitespace = .indent_2 });
    defer a.free(json);
    const proof_name = try std.fmt.allocPrint(a, "batch-{d:0>6}.proof", .{index});
    defer a.free(proof_name);
    const meta_name = try std.fmt.allocPrint(a, "batch-{d:0>6}.json", .{index});
    defer a.free(meta_name);
    try writeExclusive(directory, proof_name, bytes);
    errdefer directory.deleteFile(proof_name) catch {};
    try writeExclusive(directory, meta_name, json);
    return bytes.len;
}
pub const writeExclusive = artifact_support.writeExclusive;

/// A crash leaves a verifiable durable prefix, never a claimed complete block.
/// Only publish after proof+receipt files have synced and receiver accepted them.
pub fn checkpoint(a: std.mem.Allocator, directory: std.fs.Dir, cursor: @import("rv64_ethereum_chain.zig").Cursor) !void {
    const json = try std.json.Stringify.valueAlloc(a, .{ .schema = "rv64-ethereum-authenticated-prefix-v1", .verified_batches = cursor.batches, .completed = false, .full_block_proof_verified = false, .instructions = cursor.steps, .calls = cursor.calls }, .{ .whitespace = .indent_2 });
    defer a.free(json);
    try replaceSummary(directory, json);
}
pub const replaceSummary = artifact_support.replaceSummary;
