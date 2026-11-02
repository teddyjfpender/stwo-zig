//! Fresh-process bounded proof verification. Expected state is an explicit input.
const std = @import("std");
const native = @import("stwo_riscv_cpu_integration").rv64;
const wire = @import("stwo_proof_wire");
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const args = try std.process.argsAlloc(a);
    if (args.len != 4) return error.ExpectedStatementMetadataProof;
    var timer = try std.time.Timer.start();
    const public = try std.json.parseFromSlice(native.Statement, a, try std.fs.cwd().readFileAlloc(a, args[1], 256 * 1024), .{});
    const metadata = try std.json.parseFromSlice(native.Metadata, a, try std.fs.cwd().readFileAlloc(a, args[2], 64 * 1024), .{});
    const bytes = try std.fs.cwd().readFileAlloc(a, args[3], 16 * 1024 * 1024);
    const proof = try wire.decodeProofBytesBinary(a, bytes);
    const decode_ns = timer.lap();
    try native.verifyOwned(a, public.value, metadata.value, proof);
    const verify_ns = timer.read();
    const report = try std.json.Stringify.valueAlloc(a, .{ .verified_partial_execution = true, .execution_witness_available = false, .decode_ns = decode_ns, .independent_setup_and_verify_ns = verify_ns, .proof_bytes = bytes.len, .whole_guest_proof = false }, .{});
    try std.fs.File.stdout().writeAll(report);
    try std.fs.File.stdout().writeAll("\n");
}
