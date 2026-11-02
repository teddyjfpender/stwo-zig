//! Fresh receiver for the standalone typed MUL/BYTE provider profile.
const std = @import("std");
const native = @import("native.zig");
const wire = @import("stwo_proof_wire");
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 4) return error.ExpectedPublicClaimsProof;
    const public_bytes = try std.fs.cwd().readFileAlloc(a, args[1], 64 << 20);
    defer a.free(public_bytes);
    const claim_bytes = try std.fs.cwd().readFileAlloc(a, args[2], 16384);
    defer a.free(claim_bytes);
    const proof_bytes = try std.fs.cwd().readFileAlloc(a, args[3], 64 << 20);
    defer a.free(proof_bytes);
    const public = try std.json.parseFromSlice(native.Public, a, public_bytes, .{});
    defer public.deinit();
    const claims = try std.json.parseFromSlice(native.Claims, a, claim_bytes, .{});
    defer claims.deinit();
    var timer = try std.time.Timer.start();
    try native.verifyOwned(a, public.value, claims.value, try wire.decodeProofBytesBinary(a, proof_bytes));
    const report = try std.json.Stringify.valueAlloc(a, .{ .verified = true, .standalone_mul_byte_provider = true, .cpu_ingress = false, .ethereum_block_proof = false, .fresh_receiver_ns = timer.read(), .proof_bytes = proof_bytes.len }, .{});
    defer a.free(report);
    try std.fs.File.stdout().writeAll(report);
    try std.fs.File.stdout().writeAll("\n");
}
