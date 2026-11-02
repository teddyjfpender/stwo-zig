//! Fresh standalone arithmetic receiver; never executes native DIV/REM.
const std = @import("std");
const D = @import("stwo_riscv_frontend").rv64_air.arithmetic.division;
const native = @import("native.zig");
const wire = @import("stwo_proof_wire");
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 4) return error.ExpectedRequestsClaimProof;
    const request_bytes = try std.fs.cwd().readFileAlloc(a, args[1], 16 << 20);
    defer a.free(request_bytes);
    const claim_bytes = try std.fs.cwd().readFileAlloc(a, args[2], 1024);
    defer a.free(claim_bytes);
    const proof_bytes = try std.fs.cwd().readFileAlloc(a, args[3], 64 << 20);
    defer a.free(proof_bytes);
    const requests = try std.json.parseFromSlice([]D.trace.Request, a, request_bytes, .{});
    defer requests.deinit();
    const claim = try std.json.parseFromSlice(native.Claim, a, claim_bytes, .{});
    defer claim.deinit();
    try native.verifyOwned(a, requests.value, claim.value, try wire.decodeProofBytesBinary(a, proof_bytes));
    try std.fs.File.stdout().writeAll("{\"verified\":true,\"standalone_division_service\":true,\"cpu_ingress_verified\":false}\n");
}
