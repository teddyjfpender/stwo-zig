//! Fresh expected-request receiver for the strict-pair MUL2n/BYTE2n fixture.
const std = @import("std");
const F = @import("degree3_fixture.zig");
const rv = @import("stwo_riscv_frontend").rv64_air;
const Wire = @import("stwo_proof_wire");
const Receipt = @import("../../rv64_ethereum_batch_receipt.zig");
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 3) return error.ExpectedProduceOrVerifyDirectory;
    const public = F.Public{ .requests = &F.REQUESTS, .log_size = 5 };
    if (std.mem.eql(u8, args[1], "produce")) {
        var bundle = try F.prove(a, public);
        defer bundle.deinit(a);
        const encoded = try Wire.encodeProofBytesBinary(a, bundle.proof);
        defer a.free(encoded);
        try std.fs.cwd().makePath(args[2]);
        var dir = try std.fs.cwd().openDir(args[2], .{});
        defer dir.close();
        try Receipt.writeExclusive(dir, "proof.bin", encoded);
        const claims = try std.json.Stringify.valueAlloc(a, bundle.claims, .{});
        defer a.free(claims);
        try Receipt.writeExclusive(dir, "claims.json", claims);
        const requests = try std.json.Stringify.valueAlloc(a, F.REQUESTS, .{});
        defer a.free(requests);
        try Receipt.writeExclusive(dir, "requests.json", requests);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(encoded, &digest, .{});
        const record = try std.json.Stringify.valueAlloc(a, .{ .schema = "rv64-mul-degree3-native2n-v1", .scope = "independently-expected-typed-requests-not-CPU-ingress", .requests = F.REQUESTS.len, .log_size = 5, .main = rv.arithmetic.multiplication.degree3_layout.MAIN, .interaction = rv.arithmetic.multiplication.degree3_layout.INTERACTION, .constraints = rv.arithmetic.multiplication.degree3_layout.CONSTRAINTS, .degree = 3, .quotient_factor = 2, .queries = 70, .pow_bits = 26, .bytes = encoded.len, .sha256 = std.fmt.bytesToHex(digest, .lower) }, .{});
        defer a.free(record);
        try Receipt.writeExclusive(dir, "producer.json", record);
        try std.posix.fsync(dir.fd);
    } else if (std.mem.eql(u8, args[1], "verify")) {
        var dir = try std.fs.cwd().openDir(args[2], .{});
        defer dir.close();
        const bytes = try dir.readFileAlloc(a, "proof.bin", 64 << 20);
        defer a.free(bytes);
        const claims_bytes = try dir.readFileAlloc(a, "claims.json", 1024);
        defer a.free(claims_bytes);
        const claims = try std.json.parseFromSlice(F.Claims, a, claims_bytes, .{});
        defer claims.deinit();
        // Independently pinned requests, not producer diagnostic JSON.
        try F.verifyOwned(a, public, claims.value, try Wire.decodeProofBytesBinary(a, bytes));
        try std.fs.File.stdout().writeAll("{\"verified\":true,\"native2n\":true,\"cpu_ingress\":false}\n");
    } else return error.ExpectedProduceOrVerifyDirectory;
}
