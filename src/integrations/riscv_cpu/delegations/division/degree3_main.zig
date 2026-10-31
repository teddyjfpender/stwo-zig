//! Fresh expected-request receiver for the explicit DIV native2n fixture.
const std = @import("std");
const F = @import("degree3_fixture.zig");
const rv = @import("stwo_riscv_frontend").rv64_air;
const Receipt = @import("../../rv64_ethereum_batch_receipt.zig");
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 3) return error.ExpectedProduceOrVerifyDirectory;
    if (std.mem.eql(u8, args[1], "produce")) {
        var encoded = try F.produce(a, &F.REQUESTS);
        defer encoded.deinit(a);
        try std.fs.cwd().makePath(args[2]);
        var dir = try std.fs.cwd().openDir(args[2], .{});
        defer dir.close();
        try Receipt.writeExclusive(dir, "proof.bin", encoded.bytes);
        const claim = try std.json.Stringify.valueAlloc(a, encoded.claim, .{});
        defer a.free(claim);
        try Receipt.writeExclusive(dir, "claim.json", claim);
        const requests = try std.json.Stringify.valueAlloc(a, F.REQUESTS, .{});
        defer a.free(requests);
        try Receipt.writeExclusive(dir, "requests.json", requests);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(encoded.bytes, &digest, .{});
        const record = try std.json.Stringify.valueAlloc(a, .{ .schema = "rv64-div-degree3-native2n-v1", .scope = "independently-expected-typed-requests-not-CPU-ingress", .requests = F.REQUESTS.len, .log_size = 5, .main = rv.arithmetic.division.layout.MAIN, .interaction = rv.arithmetic.division.layout.INTERACTION, .constraints = rv.arithmetic.division.layout.CONSTRAINTS, .degree = 3, .quotient_factor = 2, .queries = 70, .pow_bits = 26, .bytes = encoded.bytes.len, .sha256 = std.fmt.bytesToHex(digest, .lower) }, .{});
        defer a.free(record);
        try Receipt.writeExclusive(dir, "producer.json", record);
        try std.posix.fsync(dir.fd);
    } else if (std.mem.eql(u8, args[1], "verify")) {
        var dir = try std.fs.cwd().openDir(args[2], .{});
        defer dir.close();
        const bytes = try dir.readFileAlloc(a, "proof.bin", 64 << 20);
        defer a.free(bytes);
        const claim_bytes = try dir.readFileAlloc(a, "claim.json", 1024);
        defer a.free(claim_bytes);
        const claim = try std.json.parseFromSlice([4]u32, a, claim_bytes, .{});
        defer claim.deinit();
        // Expected requests come from this receiver's pinned fixture, never
        // from the producer's diagnostic requests.json file.
        try F.verify(a, &F.REQUESTS, .{ .bytes = bytes, .claim = claim.value });
        try std.fs.File.stdout().writeAll("{\"verified\":true,\"native2n\":true,\"cpu_ingress\":false}\n");
    } else return error.ExpectedProduceOrVerifyDirectory;
}
