//! Durable CLOSED finite RAM-operation proof. No CPU/service/ETH execution claim.
const std = @import("std");
const C = @import("rv64_closed_ram.zig");
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 3) return error.ExpectedProduceOrVerifyAndDirectory;
    try std.fs.cwd().makePath(args[2]);
    var dir = try std.fs.cwd().openDir(args[2], .{});
    defer dir.close();
    if (std.mem.eql(u8, args[1], "produce")) {
        var encoded = try C.produce(a, C.public.fixture(), .none);
        defer encoded.deinit(a);
        try dir.writeFile(.{ .sub_path = "proof.bin", .data = encoded.bytes });
        const claims = try std.json.Stringify.valueAlloc(a, encoded.claims, .{});
        defer a.free(claims);
        try dir.writeFile(.{ .sub_path = "claims.json", .data = claims });
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(encoded.bytes, &digest, .{});
        const receipt = .{
            .scope = "experimental-closed-expected-ram-operations-complete-finite-image-policy-terminal",
            .proof_sha256 = std.fmt.bytesToHex(digest, .lower),
            .proof_bytes = encoded.bytes.len,
            .expected_identity = std.fmt.bytesToHex(try C.public.fixture().digest(), .lower),
            .queries = 70,
            .pow_bits = 26,
            .max_degree = 3,
            .quotient_factor = 2,
            .logs = [_]u32{ 5, 6, 5, 5, 5, 16, 8 },
            .main = [_]u32{ 28, 28, 23, 23, 14, 1, 1 },
            .interaction = [_]u32{ 68, 68, 48, 48, 8, 8, 8 },
            .source_cells = 807520,
            .cpu_bound = false,
            .services_bound = false,
            .general_sparse_image = false,
            .open_ram_accepted = false,
        };
        const json = try std.json.Stringify.valueAlloc(a, receipt, .{});
        defer a.free(json);
        try dir.writeFile(.{ .sub_path = "producer.json", .data = json });
    } else if (std.mem.eql(u8, args[1], "verify")) {
        const bytes = try dir.readFileAlloc(a, "proof.bin", 32 * 1024 * 1024);
        defer a.free(bytes);
        const json = try dir.readFileAlloc(a, "claims.json", 65536);
        defer a.free(json);
        const Claims = @import("stwo_riscv_frontend").rv64_air.memory.closed_ram.types.Claims;
        const claims = try std.json.parseFromSlice([7]Claims, a, json, .{});
        defer claims.deinit();
        try C.verify(a, C.public.fixture(), .{ .bytes = bytes, .claims = claims.value });
        try dir.writeFile(.{ .sub_path = "receiver.json", .data = "{\"accepted\":true,\"independently_expected_image_operations_policy_and_terminal\":true,\"cpu_bound\":false,\"open_ram_accepted\":false}\n" });
    } else return error.ExpectedProduceOrVerifyAndDirectory;
}
