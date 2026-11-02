//! Durable CLOSED finite-image LS proof. No CPU/service/ETH execution claim.
const std = @import("std");
const C = @import("rv64_load_store.zig");
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 3) return error.ExpectedProduceOrVerifyAndDirectory;
    try std.fs.cwd().makePath(args[2]);
    var dir = try std.fs.cwd().openDir(args[2], .{});
    defer dir.close();
    const data = C.Data.fixture();
    if (std.mem.eql(u8, args[1], "produce")) {
        var encoded = try C.produce(a, data.expected(), .none);
        defer encoded.deinit(a);
        try dir.writeFile(.{ .sub_path = "proof.bin", .data = encoded.bytes });
        const claims = try std.json.Stringify.valueAlloc(a, encoded.claims, .{});
        defer a.free(claims);
        try dir.writeFile(.{ .sub_path = "claims.json", .data = claims });
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(encoded.bytes, &digest, .{});
        const receipt = .{
            .scope = "experimental-closed-load-store-operations-complete-finite-image-policy-terminal",
            .proof_sha256 = std.fmt.bytesToHex(digest, .lower),
            .proof_bytes = encoded.bytes.len,
            .expected_identity = std.fmt.bytesToHex(try data.expected().digest(), .lower),
            .queries = 70,
            .pow_bits = 26,
            .max_degree = 3,
            .quotient_factor = 2,
            .logs = C.LOGS,
            .fixed = [_]u32{ 3, 3, 34, 34, 66, 3, 3, 6 },
            .main = [_]u32{ 79, 79, 23, 23, 22, 1, 1, 2 },
            .interaction = [_]u32{ 116, 116, 48, 48, 8, 8, 8, 8 },
            .source_cells = 1888960,
            .oods_masks = 832,
            .naturally_aligned = true,
            .crossword_allowed = false,
            .word_uniform_policy = true,
            .operations = 49,
            .u16_queries_including_padding = 7616,
            .u8_queries_including_padding = 1024,
            .selection_queries_including_padding = 192,
            .cpu_bound = false,
            .services_bound = false,
            .general_sparse_image = false,
            .open_loadstore_accepted = false,
        };
        const json = try std.json.Stringify.valueAlloc(a, receipt, .{});
        defer a.free(json);
        try dir.writeFile(.{ .sub_path = "producer.json", .data = json });
    } else if (std.mem.eql(u8, args[1], "verify")) {
        const bytes = try dir.readFileAlloc(a, "proof.bin", 32 * 1024 * 1024);
        defer a.free(bytes);
        const json = try dir.readFileAlloc(a, "claims.json", 65536);
        defer a.free(json);
        const Claims = @import("stwo_riscv_frontend").rv64_air.memory.load_store_v1.types.Claims;
        const claims = try std.json.parseFromSlice([8]Claims, a, json, .{});
        defer claims.deinit();
        try C.verify(a, data.expected(), .{ .bytes = bytes, .claims = claims.value });
        try dir.writeFile(.{ .sub_path = "receiver.json", .data = "{\"accepted\":true,\"independently_expected_image_raw_instructions_operands_policy_and_terminal\":true,\"native_memory_replay\":false,\"cpu_bound\":false,\"open_loadstore_accepted\":false}\n" });
    } else return error.ExpectedProduceOrVerifyAndDirectory;
}
