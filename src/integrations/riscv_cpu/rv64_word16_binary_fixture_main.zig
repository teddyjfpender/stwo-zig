//! Durable, public-IO BINARY control. No CPU/register/RAM claim is made.
const std = @import("std");
const core = @import("stwo_core");
const F = @import("word16/binary_fixture.zig");
const P = @import("stwo_riscv_frontend").rv64_air.word16_v1.binary_lookup;
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 3) return error.ExpectedProduceOrVerifyAndDirectory;
    if (std.mem.eql(u8, args[1], "produce")) {
        const encoded = try F.produce(a, false);
        defer a.free(encoded.bytes);
        try std.fs.cwd().makePath(args[2]);
        var dir = try std.fs.cwd().openDir(args[2], .{});
        defer dir.close();
        try dir.writeFile(.{ .sub_path = "proof.bin", .data = encoded.bytes });
        const claims = try std.json.Stringify.valueAlloc(a, encoded.claims, .{});
        defer a.free(claims);
        try dir.writeFile(.{ .sub_path = "claims.json", .data = claims });
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(encoded.bytes, &digest, .{});
        const source_cells = (2 + P.MAIN + P.INTERACTION + 16 + 8) * 32 + (5 + 1 + 8) * 65536;
        const encoding_digest = P.encoding.identity();
        const receipt = try std.json.Stringify.valueAlloc(a, .{
            .scope = "diagnostic-public-io-binary-and-one-pcs",
            .proof_bytes = encoded.bytes.len,
            .proof_sha256 = std.fmt.bytesToHex(digest, .lower),
            .encoding_version = P.encoding.VERSION,
            .encoding_sha256 = std.fmt.bytesToHex(encoding_digest, .lower),
            .queries = 70,
            .pow_bits = 26,
            .log_blowup = 1,
            .nominal_config_bits = 96,
            .explicit_scoped_worker_pool = false,
            .source_cells = source_cells,
            .source_bytes = source_cells * @sizeOf(core.fields.m31.M31),
            .trace_oods_masks = P.MAIN + P.INTERACTION + 52,
            .binary = .{ .log = 5, .fixed = 2, .main = P.MAIN, .interaction = P.INTERACTION },
            .public_consumer = .{ .log = 5, .fixed = 16, .main = 0, .interaction = 8 },
            .and_provider = .{ .log = 16, .fixed = 5, .main = 1, .interaction = 8 },
            .positive_function_mass = 3,
            .and_mass_including_padding = 256,
            .quotient_factor = 2,
            .cpu_bound = false,
            .ram_bound = false,
        }, .{});
        defer a.free(receipt);
        try dir.writeFile(.{ .sub_path = "producer.json", .data = receipt });
    } else if (std.mem.eql(u8, args[1], "verify")) {
        var dir = try std.fs.cwd().openDir(args[2], .{});
        defer dir.close();
        const bytes = try dir.readFileAlloc(a, "proof.bin", 32 * 1024 * 1024);
        defer a.free(bytes);
        const json = try dir.readFileAlloc(a, "claims.json", 64 * 1024);
        defer a.free(json);
        const claims = try std.json.parseFromSlice([4]core.fields.qm31.QM31, a, json, .{});
        defer claims.deinit();
        try F.verify(a, .{ .bytes = bytes, .claims = claims.value }, false);
        try dir.writeFile(.{ .sub_path = "receiver.json", .data = "{\"accepted\":true,\"independently_expected_roster_and_fixed_root\":true,\"cpu_bound\":false,\"ram_bound\":false}\n" });
    } else return error.ExpectedProduceOrVerifyAndDirectory;
}
