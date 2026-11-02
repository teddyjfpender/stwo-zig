//! Fresh-process known-public weighted BINARY proof, not an RV64 execution proof.
const std = @import("std");
const F = @import("word16/weighted_binary_fixture.zig");
const core = @import("stwo_core");
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 3) return error.ExpectedProduceOrBorrowedOrVerifyDirectory;
    try std.fs.cwd().makePath(args[2]);
    var dir = try std.fs.cwd().openDir(args[2], .{});
    defer dir.close();
    const borrowed = std.mem.eql(u8, args[1], "produce-borrowed");
    if (borrowed or std.mem.eql(u8, args[1], "produce")) {
        var proof = try F.produce(a, borrowed, .none);
        defer proof.deinit(a);
        try dir.writeFile(.{ .sub_path = "proof.bin", .data = proof.bytes });
        const raw = try std.json.Stringify.valueAlloc(a, proof.claims, .{});
        defer a.free(raw);
        try dir.writeFile(.{ .sub_path = "claims.json", .data = raw });
        try receipt(a, dir, "producer.json", proof.bytes);
    } else if (std.mem.eql(u8, args[1], "verify")) {
        const bytes = try dir.readFileAlloc(a, "proof.bin", 16 * 1024 * 1024);
        defer a.free(bytes);
        const raw = try dir.readFileAlloc(a, "claims.json", 16384);
        defer a.free(raw);
        const claims = try std.json.parseFromSlice([4]core.fields.qm31.QM31, a, raw, .{});
        defer claims.deinit();
        try F.verify(a, .{ .bytes = bytes, .claims = claims.value });
        try receipt(a, dir, "receiver.json", bytes);
    } else return error.InvalidWeightedBinaryFixtureMode;
}
fn receipt(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, bytes: []const u8) !void {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const roster = F.expectedRoster();
    const roster_digest = try @import("stwo_riscv_frontend").rv64_air.word16_v1.binary_component.expectedRosterDigest(&roster);
    const raw = try std.json.Stringify.valueAlloc(a, .{ .scope = "known-public31FUNCTION-to3weighted-BINARY-andcanonicalAND-onePCS; no CPU/RAM claim", .positive_function_queries = 31, .AND_queries = 256, .expected_roster_digest = std.fmt.bytesToHex(roster_digest, .lower), .proof_sha256 = std.fmt.bytesToHex(digest, .lower), .proof_bytes = bytes.len, .queries = 70, .pow_bits = 26, .log_blowup = 1, .nominal_config_bits = 96, .main_released_before_challenge = true, .source_cells = 921600, .source_bytes = 3686400, .trace_oods_masks = 158 }, .{ .whitespace = .indent_2 });
    defer a.free(raw);
    try dir.writeFile(.{ .sub_path = name, .data = raw });
}
