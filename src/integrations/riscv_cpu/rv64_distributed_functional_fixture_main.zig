//! Durable experimental PUBLIC FACTS ONLY control; no CPU/RAM/execution claim.
//! Producer and receiver independently construct the same pinned public roster.
const std = @import("std");
const Q = @import("stwo_core").fields.qm31.QM31;
const F = @import("rv64_distributed_v1/functional.zig");
const D = @import("rv64_distributed_v1/manifest.zig");
const W = @import("rv64_distributed_v1/wire.zig");
fn hash(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}
fn context() D.T.Context {
    return .{
        .request_id = (1 << 60) + 17,
        .request_digest = hash("distributed-functional13-public-fixture-request-v1"),
        .instance = hash("distributed-functional13-public-fixture-instance-v1"),
        .program_key = hash("public-roster32-binary-and65536-v1"),
        .input = hash("AND-OR-XOR-three-public-questions-v1"),
        .policy = hash("facts-only-no-cpu-no-ram-v1"),
        .terminal = hash("no-execution-terminal-v1"),
        .opcode_map = D.T.opcodeMapIdentity(),
        .relation_epoch = (1 << 53) + 7,
    };
}
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 3) return error.ExpectedProduceOrVerifyAndDirectory;
    const roster = F.diagnosticRoster();
    if (std.mem.eql(u8, args[1], "produce")) {
        var aggregate = try F.produce(a, context(), &roster);
        defer aggregate.deinit(a);
        try std.fs.cwd().makePath(args[2]);
        var dir = try std.fs.cwd().openDir(args[2], .{});
        defer dir.close();
        const file = try dir.createFile("manifest.bin", .{});
        defer file.close();
        try W.write(file, &aggregate.manifest);
        const names = [_][]const u8{ "consumer.bin", "binary.bin" };
        for (aggregate.proofs, names) |proof, name| try dir.writeFile(.{ .sub_path = name, .data = proof.bytes });
        const claims = try std.json.Stringify.valueAlloc(a, [2][3]Q{ aggregate.proofs[0].claims, aggregate.proofs[1].claims }, .{});
        defer a.free(claims);
        try dir.writeFile(.{ .sub_path = "claims.json", .data = claims });
        const report = try std.fmt.allocPrint(a, "{{\"scope\":\"experimental-public-functional-facts-only\",\"cpu_bound\":false,\"ram_bound\":false,\"queries\":70,\"pow_bits\":26,\"stage1_actual_pcs_roots\":true,\"complete_manifest_digest\":\"{s}\",\"consumer_bytes\":{d},\"consumer_sha256\":\"{s}\",\"binary_bytes\":{d},\"binary_sha256\":\"{s}\",\"global_positive_capacity\":32,\"actual_positive_function_mass\":3,\"and_mass_including_padding\":256}}\n", .{ std.fmt.bytesToHex(aggregate.manifest.digest, .lower), aggregate.proofs[0].bytes.len, std.fmt.bytesToHex(hash(aggregate.proofs[0].bytes), .lower), aggregate.proofs[1].bytes.len, std.fmt.bytesToHex(hash(aggregate.proofs[1].bytes), .lower) });
        defer a.free(report);
        try dir.writeFile(.{ .sub_path = "producer.json", .data = report });
    } else if (std.mem.eql(u8, args[1], "verify")) {
        // No producer state/native roots are retained. Expected facts, program
        // schema, fixed roots, and geometry are reconstructed in this process.
        var dir = try std.fs.cwd().openDir(args[2], .{});
        defer dir.close();
        const expected = try F.expectedInventory(a, &roster);
        const file = try dir.openFile("manifest.bin", .{});
        defer file.close();
        var manifest = try W.read(a, file, .{ .context = context(), .specs = &expected });
        var owns_manifest = true;
        defer if (owns_manifest) manifest.deinit();
        const first = try dir.readFileAlloc(a, "consumer.bin", 8 * 1024 * 1024);
        var owns_first = true;
        defer if (owns_first) a.free(first);
        const second = try dir.readFileAlloc(a, "binary.bin", 8 * 1024 * 1024);
        var owns_second = true;
        defer if (owns_second) a.free(second);
        const raw = try dir.readFileAlloc(a, "claims.json", 4096);
        defer a.free(raw);
        const claims = try std.json.parseFromSlice([2][3]Q, a, raw, .{});
        defer claims.deinit();
        var aggregate = F.Aggregate{ .manifest = manifest, .proofs = .{ .{ .bytes = first, .claims = claims.value[0] }, .{ .bytes = second, .claims = claims.value[1] } } };
        owns_manifest = false;
        owns_first = false;
        owns_second = false;
        defer aggregate.deinit(a);
        try F.verify(a, context(), &roster, &aggregate);
        try dir.writeFile(.{ .sub_path = "receiver.json", .data = "{\"accepted_public_functional_facts\":true,\"actual_air_fri_proofs_verified\":2,\"independently_expected_roster\":true,\"complete_manifest_alpha\":true,\"all_physical_claims_closed\":true,\"cpu_bound\":false,\"ram_bound\":false}\n" });
    } else return error.ExpectedProduceOrVerifyAndDirectory;
}
