//! Fresh-process control for ACTUAL six-instruction register-only BINARY CPU.
//! Three physical proofs. No RAM/general RV64/Ethereum execution is claimed.
const std = @import("std");
const A = @import("rv64_distributed_execution_v1/aggregate.zig");
const Native = @import("rv64_distributed_execution_v1/native_fixture.zig");
const Receipt = @import("rv64_distributed_execution_v1/receipt.zig");
const Rom = @import("stwo_riscv_frontend").rv64_air.word16_cpu.rom;
fn hash(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 3) return error.ExpectedProduceOrVerifyAndDirectory;
    var program = try Rom.Setup.init(a, .{ .base = Native.BASE, .words = &Native.WORDS });
    defer program.deinit();
    const expected = try Native.expected(&program);
    if (std.mem.eql(u8, args[1], "produce")) {
        const native = try Native.Fixture.init(a); // VM already destroyed.
        var encoded = try A.produce(a, expected, &program, native.shards, .{ &native.records[0], &native.records[1] });
        defer encoded.deinit(a);
        try std.fs.cwd().makePath(args[2]);
        var dir = try std.fs.cwd().openDir(args[2], .{});
        defer dir.close();
        try Receipt.write(dir, &encoded);
        const report = try std.fmt.allocPrint(a, "{{\"scope\":\"experimental-register-only-binary-reset-v1\",\"instructions\":6,\"cpu_shards\":2,\"shared_binary_provider\":1,\"physical_components\":12,\"physical_proofs\":3,\"queries_per_proof\":70,\"pow_bits_per_proof\":26,\"ram_bound\":false,\"ethereum_bound\":false,\"general_rv64_bound\":false,\"complete_manifest\":\"{s}\",\"actual_function_mass\":6,\"conservative_manifest_positive_capacity\":{d},\"cpu0_bytes\":{d},\"cpu0_sha256\":\"{s}\",\"cpu1_bytes\":{d},\"cpu1_sha256\":\"{s}\",\"binary_bytes\":{d},\"binary_sha256\":\"{s}\"}}\n", .{ std.fmt.bytesToHex(encoded.manifest.digest, .lower), encoded.manifest.positive_capacity, encoded.cpu[0].bytes.len, std.fmt.bytesToHex(hash(encoded.cpu[0].bytes), .lower), encoded.cpu[1].bytes.len, std.fmt.bytesToHex(hash(encoded.cpu[1].bytes), .lower), encoded.binary.bytes.len, std.fmt.bytesToHex(hash(encoded.binary.bytes), .lower) });
        defer a.free(report);
        try dir.writeFile(.{ .sub_path = "producer.json", .data = report });
    } else if (std.mem.eql(u8, args[1], "verify")) {
        var dir = try std.fs.cwd().openDir(args[2], .{});
        defer dir.close();
        // Independently expected program/genesis/finalPC/registers/counts and
        // work inventory; receiver never executes the VM or trusts native counts.
        try Receipt.readAndVerify(a, dir, expected, &program);
        try dir.writeFile(.{ .sub_path = "receiver.json", .data = "{\"accepted_register_only_binary_execution\":true,\"instructions\":6,\"cpu_shards\":2,\"verified_physical_proofs\":3,\"local_reg_rom_u16_u8_closed_each_shard\":true,\"shared_function_closed\":true,\"genesis_adjacency_terminal_output_checked\":true,\"clock_profile\":\"reset-v1\",\"ram_bound\":false,\"ethereum_bound\":false,\"general_rv64_bound\":false}\n" });
    } else return error.ExpectedProduceOrVerifyAndDirectory;
}
