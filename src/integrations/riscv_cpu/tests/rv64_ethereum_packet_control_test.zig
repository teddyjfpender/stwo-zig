//! Synthetic ABI pipeline, not an Ethereum block validator fixture. Two native
//! batches really store length43/halt1; their joined proofs close terminal RAM.
const std = @import("std");
const Collect = @import("../rv64_ethereum_native_prepare.zig");
const Worker = @import("../rv64_ethereum_packet_worker.zig");
const Inspect = @import("../rv64_ethereum_packet_inspect.zig");
const Finalize = @import("../rv64_ethereum_finalize.zig");
const Receiver = @import("../rv64_ethereum_verify_chain.zig");
const Request = @import("../rv64_ethereum_request.zig");
const Receipt = @import("../rv64_ethereum_batch_receipt.zig");
const a = std.testing.allocator;
fn image() [144]u8 {
    var bytes: [144]u8 = @splat(0);
    @memcpy(bytes[0..7], "\x7fELF\x02\x01\x01");
    std.mem.writeInt(u16, bytes[16..18], 2, .little);
    std.mem.writeInt(u16, bytes[18..20], 243, .little);
    std.mem.writeInt(u32, bytes[20..24], 1, .little);
    std.mem.writeInt(u64, bytes[24..32], 4096, .little);
    std.mem.writeInt(u64, bytes[32..40], 64, .little);
    std.mem.writeInt(u16, bytes[52..54], 64, .little);
    std.mem.writeInt(u16, bytes[54..56], 56, .little);
    std.mem.writeInt(u16, bytes[56..58], 1, .little);
    std.mem.writeInt(u32, bytes[64..68], 1, .little);
    std.mem.writeInt(u32, bytes[68..72], 5, .little);
    std.mem.writeInt(u64, bytes[72..80], 120, .little);
    std.mem.writeInt(u64, bytes[80..88], 4096, .little);
    std.mem.writeInt(u64, bytes[96..104], 24, .little);
    std.mem.writeInt(u64, bytes[104..112], 24, .little);
    std.mem.writeInt(u64, bytes[112..120], 4, .little);
    // lui x1,0xc00; addi x2,zero,43; sw x2,4(x1);
    // addi x2,zero,1; sw x2,0(x1); terminal: jal zero,0.
    const words = [_]u32{ 0x00c000b7, 0x02b00113, 0x0020a223, 0x00100113, 0x0020a023, 0x0000006f };
    for (words, 0..) |word, i| std.mem.writeInt(u32, bytes[120 + 4 * i ..][0..4], word, .little);
    return bytes;
}
fn replace(dir: std.fs.Dir, name: []const u8, bytes: []const u8) !void {
    var file = try dir.createFile(name, .{});
    defer file.close();
    try file.writeAll(bytes);
}
fn exists(dir: std.fs.Dir, name: []const u8) !bool {
    dir.access(name, .{}) catch |err| {
        if (err == error.FileNotFound) return false;
        return err;
    };
    return true;
}
test "portable packet workers prove out of order and complete only after canonical receiver" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(a, ".");
    defer a.free(root);
    const elf_path = try std.fs.path.join(a, &.{ root, "guest.elf" });
    defer a.free(elf_path);
    const input_path = try std.fs.path.join(a, &.{ root, "input" });
    defer a.free(input_path);
    const output_path = try std.fs.path.join(a, &.{ root, "artifacts" });
    defer a.free(output_path);
    const elf = image();
    try replace(temporary.dir, "guest.elf", &elf);
    try replace(temporary.dir, "input", &.{1});
    const elf_hash = std.fmt.bytesToHex(Request.sha(&elf), .lower);
    const input_hash = std.fmt.bytesToHex(Request.sha(&.{1}), .lower);
    const config = Request.Config{ .elf = elf_path, .input = input_path, .elf_sha256 = &elf_hash, .input_sha256 = &input_hash, .expected_output = "00" ** 43, .symbols = .{ .input_start = 0x800000, .input_end = 0xc00000, .halt_flag = 0xc00000, .output_len = 0xc00004, .output_data = 0xc00008, .output_end = 0x1000000, .stack_bottom = 0x1000000, .stack_top = 0x2000000, .heap_start = 0x2100000, .heap_end = 0x2200000 }, .output_directory = output_path, .terminal_pc = 4116, .batch_steps = 3, .max_steps = 10, .profile_stages = false, .workers = 1 };
    const collection = try Collect.run(a, config);
    try std.testing.expectEqual(@as(u32, 2), collection.collected_batches);
    try std.testing.expectEqual(@as(u64, 5), collection.instructions);
    try std.testing.expect(collection.completed and !collection.global_chain_accepted);
    var dir = try temporary.dir.openDir("artifacts", .{});
    defer dir.close();
    try std.testing.expect(!try exists(dir, "summary.json"));
    const inspected = try Inspect.run(a, config, 1);
    try std.testing.expectEqual(@as(u32, 2), inspected.steps);
    const Opcode = @import("stwo_riscv_frontend").rv64.decode.Opcode;
    try std.testing.expectEqual(@as(u64, 1), inspected.opcode_counts[@intFromEnum(Opcode.ADDI)]);
    try std.testing.expectEqual(@as(u64, 1), inspected.opcode_counts[@intFromEnum(Opcode.SW)]);
    var total: u64 = 0;
    for (inspected.opcode_counts) |count| total += count;
    try std.testing.expectEqual(@as(u64, inspected.steps), total);
    try std.testing.expect(!inspected.physical_proof_verified and !inspected.global_chain_accepted);
    const second = try Worker.run(a, config, 1);
    try std.testing.expect(second.physical_fragment_verified and !second.global_chain_accepted);
    try std.testing.expect(second.total_before_completion_ns >= second.authority_ns + second.packet_read_ns + second.prove_worker_ns);
    try std.testing.expect(second.prove_worker_ns >= second.metrics.prove_ns);
    try std.testing.expect(!try exists(dir, "batch-000000.proof"));
    try std.testing.expectError(error.FileNotFound, Finalize.run(a, config));
    try std.testing.expect(!try exists(dir, "summary.json"));
    _ = try Worker.run(a, config, 0);
    try std.testing.expectError(error.EthereumWorkerArtifactsAlreadyExist, Worker.run(a, config, 1));
    // Extra or missing fragments are transport failures before acceptance.
    try replace(dir, "batch-000002.proof", &.{});
    try std.testing.expectError(error.UnexpectedEthereumReceipt, Finalize.run(a, config));
    try dir.deleteFile("batch-000002.proof");
    const original = try dir.readFileAlloc(a, "batch-000000.json", 128 * 1024);
    defer a.free(original);
    const parsed = try std.json.parseFromSlice(Receipt.Receipt, a, original, .{});
    defer parsed.deinit();
    for (0..5) |mutation| {
        var changed = parsed.value;
        switch (mutation) {
            0 => changed.index = 1,
            1 => changed.public.before[0] = (changed.public.before[0] + 1) % 2147483647,
            2 => changed.public.cpu.statement.initial_pc += 4,
            3 => changed.public.cpu.statement.initial_registers[1] = 1,
            4 => changed.public.cpu.first_call_id = 2,
            else => unreachable,
        }
        const bad = try std.json.Stringify.valueAlloc(a, changed, .{});
        defer a.free(bad);
        try replace(dir, "batch-000000.json", bad);
        if (mutation == 4) try std.testing.expectError(error.InvalidEthereumServiceCoverage, Finalize.run(a, config)) else try std.testing.expectError(error.InvalidEthereumBatchAdjacency, Finalize.run(a, config));
        try std.testing.expect(!try exists(dir, "summary.json"));
    }
    try replace(dir, "batch-000000.json", original);
    const accepted = try Finalize.run(a, config);
    try std.testing.expect(accepted.full_block_proof_verified);
    try std.testing.expectEqual(@as(u64, 5), accepted.instructions);
    const fresh = try Receiver.verify(a, config, true);
    try std.testing.expect(fresh.full_block_proof_verified);
    try std.testing.expectEqualSlices(u32, &accepted.final_root, &fresh.final_root);
}
