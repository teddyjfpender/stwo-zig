//! Durable, independently context-pinned PUBLIC RAM hash receipt. No private
//! caller, CPU linkage, recursive continuation or Ethereum execution admission.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const memory = frontend.rv64_air.memory;
const codec = @import("rv64_ram_context.zig");
const proof = @import("rv64_ram_hash_proof.zig");
const a = std.heap.smp_allocator;
const Report = struct {
    schema: []const u8 = "rv64-public-ram-hash-receipt-v1",
    status: []const u8,
    context_sha256: [64]u8,
    context_bytes: usize,
    proof_sha256: ?[64]u8 = null,
    proof_bytes: ?usize = null,
    before_root: ?memory.commitment.Digest = null,
    after_root: ?memory.commitment.Digest = null,
    independent_native_final_image: bool = false,
    verified: bool = false,
    fresh_receiver_mode: bool = false,
    elapsed_ns: ?u64 = null,
    pow_bits: ?u32 = null,
    fri_queries: ?u32 = null,
    public_permutation_ledger: bool = false,
    private_ram_caller: bool = false,
    cpu_ram_relation: bool = false,
    state_continuation: bool = false,
    ethereum_execution: bool = false,
};

fn hash(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}
fn write(path: []const u8, bytes: []const u8) !void {
    var file = try std.fs.cwd().createFile(path, .{ .exclusive = true });
    errdefer std.fs.cwd().deleteFile(path) catch {};
    defer file.close();
    try file.writeAll(bytes);
    try file.sync();
}
fn emit(value: Report) !void {
    const json = try std.json.Stringify.valueAlloc(a, value, .{ .whitespace = .indent_2 });
    defer a.free(json);
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}

fn fixture(path: []const u8) !void {
    var native = frontend.rv64.memory.Memory.init(a, .{});
    defer native.deinit();
    try native.map(.{ .start = 0x1000, .size = 4096, .permissions = .{ .read = true, .write = true } });
    for (0..512) |i| try native.store(0x1000 + @as(u64, @intCast(i)) * 8, 8, @as(u64, @intCast(i)) *% 0x1234_5678_9abc_def1);
    var initial = try memory.image.snapshot(a, &native);
    defer initial.deinit();
    const updates = [_]memory.transition.NetUpdate{.{ .address = 0x1000, .value = 17, .byte_mask = 255 }};
    var witness = try memory.transition.Witness.buildFromSnapshot(a, &native, &initial, &.{1}, &updates);
    defer witness.deinit();
    try native.store(0x1000, 8, 17);
    var final = try memory.image.snapshot(a, &native);
    defer final.deinit();
    try witness.verifyUpdates(a, initial.root(), final.root(), &.{1}, &updates);
    const bytes = try codec.encode(a, &witness, &updates);
    defer a.free(bytes);
    try write(path, bytes);
    try emit(.{ .schema = "rv64-public-ram-hash-receipt-v1", .status = "synthetic_context_created", .context_sha256 = std.fmt.bytesToHex(hash(bytes), .lower), .context_bytes = bytes.len, .before_root = initial.root(), .after_root = final.root(), .independent_native_final_image = true, .ethereum_execution = false, .private_ram_caller = false, .cpu_ram_relation = false });
}

pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len > 1 and std.mem.startsWith(u8, args[1], "terminal-")) return @import("rv64_ram_terminal_receipt.zig").run(args);
    if (args.len > 1 and std.mem.startsWith(u8, args[1], "private-")) return @import("rv64_ram_private_receipt.zig").run(args);
    if (args.len == 3 and std.mem.eql(u8, args[1], "fixture")) return fixture(args[2]);
    if (args.len != 5 or args[3].len != 64) return error.ExpectedModeContextPinnedSha256Proof;
    const proving = std.mem.eql(u8, args[1], "prove");
    if (!proving and !std.mem.eql(u8, args[1], "verify")) return error.InvalidRamReceiptMode;
    var expected_sha: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_sha, args[3]);
    const context_bytes = try std.fs.cwd().readFileAlloc(a, args[2], codec.MAX_BYTES);
    defer a.free(context_bytes);
    var context = try codec.decode(a, context_bytes, expected_sha);
    defer context.deinit();
    var timer = try std.time.Timer.start();
    const bytes = if (proving) try proof.proveReceipt(a, &context.witness) else try std.fs.cwd().readFileAlloc(a, args[4], 64 * 1024 * 1024);
    defer a.free(bytes);
    if (proving) {
        try write(args[4], bytes);
    } else {
        try proof.verifyReceipt(a, &context.witness, context.witness.before, context.witness.after, context.page_indices, context.updates, bytes);
    }
    const elapsed_ns = timer.read();
    try emit(.{ .schema = "rv64-public-ram-hash-receipt-v1", .status = if (proving) "public_hash_receipt_produced" else "public_hash_receipt_verified", .verified = !proving, .fresh_receiver_mode = !proving, .context_sha256 = std.fmt.bytesToHex(expected_sha, .lower), .proof_sha256 = std.fmt.bytesToHex(hash(bytes), .lower), .context_bytes = context_bytes.len, .proof_bytes = bytes.len, .elapsed_ns = elapsed_ns, .pow_bits = 26, .fri_queries = 70, .public_permutation_ledger = true, .private_ram_caller = false, .cpu_ram_relation = false, .state_continuation = false, .ethereum_execution = false });
}
