//! Rebuild detached leaf Tree0 from an independently pinned serialized key.
//! This process never loads a proof, witness, or producer receipt.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const proof = @import("recursive_segment_v2_detached_proof.zig");
const KeyV1 = frontend.recursion.detached_segment_verifier_v1.KeyV1;

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len != 3 or args[2].len != 64)
        return error.ExpectedPinnedKeyPathAndSha256;
    var pin: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pin, args[2]);
    const bytes = try std.fs.cwd().readFileAlloc(allocator, args[1], 64 * 1024 * 1024);
    defer allocator.free(bytes);
    var actual: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &actual, .{});
    if (!std.meta.eql(actual, pin)) return error.DetachedKeySha256Mismatch;

    const parsed = try std.json.parseFromSlice(KeyV1, allocator, bytes, .{ .allocate = .alloc_always });
    defer parsed.deinit();
    const key = &parsed.value;
    try key.validate();
    const root = try proof.rebuildFixedRootFromKey(allocator, key);
    if (!std.meta.eql(root, key.preprocessed_root))
        return error.DetachedLeafTree0RootMismatch;
    std.debug.print("DETACHED_LEAF_KEY_TREE0_REBUILT key_sha256={s} root={any} proof_loaded=false\n", .{
        std.fmt.bytesToHex(actual, .lower), root,
    });
}
