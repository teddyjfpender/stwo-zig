//! Diagnostic custody only. These bytes failed the prover's OODS check and
//! must never be admitted through the verified artifact API.
const std = @import("std");
const recursion = @import("stwo_riscv_frontend").recursion;
const postcard = @import("interop_postcard");
const artifact = @import("recursive_temporal_secure_parent_artifact_v1.zig");
const resources = @import("ethereum_wrapper_resources_v1.zig");

pub fn retain(
    allocator: std.mem.Allocator,
    proof: recursion.engine.Proof,
    session: *const artifact.SessionV1,
    interaction_nonce: u64,
) !void {
    const corpus = std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_PROOF_CORPUS") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return,
        else => return err,
    };
    defer allocator.free(corpus);
    if (corpus.len == 0) return;
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try postcard.serializeProof(recursion.engine.Hasher, bytes.writer(allocator), proof);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes.items, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    // Bind the replay context too: identical proof bytes must not overwrite
    // evidence from a different session or interaction nonce.
    var case_hash = std.crypto.hash.sha2.Sha256.init(.{});
    case_hash.update("stwo-zig/failed-wrapper-custody/v1\x00");
    case_hash.update(&digest);
    case_hash.update(&session.identity_sha256);
    var nonce_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &nonce_bytes, interaction_nonce, .little);
    case_hash.update(&nonce_bytes);
    const case_hex = std.fmt.bytesToHex(case_hash.finalResult(), .lower);
    const path = try std.fs.path.join(allocator, &.{ corpus, "failed-wrapper-v1", &case_hex });
    defer allocator.free(path);
    var directory = try std.fs.cwd().makeOpenPath(path, .{});
    defer directory.close();
    var proof_name: [68]u8 = undefined;
    _ = try std.fmt.bufPrint(&proof_name, "{s}.bin", .{hex});
    try directory.writeFile(.{ .sub_path = &proof_name, .data = bytes.items });
    const metadata = try std.json.Stringify.valueAlloc(allocator, .{
        .format_version = @as(u32, 1),
        .verified = false,
        .failure = "ConstraintsNotSatisfied",
        .proof_sha256 = @as([]const u8, &hex),
        .proof_bytes = bytes.items.len,
        .session = session.*,
        .interaction_pow_nonce = interaction_nonce,
    }, .{ .whitespace = .indent_2 });
    defer allocator.free(metadata);
    var metadata_name: [69]u8 = undefined;
    _ = try std.fmt.bufPrint(&metadata_name, "{s}.json", .{hex});
    try directory.writeFile(.{ .sub_path = &metadata_name, .data = metadata });
    resources.progress("ETHEREUM_FAILED_WRAPPER_RETAINED verified=false sha256={s} bytes={d} directory={s}\n", .{ hex, bytes.items.len, path });
}
