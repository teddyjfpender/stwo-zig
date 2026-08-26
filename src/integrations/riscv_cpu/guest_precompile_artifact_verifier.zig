//! C-009 process two: decode and independently verify one profile artifact.

const std = @import("std");
const support = @import("guest_precompile_artifact_support.zig");

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const arguments = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, arguments);
    if (arguments.len != 2) {
        std.debug.print(
            "usage: guest-precompile-artifact-verifier <artifact>\n",
            .{},
        );
        return error.InvalidArguments;
    }

    try verifyArtifact(allocator, arguments[1]);
}

fn verifyArtifact(allocator: std.mem.Allocator, path: []const u8) !void {
    const encoded = try readArtifact(
        allocator,
        path,
        support.artifact_limits.max_artifact_bytes,
    );
    defer allocator.free(encoded);

    var decoded = try support.proof_artifact.decodeAllocForConfig(
        allocator,
        encoded,
        support.pcs_config,
        support.artifact_limits,
    );
    var proof_moved = false;
    defer if (proof_moved)
        decoded.deinitAfterProofMoved(allocator)
    else
        decoded.deinit(allocator);

    // The profile verifier consumes the proof on every return path. Metadata
    // remains owned here and outlives the complete call.
    proof_moved = true;
    try support.riscv_cpu.verifyPoseidon2(
        allocator,
        support.pcs_config,
        decoded.statement,
        decoded.extension,
        decoded.artifact,
        decoded.proof,
        decoded.interaction_claim,
    );
}

fn readArtifact(
    allocator: std.mem.Allocator,
    path: []const u8,
    max_bytes: usize,
) ![]u8 {
    var file = if (std.fs.path.isAbsolute(path))
        try std.fs.openFileAbsolute(path, .{})
    else
        try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const stat = try file.stat();
    if (stat.size > max_bytes) return error.ArtifactResourceLimitExceeded;
    const length = std.math.cast(usize, stat.size) orelse
        return error.ArtifactResourceLimitExceeded;
    const bytes = try allocator.alloc(u8, length);
    errdefer allocator.free(bytes);
    if (try file.readAll(bytes) != bytes.len) return error.UnexpectedEndOfFile;

    // Fail closed if the file changed size between stat and read.
    var trailing: [1]u8 = undefined;
    if (try file.read(&trailing) != 0) return error.ArtifactChangedDuringRead;
    return bytes;
}
