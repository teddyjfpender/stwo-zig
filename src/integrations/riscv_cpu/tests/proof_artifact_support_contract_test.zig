//! Real consumer of the CPU package's public artifact provider.
const std = @import("std");
const support = @import("stwo_riscv_cpu_integration").rv64_proof_artifact_support;

test "CPU artifact provider publishes durably and preserves an existing proof on refusal" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try support.writeExclusive(tmp.dir, "proof", "accepted");
    try std.testing.expectError(error.PathAlreadyExists, support.writeExclusive(tmp.dir, "proof", "replacement"));
    const proof = try tmp.dir.readFileAlloc(std.testing.allocator, "proof", 64);
    defer std.testing.allocator.free(proof);
    try std.testing.expectEqualStrings("accepted", proof);
    try support.replaceSummary(tmp.dir, "a longer old summary");
    try support.replaceSummary(tmp.dir, "new");
    const summary = try tmp.dir.readFileAlloc(std.testing.allocator, "summary.json", 64);
    defer std.testing.allocator.free(summary);
    try std.testing.expectEqualStrings("new", summary);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile("summary.pending", .{}));
}
