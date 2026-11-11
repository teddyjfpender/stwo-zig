//! Explicit opt-in real-block native-to-recursive-root physical qualification.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Request = @import("../../rv64_ethereum_request.zig");
fn options() !@import("../pure_p2_op_runtime.zig").Options {
    const raw = std.posix.getenv("STWO_OP_R6_TRUTH_LOCAL") orelse return .{};
    if (std.mem.eql(u8, raw, "1")) return .{ .truth_local_gkr = true };
    if (std.mem.eql(u8, raw, "0")) return .{};
    return error.InvalidR6TruthProtocolSelection;
}
test "OP R6 pure P2 complete real block physical recursive root" {
    const config_path = std.posix.getenv("STWO_OP_R6_ROOT_CONFIG") orelse return error.SkipZigTest;
    const artifact_path = std.posix.getenv("STWO_OP_R6_ROOT_OUT") orelse return error.MissingOpP2RootArtifactDirectory;
    const native_path = std.posix.getenv("STWO_OP_R6_ROOT_NATIVE") orelse return error.MissingOpP2RootNativeDirectory;
    const raw = try std.fs.cwd().readFileAlloc(std.testing.allocator, config_path, 16384);
    defer std.testing.allocator.free(raw);
    const config = try std.json.parseFromSlice(Request.Config, std.testing.allocator, raw, .{});
    defer config.deinit();
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 32 << 30);
    defer budget.destroy();
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var result = try @import("recursion.zig").proveDirectoryWithOptions(budget.allocator(), config.value, native_path, .op_target_b4_q72_p0_fold4_v1, .{}, try options(), .{ .artifact_directory = artifact_path });
    defer result.deinit();
    try std.testing.expect(result.members != 0);
    try std.testing.expectEqual(result.members - 1, result.reductions);
    // The final receiver is physically isolated from every native proof file.
    var original = try std.fs.cwd().openDir(native_path, .{});
    defer original.close();
    var artifact = try std.fs.cwd().openDir(artifact_path, .{});
    defer artifact.close();
    try artifact.makeDir("source-only");
    var source_only = try artifact.openDir("source-only", .{});
    defer source_only.close();
    try original.copyFile("native-op.json", source_only, "native-op.json", .{});
    try original.copyFile("cells.bin", source_only, "cells.bin", .{});
    try std.testing.expectError(error.FileNotFound, source_only.access("native-op.bin", .{}));
    const source_path = try std.fs.path.join(std.testing.allocator, &.{ artifact_path, "source-only" });
    defer std.testing.allocator.free(source_path);
    const fresh = try @import("root_runtime.zig").qualifyDirectoryWithOptions(budget.allocator(), config.value, source_path, artifact_path, .op_target_b4_q72_p0_fold4_v1, .{}, try options(), .{});
    var wrong_policy = try options();
    wrong_policy.truth_local_gkr = !wrong_policy.truth_local_gkr;
    try std.testing.expectError(error.OpNativeSchemaPolicy, @import("root_runtime.zig").verifyDirectoryWithOptions(budget.allocator(), config.value, source_path, artifact_path, .op_target_b4_q72_p0_fold4_v1, .{}, wrong_policy, .{}));
    try std.testing.expectEqual(result.members, fresh.members);
}

test "OP R6 pure P2 fresh root-only receiver reuses durable artifacts" {
    const config_path = std.posix.getenv("STWO_OP_R6_VERIFY_CONFIG") orelse return error.SkipZigTest;
    const native_path = std.posix.getenv("STWO_OP_R6_VERIFY_SOURCE") orelse return error.MissingOpP2RootNativeDirectory;
    const artifact_path = std.posix.getenv("STWO_OP_R6_VERIFY_ROOT") orelse return error.MissingOpP2RootArtifactDirectory;
    const raw = try std.fs.cwd().readFileAlloc(std.testing.allocator, config_path, 16384);
    defer std.testing.allocator.free(raw);
    const config = try std.json.parseFromSlice(Request.Config, std.testing.allocator, raw, .{});
    defer config.deinit();
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 32 << 30);
    defer budget.destroy();
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    _ = try @import("root_runtime.zig").qualifyDirectoryWithOptions(budget.allocator(), config.value, native_path, artifact_path, .op_target_b4_q72_p0_fold4_v1, .{}, try options(), .{});
}
