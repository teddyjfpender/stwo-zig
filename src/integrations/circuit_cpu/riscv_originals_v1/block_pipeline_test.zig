//! Semantic compilation and cheap rejection only. No original/proof mocks.
const std = @import("std");
const Driver = @import("block_pipeline.zig");
test "RISC direct original saved block driver rejects empty jobs before proving" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try std.testing.expectError(error.InvalidOriginalBlockInput, Driver.run(std.testing.failing_allocator, .{ .elf = &.{}, .private_input = &.{}, .trusted = undefined, .jobs = &.{} }, temporary.dir, temporary.dir, undefined, .{ .canonical_circuit_air = "unread", .canonical_circuit_projection = "unread" }));
}
test "RISC direct original saved block driver rejects resource limits before admission" {
    const Job = @import("../../../frontends/riscv/prover/block_v8_full_block_pipeline_v1.zig").Job;
    const jobs = [_]Job{.{ .kind = .native, .request = undefined }};
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const variants = [_]Driver.Options{
        .{ .max_jobs = 0, .canonical_circuit_air = "unread", .canonical_circuit_projection = "unread" },
        .{ .max_artifact_bytes = 0, .canonical_circuit_air = "unread", .canonical_circuit_projection = "unread" },
        .{ .max_artifact_bytes = (128 << 20) + 1, .canonical_circuit_air = "unread", .canonical_circuit_projection = "unread" },
        .{ .max_original_bytes_per_window = 0, .canonical_circuit_air = "unread", .canonical_circuit_projection = "unread" },
        .{ .max_metadata_live_bytes = 0, .canonical_circuit_air = "unread", .canonical_circuit_projection = "unread" },
    };
    for (variants) |options| try std.testing.expectError(error.InvalidOriginalBlockInput, Driver.run(std.testing.failing_allocator, .{ .elf = &.{}, .private_input = &.{}, .trusted = undefined, .jobs = &jobs }, temporary.dir, temporary.dir, undefined, options));
}

/// Copy ONLY original-bundle files into an isolated source tree. In
/// particular no historical parent node-*.public or node-*.proof is copied.
fn copyOriginalWindow(a: std.mem.Allocator, source: std.fs.Dir, destination: std.fs.Dir) !void {
    var iterator = source.iterate();
    var copied: usize = 0;
    while (try iterator.next()) |entry| {
        if (entry.kind != .file) continue;
        const local = std.mem.startsWith(u8, entry.name, "local-") and (std.mem.endsWith(u8, entry.name, ".json") or std.mem.endsWith(u8, entry.name, ".proof"));
        const shared = std.mem.eql(u8, entry.name, "global-public.json") or std.mem.eql(u8, entry.name, "bridge-0.proof") or std.mem.eql(u8, entry.name, "global-memory.proof");
        if (!local and !shared) continue;
        const bytes = try source.readFileAlloc(a, entry.name, 128 << 20);
        defer a.free(bytes);
        try destination.writeFile(.{ .sub_path = entry.name, .data = bytes });
        copied += 1;
    }
    if (copied < 5) return error.IncompleteOriginalBlockFixture;
}

test "RISC direct original saved block driver closes three windows without parent metadata q70" {
    if (!std.process.hasEnvVarConstant("STWO_RISCV_ORIGINALS_BLOCK_DRIVER_Q70")) return error.SkipZigTest;
    const E = @import("stwo_prover_engine");
    const Capture = @import("../../../frontends/riscv/prover/block_v7_real_window_capture_v1.zig");
    const Full = @import("../../../frontends/riscv/prover/block_v8_full_boundary_policy_v1.zig");
    const Existing = @import("../../../frontends/riscv/prover/block_v8_full_block_pipeline_v1.zig");
    const Registry = @import("../riscv_recursion/registry_v1.zig");
    const Thin = @import("../../../frontends/riscv/recursion/block_v8_window_root_wire_v1.zig");
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 48 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: E.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const elf = @import("../riscv_recursion/qualification_v1.zig").tinyElf();
    const config = @import("../../../frontends/riscv/recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    var expected: [43]u8 = @splat(0);
    expected[32] = 1;
    const trusted = Full.Trusted{ .elf_sha256 = Capture.sha(&elf), .input_sha256 = Capture.sha(&.{}), .total_cycles = 7, .expected_output = expected, .config = config };
    var retained = try std.fs.cwd().openDir("campaign/qualification/new-full-block-depth2-driver-q70-v1", .{});
    defer retained.close();
    var temporary = std.testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    var source = try temporary.dir.makeOpenPath("originals-only", .{ .iterate = true });
    defer source.close();
    var captures: [3]Capture.Captured = undefined;
    var initialized: usize = 0;
    defer for (captures[0..initialized]) |*capture| capture.deinit();
    var jobs: [3]Existing.Job = undefined;
    for (&captures, &jobs, [_]u64{ 0, 4, 6 }, [_]u32{ 4, 2, 1 }, 0..) |*capture, *job, skip, cycles, i| {
        // Tiny capture supplies external checkpoint pins only; all q70 ORIGINAL
        // proof bodies are retained files and are never regenerated here.
        capture.* = try Capture.capture(a, &elf, &.{}, .{ .elf = trusted.elf_sha256, .input = trusted.input_sha256 }, .{ .skip_cycles = skip, .cycles = cycles }, .{});
        initialized += 1;
        capture.releaseExecution();
        job.* = .{ .kind = .native, .request = .{ .elf = &elf, .elf_sha256 = trusted.elf_sha256, .config = config, .incoming = capture.incoming, .outgoing = capture.outgoing, .trusted_window = .{ .elf_sha256 = trusted.elf_sha256, .incoming_sha256 = capture.incoming.identity(), .outgoing_sha256 = capture.outgoing.identity(), .window = .{ .skip_cycles = skip, .cycles = cycles } } } };
        var name: [64]u8 = undefined;
        const path = try std.fmt.bufPrint(&name, "window-{d}", .{i});
        var input_window = try retained.openDir(path, .{ .iterate = true });
        defer input_window.close();
        var output_window = try source.makeOpenPath(path, .{});
        defer output_window.close();
        try copyOriginalWindow(a, input_window, output_window);
        try std.testing.expectError(error.FileNotFound, source.access(try std.fmt.bufPrint(&name, "node-{d}.public", .{i}), .{}));
        try std.testing.expectError(error.FileNotFound, source.access(try std.fmt.bufPrint(&name, "node-{d}.proof", .{i}), .{}));
    }
    const air = try std.fs.cwd().readFileAlloc(a, "vectors/circuit/official/circuit_air.air_programs_v1.bin", 1 << 20);
    defer a.free(air);
    const projection = try std.fs.cwd().readFileAlloc(a, "vectors/circuit/official/compiled_air_constraints_v1.bin", 1 << 20);
    defer a.free(projection);
    const backend = try Registry.BackendAuthority.load(a, air, projection);
    defer backend.deinit();
    const output_path = std.posix.getenv("STWO_RISCV_ORIGINALS_BLOCK_DRIVER_OUTPUT") orelse "campaign/qualification/new-direct-original-block-driver-q70-v1";
    try std.fs.cwd().makePath(output_path);
    var output = try std.fs.cwd().openDir(output_path, .{ .iterate = true });
    defer output.close();
    const report = try Driver.run(a, .{ .elf = &elf, .private_input = &.{}, .trusted = trusted, .jobs = &jobs }, source, output, backend, .{ .canonical_circuit_air = air, .canonical_circuit_projection = projection });
    try std.testing.expect(report.proof_verified);
    try std.testing.expectEqual(@as(u32, 3), report.windows);
    try std.testing.expectEqual(@as(u32, 2), report.folds);
    try std.testing.expectEqual(@as(u32, 3), report.original_bundles_reused);
    try std.testing.expectEqual(@as(u64, 9), report.original_codec_reads_for_metadata);
    try std.testing.expectEqual(@as(u64, 9), report.original_body_reads_for_proving);
    try std.testing.expectEqual(@as(u64, 18), report.original_proofs_read);
    try std.testing.expectEqual(@as(u32, 0), report.native_parent_proofs_generated);
    try std.testing.expectEqual(@as(u32, 0), report.legacy_recursive_proofs_read);
    try std.testing.expectEqual(@as(u32, 0), report.legacy_parent_public_metadata_read);
    try std.testing.expect(report.public_metadata_published_in_output);
    // Source remains original-only; output is self-contained in public metadata.
    for (0..3) |i| {
        var name: [64]u8 = undefined;
        const public_name = try std.fmt.bufPrint(&name, "node-{d}.public", .{i});
        try std.testing.expectError(error.FileNotFound, source.access(public_name, .{}));
        const public = try output.readFileAlloc(a, public_name, 16 << 20);
        defer a.free(public);
        var decoded = try Thin.decodeNativeLeafOwned(a, public, .{});
        defer decoded.deinit();
        try std.testing.expectEqualDeep(@as([32]u8, @splat(0)), decoded.value.main_root);
    }
    const catalog = try output.readFileAlloc(a, "catalog.public", 24 + 16 * 4095);
    defer a.free(catalog);
    try std.testing.expectEqualSlices(u8, "R8CFMD02", catalog[0..8]);
    std.debug.print("RISC_ORIGINAL_BLOCK_DRIVER q=70 pow=26 windows=3 folds=2 native_parent_proofs=0 original_proofs_generated=0 old_parent_metadata=0 root_bytes={d} root_sha256={s} whole_ns={d} final_verify_ns={d}\n", .{ report.root_bytes, report.root_sha256, report.whole_ns, report.final_fresh_verification_ns });
}
