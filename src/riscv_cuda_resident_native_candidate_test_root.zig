const std = @import("std");
const Candidate = @import("integrations/riscv_cuda/resident_native_candidate_v1.zig");
test "resident native candidate detached raw ingress and exact finite bundle" {
    const a = std.testing.allocator;
    var candidate = try Candidate.ForCommitments(4).init(a, false, false);
    defer candidate.deinit();
    const old = try @import("integrations/riscv_cuda/resident_native_plan_test_v1.zig").fixture(4, a, false);
    defer old.deinit();
    try std.testing.expectEqualSlices(u8, &old.view().identity, &candidate.program.view().identity);
    try std.testing.expectEqual(@as(usize, 3), candidate.retirement_count);
    try std.testing.expectEqual(candidate.retirement_count * 24 + candidate.clock_count * 5, candidate.raw.len);
    try std.testing.expectEqual(@as(u32, 3), candidate.program.view().composition_split);
    std.debug.print("RESIDENT_NATIVE_COLD_GEOMETRY composition={d} fri={d} mask={d}\n", .{ candidate.program.view().composition_log, candidate.program.view().fri_log, candidate.program.view().mask_log });
}

test "resident native candidate original CPU oracle survives fixture teardown" {
    const a = std.testing.allocator;
    var candidate = try Candidate.ForCommitments(4).init(a, false, true);
    defer candidate.deinit();
    try candidate.verify(&candidate.reference.?);
    try std.testing.expectEqual(@as(usize, 3 * 24), candidate.raw.len);
    try @import("integrations/riscv_cuda/resident_native_prover_v1.zig").requireQualification(true);
    try std.testing.expectError(error.UnqualifiedResidentNativeController, @import("integrations/riscv_cuda/resident_native_prover_v1.zig").requireQualification(false));
}

fn exportCandidate(comptime N: usize, a: std.mem.Allocator, options: Candidate.Options, path: []const u8) !void {
    var candidate = try Candidate.ForCommitments(N).initWithOptions(a, options);
    defer candidate.deinit();
    var writer: std.Io.Writer.Allocating = .init(a);
    defer writer.deinit();
    try @import("integrations/riscv_cuda/resident_native_kernel_bundle_v1.zig").emit(N, a, &writer.writer, candidate.program);
    var file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    try file.writeAll(writer.written());
    const p = candidate.program.view();
    const config = options.security.config();
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(writer.written(), &digest, .{});
    const receipt = .{ .schema = "stwo-native-candidate-export-v2", .program_identity = p.identity, .code_identity = p.code_identity, .source_sha256 = digest, .trees = N, .retirements = candidate.retirement_count, .composition_log = p.composition_log, .fri_log = p.fri_log, .code_identity_symbol = "stwo_native_code_identity", .gpu_qualified = false };
    const json = try std.json.Stringify.valueAlloc(a, receipt, .{ .whitespace = .indent_2 });
    defer a.free(json);
    const receipt_path = try std.fmt.allocPrint(a, "{s}.json", .{path});
    defer a.free(receipt_path);
    var receipt_file = try std.fs.cwd().createFile(receipt_path, .{});
    defer receipt_file.close();
    try receipt_file.writeAll(json);

    std.debug.print("RESIDENT_NATIVE_CANDIDATE program_identity={x} code_identity={x} trees={d} split={d} retirements={d} mul={d} loads={d} stores={d} clocks={d} raw_words={d} queries={d} pow={d} composition={d} fri={d} mask={d} gpu_qualified=false\n", .{ p.identity, p.code_identity, N, p.composition_split, candidate.retirement_count, candidate.mul_retirements, candidate.load_retirements, candidate.store_retirements, candidate.clock_count, candidate.raw.len, config.fri_config.n_queries, config.pow_bits, p.composition_log, p.fri_log, p.mask_log });
}
test "resident native candidate configured exact finite bundle export" {
    const a = std.testing.allocator;
    const path = std.process.getEnvVarOwned(a, "STWO_NATIVE_CANDIDATE_EXPORT") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer a.free(path);
    const selection = try Candidate.fromEnv(a);
    switch (selection.trees) {
        4 => try exportCandidate(4, a, selection.options, path),
        5 => try exportCandidate(5, a, selection.options, path),
        else => unreachable,
    }
}
test "resident native candidate genuine configurable retirement counts" {
    const a = std.testing.allocator;
    for ([_]u32{ 64, 1024, 32768 }) |count| {
        var candidate = try Candidate.ForCommitments(4).initWithOptions(a, .{ .retirements = count });
        defer candidate.deinit();
        try std.testing.expectEqual(@as(usize, count), candidate.retirement_count);
        try std.testing.expectEqual(@as(usize, (count - 1) / 2), candidate.mul_retirements);
        try std.testing.expectEqual(@as(usize, 24 * count + 5 * candidate.clock_count), candidate.raw.len);
        var described: usize = 0;
        const shape = candidate.program.view().profile.pin.shape;
        for (shape.component_descs[0..shape.n_components]) |d| described += d.n_rows;
        try std.testing.expectEqual(@as(usize, count), described);
        try std.testing.expect(candidate.program.view().fri_log > 2);
        std.debug.print("RESIDENT_NATIVE_REAL_SIZE retirements={d} mul={d} actual_descriptor_rows={d} fri={d}\n", .{ count, candidate.mul_retirements, described, candidate.program.view().fri_log });
    }
    try std.testing.expectError(error.InvalidResidentNativeRetirementCount, (Candidate.Options{ .retirements = 2 }).count(4));
    try std.testing.expectError(error.InvalidResidentNativeRetirementCount, (Candidate.Options{ .retirements = 3 }).count(5));
    try std.testing.expectError(error.InvalidResidentNativeRetirementCount, (Candidate.Options{ .retirements = Candidate.MAX_RETIREMENTS + 1 }).count(4));
}
test "resident native candidate real access optional q70 admission and detached CPU oracle" {
    const a = std.testing.allocator;
    var access = try Candidate.ForCommitments(5).initWithOptions(a, .{ .retirements = 64, .q2 = true, .cpu_reference = true });
    defer access.deinit();
    try std.testing.expect(access.mul_retirements > 1 and access.load_retirements > 1 and access.store_retirements > 1);
    try access.verify(&access.reference.?);
    var canonical = try Candidate.ForCommitments(4).initWithOptions(a, .{ .retirements = 64, .security = .q70 });
    defer canonical.deinit();
    try std.testing.expectEqual(@as(u32, 70), canonical.program.view().profile.epoch.config.fri_config.n_queries);
    try std.testing.expectEqual(@as(u32, 26), canonical.program.view().profile.epoch.config.pow_bits);
}

test "resident native candidate code reuse across actual retirement sizes" {
    const a = std.testing.allocator;
    var small = try Candidate.ForCommitments(4).initWithOptions(a, .{ .retirements = 64 });
    defer small.deinit();
    var large = try Candidate.ForCommitments(4).initWithOptions(a, .{ .retirements = 1024 });
    defer large.deinit();
    const x = small.program.view();
    const y = large.program.view();
    try std.testing.expect(!std.mem.eql(u8, &x.identity, &y.identity));
    try std.testing.expect(x.fri_log != y.fri_log);
    var sx: std.Io.Writer.Allocating = .init(a);
    defer sx.deinit();
    var sy: std.Io.Writer.Allocating = .init(a);
    defer sy.deinit();
    const Bundle = @import("integrations/riscv_cuda/resident_native_kernel_bundle_v1.zig");
    try Bundle.emit(4, a, &sx.writer, small.program);
    try Bundle.emit(4, a, &sy.writer, large.program);
    try std.testing.expectEqualSlices(u8, &x.code_identity, &y.code_identity);
    try std.testing.expectEqualSlices(u8, sx.written(), sy.written());
    try std.testing.expect(std.mem.indexOf(u8, sx.written(), "stwo_native_code_identity") != null);
    try std.testing.expect(std.mem.indexOf(u8, sx.written(), "stwo_native_program_identity") == null);
    std.debug.print("RESIDENT_NATIVE_CODE_REUSE small_program={x} large_program={x} code={x} bytes={d} fri={d}/{d}\n", .{ x.identity, y.identity, x.code_identity, sx.written().len, x.fri_log, y.fri_log });
}
