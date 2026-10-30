//! Actual original source qualification, not a production admission or a block
//! theorem. CPU fixture/oracle setup is timed separately from device proving.
const std = @import("std");
const Candidate = @import("integrations/riscv_cuda/resident_native_candidate_v1.zig");
const Prover = @import("integrations/riscv_cuda/resident_native_prover_v1.zig");
const core = @import("stwo_core");
const wire = @import("interop_postcard");
fn encode(a: std.mem.Allocator, proof: *const Candidate.Native.Proof) ![]u8 {
    var writer: std.Io.Writer.Allocating = .init(a);
    defer writer.deinit();
    try wire.serializeProof(core.proof_suites.Blake3.Hasher, &writer.writer, proof.stark);
    return a.dupe(u8, writer.written());
}
fn enabled(a: std.mem.Allocator, name: []const u8) !bool {
    const value = std.process.getEnvVarOwned(a, name) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return false,
        else => return err,
    };
    defer a.free(value);
    if (std.mem.eql(u8, value, "1")) return true;
    if (std.mem.eql(u8, value, "0")) return false;
    return error.InvalidResidentNativeQualificationOption;
}
fn qualify() anyerror!void {
    const a = std.testing.allocator;
    if (!try enabled(a, "STWO_RESIDENT_NATIVE_QUALIFY")) return error.SkipZigTest;
    const selection = try Candidate.fromEnv(a);
    switch (selection.trees) {
        4 => try qualifyFor(4, selection.options),
        5 => try qualifyFor(5, selection.options),
        else => unreachable,
    }
}
fn qualifyFor(comptime N: usize, selected: Candidate.Options) anyerror!void {
    const a = std.testing.allocator;
    var options = selected;
    options.cpu_reference = true;
    var setup = try std.time.Timer.start();
    var candidate = try Candidate.ForCommitments(N).initWithOptions(a, options);
    defer candidate.deinit();
    const cpu_setup_ns = setup.read();
    const identity = candidate.program.view().identity;
    const hostile = try enabled(a, "STWO_RESIDENT_NATIVE_HOSTILE");
    if (hostile) {
        // Change only transported retirement value AFTER the admitted program,
        // first roots and independent CPU oracle have been sealed.
        candidate.raw[13] ^= 1;
        try std.testing.expectError(error.InvalidResidentNativeVerdict, Prover.ForCommitments(N).prove(a, .{ .program = candidate.program, .raw_input = candidate.raw, .qualification_only = true, .limits = .{ .accepted_sms = &.{ 86, 90 } } }));
        std.debug.print("RESIDENT_NATIVE_HOSTILE rejected=true field=retirement_rd_value cold_identity={x} cpu_witness_rerun=false\n", .{identity});
        return;
    }
    var result = try Prover.ForCommitments(N).prove(a, .{ .program = candidate.program, .raw_input = candidate.raw, .qualification_only = true, .limits = .{ .accepted_sms = &.{ 86, 90 } } });
    defer result.deinit(a);
    const proof = &result.proof.original;
    const reference = &candidate.reference.?;
    const bytes = try encode(a, proof);
    defer a.free(bytes);
    const reference_bytes = try encode(a, reference);
    defer a.free(reference_bytes);
    const output: ?[]u8 = std.process.getEnvVarOwned(a, "STWO_RESIDENT_NATIVE_OUTPUT") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (output) |path| a.free(path);
    if (output) |path| {
        try std.fs.cwd().makePath(path);
        var dir = try std.fs.cwd().openDir(path, .{});
        defer dir.close();
        try dir.writeFile(.{ .sub_path = "unverified-native.stark", .data = bytes });
        try dir.writeFile(.{ .sub_path = "reference-native.stark", .data = reference_bytes });
        const claims_json = try std.json.Stringify.valueAlloc(a, .{ .verified = false, .program_identity = identity, .code_identity = candidate.program.view().code_identity, .projections = proof.claims, .access = proof.memory_claims, .reference_projections = reference.claims, .reference_access = reference.memory_claims }, .{ .whitespace = .indent_2 });
        defer a.free(claims_json);
        try dir.writeFile(.{ .sub_path = "unverified-claims.json", .data = claims_json });
    }
    // The prover's transaction/arenas/producer owners have already been freed.
    // Verification uses the unchanged independent original native verifier.
    var verify_timer = try std.time.Timer.start();
    try candidate.verify(&result.proof.original);
    const verify_ns = verify_timer.read();
    try std.testing.expectEqual(reference.claims.len, proof.claims.len);
    for (reference.claims, proof.claims) |expected, actual| try std.testing.expect(std.meta.eql(expected, actual));
    try std.testing.expectEqual(reference.memory_claims.len, proof.memory_claims.len);
    for (reference.memory_claims, proof.memory_claims) |expected, actual| try std.testing.expect(std.meta.eql(expected, actual));
    try std.testing.expectEqualSlices(u8, reference_bytes, bytes);
    try std.testing.expect(result.verdict.isResident());
    try std.testing.expectEqual(@as(u64, 1), result.verdict.counters.d2h_proof_operations);
    try std.testing.expectEqual(@as(u64, 0), result.verdict.counters.cpu_fallback_attempts);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const receipt = .{ .schema = @as(u32, 1), .proof_contract = "open_original_native_source", .production_ready = false, .execution_closed = false, .gpu_qualified = true, .timing_class = "single_request_correctness_diagnostic", .device = result.verdict.device, .platform = result.verdict.platform, .backend_build_identity = result.verdict.build_identity, .cpu_setup_ns = cpu_setup_ns, .gpu_request_ns = result.elapsed_ns, .cpu_verify_ns = verify_ns, .queries = options.security.config().fri_config.n_queries, .pow_bits = options.security.config().pow_bits, .trees = @as(u32, N), .composition_split = candidate.program.view().composition_split, .retirements = candidate.retirement_count, .mul_retirements = candidate.mul_retirements, .load_retirements = candidate.load_retirements, .store_retirements = candidate.store_retirements, .clock_records = candidate.clock_count, .raw_words = candidate.raw.len, .program_identity = identity, .code_identity = candidate.program.view().code_identity, .stark_sha256 = digest, .stark_bytes = bytes.len, .physical_claims = proof.claims.len, .access_claims = proof.memory_claims.len, .cpu_gpu_bytes_equal = true, .original_verifier = true, .device_arena_bytes = result.device_arena_bytes, .counters = result.verdict.counters, .host_timing = result.host_timing };
    const json = try std.json.Stringify.valueAlloc(a, receipt, .{ .whitespace = .indent_2 });
    defer a.free(json);
    std.debug.print("RESIDENT_NATIVE_QUALIFICATION {s}\n", .{json});
    const path = output orelse return;
    try std.fs.cwd().makePath(path);
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    var proof_file = try dir.createFile("native.stark", .{});
    defer proof_file.close();
    try proof_file.writeAll(bytes);
    var receipt_file = try dir.createFile("qualification.json", .{});
    defer receipt_file.close();
    try receipt_file.writeAll(json);
}
test "fully resident genuine native source original verifier and byte oracle" {
    try qualify();
}
