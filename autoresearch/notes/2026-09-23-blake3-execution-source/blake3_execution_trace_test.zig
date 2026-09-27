const std = @import("std");
const core = @import("stwo_core");

test "BLAKE3 execution commitment real runner proves and independently verifies" {
    checkExecution() catch |err| {
        std.debug.print("BLAKE3 execution join: {s}\n", .{@errorName(err)});
        return err;
    };
}
fn checkExecution() !void {
    const a = std.testing.allocator;
    const instructions = [_]u32{ 0x00500093, 0x00708093, 0x00100137, 0x00100193, 0x00312223, 0x00312423, 0x0000006f }; // x1=12; publish one output byte with value 1; self-loop
    const elf = @import("../runner/guest_precompile/test_elf.zig").buildProgram(instructions.len, &instructions, 0, .rv32im_zkvm_v1);
    var run = try @import("../runner/mod.zig").runWithInput(a, &elf, &.{}, 100);
    var run_alive = true;
    defer if (run_alive) run.deinit();
    try std.testing.expectEqual(@as(u32, 12), run.final_regs[1]);
    try std.testing.expectEqual(@as(usize, 6), run.step_count);
    try std.testing.expectEqualSlices(u8, &.{1}, run.output.?);
    var owner = try @import("blake3_segment_execution.zig").Owner.initRun(a, &run);
    defer owner.deinit();
    const native = owner.native;
    const hashes = owner.hashes;
    const admission = try owner.admission();
    const outputs = owner.output;
    const plan = &owner.plan;
    const memory = &owner.memory;
    // Proving must not borrow execution tapes, snapshots or public-I/O storage.
    run.deinit();
    run_alive = false;
    const saved = native.statement.component_descs[0];
    native.statement.component_descs[0].n_columns += 1;
    try std.testing.expectError(error.InvalidStatement, native.statement.validateBlake3Execution());
    native.statement.component_descs[0] = saved;
    native.statement.component_descs[0].n_rows -= 1;
    try std.testing.expectError(error.InvalidStatement, native.statement.validateBlake3Execution());
    native.statement.component_descs[0] = saved;
    const last = native.statement.n_infra - 1;
    const saved_table = native.statement.infra_descs[last];
    native.statement.infra_descs[last].n_rows -= 1;
    try std.testing.expectError(error.InvalidStatement, native.statement.validateBlake3Execution());
    native.statement.infra_descs[last] = saved_table;
    const proof_api = @import("blake3_execution_proof.zig");
    const api = proof_api.ForBackend(@import("stwo_cpu_backend").CpuBackend);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var result = try api.prove(a, native, hashes, admission, config);
    var owns_proof = true;
    defer if (owns_proof) result.proof.deinit(a);
    var substituted = result.proof.stark.commitment_scheme_proof.commitments.items[0];
    substituted[31] ^= 0x80;
    try std.testing.expectError(error.UntrustedBlake3Preprocessing, proof_api.admitPreprocessedRoot(result.proof.stark.commitment_scheme_proof.commitments.items[0], substituted));
    try std.testing.expect(native.interaction_ready);
    try std.testing.expectError(error.LookupTablesAlreadyPrepared, native.includeCommitments(hashes));
    try std.testing.expectError(error.InvalidExecutionPhase, api.prove(a, native, hashes, admission, config));
    // Production admission metadata must carry all 256 root bits and own its
    // public-I/O slices independently of the wire buffer and runner witness.
    const statement_wire = @import("guest_precompile/proof_artifact_wire.zig");
    var metadata: std.ArrayList(u8) = .empty;
    defer metadata.deinit(a);
    try statement_wire.encodeBlake3Statement(metadata.writer(a), &native.statement, .{});
    var decoded_statement = try statement_wire.decodeBlake3Statement(a, metadata.items, .{});
    defer decoded_statement.deinit(a);
    try decoded_statement.value.validateBlake3Execution();
    inline for (.{ "program_root", "initial_rw_root", "final_rw_root" }) |field| {
        try std.testing.expectEqualDeep(@field(native.statement.public_data, field), @field(decoded_statement.value.public_data, field));
    }
    try std.testing.expectError(error.EndOfStream, statement_wire.decodeBlake3Statement(a, metadata.items[0 .. metadata.items.len - 1], .{}));
    metadata.clearAndFree(a);
    const plan_wire = @import("blake3_commitment_plan_codec.zig");
    const encoded_plan = try plan_wire.encode(a, plan, admission.expected_id, .{});
    defer a.free(encoded_plan);
    var decoded_plan = try plan_wire.decode(a, encoded_plan, admission.expected_id, .{});
    defer decoded_plan.deinit();
    var wrong_plan_id = admission.expected_id;
    wrong_plan_id[31] ^= 1;
    try std.testing.expectError(error.UntrustedCommitmentPlan, plan_wire.decode(a, encoded_plan, wrong_plan_id, .{}));
    encoded_plan[44 + 31] ^= 1;
    try std.testing.expectError(error.UntrustedCommitmentPlan, plan_wire.decode(a, encoded_plan, admission.expected_id, .{}));
    encoded_plan[44 + 31] ^= 1;
    try std.testing.expectError(error.InvalidCommitmentPlanLength, plan_wire.decode(a, encoded_plan[0 .. encoded_plan.len - 1], admission.expected_id, .{}));
    try std.testing.expectError(error.CommitmentPlanResourceLimit, plan_wire.decode(a, encoded_plan, admission.expected_id, .{ .max_memory_words = 0, .max_program_words = 0 }));
    try std.testing.checkAllAllocationFailures(a, checkPlanDecode, .{ encoded_plan, admission.expected_id });
    const decoded_admission = try @import("blake3_commitment_plan.zig").Admission.init(&decoded_plan, admission.expected_id);
    const manifest = @import("blake3_execution_manifest.zig");
    const source_api = @import("blake3_execution_source.zig");
    const source = try source_api.validate(a, &elf, &.{}, &decoded_statement.value.public_data);
    decoded_statement.value.public_data.program_root.?.bytes[31] ^= 1;
    try std.testing.expectError(error.ProgramRootMismatch, source_api.validate(a, &elf, &.{}, &decoded_statement.value.public_data));
    decoded_statement.value.public_data.program_root.?.bytes[31] ^= 1;
    decoded_statement.value.public_data.initial_rw_root.?.bytes[31] ^= 1;
    try std.testing.expectError(error.InitialMemoryRootMismatch, source_api.validate(a, &elf, &.{}, &decoded_statement.value.public_data));
    decoded_statement.value.public_data.initial_rw_root.?.bytes[31] ^= 1;
    decoded_statement.value.public_data.initial_regs[1] ^= 1;
    try std.testing.expectError(error.InitialCpuMismatch, source_api.validate(a, &elf, &.{}, &decoded_statement.value.public_data));
    decoded_statement.value.public_data.initial_regs[1] ^= 1;
    const manifest_bytes = try manifest.encode(a, &decoded_statement.value, decoded_admission, config, source, .{});
    defer a.free(manifest_bytes);
    const manifest_id = manifest.identity(manifest_bytes);
    var wrong_source = source;
    wrong_source.elf_sha256[31] ^= 1;
    try std.testing.expectError(error.ExecutionSourceMismatch, manifest.decode(a, manifest_bytes, manifest_id, wrong_source, config, .{}));
    var wrong_config = config;
    wrong_config.fri_config.n_queries += 1;
    try std.testing.expectError(error.InvalidExecutionConfig, manifest.decode(a, manifest_bytes, manifest_id, source, wrong_config, .{}));
    manifest_bytes[manifest_bytes.len - 1] ^= 1;
    var no_allocations = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.UntrustedExecutionManifest, manifest.decode(no_allocations.allocator(), manifest_bytes, manifest_id, source, config, .{}));
    manifest_bytes[manifest_bytes.len - 1] ^= 1;
    // A newly pinned envelope still cannot substitute another AIR/transcript
    // authority for the one this implementation derives from typed statements.
    manifest_bytes[manifest.HEADER_BYTES - 1] ^= 1;
    try std.testing.expectError(error.ExecutionManifestAuthorityMismatch, manifest.decode(a, manifest_bytes, manifest.identity(manifest_bytes), source, config, .{}));
    manifest_bytes[manifest.HEADER_BYTES - 1] ^= 1;
    try std.testing.checkAllAllocationFailures(a, checkManifestDecode, .{ manifest_bytes, manifest_id, source, config });
    const prepared = blk: {
        var decoded = try manifest.decode(a, manifest_bytes, manifest_id, source, config, .{});
        defer decoded.deinit();
        break :blk try api.PreparedVerifier.init(a, &decoded.statement.value, try decoded.admission(), decoded.config);
    };
    defer prepared.deinit();
    const expected_id = prepared.id; // Derived from verifier-owned source inputs.
    try std.testing.expectEqualSlices(u8, &expected_id, &result.proof.key_id);
    try std.testing.expectEqual(@as(usize, 0), prepared.hashes.?.columns[0].items.len);
    try std.testing.expectEqual(@as(usize, 0), prepared.hashes.?.columns[1].items.len);
    const raw = try @import("blake3_execution_codec.zig").encode(a, &result.proof, prepared, expected_id);
    defer a.free(raw);
    result.proof.deinit(a);
    owns_proof = false;
    // Retained admission owns the source slices; later caller mutation cannot
    // silently select another statement or commitment schedule.
    outputs[0].value = 123;
    plan.programs[0].multiplicity += 1;
    try prepared.validate(expected_id);
    outputs[0].value = 1;
    plan.programs[0].multiplicity -= 1;
    try @import("blake3_execution_artifact_test_support.zig").check(api, a, prepared, expected_id, raw, result.transcript_digest, memory);
}

fn checkPlanDecode(a: std.mem.Allocator, raw: []const u8, expected: [32]u8) !void {
    var plan = try @import("blake3_commitment_plan_codec.zig").decode(a, raw, expected, .{});
    defer plan.deinit();
    try std.testing.expectEqualSlices(u8, &expected, &try plan.identity());
}

fn checkManifestDecode(a: std.mem.Allocator, raw: []const u8, expected: [32]u8, source: @import("blake3_execution_manifest.zig").Source, config: core.pcs.PcsConfig) !void {
    var decoded = try @import("blake3_execution_manifest.zig").decode(a, raw, expected, source, config, .{});
    defer decoded.deinit();
    _ = try decoded.admission();
}
