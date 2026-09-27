const std = @import("std");
const core = @import("stwo_core");
const runner = @import("../runner/mod.zig");
const public = @import("../air/public_data.zig");
const witness = @import("blake3_ethereum_witness.zig");
test "BLAKE3 execution commitment Ethereum external witness census" {
    check(false) catch |err| {
        std.debug.print("BLAKE3 Ethereum integration failed: {s}\n", .{@errorName(err)});
        return err;
    };
}
test "BLAKE3 execution commitment Ethereum full proof independently verifies" {
    check(true) catch |err| {
        std.debug.print("BLAKE3 Ethereum full proof failed: {s}\n", .{@errorName(err)});
        return err;
    };
}
fn check(comptime prove: bool) !void {
    const a = std.testing.allocator;
    const pool_mod = @import("stwo_prover_engine").work_pool;
    var pool: pool_mod.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try pool_mod.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const elf = @import("../runner/guest_precompile/test_elf.zig").buildEthereumWithCompletion(.self_loop);
    var run = try runner.runEthereumExtensionWithInput(a, &elf, &.{}, 100);
    defer run.deinit();
    try std.testing.expectEqual(@as(usize, 1), run.signer_recovery_calls.len());
    try std.testing.expectEqual(@as(usize, 1), run.keccakf_calls.len());
    const base = &run.base;
    const outputs = try a.alloc(public.OutputWord, base.output_words.len);
    defer a.free(outputs);
    for (outputs, base.output_words) |*target, word| target.* = .{ .addr = word.addr, .value = word.value, .clock = word.clock };
    const data = public.Blake3PublicData{
        .initial_pc = base.initial_pc,
        .final_pc = base.final_pc,
        .clock = @intCast(base.step_count),
        .initial_regs = base.initial_regs,
        .final_regs = base.final_regs,
        .reg_last_clock = base.state_chain_tracker.reg_last_clk,
        .program_root = null,
        .initial_rw_root = null,
        .final_rw_root = null,
        .completion = try public.completionFromRun(base.*),
        .io_entries = .{ .input_start = base.input_start, .input_len = 0, .input_words = &.{}, .output_len = 0, .output_len_addr = base.output_len_addr, .output_data_addr = base.output_data_addr, .output_words = outputs },
    };
    try std.testing.expect(outputs.len != 0);
    var missing_output = data;
    missing_output.io_entries.output_words = &.{};
    try std.testing.expectError(error.InvalidExecutionPublicIo, witness.Owner.init(a, &run, missing_output));
    var owned = witness.Owner.init(a, &run, data) catch |err| {
        std.debug.print("Ethereum BLAKE3 witness construction: {s}\n", .{@errorName(err)});
        return err;
    };
    var owned_alive = true;
    defer if (owned_alive) owned.deinit();
    try std.testing.expectEqual(@as(u32, 2), owned.native.external_retirements);
    try owned.native.statement.validateBlake3ExecutionWithExternal(2);
    try std.testing.expectError(error.InvalidStatement, owned.native.statement.validateBlake3ExecutionWithExternal(1));
    try std.testing.expectError(error.InvalidStatement, owned.native.statement.validateBlake3Execution());
    var channel = core.proof_suites.Blake3.Channel{};
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    // An external native prefix cannot masquerade as a complete base proof.
    try std.testing.expectError(error.InvalidStatement, @import("blake3_execution_protocol.zig").mix(&channel, config, &owned.native.statement, try owned.admission()));
    try std.testing.expect(!owned.native.interaction_ready);
    for (owned.native.statement.infra_descs[0..owned.native.statement.n_infra]) |desc| switch (desc.kind) {
        .program, .memory, .merkle, .poseidon2 => return error.LegacyCommitmentInBlake3Execution,
        else => {},
    };
    // Every external fetch must be represented in the full-width program plan.
    for (run.keccakf_execution_rows.rows()) |row| try expectFetch(&owned, row.pc);
    for (run.signer_recovery_execution_rows.rows()) |row| try expectFetch(&owned, row.pc);
    try std.testing.expect(owned.native.tables_ready);
    var invalid = data;
    invalid.clock += 1;
    try std.testing.expectError(error.InvalidExecutionTrace, witness.Owner.init(a, &run, invalid));
    std.debug.print("BLAKE3_ETHEREUM_WITNESS_READY external_retirements=2\n", .{});
    if (comptime prove) {
        const Api = @import("blake3_ethereum_proof.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend);
        const prepared = try Api.PreparedVerifier.init(a, &owned.native.statement, owned.statement, try owned.admission(), config);
        defer prepared.deinit();
        const expected = prepared.id;
        var wrong = expected;
        wrong[0] ^= 1;
        try std.testing.expectError(error.UntrustedExecutionKey, Api.prove(a, &owned, prepared, wrong, &pool));
        try std.testing.expect(!owned.native.interaction_ready);
        const certificate = prepared.extension.admission;
        prepared.extension.admission.memory_relation_terms += 1;
        try std.testing.expectError(error.AdmissionCertificateMismatch, prepared.validate(expected));
        prepared.extension.admission = certificate;
        var result = try Api.prove(a, &owned, prepared, expected, &pool);
        var proof_alive = true;
        defer if (proof_alive) result.proof.deinit(a);
        owned.deinit();
        owned_alive = false;
        outputs[0].value ^= 1;
        try prepared.validate(expected);
        proof_alive = false;
        const digest = try Api.verifyOwned(a, result.proof, prepared, expected);
        try std.testing.expectEqualSlices(u8, &result.transcript_digest, &digest);
        std.debug.print("BLAKE3_ETHEREUM_PROOF verified=true keccak=1 signer=1 queries=8 pow_bits=0 witness_released=true admission_independent=true\n", .{});
    } else try checkClosure(a, &owned, &pool);
    std.debug.print("BLAKE3_ETHEREUM_WITNESS keccak=1 signer=1 external_retirements=2 legacy_commitments=0 base_protocol_rejects=true relations_closed=true\n", .{});
}
fn expectFetch(owned: *const witness.Owner, pc: u32) !void {
    for (owned.memory.programs) |item| {
        if (item.address == pc) return;
    }
    return error.MissingExternalProgramFetch;
}

fn checkClosure(a: std.mem.Allocator, owned: *witness.Owner, pool: *@import("stwo_prover_engine").work_pool.WorkPool) !void {
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{0x45544833});
    const universal = try @import("../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
    const shared = try @import("../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(&universal);
    const relations = try @import("guest_precompile/ethereum_transcript.zig").Relations.drawAfterBase(a, &channel, shared.native);
    try owned.native.generateInteractions(&shared.native);
    var hashes = try owned.hashes.interactions(a, &universal);
    defer hashes.deinit();
    var extension = try @import("guest_precompile/ethereum_interaction.zig").generate(a, &owned.extension, &relations, pool);
    defer extension.deinit(a);
    const shape = &owned.native.statement;
    const claims = &owned.native.claims;
    var total = (try @import("../air/public_logup.zig").blake3RelationSums(&shape.public_data, &shared.native)).total();
    for (shape.component_descs[0..shape.n_components], 0..) |desc, i| total = total.add(try claims.opcodeClaimTotal(desc.family, i));
    for (shape.infra_descs[0..shape.n_infra], 0..) |desc, i| total = total.add(try claims.infraClaimTotal(desc.kind, i));
    for (hashes.claims) |claim| total = total.add(claim);
    try std.testing.expect(!extension.claim.componentSum().isZero());
    try std.testing.expect(!total.isZero());
    const residual = total.add(extension.claim.componentSum());
    if (!residual.isZero()) std.debug.print("BLAKE3_ETHEREUM_CLOSURE residual={any} native_hashes={any} extension={any}\n", .{ residual, total, extension.claim.componentSum() });
    try std.testing.expect(residual.isZero());
}
