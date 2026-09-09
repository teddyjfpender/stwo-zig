//! Tiny real full-RISC-V + ordered narrow-memory provider integration.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const riscv_cpu = @import("stwo_riscv_cpu_integration");
const postcard = @import("interop_postcard");
const pcs = @import("stwo_core").pcs;
const shard_planner = @import("stwo_prover_engine").pcs.residency_shard_plan;

const authority = frontend.testing.narrow_memory_provider_shard_authority;
const harness = frontend.testing.narrow_memory_provider_proof_harness;
const joint = frontend.testing.narrow_memory_provider_joint_protocol;
const joint_proof = frontend.testing.narrow_memory_provider_joint_proof;
const full_core = frontend.testing.narrow_memory_provider_full_core_joint_protocol;
const full_core_verifier = frontend.testing.narrow_memory_provider_full_core_joint_verifier;
const full_provider = frontend.testing.narrow_memory_provider_full_core_provider_proof_v2;
const orchestration = frontend.testing.prover_orchestration;
const CommitmentWitness = frontend.testing.commitment_witness.CommitmentWitness;
const public_data_mod = frontend.air.public_data;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;
const Engine = riscv_cpu.CpuProverEngine;

const CONFIG = pcs.PcsConfig{
    .pow_bits = 0,
    .fri_config = pcsConfig(),
};

fn pcsConfig() @import("stwo_core").fri.FriConfig {
    return @import("stwo_core").fri.FriConfig.init(0, 1, 3) catch unreachable;
}

pub fn run() !void {
    const allocator = std.testing.allocator;
    const elf = frontend.runner.trace_dump.buildTestElf(5, .{
        0x00100093, // ADDI x1, x0, 1
        0x00100093,
        0x00100093,
        0x00100093,
        0x0000006f, // canonical completion sentinel
    });
    var execution = try frontend.runner.run(allocator, &elf, 1000);
    defer execution.deinit();

    const input_words = try public_data_mod.packInputWords(allocator, execution.input);
    defer allocator.free(input_words);
    const output_words = try allocator.alloc(
        public_data_mod.OutputWord,
        execution.output_words.len,
    );
    defer allocator.free(output_words);
    for (output_words, execution.output_words) |*destination, source| {
        destination.* = .{
            .addr = source.addr,
            .value = source.value,
            .clock = source.clock,
        };
    }
    const public_data = public_data_mod.PublicData{
        .initial_pc = execution.initial_pc,
        .final_pc = execution.final_pc,
        .clock = @intCast(execution.step_count),
        .initial_regs = execution.initial_regs,
        .final_regs = execution.final_regs,
        .reg_last_clock = execution.state_chain_tracker.reg_last_clk,
        .program_root = null,
        .initial_rw_root = null,
        .final_rw_root = null,
        .completion = try public_data_mod.completionFromRun(execution),
        .io_entries = .{
            .input_start = execution.input_start,
            .input_len = @intCast(execution.input.len),
            .input_words = input_words,
            .output_len = execution.output_len,
            .output_len_addr = execution.output_len_addr,
            .output_data_addr = execution.output_data_addr,
            .output_words = output_words,
        },
    };
    var witness = try CommitmentWitness.build(
        allocator,
        &execution.execution_trace,
        &execution.rw_memory,
        public_data.completion.?,
    );
    defer witness.deinit(allocator);
    const calls = witness.poseidonCalls();
    try std.testing.expect(calls.len != 0);

    var plan = try authority.ProviderShardPlanV1.create(
        allocator,
        [_]u8{0x83} ** 32,
        calls,
        residencyRequest(calls.len),
    );
    defer plan.deinit(allocator);
    try std.testing.expect(plan.shards.len != 0);
    for (plan.shards) |descriptor|
        try std.testing.expectEqual(@as(u32, 4), descriptor.expected_log_size);

    // Reuse only the proven Stage-A provider-root constructor. The tiny caller
    // roots in this source manifest are discarded by ProviderStageASource.
    const ignored_tiny_core = try joint_proof.commitCoreStageA(
        Engine,
        allocator,
        CONFIG,
        &plan,
        calls,
    );
    const provider_roots = try allocator.alloc(
        harness.StageACommitment(Engine),
        plan.shards.len,
    );
    defer allocator.free(provider_roots);
    for (provider_roots, 0..) |*slot, index| {
        slot.* = try harness.commitStageA(
            Engine,
            allocator,
            CONFIG,
            &plan,
            calls,
            @intCast(index),
        );
    }
    var provider_manifest = try joint.JointManifest(Engine).create(
        allocator,
        &plan,
        calls,
        ignored_tiny_core,
        provider_roots,
    );
    defer provider_manifest.deinit(allocator);
    const source = try full_core.ProviderStageASource(Engine).init(
        &plan,
        calls,
        &provider_manifest,
    );

    var manifest: full_core.FullCoreManifestV1(Engine) = undefined;
    var shared: full_core.SharedRelationAuthorityV1 = undefined;
    const extension = full_core.ProveExtension(Engine){
        .source = &source,
        .manifest_out = &manifest,
        .shared_out = &shared,
    };
    var channel = Engine.Channel{};
    var core_output = try orchestration
        .runRiscVWithEngineAndPublicDataUsingChannelAndTranscriptExtension(
        Engine,
        allocator,
        CONFIG,
        &execution.execution_trace,
        &execution.state_chain_tracker,
        &execution.rw_memory,
        null,
        public_data,
        &channel,
        .{},
        extension,
    );
    defer core_output.deinit(allocator);
    try manifest.validate(&source, &core_output.statement);
    try shared.validate(manifest.identity);

    var core_bytes: std.ArrayList(u8) = .{};
    defer core_bytes.deinit(allocator);
    try postcard.serializeProof(
        Engine.Hasher,
        core_bytes.writer(allocator),
        core_output.proof,
    );
    var core_stream = std.io.fixedBufferStream(core_bytes.items);
    const core_receipt = try full_core_verifier.verifyFreshAndMintResidual(
        Engine,
        allocator,
        CONFIG,
        &source,
        &manifest,
        shared,
        core_output.statement,
        try postcard.deserializeProof(Engine.Hasher, allocator, core_stream.reader()),
        core_output.interaction_claim,
    );
    try core_receipt.validate();

    const provider_receipts = try allocator.alloc(
        full_provider.FreshProviderClaimV2,
        plan.shards.len,
    );
    defer allocator.free(provider_receipts);
    for (provider_receipts, 0..) |*receipt, index| {
        var output = try full_provider.proveProviderV2(
            Engine,
            allocator,
            CONFIG,
            &source,
            &core_output.statement,
            &manifest,
            shared,
            @intCast(index),
        );
        defer output.proof.deinit(allocator);
        var bytes: std.ArrayList(u8) = .{};
        defer bytes.deinit(allocator);
        try postcard.serializeProof(Engine.Hasher, bytes.writer(allocator), output.proof);
        var stream = std.io.fixedBufferStream(bytes.items);
        receipt.* = try full_provider.verifyProviderFreshV2(
            Engine,
            allocator,
            CONFIG,
            &source,
            &core_output.statement,
            &manifest,
            shared,
            output.statement,
            try postcard.deserializeProof(Engine.Hasher, allocator, stream.reader()),
        );
    }

    const closure = try full_provider.closeFreshClaimsV2(
        allocator,
        &source,
        manifest.identity,
        shared,
        core_receipt,
        provider_receipts,
    );
    try closure.validate();
    try std.testing.expect(closure.closed_sum.isZero());
    try std.testing.expect(closure.every_ordered_call_air_verified);
    try std.testing.expect(closure.native_provider_retained);
    try std.testing.expect(!closure.omit_recompute_owner_verified);
    try std.testing.expect(!closure.production_eligible);
    try std.testing.expect(!full_core.ACTIVATES_PRODUCTION_PROOF);
    try std.testing.expect(!full_provider.ACTIVATES_PRODUCTION_PROOF);

    try adversarialClosureChecks(
        allocator,
        &source,
        &provider_manifest,
        &core_output.statement,
        &manifest,
        shared,
        core_receipt,
        provider_receipts,
    );
}

fn adversarialClosureChecks(
    allocator: std.mem.Allocator,
    source: anytype,
    provider_manifest: anytype,
    core_statement: *const frontend.prover_mod.RiscVStatement,
    manifest: anytype,
    shared: full_core.SharedRelationAuthorityV1,
    core: full_core.FreshFullCoreResidualV1,
    providers: []const full_provider.FreshProviderClaimV2,
) !void {
    try std.testing.expect(providers.len > 1);
    try std.testing.expectError(
        error.ShardClaimCountMismatch,
        full_provider.closeFreshClaimsV2(
            allocator,
            source,
            manifest.identity,
            shared,
            core,
            providers[0 .. providers.len - 1],
        ),
    );

    const reordered = try allocator.dupe(full_provider.FreshProviderClaimV2, providers);
    defer allocator.free(reordered);
    std.mem.swap(
        full_provider.FreshProviderClaimV2,
        &reordered[0],
        &reordered[1],
    );
    try std.testing.expectError(
        error.NonCanonicalFreshProviderOrder,
        full_provider.closeFreshClaimsV2(
            allocator,
            source,
            manifest.identity,
            shared,
            core,
            reordered,
        ),
    );

    var wrong_context = shared;
    wrong_context.relation_context.identity[0] ^= 1;
    try std.testing.expectError(
        error.RelationContextMismatch,
        full_core.replaySharedTranscript(
            Engine,
            allocator,
            CONFIG,
            source,
            core_statement,
            manifest,
            wrong_context,
        ),
    );

    std.mem.swap(
        joint.ProviderStageARecord(Engine),
        &provider_manifest.providers[0],
        &provider_manifest.providers[1],
    );
    defer std.mem.swap(
        joint.ProviderStageARecord(Engine),
        &provider_manifest.providers[0],
        &provider_manifest.providers[1],
    );
    try std.testing.expectError(
        error.ShardIdentityMismatch,
        provider_manifest.validate(source.plan, source.calls),
    );
}

fn residencyRequest(call_count: usize) shard_planner.Request {
    return .{
        .logical_row_count = @intCast(call_count),
        .column_count = authority.main_column_count,
        .min_shard_log_size = 4,
        .max_shard_log_size = 4,
        .log_blowup_factor = CONFIG.fri_config.log_blowup_factor,
        .retention_policy = .never,
        .host_byte_budget = 1024 * 1024 * 1024,
        .reserved_host_bytes = 0,
        .requested_parallel_shards = 1,
    };
}
