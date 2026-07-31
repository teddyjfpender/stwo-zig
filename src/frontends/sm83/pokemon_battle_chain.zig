//! Backend-neutral streamed proof chain for pinned Pokemon replay profiles.

const std = @import("std");
const core = @import("stwo_core");
const action_schedule = @import("action_schedule.zig");
const chain = @import("machine_environment_chain.zig");
const memory_image = @import("memory.zig");
const prover = @import("machine_environment_prover.zig");
const statement = @import("machine_environment_statement.zig");
const verifier = @import("machine_environment_verifier.zig");
const replay = @import("pokemon_checkpoint_replay.zig");

pub const Profile = enum {
    visual_prefix,
    benchmark,
};

pub const Counts = struct {
    rows: usize = 0,
    mcycles: u32 = 0,
    callbacks: usize = 0,
    actions: usize = 0,
    dma_source_bytes: usize = 0,
};

pub const Receipt = struct {
    profile: Profile,
    security_bits: u32,
    chunks: usize,
    counts: Counts,
    initial_mcycle: u32,
    final_mcycle: u32,
    action_digest: action_schedule.Digest,
    rom_digest: [32]u8,
    initial_system_digest: [32]u8,
    final_system_digest: [32]u8,
    initial_sram_digest: [32]u8,
    final_sram_digest: [32]u8,
    first_statement_digest: statement.Digest,
    last_statement_digest: statement.Digest,
    outcome: ?replay.BenchmarkOutcome,
};

pub fn printReceipt(backend: []const u8, receipt: Receipt) void {
    const outcome = receipt.outcome orelse unreachable;
    const action_hex = std.fmt.bytesToHex(receipt.action_digest, .lower);
    const final_system_hex = std.fmt.bytesToHex(
        receipt.final_system_digest,
        .lower,
    );
    const rom_hex = std.fmt.bytesToHex(receipt.rom_digest, .lower);
    const initial_system_hex = std.fmt.bytesToHex(
        receipt.initial_system_digest,
        .lower,
    );
    const initial_sram_hex = std.fmt.bytesToHex(
        receipt.initial_sram_digest,
        .lower,
    );
    const final_sram_hex = std.fmt.bytesToHex(
        receipt.final_sram_digest,
        .lower,
    );
    const first_statement_hex = std.fmt.bytesToHex(
        receipt.first_statement_digest,
        .lower,
    );
    const last_statement_hex = std.fmt.bytesToHex(
        receipt.last_statement_digest,
        .lower,
    );
    std.debug.print(
        "SM83 Pokemon {s} battle proof: PASS proof_ready={} " ++
            "security_bits={d} chunks={d} rows={d} mcycles={d} " ++
            "callbacks={d} actions={d} dma_sources={d} " ++
            "initial_mcycle={d} final_mcycle={d} " ++
            "action_digest={s} final_system_digest={s} " ++
            "battle_result={d} enemy_hp={d} battle_hp={d} " ++
            "party_hp={d} in_battle={d} stage={d} " ++
            "rom_digest={s} initial_system_digest={s} " ++
            "initial_sram_digest={s} final_sram_digest={s} " ++
            "first_statement_digest={s} last_statement_digest={s}\n",
        .{
            backend,
            proofReady(receipt.security_bits),
            receipt.security_bits,
            receipt.chunks,
            receipt.counts.rows,
            receipt.counts.mcycles,
            receipt.counts.callbacks,
            receipt.counts.actions,
            receipt.counts.dma_source_bytes,
            receipt.initial_mcycle,
            receipt.final_mcycle,
            &action_hex,
            &final_system_hex,
            outcome.battle_result,
            outcome.enemy_hp,
            outcome.battle_hp,
            outcome.party_hp,
            outcome.in_battle,
            outcome.stage,
            &rom_hex,
            &initial_system_hex,
            &initial_sram_hex,
            &final_sram_hex,
            &first_statement_hex,
            &last_statement_hex,
        },
    );
}

fn proofReady(security_bits: u32) bool {
    return security_bits >= 96;
}

const EXPECTED_VISUAL_ACTION_DIGEST: action_schedule.Digest = .{
    0x6e, 0xab, 0xf9, 0xe7, 0x57, 0x68, 0x4a, 0x8e,
    0x96, 0x3e, 0x9b, 0x8f, 0x42, 0x49, 0x1d, 0x3c,
    0xa2, 0x17, 0x1f, 0xaf, 0xe1, 0x57, 0x01, 0x41,
    0x55, 0x94, 0x94, 0xf8, 0x64, 0x96, 0x57, 0x24,
};

const EXPECTED_BENCHMARK_ACTION_DIGEST: action_schedule.Digest = .{
    0x89, 0xbe, 0x37, 0x76, 0x1c, 0xde, 0xf9, 0x91,
    0xee, 0x29, 0x9f, 0x16, 0xad, 0xfd, 0xe1, 0x9f,
    0xad, 0x40, 0x5b, 0xe3, 0xa5, 0xc1, 0xad, 0xf5,
    0x0b, 0x92, 0x5e, 0xe1, 0xa4, 0xb9, 0x14, 0xba,
};

const Configuration = struct {
    replay_profile: replay.Profile,
    rows: usize,
    expectations: []const replay.Expectation,
};

const Segment = struct {
    statement_value: prover.ExecutionStatement,
    counts: Counts,
};

pub fn proveAndVerify(
    comptime ProverEngine: type,
    comptime VerifierEngine: type,
    allocator: std.mem.Allocator,
    pcs_config: core.pcs.PcsConfig,
    corpus_root: []const u8,
    profile: Profile,
) !Receipt {
    comptime prover.assertProverEngine(ProverEngine);
    comptime verifier.assertProverEngine(VerifierEngine);
    const configuration = configurationFor(profile);
    const session = try replay.Session.init(allocator, corpus_root, .{
        .profile = configuration.replay_profile,
        .rows = configuration.rows,
    });
    defer session.deinit();

    var actions: std.ArrayList(action_schedule.Action) = .empty;
    defer actions.deinit(allocator);
    var first: ?prover.ExecutionStatement = null;
    var previous: ?prover.ExecutionStatement = null;
    var last: ?prover.ExecutionStatement = null;
    var totals = Counts{};

    for (configuration.expectations, 0..) |expected, index| {
        std.debug.print(
            "SM83 Pokemon proof chunk {d}/{d}: proving\n",
            .{ index + 1, configuration.expectations.len },
        );
        const segment = try proveNext(
            ProverEngine,
            VerifierEngine,
            allocator,
            pcs_config,
            session,
            expected,
            index,
            totals.callbacks,
            index + 1 == configuration.expectations.len,
            profile,
            &actions,
        );
        if (previous) |prior| {
            try chain.validate(prior, segment.statement_value);
            try rejectJoinMutation(prior, segment.statement_value);
        } else first = segment.statement_value;
        previous = segment.statement_value;
        last = segment.statement_value;
        totals = try addCounts(totals, segment.counts);
        std.debug.print(
            "SM83 Pokemon proof chunk {d}/{d}: verified\n",
            .{ index + 1, configuration.expectations.len },
        );
    }
    const terminal = try session.finish();
    try validateTotals(profile, totals, actions.items.len, terminal);

    const first_statement = first orelse return error.EmptyPokemonBattleChain;
    const last_statement = last orelse return error.EmptyPokemonBattleChain;
    const initial_mcycle = first_statement.base.base.initial.mcycle;
    const final_mcycle = last_statement.base.base.final.mcycle;
    const action_digest = try action_schedule.digest(
        initial_mcycle,
        final_mcycle,
        actions.items,
    );
    const expected_digest = switch (profile) {
        .visual_prefix => EXPECTED_VISUAL_ACTION_DIGEST,
        .benchmark => EXPECTED_BENCHMARK_ACTION_DIGEST,
    };
    if (!std.mem.eql(u8, &action_digest, &expected_digest))
        return error.InvalidOuterActionDigest;

    const first_base = first_statement.base.base;
    const last_base = last_statement.base.base;
    if (!std.mem.eql(u8, &first_base.rom_digest, &last_base.rom_digest))
        return error.RomDigestMismatch;
    return .{
        .profile = profile,
        .security_bits = pcs_config.securityBits(),
        .chunks = configuration.expectations.len,
        .counts = totals,
        .initial_mcycle = initial_mcycle,
        .final_mcycle = final_mcycle,
        .action_digest = action_digest,
        .rom_digest = first_base.rom_digest,
        .initial_system_digest = first_base.initial_system_digest,
        .final_system_digest = last_base.final_system_digest,
        .initial_sram_digest = first_base.initial_sram_digest,
        .final_sram_digest = last_base.final_sram_digest,
        .first_statement_digest = statement.publicDigest(first_statement),
        .last_statement_digest = statement.publicDigest(last_statement),
        .outcome = if (profile == .benchmark)
            replay.EXPECTED_BENCHMARK_OUTCOME
        else
            null,
    };
}

fn proveNext(
    comptime ProverEngine: type,
    comptime VerifierEngine: type,
    allocator: std.mem.Allocator,
    pcs_config: core.pcs.PcsConfig,
    session: *replay.Session,
    expected: replay.Expectation,
    expected_index: usize,
    expected_oracle_start: usize,
    final_segment: bool,
    profile: Profile,
    actions: *std.ArrayList(action_schedule.Action),
) !Segment {
    var chunk = try session.next(expected);
    defer chunk.deinit();
    const input = chunk.input();
    const summary = chunk.summary();
    if (summary.index != expected_index or
        summary.row_start != expected_index * session.options.rows or
        summary.oracle_start != expected_oracle_start or
        summary.rows != input.results.len or summary.mcycles == 0 or
        summary.callbacks == 0 or summary.actions != input.actions.len or
        summary.dma_source_bytes != input.dma_source_bytes.len)
    {
        return error.InvalidPokemonBattleBoundary;
    }
    if (final_segment and profile == .benchmark)
        try replay.validateBenchmarkOutcome(input.final_images.system.bytes);
    try actions.appendSlice(allocator, input.actions);

    var output = try prover.proveExecutionWithEngine(
        ProverEngine,
        allocator,
        pcs_config,
        input,
        .{},
    );
    var proof_owned = true;
    defer if (proof_owned) output.proof.deinit(allocator);
    if (output.statement.base.action_count != input.actions.len or
        output.statement.dma_execution_lookup_claims.execution_count !=
            summary.mcycles)
    {
        return error.InvalidPokemonBattleStatement;
    }
    const commitment_count =
        output.proof.commitment_scheme_proof.commitments.items.len;
    try rejectActionMutation(
        allocator,
        output.statement,
        input,
        commitment_count,
    );
    try rejectObservationMutation(
        allocator,
        output.statement,
        input,
        commitment_count,
    );
    try rejectFinalImageMutation(
        allocator,
        output.statement,
        input,
        commitment_count,
    );

    proof_owned = false;
    try verifier.verifyExecutionWithEngine(
        VerifierEngine,
        allocator,
        pcs_config,
        input.rom,
        input.initial_images,
        input.final_images,
        input.actions,
        input.observation_regions,
        input.intermediate_observations,
        output.statement,
        output.proof,
    );
    return .{
        .statement_value = output.statement,
        .counts = .{
            .rows = summary.rows,
            .mcycles = summary.mcycles,
            .callbacks = summary.callbacks,
            .actions = summary.actions,
            .dma_source_bytes = summary.dma_source_bytes,
        },
    };
}

fn rejectActionMutation(
    allocator: std.mem.Allocator,
    execution_statement: verifier.ExecutionStatement,
    input: prover.Input,
    commitment_count: usize,
) !void {
    if (input.actions.len == 0) return;
    const mutated = try allocator.dupe(action_schedule.Action, input.actions);
    defer allocator.free(mutated);
    mutated[0].pressed ^= 1;
    verifier.testing.validatePublicAndShape(
        execution_statement,
        input.rom,
        input.initial_images,
        input.final_images,
        mutated,
        input.observation_regions,
        input.intermediate_observations,
        commitment_count,
    ) catch |err| {
        if (err == error.ActionDigestMismatch) return;
        return err;
    };
    return error.ExpectedActionMutationRejection;
}

fn rejectObservationMutation(
    allocator: std.mem.Allocator,
    execution_statement: verifier.ExecutionStatement,
    input: prover.Input,
    commitment_count: usize,
) !void {
    const Sample = @import("air/intermediate_ram_observation_lookup.zig").Sample;
    const mutated = try allocator.dupe(Sample, input.intermediate_observations);
    defer allocator.free(mutated);
    mutated[0].expected ^= 1;
    verifier.testing.validatePublicAndShape(
        execution_statement,
        input.rom,
        input.initial_images,
        input.final_images,
        input.actions,
        input.observation_regions,
        mutated,
        commitment_count,
    ) catch |err| {
        if (err == error.IntermediateObservationDigestMismatch) return;
        return err;
    };
    return error.ExpectedObservationMutationRejection;
}

fn rejectFinalImageMutation(
    allocator: std.mem.Allocator,
    execution_statement: verifier.ExecutionStatement,
    input: prover.Input,
    commitment_count: usize,
) !void {
    const system = try allocator.create([memory_image.SIZE]u8);
    defer allocator.destroy(system);
    @memcpy(system, input.final_images.system.bytes);
    system[0xd357] ^= 1;
    var final_images = input.final_images;
    final_images.system = try memory_image.Image.init(system);
    verifier.testing.validatePublicAndShape(
        execution_statement,
        input.rom,
        input.initial_images,
        final_images,
        input.actions,
        input.observation_regions,
        input.intermediate_observations,
        commitment_count,
    ) catch |err| {
        if (err == error.FinalSystemDigestMismatch) return;
        return err;
    };
    return error.ExpectedFinalImageMutationRejection;
}

fn rejectJoinMutation(
    previous: prover.ExecutionStatement,
    next: prover.ExecutionStatement,
) !void {
    var mutated = next;
    mutated.base.base.initial.cpu.a ^= 1;
    chain.validate(previous, mutated) catch |err| {
        if (err == error.CpuBoundaryMismatch) return;
        return err;
    };
    return error.ExpectedJoiningEndpointMutationRejection;
}

fn configurationFor(profile: Profile) Configuration {
    return switch (profile) {
        .visual_prefix => .{
            .replay_profile = .visual,
            .rows = replay.DEFAULT_ROWS,
            .expectations = &replay.VERIFIED_PREFIX,
        },
        .benchmark => .{
            .replay_profile = .benchmark,
            .rows = 1 << 16,
            .expectations = &replay.BENCHMARK_PROOF_PREFIX,
        },
    };
}

fn addCounts(left: Counts, right: Counts) !Counts {
    return .{
        .rows = std.math.add(usize, left.rows, right.rows) catch
            return error.InvalidPokemonBattleChainCounts,
        .mcycles = std.math.add(u32, left.mcycles, right.mcycles) catch
            return error.InvalidPokemonBattleChainCounts,
        .callbacks = std.math.add(usize, left.callbacks, right.callbacks) catch
            return error.InvalidPokemonBattleChainCounts,
        .actions = std.math.add(usize, left.actions, right.actions) catch
            return error.InvalidPokemonBattleChainCounts,
        .dma_source_bytes = std.math.add(
            usize,
            left.dma_source_bytes,
            right.dma_source_bytes,
        ) catch return error.InvalidPokemonBattleChainCounts,
    };
}

fn validateTotals(
    profile: Profile,
    totals: Counts,
    action_count: usize,
    terminal: replay.FinishSummary,
) !void {
    const expected: Counts = switch (profile) {
        .visual_prefix => .{
            .rows = 393_216,
            .mcycles = 446_882,
            .callbacks = 42_302,
            .actions = 2,
            .dma_source_bytes = 4_000,
        },
        .benchmark => .{
            .rows = 786_432,
            .mcycles = 1_505_332,
            .callbacks = 601_239,
            .actions = 33,
            .dma_source_bytes = 13_600,
        },
    };
    const expected_lookahead: usize = switch (profile) {
        .visual_prefix => 7_468,
        .benchmark => 3_228,
    };
    const expected_lookahead_mcycles: u32 = switch (profile) {
        .visual_prefix => 7_475,
        .benchmark => 3_235,
    };
    if (!std.meta.eql(totals, expected) or totals.actions != action_count or
        terminal.actions != 0 or
        terminal.lookahead_rows != expected_lookahead or
        terminal.lookahead_mcycles != expected_lookahead_mcycles or
        terminal.oracle_records != totals.callbacks + 1)
    {
        return error.InvalidPokemonBattleChainCounts;
    }
}

test "Pokemon battle chain profiles pin independent power-of-two geometry" {
    const visual = configurationFor(.visual_prefix);
    const benchmark = configurationFor(.benchmark);
    try std.testing.expect(std.math.isPowerOfTwo(visual.rows));
    try std.testing.expect(std.math.isPowerOfTwo(benchmark.rows));
    try std.testing.expectEqual(@as(usize, 3), visual.expectations.len);
    try std.testing.expectEqual(@as(usize, 12), benchmark.expectations.len);
}

test "Pokemon proof readiness requires the production security floor" {
    try std.testing.expect(!proofReady(3));
    try std.testing.expect(proofReady(96));
}
