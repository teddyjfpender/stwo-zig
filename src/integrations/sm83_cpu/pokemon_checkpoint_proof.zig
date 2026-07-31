//! CPU/SIMD proof gate for the first hash-pinned Pokémon checkpoint slice.

const std = @import("std");
const core = @import("stwo_core");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_sm83_frontend");

const fixture_mod = frontend.pokemon_checkpoint_fixture;
const prover = frontend.machine_environment_prover;
const verifier = frontend.machine_environment_verifier;
const ProverEngine = prover.ProverEngineForBackend(CpuBackend);
const VerifierEngine = verifier.ProverEngineForBackend(CpuBackend);

const SecurityProfile = enum {
    smoke,
    secure,
};

const Options = struct {
    security: SecurityProfile = .secure,
    fixture: fixture_mod.Profile = .short,
};

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const arguments = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, arguments);
    const options = parseOptions(arguments) catch {
        std.debug.print(
            "usage: sm83-pokemon-cpu-proof /path/to/PE-AGI/v1 " ++
                "[--proof-fast|--proof-fast-dma-probe|" ++
                "--proof-fast-chunk-1|" ++
                "--proof-fast-chunk-2|--proof-fast-turn|" ++
                "--start-release|" ++
                "--battle-chunk-1|--battle-chunk-2] " ++
                "[--smoke]\n",
            .{},
        );
        return error.InvalidArguments;
    };

    var fixture = try fixture_mod.Fixture.loadProfile(
        allocator,
        arguments[1],
        options.fixture,
    );
    defer fixture.deinit();
    const input = fixture.input();
    const summary = fixture.summary();
    const config = try proofConfig(options.security);
    var output = try prover.proveExecutionWithEngine(
        ProverEngine,
        allocator,
        config,
        input,
        .{},
    );
    var proof_owned = true;
    defer if (proof_owned) output.proof.deinit(allocator);

    try validatePositiveCounts(
        output.statement,
        input,
        summary,
        options.fixture,
    );
    try rejectObservationMutation(
        allocator,
        output.statement,
        input,
        output.proof.commitment_scheme_proof.commitments.items.len,
    );
    try rejectActionMutation(
        allocator,
        output.statement,
        input,
        output.proof.commitment_scheme_proof.commitments.items.len,
    );

    proof_owned = false;
    try verifier.verifyExecutionWithEngine(
        VerifierEngine,
        allocator,
        config,
        input.rom,
        input.initial_images,
        input.final_images,
        input.actions,
        input.observation_regions,
        input.intermediate_observations,
        output.statement,
        output.proof,
    );
    std.debug.print(
        "SM83 Pokemon CPU proof: PASS profile={s} fixture_profile={s} " ++
            "security_bits={d} rows={d} mcycles={d} callbacks={d} " ++
            "actions={d} dma_sources={d} apu_events={d} observations={d}\n",
        .{
            @tagName(options.security),
            @tagName(options.fixture),
            config.securityBits(),
            input.results.len,
            summary.mcycles,
            summary.callbacks,
            input.actions.len,
            input.dma_source_bytes.len,
            output.statement.apu_execution_lookup_claims.apu_count,
            input.intermediate_observations.len,
        },
    );
}

fn parseOptions(arguments: []const []const u8) !Options {
    if (arguments.len < 2 or
        arguments[1].len == 0 or
        std.mem.startsWith(u8, arguments[1], "--"))
        return error.InvalidArguments;
    var result = Options{};
    var saw_smoke = false;
    var saw_fixture = false;
    for (arguments[2..]) |argument| {
        if (std.mem.eql(u8, argument, "--smoke") and !saw_smoke) {
            saw_smoke = true;
            result.security = .smoke;
        } else if (std.mem.eql(u8, argument, "--start-release") and
            !saw_fixture)
        {
            saw_fixture = true;
            result.fixture = .start_release;
        } else if (std.mem.eql(u8, argument, "--proof-fast") and
            !saw_fixture)
        {
            saw_fixture = true;
            result.fixture = .proof_fast_short;
        } else if (std.mem.eql(u8, argument, "--proof-fast-dma-probe") and
            !saw_fixture)
        {
            saw_fixture = true;
            result.fixture = .proof_fast_dma_probe;
        } else if (std.mem.eql(u8, argument, "--proof-fast-chunk-1") and
            !saw_fixture)
        {
            saw_fixture = true;
            result.fixture = .proof_fast_chunk_1;
        } else if (std.mem.eql(u8, argument, "--proof-fast-chunk-2") and
            !saw_fixture)
        {
            saw_fixture = true;
            result.fixture = .proof_fast_chunk_2;
        } else if (std.mem.eql(u8, argument, "--proof-fast-turn") and
            !saw_fixture)
        {
            saw_fixture = true;
            result.fixture = .proof_fast_turn;
        } else if (std.mem.eql(u8, argument, "--battle-chunk-1") and
            !saw_fixture)
        {
            saw_fixture = true;
            result.fixture = .battle_chunk_1;
        } else if (std.mem.eql(u8, argument, "--battle-chunk-2") and
            !saw_fixture)
        {
            saw_fixture = true;
            result.fixture = .battle_chunk_2;
        } else return error.InvalidArguments;
    }
    return result;
}

fn validatePositiveCounts(
    statement: prover.ExecutionStatement,
    input: prover.Input,
    summary: fixture_mod.Summary,
    profile: fixture_mod.Profile,
) !void {
    const expected_log_size: u32 = switch (profile) {
        .short => 12,
        .proof_fast_short => 13,
        .proof_fast_dma_probe => 14,
        .proof_fast_chunk_1, .proof_fast_chunk_2, .start_release, .battle_chunk_1, .battle_chunk_2 => 17,
        .proof_fast_turn => 18,
    };
    const expected_actions: usize = switch (profile) {
        .short, .proof_fast_short, .proof_fast_dma_probe, .proof_fast_chunk_1, .battle_chunk_1 => 0,
        .proof_fast_chunk_2, .start_release, .battle_chunk_2 => 1,
        .proof_fast_turn => 2,
    };
    if (statement.base.base.log_size != expected_log_size or
        summary.rows != input.results.len or
        summary.callbacks == 0 or
        summary.mcycles == 0 or
        summary.dma_source_bytes != input.dma_source_bytes.len or
        input.actions.len != expected_actions or
        statement.dma_execution_lookup_claims.execution_count !=
            summary.mcycles or
        statement.dma_execution_lookup_claims.dma_count != summary.mcycles or
        statement.base.action_count !=
            @as(u32, @intCast(input.actions.len)) or
        statement.base.observation_region_count !=
            @as(u32, @intCast(input.observation_regions.len)) or
        statement.base.intermediate_observation_schedule_claim.count !=
            @as(u32, @intCast(input.intermediate_observations.len)))
    {
        return error.InvalidPokemonProofCounts;
    }
}

fn rejectObservationMutation(
    allocator: std.mem.Allocator,
    statement: verifier.ExecutionStatement,
    input: prover.Input,
    commitment_count: usize,
) !void {
    const Sample = frontend.air.intermediate_ram_observation_lookup.Sample;
    const mutated = try allocator.dupe(
        Sample,
        input.intermediate_observations,
    );
    defer allocator.free(mutated);
    mutated[0].expected ^= 1;
    verifier.testing.validatePublicAndShape(
        statement,
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

fn rejectActionMutation(
    allocator: std.mem.Allocator,
    statement: verifier.ExecutionStatement,
    input: prover.Input,
    commitment_count: usize,
) !void {
    if (input.actions.len == 0) return;
    const mutated = try allocator.dupe(
        frontend.action_schedule.Action,
        input.actions,
    );
    defer allocator.free(mutated);
    mutated[0].pressed ^= 1;
    verifier.testing.validatePublicAndShape(
        statement,
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

fn proofConfig(profile: SecurityProfile) !core.pcs.PcsConfig {
    const config: core.pcs.PcsConfig = switch (profile) {
        .smoke => .{
            .pow_bits = 0,
            .fri_config = try core.fri.FriConfig.init(0, 1, 3),
        },
        .secure => .{
            .pow_bits = 26,
            .fri_config = try core.fri.FriConfig.init(0, 1, 70),
        },
    };
    const expected: u32 = switch (profile) {
        .smoke => 3,
        .secure => 96,
    };
    if (config.securityBits() != expected)
        return error.InvalidPokemonProofSecurity;
    return config;
}

test "SM83 Pokemon checkpoint proof defaults to the secure profile" {
    const arguments = [_][]const u8{
        "sm83-pokemon-cpu-proof",
        "/path/to/PE-AGI/v1",
    };
    const options = try parseOptions(&arguments);
    const config = try proofConfig(options.security);

    try std.testing.expectEqual(SecurityProfile.secure, options.security);
    try std.testing.expectEqual(@as(u32, 96), config.securityBits());
    try std.testing.expectEqual(fixture_mod.Profile.short, options.fixture);
}

test "SM83 Pokemon checkpoint proof smoke profile requires an explicit flag" {
    const arguments = [_][]const u8{
        "sm83-pokemon-cpu-proof",
        "/path/to/PE-AGI/v1",
        "--smoke",
    };
    const options = try parseOptions(&arguments);
    const config = try proofConfig(options.security);

    try std.testing.expectEqual(SecurityProfile.smoke, options.security);
    try std.testing.expectEqual(@as(u32, 3), config.securityBits());

    const fast_arguments = [_][]const u8{
        "sm83-pokemon-cpu-proof",
        "/path/to/PE-AGI/v1",
        "--proof-fast",
        "--smoke",
    };
    const fast = try parseOptions(&fast_arguments);
    try std.testing.expectEqual(
        fixture_mod.Profile.proof_fast_short,
        fast.fixture,
    );
    const dma_probe = try parseOptions(&.{
        "sm83-pokemon-cpu-proof",
        "/path/to/PE-AGI/v1",
        "--proof-fast-dma-probe",
    });
    try std.testing.expectEqual(
        fixture_mod.Profile.proof_fast_dma_probe,
        dma_probe.fixture,
    );
    const fast_chunk = try parseOptions(&.{
        "sm83-pokemon-cpu-proof",
        "/path/to/PE-AGI/v1",
        "--proof-fast-chunk-2",
    });
    try std.testing.expectEqual(
        fixture_mod.Profile.proof_fast_chunk_2,
        fast_chunk.fixture,
    );
}

test "SM83 Pokemon checkpoint proof rejects duplicate and unknown flags" {
    const duplicate_smoke = [_][]const u8{
        "sm83-pokemon-cpu-proof",
        "/path/to/PE-AGI/v1",
        "--smoke",
        "--smoke",
    };
    try std.testing.expectError(
        error.InvalidArguments,
        parseOptions(&duplicate_smoke),
    );

    const duplicate_fixture = [_][]const u8{
        "sm83-pokemon-cpu-proof",
        "/path/to/PE-AGI/v1",
        "--start-release",
        "--battle-chunk-1",
    };
    try std.testing.expectError(
        error.InvalidArguments,
        parseOptions(&duplicate_fixture),
    );

    const retired_secure = [_][]const u8{
        "sm83-pokemon-cpu-proof",
        "/path/to/PE-AGI/v1",
        "--secure",
    };
    try std.testing.expectError(
        error.InvalidArguments,
        parseOptions(&retired_secure),
    );

    const unknown = [_][]const u8{
        "sm83-pokemon-cpu-proof",
        "/path/to/PE-AGI/v1",
        "--unknown",
    };
    try std.testing.expectError(error.InvalidArguments, parseOptions(&unknown));

    const missing_path = [_][]const u8{
        "sm83-pokemon-cpu-proof",
        "--smoke",
    };
    try std.testing.expectError(
        error.InvalidArguments,
        parseOptions(&missing_path),
    );
}
