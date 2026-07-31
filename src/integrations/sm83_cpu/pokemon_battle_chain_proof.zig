//! CPU/SIMD proof for a streamed pinned Pokémon battle prefix.

const std = @import("std");
const core = @import("stwo_core");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_sm83_frontend");

const replay = frontend.pokemon_checkpoint_replay;
const battle_chain = frontend.pokemon_battle_chain;
const prover = frontend.machine_environment_prover;
const verifier = frontend.machine_environment_verifier;
const ProverEngine = prover.ProverEngineForBackend(CpuBackend);
const VerifierEngine = verifier.ProverEngineForBackend(CpuBackend);

const EXPECTED_THREE_CHUNK_ACTION_DIGEST: frontend.action_schedule.Digest = .{
    0x6e, 0xab, 0xf9, 0xe7, 0x57, 0x68, 0x4a, 0x8e,
    0x96, 0x3e, 0x9b, 0x8f, 0x42, 0x49, 0x1d, 0x3c,
    0xa2, 0x17, 0x1f, 0xaf, 0xe1, 0x57, 0x01, 0x41,
    0x55, 0x94, 0x94, 0xf8, 0x64, 0x96, 0x57, 0x24,
};
const DEFAULT_CHUNKS: usize = 3;
/// Operational argument bound only; it is not an authoritative battle end.
const MAX_CHUNKS: usize = 256;

const Counts = struct {
    rows: usize,
    mcycles: u32,
    callbacks: usize,
    actions: usize,
};

const Segment = struct {
    statement: prover.ExecutionStatement,
    counts: Counts,
};

const SecurityProfile = enum {
    secure,
    smoke,
};

const Options = struct {
    corpus_root: []const u8,
    security: SecurityProfile = .secure,
    chunks: usize = DEFAULT_CHUNKS,
    benchmark: bool = false,
};

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const arguments = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, arguments);
    const options = parseOptions(arguments) catch {
        std.debug.print(
            "usage: sm83-pokemon-cpu-battle-chain /path/to/PE-AGI/v1 " ++
                "[--benchmark] [--smoke] [--chunks N]\n",
            .{},
        );
        return error.InvalidArguments;
    };

    const config = try proofConfig(options.security);
    if (options.benchmark) {
        if (options.chunks != DEFAULT_CHUNKS)
            return error.BenchmarkChunkCountIsPinned;
        const receipt = try battle_chain.proveAndVerify(
            ProverEngine,
            VerifierEngine,
            allocator,
            config,
            options.corpus_root,
            .benchmark,
        );
        battle_chain.printReceipt("CPU", receipt);
        return;
    }
    var session = try replay.Session.init(
        allocator,
        options.corpus_root,
        .{},
    );
    defer session.deinit();
    var actions: std.ArrayList(frontend.action_schedule.Action) = .empty;
    defer actions.deinit(allocator);
    var previous: ?prover.ExecutionStatement = null;
    var initial_mcycle: ?u32 = null;
    var final_mcycle: ?u32 = null;
    var totals = Counts{ .rows = 0, .mcycles = 0, .callbacks = 0, .actions = 0 };
    for (0..options.chunks) |index| {
        const segment = try proveNextSegment(
            allocator,
            session,
            expectationFor(index),
            index,
            totals.callbacks,
            config,
            &actions,
        );
        if (previous) |first| {
            try frontend.machine_environment_chain.validate(
                first,
                segment.statement,
            );
            try rejectJoiningEndpointMutation(first, segment.statement);
        } else {
            initial_mcycle = segment.statement.base.base.initial.mcycle;
        }
        previous = segment.statement;
        final_mcycle = segment.statement.base.base.final.mcycle;
        totals = try addCounts(totals, segment.counts);
    }
    const terminal = try session.finish();
    try validateChainCounts(options.chunks, totals, actions.items.len, terminal);
    const outer_digest = try frontend.action_schedule.digest(
        initial_mcycle orelse return error.EmptyPokemonBattleChain,
        final_mcycle orelse return error.EmptyPokemonBattleChain,
        actions.items,
    );
    if (options.chunks == DEFAULT_CHUNKS and
        !std.mem.eql(
            u8,
            &outer_digest,
            &EXPECTED_THREE_CHUNK_ACTION_DIGEST,
        ))
    {
        return error.InvalidOuterActionDigest;
    }

    std.debug.print(
        "SM83 Pokemon CPU battle chain: PASS security_bits={d} rows={d} " ++
            "mcycles={d} callbacks={d} actions={d} chunks={d}\n",
        .{
            config.securityBits(),
            totals.rows,
            totals.mcycles,
            totals.callbacks,
            actions.items.len,
            options.chunks,
        },
    );
}

fn proveNextSegment(
    allocator: std.mem.Allocator,
    session: *replay.Session,
    expected: ?replay.Expectation,
    expected_index: usize,
    expected_oracle_start: usize,
    config: core.pcs.PcsConfig,
    actions: *std.ArrayList(frontend.action_schedule.Action),
) !Segment {
    var chunk = try session.next(expected);
    defer chunk.deinit();
    const input = chunk.input();
    const summary = chunk.summary();
    try validateChunkBoundary(
        summary,
        expected_index,
        expected_oracle_start,
    );
    if (summary.rows != replay.DEFAULT_ROWS or
        summary.rows != input.results.len or
        summary.mcycles == 0 or
        summary.callbacks == 0 or
        summary.actions != input.actions.len or
        summary.dma_source_bytes != input.dma_source_bytes.len)
    {
        return error.InvalidPokemonBattleCounts;
    }
    try actions.appendSlice(allocator, input.actions);

    var output = try prover.proveExecutionWithEngine(
        ProverEngine,
        allocator,
        config,
        input,
        .{},
    );
    var proof_owned = true;
    defer if (proof_owned) output.proof.deinit(allocator);
    if (output.statement.base.action_count !=
        @as(u32, @intCast(input.actions.len)) or
        output.statement.dma_execution_lookup_claims.execution_count !=
            summary.mcycles)
    {
        return error.InvalidPokemonBattleStatement;
    }

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
    return .{
        .statement = output.statement,
        .counts = .{
            .rows = summary.rows,
            .mcycles = summary.mcycles,
            .callbacks = summary.callbacks,
            .actions = summary.actions,
        },
    };
}

fn parseOptions(arguments: []const []const u8) !Options {
    if (arguments.len < 2) return error.InvalidArguments;
    if (arguments[1].len == 0 or
        std.mem.startsWith(u8, arguments[1], "--"))
    {
        return error.InvalidArguments;
    }
    var result = Options{ .corpus_root = arguments[1] };
    var saw_smoke = false;
    var saw_chunks = false;
    var saw_benchmark = false;
    var index: usize = 2;
    while (index < arguments.len) {
        const argument = arguments[index];
        if (std.mem.eql(u8, argument, "--smoke") and !saw_smoke) {
            saw_smoke = true;
            result.security = .smoke;
            index += 1;
            continue;
        }
        if (std.mem.eql(u8, argument, "--benchmark") and !saw_benchmark) {
            saw_benchmark = true;
            result.benchmark = true;
            index += 1;
            continue;
        }
        if (std.mem.eql(u8, argument, "--chunks") and !saw_chunks) {
            if (index + 1 >= arguments.len) return error.InvalidArguments;
            const chunks = std.fmt.parseUnsigned(
                usize,
                arguments[index + 1],
                10,
            ) catch return error.InvalidArguments;
            if (chunks == 0 or chunks > MAX_CHUNKS)
                return error.InvalidArguments;
            saw_chunks = true;
            result.chunks = chunks;
            index += 2;
            continue;
        }
        return error.InvalidArguments;
    }
    return result;
}

fn expectationFor(index: usize) ?replay.Expectation {
    if (index >= replay.VERIFIED_PREFIX.len) return null;
    return replay.VERIFIED_PREFIX[index];
}

fn validateChunkBoundary(
    summary: replay.Summary,
    expected_index: usize,
    expected_oracle_start: usize,
) !void {
    const expected_row_start = std.math.mul(
        usize,
        expected_index,
        replay.DEFAULT_ROWS,
    ) catch return error.InvalidPokemonBattleBoundary;
    if (summary.index != expected_index or
        summary.row_start != expected_row_start or
        summary.oracle_start != expected_oracle_start)
    {
        return error.InvalidPokemonBattleBoundary;
    }
}

fn addCounts(left: Counts, right: Counts) !Counts {
    return .{
        .rows = std.math.add(usize, left.rows, right.rows) catch
            return error.InvalidPokemonBattleChainCounts,
        .mcycles = std.math.add(u32, left.mcycles, right.mcycles) catch
            return error.InvalidPokemonBattleChainCounts,
        .callbacks = std.math.add(
            usize,
            left.callbacks,
            right.callbacks,
        ) catch return error.InvalidPokemonBattleChainCounts,
        .actions = std.math.add(usize, left.actions, right.actions) catch
            return error.InvalidPokemonBattleChainCounts,
    };
}

fn validateChainCounts(
    chunks: usize,
    totals: Counts,
    action_count: usize,
    terminal: replay.FinishSummary,
) !void {
    const expected_rows = std.math.mul(
        usize,
        chunks,
        replay.DEFAULT_ROWS,
    ) catch return error.InvalidPokemonBattleChainCounts;
    const expected_records = std.math.add(
        usize,
        totals.callbacks,
        1,
    ) catch return error.InvalidPokemonBattleChainCounts;
    if (totals.rows != expected_rows or
        totals.mcycles == 0 or
        totals.callbacks == 0 or
        totals.actions != action_count or
        terminal.lookahead_rows == 0 or
        terminal.oracle_records != expected_records or
        terminal.actions != 0)
    {
        return error.InvalidPokemonBattleChainCounts;
    }
    if (chunks == DEFAULT_CHUNKS and
        (totals.mcycles != 446_882 or
            totals.callbacks != 42_302 or
            totals.actions != 2 or
            terminal.lookahead_rows != 7_468))
    {
        return error.InvalidPokemonBattleChainCounts;
    }
}

fn rejectJoiningEndpointMutation(
    first: prover.ExecutionStatement,
    second: prover.ExecutionStatement,
) !void {
    var mutated = second;
    mutated.base.base.initial.cpu.a ^= 1;
    frontend.machine_environment_chain.validate(first, mutated) catch |err| {
        if (err == error.CpuBoundaryMismatch) return;
        return err;
    };
    return error.ExpectedJoiningEndpointMutationRejection;
}

fn proofConfig(profile: SecurityProfile) !core.pcs.PcsConfig {
    const config: core.pcs.PcsConfig = switch (profile) {
        .secure => .{
            .pow_bits = 26,
            .fri_config = try core.fri.FriConfig.init(0, 1, 70),
        },
        .smoke => .{
            .pow_bits = 0,
            .fri_config = try core.fri.FriConfig.init(0, 1, 3),
        },
    };
    const expected: u32 = switch (profile) {
        .secure => 96,
        .smoke => 3,
    };
    if (config.securityBits() != expected)
        return error.InvalidPokemonBattleSecurity;
    return config;
}

test "SM83 Pokemon battle chain is secure by default and smoke is explicit" {
    const secure = try parseOptions(&.{ "battle-chain", "/corpus" });
    try std.testing.expectEqual(SecurityProfile.secure, secure.security);
    try std.testing.expectEqual(@as(usize, DEFAULT_CHUNKS), secure.chunks);
    try std.testing.expectEqualStrings("/corpus", secure.corpus_root);
    try std.testing.expectEqual(
        @as(u32, 96),
        (try proofConfig(secure.security)).securityBits(),
    );

    const smoke = try parseOptions(&.{
        "battle-chain",
        "/corpus",
        "--smoke",
        "--chunks",
        "17",
    });
    try std.testing.expectEqual(SecurityProfile.smoke, smoke.security);
    try std.testing.expectEqual(@as(usize, 17), smoke.chunks);
    try std.testing.expectEqual(
        @as(u32, 3),
        (try proofConfig(smoke.security)).securityBits(),
    );

    const benchmark = try parseOptions(&.{
        "battle-chain",
        "/corpus",
        "--benchmark",
    });
    try std.testing.expect(benchmark.benchmark);
    try std.testing.expectEqual(SecurityProfile.secure, benchmark.security);

    try std.testing.expectError(
        error.InvalidArguments,
        parseOptions(&.{"battle-chain"}),
    );
    try std.testing.expectError(
        error.InvalidArguments,
        parseOptions(&.{ "battle-chain", "" }),
    );
    try std.testing.expectError(
        error.InvalidArguments,
        parseOptions(&.{ "battle-chain", "--smoke" }),
    );
    try std.testing.expectError(
        error.InvalidArguments,
        parseOptions(&.{ "battle-chain", "/corpus", "--secure" }),
    );
    try std.testing.expectError(
        error.InvalidArguments,
        parseOptions(&.{ "battle-chain", "/corpus", "--smoke", "--smoke" }),
    );
}

test "SM83 Pokemon battle chunk count is positive bounded and order independent" {
    const minimum = try parseOptions(&.{
        "battle-chain",
        "/corpus",
        "--chunks",
        "1",
    });
    try std.testing.expectEqual(@as(usize, 1), minimum.chunks);
    const maximum = try parseOptions(&.{
        "battle-chain",
        "/corpus",
        "--chunks",
        "256",
        "--smoke",
    });
    try std.testing.expectEqual(@as(usize, MAX_CHUNKS), maximum.chunks);
    try std.testing.expectEqual(SecurityProfile.smoke, maximum.security);

    inline for (.{
        &.{ "battle-chain", "/corpus", "--chunks" },
        &.{ "battle-chain", "/corpus", "--chunks", "0" },
        &.{ "battle-chain", "/corpus", "--chunks", "257" },
        &.{ "battle-chain", "/corpus", "--chunks", "nope" },
        &.{
            "battle-chain",
            "/corpus",
            "--chunks",
            "1",
            "--chunks",
            "2",
        },
    }) |arguments| {
        try std.testing.expectError(
            error.InvalidArguments,
            parseOptions(arguments),
        );
    }
}

test "SM83 Pokemon battle chunk boundaries and pinned frontier fail closed" {
    try std.testing.expect(expectationFor(0) != null);
    try std.testing.expect(expectationFor(DEFAULT_CHUNKS - 1) != null);
    try std.testing.expect(expectationFor(DEFAULT_CHUNKS) == null);

    var summary = std.mem.zeroes(replay.Summary);
    summary.index = 2;
    summary.row_start = 2 * replay.DEFAULT_ROWS;
    summary.oracle_start = 33_924;
    try validateChunkBoundary(summary, 2, 33_924);
    summary.row_start -= 1;
    try std.testing.expectError(
        error.InvalidPokemonBattleBoundary,
        validateChunkBoundary(summary, 2, 33_924),
    );
}
